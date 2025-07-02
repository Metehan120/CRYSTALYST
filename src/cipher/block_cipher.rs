use std::{sync::Arc, time::Instant};

use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Sha3_512};
use subtle::{ConstantTimeEq, ConstantTimeLess};

#[cfg(feature = "key_derivation")]
use crate::derive_password_key;

use crate::{
    Config, Errors, KeyBuffer, RoundKeyBuffer, VERSION, calculate_hmac,
    engine::{
        cache_warmup::{CacheWarmup, CacheWarmup64},
        engine::{
            GaloisField, apply_gf, ctr_decrypt, ctr_encrypt, generate_dynamic_sbox,
            generate_inv_s_box, in_s_bytes, inverse_shift_rows, rxa_decrypt, rxa_encrypt, s_bytes,
            shift_rows,
        },
    },
    generate_recovery_key, parse_recovery_key,
    rng_utils::{
        nonce::{AsNonce, NonceData},
        salt::{AsSalt, Salt},
    },
    secure_zeroize,
    utils::base_utils::AsBase,
};

fn encrypt<'a>(
    password: &[u8],
    data: &'a [u8],
    nonce: NonceData,
    config: Config,
    custom_salt: Option<Salt>,
    wrap_all: bool,
    recovery_key: Option<bool>,
    output_buffer: &mut Vec<u8>,
) -> Result<(), Errors> {
    let mut data = data.to_vec();

    let estimated_size = data.len() + nonce.as_bytes().len() + VERSION.len() + 64 + 32;

    output_buffer.clear();
    output_buffer.reserve(estimated_size);

    let mut hash_data = Sha3_512::new();
    hash_data.update(&data);
    let data_for_mac = hash_data.finalize();

    if password.len().ct_ne(&0).unwrap_u8() != 1 {
        return Err(Errors::EmptyPassword);
    } else if (password.len() as u32).ct_lt(&32).unwrap_u8() == 1 {
        return Err(Errors::PasswordTooShort(format!(
            "Password must be at least {} characters for cryptographic strength.",
            32
        )));
    }

    let nonce = nonce.as_bytes();

    #[cfg(feature = "key_derivation")]
    let key = if config.key_derivation {
        let pwd = derive_password_key(password, nonce, custom_salt, config, 32 as u64)?;
        KeyBuffer::new(pwd)
    } else {
        KeyBuffer::new(password.to_vec())
    };

    #[cfg(not(feature = "key_derivation"))]
    let key = KeyBuffer::new(password.to_vec());

    let mut buffer = [0u8; 64];
    let pwd: Vec<u8> = key.expose_secret().iter().take(64).cloned().collect();
    let sbox = generate_dynamic_sbox(nonce, key.expose_secret(), config)?;
    let inv_sbox = generate_inv_s_box(&sbox);
    buffer[..pwd.len()].copy_from_slice(&pwd);
    let pwd = CacheWarmup64::new(buffer, sbox, inv_sbox);
    if config.hardware.warmup_cache {
        pwd.warm_cache();
    }

    if let Some(recovery_key) = recovery_key {
        if recovery_key == true {
            println!("Recovery Key: {}", generate_recovery_key(&pwd.key, nonce));
        }
    }

    let gf = Arc::new(GaloisField::new(config.gf_poly.value()));

    if wrap_all {
        output_buffer.extend_from_slice(nonce);
    }

    {
        let mut version = VERSION.to_vec();
        rxa_encrypt(&pwd, &mut version, config)?;
        output_buffer.extend_from_slice(&version);
    }

    rxa_encrypt(&pwd, &mut data, config)?;

    s_bytes(&mut data, &pwd, config)?;

    rxa_encrypt(&pwd, &mut data, config)?;

    apply_gf(&mut data, &config, &gf, nonce)?;

    shift_rows(&mut data, &config);

    s_bytes(&mut data, &pwd, config)?;

    let mut round_key_buffer = RoundKeyBuffer::new(vec![0u8; 64]);

    for i in 1..=config.rounds {
        let slice_end = std::cmp::min(i * 32, 64);
        let round_key = {
            let mut hash = Sha3_512::new();
            hash.update(&pwd.key[..slice_end]);
            let result = hash.finalize();
            round_key_buffer.0.copy_from_slice(&result);
            &round_key_buffer.0
        };

        let mut buffer = [0u8; 64];
        buffer.copy_from_slice(&round_key);
        let round_key = &CacheWarmup64 {
            key: buffer,
            sbox: [0u8; 256],
            inv_sbox: [0u8; 256],
        };
        if config.hardware.warmup_cache {
            round_key.warm_cache();
        }

        data.chunks_mut(1024 * 1024)
            .try_for_each(|chunk| -> Result<(), Errors> {
                rxa_encrypt(&round_key, chunk, config)?;
                match config.multi_round_galois_field {
                    true => apply_gf(chunk, &config, &gf, nonce)?,
                    false => {
                        if i == 1 {
                            apply_gf(chunk, &config, &gf, nonce)?;
                        }
                    }
                }
                Ok(())
            })?;
    }

    drop(round_key_buffer);

    if config.ctr_layer && data.len() >= 128 {
        let mut iv = [0u8; 32];
        iv.clone_from_slice(&nonce[0..32]);
        ctr_encrypt(nonce, &mut data, &iv);
    }

    let mut hash_data = Sha3_512::new();
    hash_data.update(&data);
    let mac_data_1 = hash_data.finalize().to_vec();
    let meta_data = vec![0xac, 0x07, 0x13, 0x00];

    let total_len =
        mac_data_1.len() + mac_data_1.len() + VERSION.len() + meta_data.len() + nonce.len();

    let mut mac_data = Vec::with_capacity(total_len);
    mac_data.extend_from_slice(&data_for_mac);
    mac_data.extend_from_slice(&mac_data_1);
    mac_data.extend_from_slice(VERSION);
    mac_data.extend_from_slice(&meta_data);
    mac_data.extend_from_slice(nonce);
    let mac = calculate_hmac(&pwd.key, &mac_data)?;

    drop(pwd);

    output_buffer.extend_from_slice(&data);
    output_buffer.extend_from_slice(&mac);

    secure_zeroize(&mut data, &config);

    if wrap_all {
        if custom_salt.is_some() {
            output_buffer.extend_from_slice(
                custom_salt
                    .ok_or(Errors::BuildFailed("Cannot Open Salt".to_string()))?
                    .as_bytes(),
            );
        } else {
            output_buffer.extend_from_slice(nonce);
        }
    }

    Ok(())
}

// -----------------------------------------------------

fn decrypt<'a>(
    password: &[u8],
    data: &'a [u8],
    nonce: Option<NonceData>,
    config: Config,
    custom_salt: Option<Salt>,
    wrap_all: bool,
    recovery_key: Option<SecretBox<[u8]>>,
    output_buffer: &mut Vec<u8>,
) -> Result<(), Errors> {
    #[cfg(feature = "key_derivation")]
    let (nonce_data, custom_salt) = if let Some(nonce) = nonce {
        (nonce, custom_salt)
    } else {
        let (_, custom_salt) = data.split_at(data.len() - 32);
        let (nonce, _) = data.split_at(32);

        (nonce.as_nonce(), Option::from(custom_salt.as_salt()))
    };

    #[cfg(not(feature = "key_derivation"))]
    let (nonce_data, _) = if let Some(nonce) = nonce {
        (nonce, custom_salt)
    } else {
        let (_, custom_salt) = data.split_at(data.len() - 32);
        let (nonce, _) = data.split_at(32);

        (nonce.as_nonce(), Option::from(custom_salt.as_salt()))
    };

    output_buffer.clear();

    let nonce_byte = nonce_data.as_bytes();

    #[cfg(feature = "key_derivation")]
    let pwd = if config.key_derivation {
        let pwd = derive_password_key(password, nonce_byte, custom_salt, config, 64)?;
        pwd
    } else {
        password.to_vec()
    };

    #[cfg(not(feature = "key_derivation"))]
    let pwd = password.to_vec();

    let key = if let Some(key) = recovery_key {
        KeyBuffer::new(parse_recovery_key(
            &key.expose_secret().to_vec().as_string(),
            nonce_byte,
        )?)
    } else {
        KeyBuffer::new(pwd)
    };

    let mut buffer = [0u8; 64];
    let pwd: Vec<u8> = key.expose_secret().iter().take(64).cloned().collect();
    let sbox = generate_dynamic_sbox(nonce_byte, key.expose_secret(), config)?;
    let inv_sbox = generate_inv_s_box(&sbox);
    buffer[..pwd.len()].copy_from_slice(&pwd);
    let mut pwd = CacheWarmup64::new(buffer, sbox, inv_sbox);
    if config.hardware.warmup_cache {
        pwd.warm_cache();
    }

    if data.len() < 32 + VERSION.len() {
        return Err(Errors::InvalidMac("Data is too short".to_string()));
    }

    let version_len = VERSION.len();
    let mut wrapped = false;

    let (rest, encrypted_version) = if nonce.is_some() && !wrap_all {
        let (encrypted_version, rest) = data.split_at(version_len);

        (rest, encrypted_version)
    } else {
        let (_, rest) = data.split_at(32);
        let (encrypted_version, rest) = rest.split_at(version_len);

        wrapped = true;
        (rest, encrypted_version)
    };

    let mut encrypted_version = encrypted_version.to_vec();
    rxa_decrypt(&pwd, &mut encrypted_version, config)?;

    if !encrypted_version.starts_with(b"CRYSTALYST-version") {
        secure_zeroize(&mut pwd.key, &config);
        return Err(Errors::InvalidAlgorithm);
    }

    if encrypted_version.starts_with(b"CRYSTALYST-version:0x8") {
        secure_zeroize(&mut pwd.inv_sbox, &config);
        return Err(Errors::NotBackwardCompatible);
    }

    let (mut crypted, mac_key) = if encrypted_version.starts_with(b"CRYSTALYST-version") && wrapped
    {
        let (data_without_salt, _) = rest.split_at(rest.len() - 32);
        let (crypted, mac_key) = data_without_salt.split_at(data_without_salt.len() - 64);
        (crypted.to_vec(), mac_key.to_vec())
    } else {
        let (crypted, mac_key) = rest.split_at(rest.len() - 64);
        (crypted.to_vec(), mac_key.to_vec())
    };

    let mut hash_data = Sha3_512::new();
    hash_data.update(&crypted);
    let mac_data_1 = hash_data.finalize().to_vec();

    if config.ctr_layer && crypted.len() >= 128 {
        let mut iv = [0u8; 32];
        iv.clone_from_slice(&nonce_byte[0..32]);
        ctr_decrypt(nonce_byte, &mut crypted, &iv);
    }

    let gf = Arc::new(GaloisField::new(config.gf_poly.value()));

    let mut round_key_buffer = RoundKeyBuffer::new(vec![0u8; 64]);

    for i in (1..=config.rounds).rev() {
        let slice_end = std::cmp::min(i * 32, 64);

        let round_key = {
            let mut hash = Sha3_512::new();
            hash.update(&pwd.key[..slice_end]);
            let result = hash.finalize();
            round_key_buffer.0.copy_from_slice(&result);
            &round_key_buffer.0
        };

        let mut buffer = [0u8; 64];
        buffer.copy_from_slice(&round_key);
        let round_key = CacheWarmup64 {
            key: buffer,
            sbox: [0u8; 256],
            inv_sbox: [0u8; 256],
        };

        if config.hardware.warmup_cache {
            round_key.warm_cache();
        }

        crypted
            .chunks_mut(1024 * 1024)
            .try_for_each(|chunk| -> Result<(), Errors> {
                match config.multi_round_galois_field {
                    true => apply_gf(chunk, &config, &gf, nonce_byte)?,
                    false => {
                        if i == 1 {
                            apply_gf(chunk, &config, &gf, nonce_byte)?;
                        }
                    }
                }

                rxa_decrypt(&round_key, chunk, config)?;
                Ok(())
            })?;
    }

    drop(round_key_buffer);

    in_s_bytes(&mut crypted, &pwd, config)?;

    inverse_shift_rows(&mut crypted, &config);

    apply_gf(&mut crypted, &config, &gf, nonce_byte)?;

    rxa_decrypt(&pwd, &mut crypted, config)?;

    in_s_bytes(&mut crypted, &pwd, config)?;

    rxa_decrypt(&pwd, &mut crypted, config)?;

    let metdata = vec![0xac, 0x07, 0x13, 0x00];
    let mut hash_data = Sha3_512::new();
    hash_data.update(&crypted);
    let mac_data_2 = hash_data.finalize();

    let total_len = mac_data_2.len()
        + mac_data_1.len()
        + encrypted_version.len()
        + metdata.len()
        + nonce_byte.len();

    let mut mac_data = Vec::with_capacity(total_len);
    mac_data.extend_from_slice(&mac_data_2);
    mac_data.extend_from_slice(&mac_data_1);
    mac_data.extend_from_slice(&encrypted_version);
    mac_data.extend_from_slice(&metdata);
    mac_data.extend_from_slice(nonce_byte);
    let mut mac = calculate_hmac(&pwd.key, &mac_data)?;

    if mac.ct_eq(&mac_key).unwrap_u8() != 1 {
        secure_zeroize(&mut crypted, &config);
        secure_zeroize(&mut mac, &config);
        secure_zeroize(&mut mac_data, &config);
        return Err(Errors::InvalidMac("Invalid authentication".to_string()));
    }

    secure_zeroize(&mut mac_data, &config);

    output_buffer.reserve(crypted.len());
    output_buffer.extend_from_slice(&crypted);

    Ok(())
}

// -----------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Utils {
    pub benchmark: bool,
    pub recovery_key: Option<bool>,
    pub wrap_all: bool,
}

impl Utils {
    pub fn new() -> Self {
        Self {
            recovery_key: None,
            benchmark: false,
            wrap_all: false,
        }
    }

    pub fn benchmark(mut self, benchmark: bool) -> Self {
        self.benchmark = benchmark;
        self
    }

    pub fn recovery_key(mut self, recovery_key: bool) -> Self {
        self.recovery_key = Some(recovery_key);
        self
    }

    pub fn wrap_all(mut self, wrap_all: bool) -> Self {
        self.wrap_all = wrap_all;
        self
    }
}

/// ### Builder for CRYSTALYST
/// - You can encrypte & decrypte data using the builder.
pub struct CrystalystBuilder<'a> {
    config: Option<Config>,
    data: Option<&'a [u8]>,
    password: Option<SecretBox<[u8]>>,
    nonce: Option<NonceData>,
    salt: Option<Salt>,
    decryption_key: Option<SecretBox<[u8]>>,
    utils: Option<Utils>,
}

impl<'a> CrystalystBuilder<'a> {
    /// Creates a new instance of CrystalystBuilder.
    pub fn new() -> Self {
        Self {
            password: None,
            data: None,
            config: None,
            nonce: None,
            salt: None,
            decryption_key: None,
            utils: None,
        }
    }

    /// Sets the data to be encrypted.
    /// -  Recommended using '&' when using `Vector<u8>`.
    pub fn data(mut self, data: &'a [u8]) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets the configuration for the encryption.
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the password for the encryption.
    pub fn password(mut self, password: &[u8]) -> Self {
        self.password = Some(SecretBox::new(password.to_vec().into_boxed_slice()));
        self
    }

    /// Sets the nonce for the encryption.
    pub fn nonce(mut self, nonce: NonceData) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the salt for the encryption.
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the recovery decryption key for the decryption.
    pub fn decrypt_from_recovery_key(mut self, decryption_key: String) -> Self {
        self.decryption_key = Some(SecretBox::new(
            decryption_key.as_bytes().to_vec().into_boxed_slice(),
        ));
        self
    }

    pub fn utils(mut self, utils: Utils) -> Self {
        self.utils = Some(utils);
        self
    }

    /// Encrypts the data using the provided configuration, password, and nonce.
    /// - Recommended using at the end of build.
    ///
    /// # Errors
    /// Returns an error if any of the required fields are missing.
    ///
    /// # Recommendations
    /// - Use a strong password.
    /// - Use a unique nonce for each encryption.
    pub fn encrypt(self, output_buffer: &mut Vec<u8>) -> Result<(), Errors> {
        let config = self
            .config
            .ok_or_else(|| Errors::BuildFailed("Missing Config".to_string()))?;
        let mut data = self
            .data
            .ok_or_else(|| Errors::BuildFailed("Missing Data".to_string()))?;
        let password = self
            .password
            .ok_or_else(|| Errors::BuildFailed("Missing Password".to_string()))?;
        let nonce = self
            .nonce
            .ok_or_else(|| Errors::BuildFailed("Missing Nonce".to_string()))?;
        let salt = self.salt;
        let (recovery_key, benchmark, wrap_all) = if let Some(utils) = self.utils {
            (utils.recovery_key, utils.benchmark, utils.wrap_all)
        } else {
            (None, false, false)
        };

        if benchmark {
            let start = Instant::now();
            let out = encrypt(
                &password.expose_secret(),
                &mut data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
                output_buffer,
            )?;
            let duration = start.elapsed();
            println!("Encryption took {}ms", duration.as_millis());
            Ok(out)
        } else {
            encrypt(
                &password.expose_secret(),
                &mut data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
                output_buffer,
            )
        }
    }

    /// Decrypts the data using the provided configuration, password, and nonce.
    /// - Recommended using at the end of build.
    /// - Recommended not using with encryption in same builder.
    ///
    /// # Errors
    /// Returns an error if any of the required fields are missing.
    ///
    /// # Recommendations
    /// - Renew the nonce after each decryption.
    pub fn decrypt(self, output_buffer: &mut Vec<u8>) -> Result<(), Errors> {
        let config = self
            .config
            .ok_or_else(|| Errors::BuildFailed("Missing Config".to_string()))?;
        let data = self
            .data
            .ok_or_else(|| Errors::BuildFailed("Missing Data".to_string()))?;
        let password = self
            .password
            .ok_or_else(|| Errors::BuildFailed("Missing Password".to_string()))?;
        let nonce = self.nonce;
        let salt = self.salt;
        let recovery_key = self.decryption_key;
        let (benchmark, wrap_all) = if let Some(utils) = self.utils {
            (utils.benchmark, utils.wrap_all)
        } else {
            (false, false)
        };

        if benchmark {
            let start = Instant::now();
            let out = decrypt(
                &password.expose_secret(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
                output_buffer,
            );
            let duration = start.elapsed();
            println!("Decryption took {}ms", duration.as_millis());
            out
        } else {
            decrypt(
                &password.expose_secret(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
                output_buffer,
            )
        }
    }
}
