use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    sync::Arc,
    time::Instant,
};

use sha3::{Digest, Sha3_512};
use subtle::{ConstantTimeEq, ConstantTimeLess};

use crate::{
    Config, Errors, KeyBuffer, NonceData, RoundKeyBuffer,
    engine::{
        cache_warmup::{CacheWarmup, CacheWarmup64},
        engine::{
            GaloisField, apply_gf, ctr_decrypt, ctr_encrypt, generate_dynamic_sbox,
            generate_inv_s_box, in_s_bytes, inverse_shift_rows, rxa_decrypt, rxa_encrypt, s_bytes,
            shift_rows,
        },
    },
};

pub const CHUNK_SIZE: usize = 1024 * 1024;

fn keystream(key: &[u8], nonce: &[u8], counter: u64) -> KeyBuffer {
    let key = key
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let unique_counter = (*b as u64)
                .wrapping_add(counter)
                .wrapping_add(i as u64)
                .wrapping_add(nonce[i % nonce.len()] as u64)
                .wrapping_mul(0x9E3779B97F4A7C15);

            unique_counter as u8
        })
        .collect::<Vec<u8>>();

    KeyBuffer::new(key)
}

pub struct CrystalystStreamUtils {
    pub benchmark: bool,
}

impl CrystalystStreamUtils {
    pub fn new(bench_mark: bool) -> Self {
        Self {
            benchmark: bench_mark,
        }
    }
}

pub struct CrystalystStream {
    config: Config,
    pwd: KeyBuffer,
    nonce: [u8; 32],
    gf: Arc<GaloisField>,
    utils: CrystalystStreamUtils,
}

impl CrystalystStream {
    fn process_chunk(&self, chunk: &mut [u8], key: &[u8], key_len: usize) -> Result<(), Errors> {
        let config = self.config;
        let nonce = self.nonce;
        let gf = &self.gf;

        let mut buffer = [0u8; 64];
        let pwd: Vec<u8> = key.iter().take(64).cloned().collect();
        let sbox = generate_dynamic_sbox(&nonce, key, config)?;
        let inv_sbox = generate_inv_s_box(&sbox);
        buffer[..pwd.len()].copy_from_slice(&pwd);
        let pwd = CacheWarmup64::new(buffer, sbox, inv_sbox);
        if config.hardware.warmup_cache {
            pwd.warm_cache();
        }

        rxa_encrypt(&pwd, chunk, config)?;

        s_bytes(chunk, &pwd, config)?;

        rxa_encrypt(&pwd, chunk, config)?;

        apply_gf(chunk, &config, &gf, &nonce)?;

        shift_rows(chunk, &config);

        s_bytes(chunk, &pwd, config)?;

        let mut round_key_buffer = RoundKeyBuffer::new(vec![0u8; key_len * 2]);

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

            chunk
                .chunks_mut(CHUNK_SIZE)
                .try_for_each(|chunk| -> Result<(), Errors> {
                    rxa_encrypt(round_key, chunk, config)?;
                    match config.multi_round_galois_field {
                        true => apply_gf(chunk, &config, &gf, &nonce)?,
                        false => {
                            if i == 1 {
                                apply_gf(chunk, &config, &gf, &nonce)?;
                            }
                        }
                    }
                    Ok(())
                })?;
        }

        drop(round_key_buffer);

        if config.ctr_layer && chunk.len() >= 128 {
            let mut iv = [0u8; 32];
            iv.clone_from_slice(&nonce[0..32]);
            ctr_encrypt(&nonce, chunk, &iv);
        }

        Ok(())
    }

    fn process_decrypt_chunk(
        &self,
        chunk: &mut [u8],
        key: &[u8],
        key_len: usize,
    ) -> Result<(), Errors> {
        let config = self.config;
        let nonce = self.nonce;
        let gf = &self.gf;

        let mut buffer = [0u8; 64];
        let pwd: Vec<u8> = key.iter().take(64).cloned().collect();
        let sbox = generate_dynamic_sbox(&nonce, key, config)?;
        let inv_sbox = generate_inv_s_box(&sbox);
        buffer[..pwd.len()].copy_from_slice(&pwd);
        let pwd = CacheWarmup64::new(buffer, sbox, inv_sbox);
        if config.hardware.warmup_cache {
            pwd.warm_cache();
        }

        if config.ctr_layer && chunk.len() >= 128 {
            let mut iv = [0u8; 32];
            iv.clone_from_slice(&nonce[0..32]);
            ctr_decrypt(&nonce, chunk, &iv);
        }

        let mut round_key_buffer = RoundKeyBuffer::new(vec![0u8; key_len as usize * 2]);

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
            let round_key = &CacheWarmup64 {
                key: buffer,
                sbox: [0u8; 256],
                inv_sbox: [0u8; 256],
            };
            if config.hardware.warmup_cache {
                round_key.warm_cache();
            }

            chunk
                .chunks_mut(CHUNK_SIZE)
                .try_for_each(|chunk| -> Result<(), Errors> {
                    match config.multi_round_galois_field {
                        true => apply_gf(chunk, &config, &gf, &nonce)?,
                        false => {
                            if i == 1 {
                                apply_gf(chunk, &config, &gf, &nonce)?;
                            }
                        }
                    }

                    rxa_decrypt(round_key, chunk, config)?;
                    Ok(())
                })?;
        }

        drop(round_key_buffer);

        in_s_bytes(chunk, &pwd, config)?;

        inverse_shift_rows(chunk, &config);

        apply_gf(chunk, &config, &gf, &nonce)?;

        rxa_decrypt(&pwd, chunk, config)?;

        in_s_bytes(chunk, &pwd, config)?;

        rxa_decrypt(&pwd, chunk, config)?;

        Ok(())
    }

    pub fn new(config: Config, pwd: &[u8], nonce: NonceData) -> Self {
        Self {
            config,
            pwd: KeyBuffer::new(pwd.to_vec()),
            nonce: *nonce.as_bytes(),
            gf: Arc::new(GaloisField::new(config.gf_poly.value())),
            utils: CrystalystStreamUtils::new(false),
        }
    }

    pub fn utils(mut self, utils: CrystalystStreamUtils) -> Self {
        self.utils = utils;
        self
    }

    pub fn stream_encrypt(&mut self, raw_data: &mut [u8]) -> Result<(), Errors> {
        let start = Instant::now();

        let key_len = 32;

        if (self.pwd.expose_secret().len() as u64)
            .ct_ne(&0)
            .unwrap_u8()
            != 1
        {
            return Err(Errors::EmptyPassword);
        } else if (self.pwd.expose_secret().len() as u32)
            .ct_lt(&key_len)
            .unwrap_u8()
            == 1
        {
            return Err(Errors::PasswordTooShort(format!(
                "Password must be at least {} characters for cryptographic strength.",
                key_len
            )));
        }

        let pwd = self.pwd.expose_secret().to_vec();

        for (i, chunk) in raw_data.chunks_mut(CHUNK_SIZE).enumerate() {
            let counter = i + 1;
            let pwd = keystream(&pwd, &self.nonce, counter as u64);

            self.process_chunk(chunk, &pwd.expose_secret(), key_len as usize)?;
            drop(pwd);
        }

        if self.utils.benchmark {
            println!("Stream encryption took: {:?}", start.elapsed());
        }

        Ok(())
    }

    pub fn stream_decrypt(&mut self, encrypted_data: &mut [u8]) -> Result<(), Errors> {
        let start = Instant::now();

        let key_len = 32;

        let pwd = self.pwd.expose_secret().to_vec();

        for (i, chunk) in encrypted_data.chunks_mut(CHUNK_SIZE).enumerate() {
            let counter = i + 1;
            let pwd = keystream(&pwd, &self.nonce, counter as u64);

            self.process_decrypt_chunk(chunk, &pwd.expose_secret(), key_len)?;
            drop(pwd);
        }

        if self.utils.benchmark {
            println!("Stream decryption took: {:?}", start.elapsed());
        }

        Ok(())
    }

    pub fn stream_file_encrypt(
        &mut self,
        file: File,
        out_buffer: &mut Vec<u8>,
    ) -> Result<(), Errors> {
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0u8; 1024 * 1024];

        let key_len = 32;

        if (self.pwd.expose_secret().len() as u64)
            .ct_ne(&0)
            .unwrap_u8()
            != 1
        {
            return Err(Errors::EmptyPassword);
        } else if (self.pwd.expose_secret().len() as u32)
            .ct_lt(&key_len)
            .unwrap_u8()
            == 1
        {
            return Err(Errors::PasswordTooShort(format!(
                "Password must be at least {} characters for cryptographic strength.",
                key_len
            )));
        }

        let start = Instant::now();
        let mut counter = 1;
        let mut pwd = self.pwd.expose_secret().to_vec();

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|_| Errors::EmptyPassword)?;

            if bytes_read == 0 {
                break;
            }

            let pwd = keystream(&mut pwd, &self.nonce, counter);

            let chunk = &mut buffer[..bytes_read];
            self.process_chunk(chunk, &pwd.expose_secret(), key_len as usize)?;
            drop(pwd);
            out_buffer.extend_from_slice(chunk);
            counter += 1;
        }

        if self.utils.benchmark {
            println!("{:?}", start.elapsed());
        }

        Ok(())
    }

    pub fn stream_file_decrypt(
        &mut self,
        file: File,
        out_buffer: &mut Vec<u8>,
    ) -> Result<(), Errors> {
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0u8; 1024 * 1024];

        let key_len = 32;

        let start = Instant::now();
        let mut counter = 1;
        let mut pwd = self.pwd.expose_secret().to_vec();

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|_| Errors::EmptyPassword)?;

            if bytes_read == 0 {
                break;
            }

            let pwd = keystream(&mut pwd, &self.nonce, counter as u64);

            let chunk = &mut buffer[..bytes_read];
            self.process_decrypt_chunk(chunk, &pwd.expose_secret(), key_len as usize)?;
            drop(pwd);
            out_buffer.extend_from_slice(chunk);
            counter += 1;
        }

        if self.utils.benchmark {
            println!("{:?}", start.elapsed());
        }

        Ok(())
    }

    pub fn stream_file_to_file_encrypt(
        &mut self,
        file: File,
        out_buffer: &mut File,
    ) -> Result<(), Errors> {
        let mut reader = BufReader::new(file);
        let mut writer = BufWriter::new(out_buffer);
        let mut buffer = vec![0u8; 1024 * 1024];

        let key_len = 32;

        if (self.pwd.expose_secret().len() as u64)
            .ct_ne(&0)
            .unwrap_u8()
            != 1
        {
            return Err(Errors::EmptyPassword);
        } else if (self.pwd.expose_secret().len() as u32)
            .ct_lt(&key_len)
            .unwrap_u8()
            == 1
        {
            return Err(Errors::PasswordTooShort(format!(
                "Password must be at least {} characters for cryptographic strength.",
                key_len
            )));
        }

        let start = Instant::now();
        let mut counter = 1;
        let pwd = self.pwd.expose_secret().to_vec();

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|_| Errors::EmptyPassword)?;

            if bytes_read == 0 {
                break;
            }

            let pwd = keystream(&pwd, &self.nonce, counter);

            let chunk = &mut buffer[..bytes_read];
            self.process_chunk(chunk, &pwd.expose_secret(), key_len as usize)?;
            drop(pwd);
            writer
                .write(chunk)
                .map_err(|_| Errors::BuildFailed("Cannot Write Data".to_string()))?;
            counter += 1;
        }

        if self.utils.benchmark {
            println!("{:?}", start.elapsed());
        }

        writer
            .flush()
            .map_err(|_| Errors::BuildFailed("Cannot flush writer".to_string()))?;

        Ok(())
    }

    pub fn stream_file_to_file_decrypt(
        &mut self,
        file: File,
        out_buffer: &mut File,
    ) -> Result<(), Errors> {
        let mut reader = BufReader::new(file);
        let mut writer = BufWriter::new(out_buffer);
        let mut buffer = vec![0u8; 1024 * 1024];

        let key_len = 32;

        let start = Instant::now();
        let mut counter = 1;
        let pwd = self.pwd.expose_secret().to_vec();

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|_| Errors::EmptyPassword)?;

            if bytes_read == 0 {
                break;
            }

            let pwd = keystream(&pwd, &self.nonce, counter as u64);

            let chunk = &mut buffer[..bytes_read];
            self.process_decrypt_chunk(chunk, &pwd.expose_secret(), key_len as usize)?;
            drop(pwd);
            writer
                .write(chunk)
                .map_err(|_| Errors::BuildFailed("Cannot Write Data".to_string()))?;
            counter += 1;
        }

        writer
            .flush()
            .map_err(|_| Errors::BuildFailed("Cannot flush writer".to_string()))?;

        if self.utils.benchmark {
            println!("{:?}", start.elapsed());
        }

        Ok(())
    }
}
