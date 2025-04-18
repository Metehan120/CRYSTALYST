/*! # AtomCrypte

A high-performance, multi-layered encryption library designed for flexibility, security, and speed.

---

## 🚧 Disclaimer
This project is experimental and should not be used in production systems. It is created for academic research, cryptographic experimentation, and learning purposes. Use at your own discretion.

---

## Overview

AtomCrypte is a robust encryption library that combines multiple cryptographic techniques to provide state-of-the-art security with configurable parameters. By leveraging parallel processing capabilities and GPU acceleration, AtomCrypte achieves excellent performance while maintaining a high security standard.

## Key Features

- **Multi-layered encryption architecture**: Combines multiple cryptographic primitives
- **High performance**: Processes 100MB in approximately 1 seconds
- **Parallelized operations**: Utilizes all available CPU cores via Rayon
- **GPU acceleration**: Optional GPU-based processing for higher performance
- **Galois Field mathematics**: Configurable finite field operations
- **Dynamic S-boxes**: Password and/or nonce-dependent substitution tables
- **Authenticated encryption**: MAC validation ensures data integrity
- **Constant-time operations**: Protection against timing attacks
- **Secure memory handling**: Sensitive data is properly zeroized from memory

## Cryptographic Components

AtomCrypte integrates several cryptographic primitives and techniques:

- **Blake3**: For fast and secure key derivation
- **Argon2**: For password-based key derivation with tunable parameters
- **Dynamic S-boxes**: For substitution operations
- **Galois Field Mathematics**: For efficient diffusion operations (similar to AES MixColumns)
- **MAC validation**: Ensures data integrity and authenticity

## Configuration Options

AtomCrypte is highly configurable, allowing users to tailor encryption to their specific needs:

### Device Selection
```rust
pub enum DeviceList {
    Auto,   // Automatically choose between CPU and GPU based on availability
    Cpu,    // Force CPU-based processing
    Gpu,    // Force GPU-based processing
}
```

### S-box Generation
```rust
pub enum SboxTypes {
    PasswordBased,         // Generate S-box based on password only
    NonceBased,            // Generate S-box based on nonce only
    PasswordAndNonceBased, // Generate S-box based on both password and nonce
}
```

### Galois Field Polynomials
```rust
pub enum IrreduciblePoly {
    AES,         // Use the standard AES polynomial (0x1b)
    Custom(u8),  // Use a custom irreducible polynomial
}
```

### Predefined Profiles
```rust
pub enum Profile {
    Secure,    // Maximum security, CPU-based
    Balanced,  // Balance between security and performance
    Fast,      // Maximum performance, GPU-based when available
}
```

### Nonce Types
```rust
pub enum NonceData {
    TaggedNonce([u8; 32]),     // Nonce with user-provided tag
    HashedNonce([u8; 32]),     // Cryptographically hashed nonce
    Nonce([u8; 32]),           // Standard random nonce
    MachineNonce([u8; 32]),    // Machine-specific nonce
}
```

## Usage Examples

### Basic Encryption/Decryption

```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile, Rng, Nonce};

// Generate a nonce
let nonce = Nonce::nonce(Rng::osrng());

// Create a configuration with default settings
let config = Config::default();

// Encrypt data
let encrypted = AtomCrypteBuilder::new()
    .data("Hello, world!".as_bytes())
    .password("secure_password")
    .nonce(nonce)
    .config(config)
    .encrypt()
    .expect("Encryption failed");

// Decrypt data
let decrypted = AtomCrypteBuilder::new()
    .data(&encrypted)
    .password("secure_password")
    .nonce(nonce)
    .config(config)
    .decrypt()
    .expect("Decryption failed");

assert_eq!(decrypted, "Hello, world!".as_bytes());
```

### Custom Configuration

```rust
use atom_crypte::{AtomCrypteBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

// Create a custom configuration
let config = Config::default()
    .with_device(DeviceList::Gpu)              // Use GPU if available
    .with_sbox(SboxTypes::PasswordAndNonceBased) // Use both password and nonce for S-box
    .set_thread(8)                            // Use 8 threads
    .gf_poly(IrreduciblePoly::Custom(0x4d));  // Use custom polynomial

// Encryption using custom config
// ...
```

### Using Predefined Profiles

```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile};

// Create a configuration from a predefined profile
let config = Config::from_profile(Profile::Fast);

// Encryption using profile-based config
// ...
```

### Machine-specific Encryption

```rust
use atom_crypte::{AtomCrypteBuilder, Config, Nonce};

// Generate a machine-specific nonce
let nonce = Nonce::machine_nonce(None); // or
let nonce = Nonce::machine_nonce(Some(Rng::osrng()));

let password = "your_password_here".machine_rng(); // machine special password

// Encryption using machine-specific nonce
// ...
```

## Performance

AtomCrypte is designed for high performance with reasonable security margins:

- **CPU Mode**: Efficiently utilizes all available cores via Rayon
- **GPU Mode**: Leverages GPU acceleration for operations that benefit from parallelism
- **Benchmark**: ~100MB Encrypt/Decrypt ~1s on average hardware

## Security Considerations

- Uses authenticated encryption with MAC validation
- Implements constant-time operations to prevent timing attacks
- Memory containing sensitive data is properly zeroized
- Multiple cryptographic layers provide defense in depth !*/

use argon2::{Argon2, password_hash::SaltString};
use blake3::derive_key;
use gpu::{dynamic_shift_gpu, dynamic_unshift_gpu};
use rand::{TryRngCore, rngs::OsRng};
use rayon::prelude::*;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;
pub mod gpu;

static VERSION: &[u8] = b"atom-version:0x2";

/// Represents different types of nonces used in the encryption process.
/// - TaggedNonce: Nonce combined with a user-provided tag
/// - HashedNonce: Cryptographically hashed nonce for extra randomness
/// - Nonce: Standard cryptographically secure random nonce
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NonceData {
    TaggedNonce([u8; 32]),
    HashedNonce([u8; 32]),
    Nonce([u8; 32]),
    MachineNonce([u8; 32]),
} // Multiple data types for future usage

/// Represents different types of errors that can occur during encryption or decryption.
/// - This enum provides a comprehensive set of error types that can be encountered
/// - during the encryption and decryption processes. Each error variant includes a
/// - descriptive message that helps in identifying the root cause of the issue.
#[derive(Debug, Error)]
pub enum Errors {
    #[error("Decryption failed: {0}")]
    InvalidNonce(String),
    #[error("Invalid MAC: {0}")]
    InvalidMac(String),
    #[error("XOR failed: {0}")]
    InvalidXor(String),
    #[error("Thread Pool Failed: {0}")]
    ThreadPool(String),
    #[error("Argon2 failed: {0}")]
    Argon2Failed(String),
    #[error("Invalid Algorithm")]
    InvalidAlgorithm,
    #[error("Kernel Error: {0}")]
    KernelError(String),
    #[error("Build Failed: {0}")]
    BuildFailed(String),
}

/// Represents different types of devices that can be used for encryption and decryption.
#[derive(Debug, Clone, Copy)]
pub enum DeviceList {
    Auto,
    Cpu,
    Gpu,
}

/// Represents different types of sboxes that can be used for encryption and decryption.
/// # Not recommended for use in production environments.
#[derive(Debug, Clone, Copy)]
pub enum SboxTypes {
    PasswordBased,
    NonceBased,
    PasswordAndNonceBased,
}

/// Represents different types of irreducible polynomials that can be used for encryption and decryption.
#[derive(Debug, Clone, Copy)]
pub enum IrreduciblePoly {
    AES,
    Custom(u8),
}

impl IrreduciblePoly {
    fn value(&self) -> u8 {
        match self {
            IrreduciblePoly::AES => 0x1b, // x^8 + x^4 + x^3 + x + 1
            IrreduciblePoly::Custom(val) => *val,
        }
    }
}

/// Configuration for the encryption and decryption process.
/// - `device`: The device to use for encryption.
/// - `sbox`: The S-box to use for encryption.
/// - `thread_num`: The number of threads to use for encryption.
/// - `gf_poly`: The Galois field polynomial to use for encryption.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub device: DeviceList,
    pub sbox: SboxTypes,
    pub thread_num: usize,
    pub gf_poly: IrreduciblePoly,
} // For feature use

/// Profile for the encryption and decryption process.
#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Secure,
    Balanced,
    Fast,
}

impl Default for Config {
    /// Default configuration for the encryption and decryption process.
    fn default() -> Self {
        Self {
            device: DeviceList::Cpu,
            sbox: SboxTypes::PasswordAndNonceBased,
            thread_num: num_cpus::get(),
            gf_poly: IrreduciblePoly::AES,
        }
    }
}

impl Config {
    /// Sets S-Box generation type for encryption and decryption.
    /// - Not recommended changing the S-Box.
    pub fn with_sbox(mut self, sbox: SboxTypes) -> Self {
        self.sbox = sbox;
        self
    }

    /// Sets the device to use for encryption and decryption.
    /// - Not recommended changing the device after initialization.
    pub fn with_device(mut self, device: DeviceList) -> Self {
        self.device = device;
        self
    }

    /// Sets the number of threads to use for encryption and decryption.
    /// - Not recommended changing the number of threads after initialization.
    pub fn set_thread(mut self, num: usize) -> Self {
        self.thread_num = num;
        self
    }

    /// Sets the Galois field polynomial to use for encryption and decryption.
    /// - Not recommended changing the Galois field polynomial after initialization.
    pub fn gf_poly(mut self, poly: IrreduciblePoly) -> Self {
        self.gf_poly = poly;
        self
    }

    /// Create a configuration from a profile.
    pub fn from_profile(profile: Profile) -> Self {
        match profile {
            Profile::Fast => Self {
                device: DeviceList::Gpu,
                sbox: SboxTypes::PasswordBased,
                thread_num: num_cpus::get(),
                gf_poly: IrreduciblePoly::AES,
            },

            Profile::Balanced => Self {
                device: DeviceList::Auto,
                sbox: SboxTypes::PasswordAndNonceBased,
                thread_num: num_cpus::get(),
                gf_poly: IrreduciblePoly::AES,
            },
            Profile::Secure => Self {
                device: DeviceList::Cpu,
                sbox: SboxTypes::PasswordAndNonceBased,
                thread_num: num_cpus::get(),
                gf_poly: IrreduciblePoly::AES,
            },
        }
    }
}

impl NonceData {
    /// Converts the nonce data into a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            NonceData::Nonce(n)
            | NonceData::HashedNonce(n)
            | NonceData::TaggedNonce(n)
            | NonceData::MachineNonce(n) => n,
        }
    }
    /// Converts the nonce data into a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            NonceData::Nonce(n)
            | NonceData::HashedNonce(n)
            | NonceData::TaggedNonce(n)
            | NonceData::MachineNonce(n) => n.to_vec(),
        }
    }
}

/// Converts bytes or vector of bytes into a NonceData.
pub trait AsNonce {
    fn as_nonce(&self) -> Result<NonceData, Errors>;
}

impl TryFrom<&[u8]> for NonceData {
    type Error = Errors;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 32 {
            return Err(Errors::InvalidNonce(
                "Nonce must be exactly 32 bytes".to_string(),
            ));
        }

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(slice);
        Ok(NonceData::Nonce(nonce))
    }
}

impl TryFrom<Vec<u8>> for NonceData {
    type Error = Errors;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        if vec.len() != 32 {
            return Err(Errors::InvalidNonce(
                "Nonce must be exactly 32 bytes".to_string(),
            ));
        }

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&vec);
        Ok(NonceData::Nonce(nonce))
    }
}

/// Converts the bytes into a nonce data.
impl AsNonce for [u8] {
    fn as_nonce(&self) -> Result<NonceData, Errors> {
        NonceData::try_from(self)
    }
}

/// Converts the bytes vector into a nonce data.
impl AsNonce for Vec<u8> {
    fn as_nonce(&self) -> Result<NonceData, Errors> {
        NonceData::try_from(self.as_slice())
    }
}

/// Generates a random nonce using the operating system's random number generator.
pub enum Rng {
    OsRngNonce([u8; 32]),
    TaggedOsRngNonce([u8; 32]),
}

impl Rng {
    /// Generates a random nonce using the operating system's random number generator.
    pub fn osrng() -> Self {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .expect("Nonce generation failed");
        Self::OsRngNonce(nonce)
    }

    /// Generates a random nonce using the operating system's random number generator, with a tag.
    pub fn tagged_osrng(tag: &[u8]) -> Self {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .expect("Nonce generation failed");

        let new_nonce: Vec<u8> = nonce
            .iter()
            .enumerate()
            .map(|(i, b)| b.wrapping_add(tag[i % tag.len()] ^ i as u8))
            .collect();

        let mut final_nonce = [0u8; 32];
        final_nonce.copy_from_slice(&new_nonce[..32]);

        Self::TaggedOsRngNonce(final_nonce)
    }

    /// Returns the RNG as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match &self {
            Self::OsRngNonce(a) | Self::TaggedOsRngNonce(a) => a,
        }
    }

    /// Returns the RNG as a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Generates a unique identifier based on the machine's configuration.
pub trait MachineRng {
    fn machine_rng(&self) -> String;
}

/// Generates a unique identifier based on the machine's configuration.
impl MachineRng for str {
    fn machine_rng(&self) -> String {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();
        let distro = whoami::distro();

        let mut data = Vec::new();
        data.extend_from_slice(user_name.as_bytes());
        data.extend_from_slice(device_name.as_bytes());
        data.extend_from_slice(real_name.as_bytes());
        data.extend_from_slice(distro.as_bytes());
        data.extend_from_slice(self.as_bytes());

        let hash = blake3::hash(&data);
        hash.to_hex().to_string()
    }
}

/// ### Builder for AtomCrypte
/// - You can encrypte & decrypte data using the builder.
pub struct AtomCrypteBuilder {
    config: Option<Config>,
    data: Option<Vec<u8>>,
    password: Option<String>,
    nonce: Option<NonceData>,
}

/// Generates a Unique Nonce
pub struct Nonce;

struct GaloisField {
    mul_table: [[u8; 256]; 256],
    inv_table: [u8; 256],
    irreducible_poly: u8,
}

// -----------------------------------------------------

impl GaloisField {
    fn new(irreducible_poly: u8) -> Self {
        let mut gf = Self {
            mul_table: [[0; 256]; 256],
            inv_table: [0; 256],
            irreducible_poly,
        };

        gf.initialize_tables();
        gf
    }

    fn initialize_tables(&mut self) {
        for i in 0..256 {
            for j in 0..256 {
                self.mul_table[i][j] = self.multiply(i as u8, j as u8);
            }
        }
        for i in 1..256 {
            for j in 1..256 {
                if self.mul_table[i][j] == 1 {
                    self.inv_table[i] = j as u8;
                }
            }
        }
    }

    fn multiply(&self, a: u8, b: u8) -> u8 {
        let mut p = 0;
        let mut a_val = a as u16;
        let mut b_val = b as u16;

        while a_val != 0 && b_val != 0 {
            if b_val & 1 != 0 {
                p ^= a_val as u8;
            }

            let high_bit_set = a_val & 0x80;
            a_val <<= 1;

            if high_bit_set != 0 {
                a_val ^= self.irreducible_poly as u16;
            }

            b_val >>= 1;
        }

        p as u8
    }

    fn fast_multiply(&self, a: u8, b: u8) -> u8 {
        self.mul_table[a as usize][b as usize]
    }

    fn inverse(&self, a: u8) -> Option<u8> {
        if a == 0 {
            None // 0'ın tersi yoktur
        } else {
            Some(self.inv_table[a as usize])
        }
    }
}

impl Nonce {
    /// # Generates a Unique Nonce via Hash
    /// - Recommended for use in most cases
    /// - Adding extra security by hashing the nonce
    pub fn hashed_nonce(osrng: Rng) -> NonceData {
        let mut nonce = *osrng.as_bytes();

        for i in 0..=4 {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::HashedNonce(nonce)
    }

    /// # Generates a Unique Nonce via Tag and Hash
    /// - Adding extra security by hashing the nonce
    /// - Adding tag to the nonce (Extra Security)
    pub fn tagged_nonce(osrng: Rng, tag: &[u8]) -> NonceData {
        let mut nonce = *osrng.as_bytes();

        for i in 0..=4 {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::TaggedNonce(*blake3::hash(&[&nonce, tag].concat()).as_bytes()) // Hash the nonce to get a 32 byte more random nonce (Extra Security)
    }

    /// Generates a Unique Nonce via Machine Info and Hash
    /// - Adding extra security by hashing the nonce
    /// - Adding machine info to the nonce (Extra Security)
    pub fn machine_nonce(osrng: Option<Rng>) -> NonceData {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();
        let distro = whoami::distro();

        let mut all_data = Vec::new();

        all_data.extend_from_slice(user_name.as_bytes());
        all_data.extend_from_slice(device_name.as_bytes());
        all_data.extend_from_slice(real_name.as_bytes());
        all_data.extend_from_slice(distro.as_bytes());

        if let Some(rng) = osrng {
            all_data.extend_from_slice(rng.as_bytes());
        }

        let hash = blake3::hash(&all_data);

        NonceData::MachineNonce(*hash.as_bytes())
    }

    /// Generates a unique Nonce
    /// - Classic method with random bytes
    pub fn nonce(osrng: Rng) -> NonceData {
        let nonce = *osrng.as_bytes();

        let new_nonce_vec = nonce
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let add = (osrng.as_bytes()[i % osrng.as_bytes().len()] as usize) % (i + 1);
                b.wrapping_add(add as u8)
            })
            .collect::<Vec<u8>>();

        let mut new_nonce = [0u8; 32];
        new_nonce.copy_from_slice(&new_nonce_vec[..32]);

        NonceData::Nonce(new_nonce)
    }
}

fn triangle_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?; // Builds Thread Pool for performance and resource usage optimization.

    pool.install(|| {
        data.par_chunks_exact_mut(3).for_each(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            let c = chunk[2];

            chunk[0] = gf.fast_multiply(3, a) ^ gf.fast_multiply(2, b) ^ c;
            chunk[1] = gf.fast_multiply(4, b) ^ c;
            chunk[2] = gf.fast_multiply(5, c);
        })
    });

    Ok(data.to_vec())
}

fn inverse_triangle_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?; // Builds Thread Pool for performance and resource usage optimization.

    pool.install(|| {
        data.par_chunks_exact_mut(3).for_each(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            let c = chunk[2];

            let inv_5 = gf.inverse(5).unwrap_or(1);
            let c_prime = gf.fast_multiply(inv_5, c);

            let inv_4 = gf.inverse(4).unwrap_or(1);
            let b_prime = gf.fast_multiply(inv_4, b ^ gf.fast_multiply(1, c_prime));

            let inv_3 = gf.inverse(3).unwrap_or(1);
            let a_prime = gf.fast_multiply(inv_3, a ^ gf.fast_multiply(2, b_prime) ^ c_prime);

            chunk[0] = a_prime;
            chunk[1] = b_prime;
            chunk[2] = c_prime;
        })
    });

    Ok(data.to_vec())
}

fn xor_encrypt(nonce: &[u8], pwd: &[u8], input: &[u8], config: Config) -> Result<Vec<u8>, Errors> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;
    let out = pool.install(|| {
        input
            .into_par_iter()
            .enumerate()
            .map(|(i, b)| {
                let masked = b ^ (nonce[i % nonce.len()] ^ pwd[i % pwd.len()]); // XOR the byte with the nonce and password
                let mut masked =
                    masked.rotate_left((nonce[i % nonce.len()] ^ pwd[i % pwd.len()] % 8) as u32); // Rotate the byte left by the nonce value

                masked = masked.wrapping_add(nonce[i % nonce.len()]); // Add the nonce to the byte
                masked = masked.wrapping_add(pwd[i % pwd.len()]); // Add the password to the byte

                masked
            })
            .collect::<Vec<u8>>()
    });

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(out),
    }
}

fn xor_decrypt(nonce: &[u8], pwd: &[u8], input: &[u8], config: Config) -> Result<Vec<u8>, Errors> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    let out = pool.install(|| {
        input
            .into_par_iter()
            .enumerate()
            .map(|(i, b)| {
                let masked = b.wrapping_sub(pwd[i % pwd.len()]); // Subtract the password from the byte
                let masked = masked.wrapping_sub(nonce[i % nonce.len()]); // Subtract the nonce from the byte

                let masked =
                    masked.rotate_right((nonce[i % nonce.len()] ^ pwd[i % pwd.len()] % 8) as u32); // Rotate the byte right by the nonce value

                masked ^ (nonce[i % nonce.len()] ^ pwd[i % pwd.len()]) // XOR the byte with the nonce and password
            })
            .collect::<Vec<u8>>()
    });

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())), // If out vector is empty then returns an Error
        false => Ok(out),
    }
}

fn mix_blocks(
    data: &mut Vec<u8>,
    nonce: &[u8],
    pwd: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let nonce = blake3::hash(&[nonce, pwd].concat());
    let nonce = nonce.as_bytes();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?; // Builds Thread Pool for performance and resource usage optimization.

    if data.len().ct_eq(&3).unwrap_u8() == 1 {
        return Ok(data.to_vec()); // If data len <
    }

    let pool = pool.install(|| {
        data.into_par_iter()
            .enumerate()
            .map(|(i, byte)| {
                let n = nonce[i % nonce.len()];
                let mut byte = *byte;
                byte = byte.wrapping_add(n);
                byte = byte.rotate_right((n % 8) as u32); // Rotate the byte right by the nonce value
                byte ^= n; // XOR the byte with the nonce
                byte = byte.wrapping_add(n);

                byte
            })
            .collect::<Vec<u8>>() // While going through data changing bits, bits by bits
    });

    Ok(pool)
}

fn unmix_blocks(
    data: &mut Vec<u8>,
    nonce: &[u8],
    pwd: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let nonce = blake3::hash(&[nonce, pwd].concat());
    let nonce = nonce.as_bytes();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    if data.len().ct_eq(&3).unwrap_u8() == 1 {
        return Ok(data.to_vec());
    }

    let pool = pool.install(|| {
        data.into_par_iter()
            .enumerate()
            .map(|(i, byte)| {
                let n = nonce[i % nonce.len()];
                let mut byte = *byte;
                byte = byte.wrapping_sub(n);
                byte ^= n; // XOR the byte with the nonce
                byte = byte.rotate_left((n % 8) as u32); // Rotate the byte left by the nonce value
                byte = byte.wrapping_sub(n);

                byte
            })
            .collect::<Vec<u8>>()
    });

    Ok(pool)
}

fn derive_password_key(pwd: &[u8], salt: &[u8]) -> Result<Vec<u8>, Errors> {
    if pwd.len().ct_eq(&32).unwrap_u8() != 1 {
        return Err(Errors::Argon2Failed("Invalid Password".to_string()));
    }

    // TODO: Better Salt
    let salt = SaltString::encode_b64(salt).map_err(|e| Errors::Argon2Failed(e.to_string()))?;
    let argon = Argon2::default();

    let mut out = vec![0u8; 32]; // 256-bit key
    argon
        .hash_password_into(pwd, salt.as_str().as_bytes(), &mut out)
        .map_err(|e| Errors::Argon2Failed(e.to_string()))?; // Hashing Password VIA Argon2

    Ok(out)
}

// TODO: Better key verification system via new dervition system; While Argon2 getting better salt Key will become more secure and easy to verify
fn verify_keys_constant_time(key1: &[u8], key2: &[u8]) -> Result<bool, Errors> {
    if key1.len().ct_eq(&key2.len()).unwrap_u8() != 1 {
        return Ok(false);
    }

    let result = key1.ct_eq(key2).unwrap_u8() == 1;
    Ok(result)
}

fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
    let mut inv_s_box = [0u8; 256];
    for (i, &val) in s_box.iter().enumerate() {
        // Iterate over the s_box
        inv_s_box[val as usize] = i as u8; // Inverse the s_box
    }

    inv_s_box
}

fn generate_dynamic_sbox(nonce: &[u8], key: &[u8], cfg: Config) -> [u8; 256] {
    let mut sbox: [u8; 256] = [0; 256];
    for i in 0..256 {
        sbox[i] = i as u8;
    }

    let seed = match cfg.sbox {
        SboxTypes::PasswordBased => blake3::hash(&[key].concat()).as_bytes().to_vec(),
        SboxTypes::NonceBased => blake3::hash(&[nonce].concat()).as_bytes().to_vec(),
        SboxTypes::PasswordAndNonceBased => {
            blake3::hash(&[nonce, key].concat()).as_bytes().to_vec()
        }
    };

    for i in (1..256).rev() {
        let index = (seed[i % seed.len()] as usize + seed[(i * 7) % seed.len()] as usize) % (i + 1); // Generate a random index
        sbox.swap(i, index); // Swap the values in the sbox
    }

    sbox
}

fn in_s_bytes(data: &[u8], nonce: &[u8], pwd: &[u8], cfg: Config) -> Result<Vec<u8>, Errors> {
    let mut sbox = generate_dynamic_sbox(nonce, pwd, cfg); // Generate the sbox
    let inv_sbox = generate_inv_s_box(&sbox); // Generate the inverse sbox

    sbox.zeroize();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    Ok(pool.install(|| data.par_iter().map(|b| inv_sbox[*b as usize]).collect())) // Inverse the sbox
}

fn s_bytes(data: &[u8], sbox: &[u8; 256], cfg: Config) -> Result<Vec<u8>, Errors> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    Ok(pool.install(|| data.par_iter().map(|b| sbox[*b as usize]).collect())) // Apply the sbox
}

fn dynamic_sizes(data_len: usize) -> u32 {
    match data_len {
        0..1_000 => 14,
        1_000..10_000 => 24,
        10_000..100_000 => 64,
        100_000..1_000_000 => 128,
        1_000_000..10_000_000 => 4096,
        10_000_000..100_000_000 => 8096,
        100_000_000..1_000_000_000 => 16384,
        1_000_000_000..10_000_000_000 => 16384,
        10_000_000_000..100_000_000_000 => 32768,
        100_000_000_000..1_000_000_000_000 => 32768,
        1_000_000_000_000..10_000_000_000_000 => 65536,
        10_000_000_000_000..100_000_000_000_000 => 65536,
        100_000_000_000_000..1_000_000_000_000_000 => 1048576,
        1_000_000_000_000_000..10_000_000_000_000_000 => 1048576,
        10_000_000_000_000_000..100_000_000_000_000_000 => 2097152,
        100_000_000_000_000_000..1_000_000_000_000_000_000 => 2097152,
        1_000_000_000_000_000_000..10_000_000_000_000_000_000 => 4194304,
        _ => unreachable!(),
    }
}

// TODO: Better chunk generation
fn get_chunk_sizes(data_len: usize, nonce: &[u8], key: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut pos = 0;
    let hash = blake3::hash(&[nonce, key].concat());
    let seed = hash.as_bytes();

    let data_size = dynamic_sizes(data_len) as usize;

    while pos < data_len {
        let size = data_size + (seed[pos % seed.len()] as usize % 8); // Generate a random size for the chunk via Pos % Seed Lenght
        sizes.push(size.min(data_len - pos)); // Prevents code from unexpected errors and pushing data to sizes Vector
        pos += size;
    }

    sizes
}

fn dynamic_shift(
    data: &[u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let key = blake3::hash(&[nonce, password].concat())
        .as_bytes()
        .to_vec();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key);

    let mut shifted = Vec::new();
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let mut chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value
        let xor_val = key[i % key.len()]; // XOR the byte with the nonce

        pool.install(|| {
            chunk.par_iter_mut().for_each(|b| {
                *b = b.rotate_left(rotate_by); // Rotate the byte left by the nonce value
                *b ^= xor_val; // XOR the byte with the nonce
            });

            shifted.par_extend(chunk);
            cursor += size; // Move the cursor to the next chunk
        })
    }

    shifted = shifted.iter().rev().cloned().collect::<Vec<u8>>();
    Ok(shifted)
}

fn dynamic_unshift(
    data: &[u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let data = data.iter().rev().cloned().collect::<Vec<u8>>();
    let key = blake3::hash(&[nonce, password].concat())
        .as_bytes()
        .to_vec();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.thread_num)
        .build()
        .map_err(|e| Errors::ThreadPool(e.to_string()))?;

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key);

    let mut original = Vec::new();
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let mut chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value
        let xor_val = key[i % key.len()]; // XOR the byte with the nonce

        pool.install(|| {
            chunk.par_iter_mut().for_each(|b| {
                *b ^= xor_val; // XOR the byte with the nonce
                *b = b.rotate_right(rotate_by); // Rotate the byte right by the nonce value
            });

            original.par_extend(chunk);
            cursor += size; // Move the cursor to the next chunk
        })
    }

    Ok(original)
}

fn auto_dynamic_chunk_shift(
    data: &[u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    match config.device {
        DeviceList::Cpu => Ok(dynamic_shift(data, nonce, password, config)?),
        DeviceList::Gpu => dynamic_shift_gpu(data, nonce, password),
        DeviceList::Auto => {
            if ocl::Platform::list().is_empty() {
                Ok(dynamic_shift(data, nonce, password, config)?)
            } else {
                dynamic_shift_gpu(data, nonce, password)
            }
        }
    }
}

fn auto_dynamic_chunk_unshift(
    data: &[u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    match config.device {
        DeviceList::Cpu => Ok(dynamic_unshift(data, nonce, password, config)?),
        DeviceList::Gpu => dynamic_unshift_gpu(data, nonce, password),
        DeviceList::Auto => {
            if ocl::Platform::list().is_empty() {
                Ok(dynamic_unshift(data, nonce, password, config)?)
            } else {
                dynamic_unshift_gpu(data, nonce, password)
            }
        }
    }
}

// -----------------------------------------------------

fn encrypt(
    password: &str,
    data: &[u8],
    nonce: NonceData,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let nonce = nonce.as_bytes();

    let mut password = derive_key(password, nonce);
    let mut pwd = derive_password_key(&password, nonce)?;

    password.zeroize();

    let mut out_vec = Vec::new();
    let encrypted_version = xor_encrypt(nonce, &pwd, VERSION, config)?;
    out_vec.extend(encrypted_version);

    let mut s_block = generate_dynamic_sbox(nonce, &pwd, config);
    let mut mixed_data = mix_blocks(&mut s_bytes(data, &s_block, config)?, nonce, &pwd, config)?;
    let mut mixed_columns_data = triangle_mix_columns(
        &mut mixed_data,
        &GaloisField::new(config.gf_poly.value()),
        config,
    )?;

    mixed_data.zeroize();

    let mut shifted_data = s_bytes(
        &auto_dynamic_chunk_shift(&mixed_columns_data, nonce, &pwd, config)?,
        &s_block,
        config,
    )?;

    s_block.zeroize();
    mixed_columns_data.zeroize();

    let crypted = shifted_data
        .par_chunks(dynamic_sizes(shifted_data.len()) as usize)
        .map(|data: &[u8]| {
            xor_encrypt(nonce, &pwd, &data, config).map_err(|e| Errors::InvalidXor(e.to_string()))
        })
        .collect::<Result<Vec<Vec<u8>>, Errors>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    shifted_data.zeroize();

    let mac = *blake3::keyed_hash(
        blake3::hash(&crypted).as_bytes(),
        &xor_encrypt(nonce, &pwd, &data, config)?,
    )
    .as_bytes(); // Generate a MAC for the data

    pwd.zeroize();

    out_vec.extend(crypted);
    out_vec.extend(mac);

    Ok(out_vec)
}

// -----------------------------------------------------

fn decrypt(
    password: &str,
    data: &[u8],
    nonce: NonceData,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let nonce = nonce.as_bytes();

    let password_hash: [u8; 32] = derive_key(password, nonce);
    let mut expected_password = derive_password_key(&derive_key(password, nonce), nonce)?;
    let mut pwd = derive_password_key(&password_hash, nonce)?;

    if !verify_keys_constant_time(&pwd, &expected_password)? {
        pwd.zeroize();
        expected_password.zeroize();
        return Err(Errors::InvalidMac("Invalid key".to_string()));
    }

    expected_password.zeroize();

    if data.len() < 32 + VERSION.len() {
        return Err(Errors::InvalidMac("Data is too short".to_string()));
    }

    let version_len = VERSION.len();
    let (encrypted_version, rest) = data.split_at(version_len);
    let (crypted, mac_key) = rest.split_at(rest.len() - 32);

    {
        let version = xor_decrypt(nonce, &pwd, encrypted_version, config)?;

        if !version.starts_with(b"atom-version") {
            pwd.zeroize();
            return Err(Errors::InvalidAlgorithm);
        }
    }

    let mut xor_decrypted = crypted
        .to_vec()
        .par_chunks_mut(dynamic_sizes(crypted.len()) as usize)
        .map(|data: &mut [u8]| {
            xor_decrypt(nonce, &pwd, data, config).map_err(|e| Errors::InvalidXor(e.to_string()))
        })
        .collect::<Result<Vec<Vec<u8>>, Errors>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    let mut unshifted = auto_dynamic_chunk_unshift(
        &in_s_bytes(&xor_decrypted, nonce, &pwd, config)?,
        nonce,
        &pwd,
        config,
    )?;

    xor_decrypted.zeroize();

    let mut inversed_columns = inverse_triangle_mix_columns(
        &mut unshifted,
        &GaloisField::new(config.gf_poly.value()),
        config,
    )?;
    let mut unmixed = unmix_blocks(&mut inversed_columns, nonce, &pwd, config)?;

    unshifted.zeroize();
    inversed_columns.zeroize();

    let mut decrypted_data = in_s_bytes(&unmixed, nonce, &pwd, config)?;

    unmixed.zeroize();

    let mac = blake3::keyed_hash(
        blake3::hash(&crypted).as_bytes(),
        &xor_encrypt(nonce, &pwd, &decrypted_data, config)?,
    ); // Generate a MAC for the data

    pwd.zeroize();

    if mac.as_bytes().ct_eq(mac_key).unwrap_u8() != 1 {
        // Check if the MAC is valid
        decrypted_data.zeroize();
        return Err(Errors::InvalidMac("Invalid authentication".to_string()));
    }

    Ok(decrypted_data)
}

impl AtomCrypteBuilder {
    /// Creates a new instance of AtomCrypteBuilder.
    pub fn new() -> Self {
        Self {
            password: None,
            data: None,
            config: None,
            nonce: None,
        }
    }

    /// Sets the data to be encrypted.
    /// -  Recommended using '&' when using `Vector<u8>`.
    pub fn data(mut self, data: &[u8]) -> Self {
        self.data = Some(data.to_vec());
        self
    }

    /// Sets the configuration for the encryption.
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the password for the encryption.
    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Sets the nonce for the encryption.
    pub fn nonce(mut self, nonce: NonceData) -> Self {
        self.nonce = Some(nonce);
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
    pub fn encrypt(self) -> Result<Vec<u8>, Errors> {
        let config = self
            .config
            .ok_or_else(|| Errors::BuildFailed("Missing Config".to_string()))?;
        let data = self
            .data
            .ok_or_else(|| Errors::BuildFailed("Missing Data".to_string()))?;
        let password = self
            .password
            .ok_or_else(|| Errors::BuildFailed("Missing Password".to_string()))?;
        let nonce = self
            .nonce
            .ok_or_else(|| Errors::BuildFailed("Missing Nonce".to_string()))?;

        encrypt(password.as_str(), &data, nonce, config)
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
    pub fn decrypt(self) -> Result<Vec<u8>, Errors> {
        let config = self
            .config
            .ok_or_else(|| Errors::BuildFailed("Missing Config".to_string()))?;
        let data = self
            .data
            .ok_or_else(|| Errors::BuildFailed("Missing Data".to_string()))?;
        let password = self
            .password
            .ok_or_else(|| Errors::BuildFailed("Missing Password".to_string()))?;
        let nonce = self
            .nonce
            .ok_or_else(|| Errors::BuildFailed("Missing Nonce".to_string()))?;

        decrypt(password.as_str(), &data, nonce, config)
    }
}
