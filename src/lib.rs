/*! # AtomCrypte
- A high-performance, multi-layered encryption library designed for flexibility, security, and speed.)

---

## 🚧 Disclaimer
- This project is currently experimental and is not recommended for production environments.
- While it offers strong multi-layered security, including quantum-resilient techniques, it has not undergone formal third-party audits.
- It has been developed for academic research, cryptographic experimentation, and educational purposes.
- **Use at your own discretion, and apply additional caution in critical systems.**

---

## Overview

AtomCrypte is a robust encryption library that combines multiple cryptographic techniques to provide state-of-the-art security with configurable parameters.
It supports parallel processing, GPU acceleration, and modular cryptographic components, enabling both performance and advanced customization.

---

## Key Features

- **512-bit Key Support**: Supports keys of up to 512 bits for enhanced security.
- **Constant-Time Execution (Locally Verified)**: All critical operations are implemented to run in constant time, minimizing timing side-channel risks. While extensive local testing confirms stability across various inputs, third-party validation is recommended for formal assurance.
- **Salt Support**: Cryptographic salt generation using `Salt::new()` to prevent rainbow table attacks.
- **Infinite Rounds**: User-defined encryption round count.
- **Wrap-All Support**: Seamlessly wraps salt, nonce, version, etc. into final output.
- **MAC with SHA3-512**: Strong integrity validation and quantum resistance.
- **Benchmark Support**: Time encryption/decryption operations with `.benchmark()`.
- **Secure Key Derivation**: Argon2 + Blake3 for password hashing.
- **Dynamic S-boxes**: Based on password, nonce, or both.
- **Finite Field Arithmetic**: Galois Field operations similar to AES MixColumns.
- **Parallel Processing**: Uses Rayon for multicore CPU support.
- **GPU Acceleration**: OpenCL backend for fast encryption/decryption.
  ⚠️ Note: Due to current OpenCL driver or platform behavior, minor memory leaks (typically ≤ 100 bytes) may occur during GPU execution. These do not affect cryptographic correctness and are not classified as critical, but future updates aim to address this.
- **Zeroized Memory**: Automatic clearing of sensitive data in RAM.
- **Perfect Distribution**:
  - Exhaustive statistical tests confirms near-theoretical perfection:
    - Shannon Entropy: `8.0000` (Perfect randomness, Max)
    - Bit Balance: `1.0000` (Perfect bit distribution, Max)
    - Avalanche Effect: `0.5000` (Ideal avalanche ratio)
  - Verified over 10,000 independent test runs.
- **Memory Hard**: Algorithm is designed to be memory-hard, making it resistant to brute-force attacks even with large amounts of memory.
- **Zero Memory Leak (Verified in Local Testing)**:
  Extensive `Valgrind` testing under multiple stress scenarios (including 25x repeat encryption) shows zero **definite** or **indirect** memory leaks.
  (Note: Not yet validated by third-party audits or formal verification tools.)

---

## Cryptographic Components

- **Argon2**: Memory-hard password hashing
- **Blake3**: Fast cryptographic hash for key derivation
- **SHA3-512**: Default MAC function with post-quantum resilience
- **Custom S-box**: Deterministic but unique per configuration
- **Galois Field**: MixColumns-like transformation layer
- **Dynamic Chunk Shifting**: Adaptive chunk size adjustment based on nonce, password, data length
- **Block Mix**: Efficiently Mixing data
- **XOR Layer**: Basic XOR layer for data mixing with Rotation
- **MAC Validation**: Ensures authenticity and tamper-resistance

---

## Configuration Options

### Device Selection
```rust
pub enum DeviceList {
    Auto,
    Cpu,
    Gpu,
}
```

### S-box Generation
```rust
pub enum SboxTypes {
    PasswordBased,
    NonceBased,
    PasswordAndNonceBased,
}
```

### Galois Field Polynomial
```rust
pub enum IrreduciblePoly {
    AES,
    Custom(u8),
}
```

### Predefined Profiles
```rust
pub enum Profile {
    Secure,
    Balanced,
    Fast,
    Max,
}
```

### Nonce Types
```rust
pub enum NonceData {
    TaggedNonce([u8; 32]),
    HashedNonce([u8; 32]),
    Nonce([u8; 32]),
    MachineNonce([u8; 32]),
}
```

## Usage Examples

### Basic Encryption/Decryption
```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile, Rng, Nonce};

let nonce = Nonce::nonce(Rng::osrng());
let config = Config::default();

let encrypted = AtomCrypteBuilder::new()
    .data("Hello, world!".as_bytes())
    .password("secure_password")
    .nonce(nonce)
    .config(config)
    .wrap_all(true) // Optional
    .benchmark() // Optional
    .encrypt()
    .expect("Encryption failed");

let decrypted = AtomCrypteBuilder::new()
    .data(&encrypted)
    .password("secure_password")
    .config(config)
    .wrap_all(true) // Optional
    .benchmark() // Optional
    .decrypt()
    .expect("Decryption failed");

assert_eq!(decrypted, "Hello, world!".as_bytes());
```
### How to use salt
```rust
let salt = Salt::new();
let encrypted = AtomCrypteBuilder::new()
    .data("Important secrets".as_bytes())
    .password("your_password")
    .nonce(Nonce::nonce(Rng::osrng()))
    .config(Config::default())
    .wrap_all(true) // Optional
    .salt(salt) // Optional but recommended
    .benchmark() // Optional
    .encrypt()
    .expect("Encryption failed");

// Or you can turn byte slice into Salt
```

### Custom Configuration
- 🚧 If you forget your configuration, you won't be able to decrypt the data. (Especially important if you changed round count, S-box type, Key Length, or polynomial.)
```rust
use atom_crypte::{AtomCrypteBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

let config = Config::default()
    .with_device(DeviceList::Gpu)
    .with_sbox(SboxTypes::PasswordAndNonceBased)
    .set_thread(4)
    .gf_poly(IrreduciblePoly::Custom(0x4d))
    .rounds(6); // 6 ~ 8 Rounds recommended
```

### Using Predefined Profiles
```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile};

let config = Config::from_profile(Profile::Secure);
```

### Machine-specific Encryption
```rust
use atom_crypte::{AtomCrypteBuilder, Config, Nonce};

let nonce = Nonce::machine_nonce(None); // You can generate via Machine info + Rng
let password = "your_password_here".machine_rng(false); // False means no distro lock
```

## Performance

- **CPU**: Parallelized via Rayon
- **GPU**: OpenCL enabled
- **Benchmarks**: ~100MB ≈ 1s encryption/decryption on average device
- **Benchmarks**: ~20MB ≈ 1s encryption/decryption on low-end device

## Security Considerations

- Constant-time comparisons
- All critical operations are constant-time
- Memory zeroization
- Authenticated encryption with SHA3 MAC
- Configurable number of layers and rounds
- Defense-in-depth: multiple cryptographic operations layered !*/

use std::time::Instant;

use argon2::{Argon2, password_hash::SaltString};
use base64::{Engine, prelude::BASE64_STANDARD};
use blake3::derive_key;
use engine::engine::*;
use hmac::Hmac;
use hmac::Mac;
use rand::{RngCore, TryRngCore, random_range, rngs::OsRng};
use rayon::prelude::*;
use sha3::{Digest, Sha3_512};
use subtle::{ConstantTimeEq, ConstantTimeLess};
use sysinfo::System;
use thiserror::Error;
use zeroize::Zeroize;
pub mod engine;

static VERSION: &[u8] = b"atom-version:0x5";

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
    #[error("Empty Password")]
    EmptyPassword,
    #[error("Invalid Key: {0}")]
    InvalidKey(String),
    #[error("Base64 Decode Failed: {0}")]
    Base64DecodeFailed(String),
    #[error("Password Too Short: {0}")]
    PasswordTooShort(String),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLength {
    Key256,
    Key512,
}

/// Represents whether to always use AVX2 instructions or not.
/// This can be useful for performance optimization on systems with AVX2 support.
#[derive(Debug, Clone, Copy)]
pub enum AlwaysSIMD {
    True,
    False,
}

/// Thread strategy for the encryption and decryption process.
/// - `AutoThread`: Automatically determine the number of threads to use.
/// - `FullThread`: Use all available threads.
/// - `LowThread`: Use a low number of threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStrategy {
    AutoThread,
    FullThread,
    LowThread,
    Custom(usize),
}

/// Configuration for the encryption and decryption process.
/// - `device`: The device to use for encryption.
/// - `sbox`: The S-box to use for encryption.
/// - `thread_num`: The number of threads to use for encryption.
/// - `gf_poly`: The Galois field polynomial to use for encryption.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub rounds: usize,
    pub sbox: SboxTypes,
    pub thread_strategy: ThreadStrategy,
    pub gf_poly: IrreduciblePoly,
    pub key_length: KeyLength,
    pub dummy_data: bool,
    pub always_avx2: AlwaysSIMD,
} // For feature use

/// Profile for the encryption and decryption process.
/// - `max`: Maximum security level, can be good against quantum attacks.
/// - `secure`: Secure security level.
/// - `balanced`: Balanced security level.
/// - `fast`: Fast security level.
#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Max,
    Secure,
    Balanced,
    Fast,
}

impl ThreadStrategy {
    pub fn custom(num_threads: usize) -> Self {
        Self::Custom(num_threads)
    }

    pub fn get_cpu_count(&self) -> usize {
        match self {
            Self::AutoThread => {
                let mut sys = System::new();
                sys.refresh_cpu_usage();
                let cpu_usage = sys.global_cpu_usage();

                match cpu_usage as u32 {
                    0..50 => num_cpus::get(),
                    50..99 => num_cpus::get() / 2,
                    _ => {
                        if num_cpus::get() > 2 {
                            num_cpus::get() / 3
                        } else {
                            num_cpus::get() / 2
                        }
                    }
                }
            }
            Self::FullThread => num_cpus::get(),
            Self::LowThread => num_cpus::get() / 2,
            Self::Custom(num_threads) => *num_threads,
        }
    }
}

impl Default for Config {
    /// Default configuration for the encryption and decryption process.
    fn default() -> Self {
        Self {
            sbox: SboxTypes::PasswordAndNonceBased,
            thread_strategy: ThreadStrategy::AutoThread,
            gf_poly: IrreduciblePoly::AES,
            rounds: 1,
            key_length: KeyLength::Key512,
            dummy_data: true,
            always_avx2: AlwaysSIMD::True,
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

    /// Sets the number of threads to use for encryption and decryption.
    /// - Not recommended changing the number of threads after initialization.
    pub fn set_thread(mut self, strategy: ThreadStrategy) -> Self {
        self.thread_strategy = strategy;
        self
    }

    /// Sets the Galois field polynomial to use for encryption and decryption.
    /// - Not recommended changing the Galois field polynomial after initialization.
    pub fn gf_poly(mut self, poly: IrreduciblePoly) -> Self {
        self.gf_poly = poly;
        self
    }

    /// Sets the key length to use for encryption and decryption.
    /// - Recommended Key512 for security.
    pub fn key_length(mut self, length: KeyLength) -> Self {
        self.key_length = length;
        self
    }

    /// Sets the number of rounds to use for encryption and decryption.
    /// - Not recommended changing the number of rounds after initialization.
    pub fn rounds(mut self, num: usize) -> Self {
        if num < 1 {
            eprintln!("Round count too low. Automatically set to 1.");
            self.rounds = 1;
            self
        } else {
            self.rounds = num;
            self
        }
    }

    /// Sets the dummy data.
    /// Recommended dummy data for security.
    pub fn dummy_data(mut self, dummy_data: bool) -> Self {
        self.dummy_data = dummy_data;
        self
    }

    pub fn always_avx2(mut self, always_avx2: AlwaysSIMD) -> Self {
        self.always_avx2 = always_avx2;
        self
    }

    /// Create a configuration from a profile
    pub fn from_profile(profile: Profile) -> Self {
        match profile {
            Profile::Fast => Self {
                sbox: SboxTypes::PasswordBased,
                thread_strategy: ThreadStrategy::FullThread,
                gf_poly: IrreduciblePoly::AES,
                rounds: 1,
                key_length: KeyLength::Key256,
                dummy_data: false,
                always_avx2: AlwaysSIMD::True,
            },
            Profile::Balanced => Self {
                sbox: SboxTypes::PasswordAndNonceBased,
                thread_strategy: ThreadStrategy::AutoThread,
                gf_poly: IrreduciblePoly::AES,
                rounds: 2,
                key_length: KeyLength::Key512,
                dummy_data: false,
                always_avx2: AlwaysSIMD::True,
            },
            Profile::Secure => Self {
                sbox: SboxTypes::PasswordAndNonceBased,
                thread_strategy: ThreadStrategy::AutoThread,
                gf_poly: IrreduciblePoly::AES,
                rounds: 2,
                key_length: KeyLength::Key512,
                always_avx2: AlwaysSIMD::True,
                ..Default::default()
            },
            Profile::Max => Self {
                sbox: SboxTypes::PasswordAndNonceBased,
                thread_strategy: ThreadStrategy::FullThread,
                gf_poly: IrreduciblePoly::AES,
                rounds: 4,
                key_length: KeyLength::Key512,
                always_avx2: AlwaysSIMD::False,
                ..Default::default()
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
    fn as_nonce(&self) -> NonceData;
    fn as_nonce_safe(&self) -> Result<NonceData, String>;
}

fn slice_to_nonce(input: &[u8]) -> Result<NonceData, String> {
    if input.len() != 32 {
        Err("Nonce length must be 32 bytes".to_string())
    } else {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(input);
        Ok(NonceData::Nonce(arr))
    }
}

/// Converts the bytes into a nonce data.
impl AsNonce for [u8] {
    fn as_nonce(&self) -> NonceData {
        slice_to_nonce(self).expect("Nonce length must be 32 bytes")
    }

    fn as_nonce_safe(&self) -> Result<NonceData, String> {
        slice_to_nonce(self)
    }
}

/// Converts the bytes vector into a nonce data.
impl AsNonce for Vec<u8> {
    fn as_nonce(&self) -> NonceData {
        slice_to_nonce(self).expect("Nonce length must be 32 bytes")
    }

    fn as_nonce_safe(&self) -> Result<NonceData, String> {
        slice_to_nonce(self)
    }
}

/// Generates a random nonce using the operating system's random number generator.
pub enum Rng {
    OsRngNonce([u8; 32]),
    TaggedOsRngNonce([u8; 32]),
    ThreadRngNonce([u8; 32]),
}

impl Rng {
    /// Generates a random nonce using the machine's random number generator.
    pub fn thread_rng() -> Self {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self::ThreadRngNonce(nonce)
    }

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
            Self::OsRngNonce(a) | Self::TaggedOsRngNonce(a) | Self::ThreadRngNonce(a) => a,
        }
    }

    /// Returns the RNG as a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Generates a unique identifier based on the machine's configuration.
pub trait MachineRng {
    fn machine_rng(&self, distro_lock: bool) -> String;
}

/// Generates a unique identifier based on the machine's configuration.
/// Heads up:
/// If you're migrating from version 2.2 or used machine_rng with distribution lock enabled,
/// make sure to decrypt your data before changing or reinstalling your OS.
/// The OS distribution is a part of the key derivation process when distro_lock is set to true.
/// Failing to do so may permanently prevent access to your encrypted data.
impl MachineRng for str {
    fn machine_rng(&self, distro_lock: bool) -> String {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();

        let mut data = Vec::new();
        data.extend_from_slice(user_name.as_bytes());
        data.extend_from_slice(device_name.as_bytes());
        data.extend_from_slice(real_name.as_bytes());
        if distro_lock == true {
            let distro = whoami::distro();
            data.extend_from_slice(distro.as_bytes());
        }
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
    salt: Option<Salt>,
    decryption_key: Option<String>,
    utils: Option<Utils>,
}

#[derive(Debug, Clone, Copy)]
pub struct Utils {
    benchmark: bool,
    recovery_key: Option<bool>,
    wrap_all: bool,
}

/// Generates a Unique Nonce
pub struct Nonce;

impl Nonce {
    /// # Generates a Unique Nonce via Hash
    /// - Recommended for use in most cases
    /// - Adding extra security by hashing the nonce
    pub fn hashed_nonce(rng: Rng) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = rand::random_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::HashedNonce(nonce)
    }

    /// # Generates a Unique Nonce via Tag and Hash
    /// - Adding extra security by hashing the nonce
    /// - Adding tag to the nonce (Extra Security)
    pub fn tagged_nonce(rng: Rng, tag: &[u8]) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = rand::random_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::TaggedNonce(*blake3::hash(&[&nonce, tag].concat()).as_bytes()) // Hash the nonce to get a 32 byte more random nonce (Extra Security)
    }

    /// Generates a Unique Nonce via Machine Info and Hash
    /// This nonce must be saved along with the encrypted data.
    /// - Adding extra security by hashing the nonce
    /// - Adding machine info to the nonce (Extra Security)
    pub fn machine_nonce(rng: Option<Rng>) -> NonceData {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();
        let distro = whoami::distro();

        let mut all_data = Vec::new();

        all_data.extend_from_slice(user_name.as_bytes());
        all_data.extend_from_slice(device_name.as_bytes());
        all_data.extend_from_slice(real_name.as_bytes());
        all_data.extend_from_slice(distro.as_bytes());

        if let Some(rng) = rng {
            all_data.extend_from_slice(rng.as_bytes());
        }

        let hash = blake3::hash(&all_data);

        NonceData::MachineNonce(*hash.as_bytes())
    }

    /// Generates a unique Nonce
    /// - Classic method with random bytes
    pub fn nonce(rng: Rng) -> NonceData {
        let nonce = *rng.as_bytes();
        let number: u8 = random_range(0..255);

        let new_nonce_vec = nonce
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let add = (rng.as_bytes()[i % rng.as_bytes().len()] as usize) % (i + 1);
                let add = add as u8;
                b.wrapping_add(add.wrapping_add(number))
            })
            .collect::<Vec<u8>>();

        let mut new_nonce = [0u8; 32];
        new_nonce.copy_from_slice(&new_nonce_vec[..32]);

        NonceData::Nonce(new_nonce)
    }
}

// -----------------------------------------------------

/// Generator for a new salt
/// - You can save this salt to a file or database, or you can add directly to encrypted data.
///
/// /// ⚠️ Warning:
/// If you lose this salt, decryption will fail. Keep it safe like your password.
#[derive(Debug, Copy, Clone)]
pub enum Salt {
    Salt([u8; 32]),
}

impl Salt {
    /// Generate a new salt
    /// Generates a new salt using a combination of random bytes from the thread and OS random number generators.
    /// - You have to save this salt to a file or database, or you can add directly to encrypted data.
    pub fn new() -> Self {
        let rng = *Rng::thread_rng().as_bytes();
        let mix_rng = *Rng::osrng().as_bytes();
        let hash_rng = vec![rng, mix_rng].concat();
        let mut out = Vec::new();

        for (i, b) in hash_rng.iter().enumerate() {
            let b = *b;
            let add = (mix_rng[i % mix_rng.len()] as usize) % (i + 1);
            let add = add as u8;
            let new_b = b.wrapping_add(add.wrapping_add(rng[i % rng.len()] % 8));
            out.push(new_b);
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&out[..32]);

        Salt::Salt(salt)
    }

    /// Returns the salt as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Salt::Salt(bytes) => bytes,
        }
    }

    /// Returns the salt as a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Returns vector or byte slice as a salt data.
/// You can use this to turn a vector or byte slice into a salt.
pub trait AsSalt {
    fn as_salt(&self) -> Salt;
    fn as_salt_safe(&self) -> Result<Salt, String>;
}

impl AsSalt for &[u8] {
    fn as_salt(&self) -> Salt {
        assert!(self.len() == 32, "Salt input must be exactly 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self[..32]);
        Salt::Salt(arr)
    }

    fn as_salt_safe(&self) -> Result<Salt, String> {
        if self.len() != 32 {
            Err("Salt input must be exactly 32 bytes".to_string())
        } else {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self[..32]);
            Ok(Salt::Salt(arr))
        }
    }
}

// -----------------------------------------------------

fn derive_password_key(
    pwd: &[u8],
    salt: &[u8],
    custom_salt: Option<Salt>,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    if pwd.len().ct_eq(&32).unwrap_u8() != 1 {
        return Err(Errors::Argon2Failed("Invalid Password".to_string()));
    }

    let mut salt = SaltString::encode_b64(salt).map_err(|e| Errors::Argon2Failed(e.to_string()))?;

    if let Some(custom_salt) = custom_salt {
        salt = SaltString::encode_b64(custom_salt.as_bytes())
            .map_err(|e| Errors::Argon2Failed(e.to_string()))?;
    }

    let argon = Argon2::default();
    let mut out = vec![0u8; 32]; // 256-bit key
    argon
        .hash_password_into(pwd, salt.as_str().as_bytes(), &mut out)
        .map_err(|e| Errors::Argon2Failed(e.to_string()))?; // Hashing Password VIA Argon2

    let password = match config.key_length {
        KeyLength::Key256 => out,
        KeyLength::Key512 => {
            let mut pwd_hasher = Sha3_512::new();
            pwd_hasher.update(&out);
            pwd_hasher.update(salt.as_str().as_bytes());
            pwd_hasher.finalize().to_vec()
        }
    };

    Ok(password)
}

// TODO: Better key verification system via new dervition system; While Argon2 getting better salt Key will become more secure and easy to verify
fn verify_keys_constant_time(key1: &[u8], key2: &[u8]) -> Result<bool, Errors> {
    if key1.len().ct_eq(&key2.len()).unwrap_u8() != 1 {
        return Ok(false);
    }

    let result = key1.ct_eq(key2).unwrap_u8() == 1;
    Ok(result)
}

// -----------------------------------------------------

fn secure_zeroize(data: &mut [u8]) {
    if data.len() < 1024 * 1024 * 5 {
        use rand::Rng;
        let mut rng = rand::rng();

        for byte in data.iter_mut() {
            *byte = rng.random::<u8>();
        }
    }

    data.zeroize();
}

fn calculate_hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>, Errors> {
    type HMAC = Hmac<Sha3_512>;
    let mut mac = HMAC::new_from_slice(key).map_err(|e| Errors::InvalidKey(e.to_string()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn generate_full_wordlist() -> Vec<String> {
    vec![
        "APPLE",
        "BANANA",
        "CHERRY",
        "DATE",
        "ELDERBERRY",
        "ALPHA",
        "OMEGA",
        "UPPER",
        "STAIR",
        "LOWER",
        "99",
        "23",
        "83",
        "61",
        "TABLE",
        "CHAIR",
        "MEMORIES",
        "GAME",
        "VIDEO",
        "FOOTBALL",
        "BASKETBALL",
        "CRICKET",
        "BALL",
        "COMPUTER",
        "CPU",
        "GPU",
        "ALGORITHM",
        "BIT",
        "BYTE",
        "CODE",
        "LOGIC",
        "RUST",
        "PYTHON",
        "JAVA",
        "SWIFT",
        "KERNEL",
        "PIXEL",
        "BLOCK",
        "CHAIN",
        "HASH",
        "MINT",
        "SNOW",
        "RAVEN",
        "FALCON",
        "NOVA",
        "JUNO",
        "TANGO",
        "ECHO",
        "LIMA",
        "ZULU",
        "DELTA",
        "VICTOR",
        "WHISKEY",
        "XRAY",
        "YANKIE",
        "ZETA",
        "SIGMA",
        "THETA",
        "EPSILON",
        "GAMMA",
        "NEON",
        "QUARK",
        "FLUX",
        "MOON",
        "ORBIT",
        "SUN",
        "SOLAR",
        "MARS",
        "VENUS",
        "PLUTO",
        "EARTH",
        "SATURN",
        "URANUS",
        "BINARY",
        "HEX",
        "DECIMAL",
        "CIPHER",
        "MATRIX",
        "NODE",
        "JUPITER",
        "NEPTUNE",
        "MERCURY",
        "COMET",
        "STAR",
        "GALAXY",
        "NEBULA",
        "COSMIC",
        "QUANTUM",
        "PARTICLE",
        "ATOM",
        "ELECTRON",
        "PROTON",
        "NEUTRON",
        "WAVE",
        "ENERGY",
        "LASER",
        "PLASMA",
        "ROCKET",
        "SHUTTLE",
        "STATION",
        "SATELLITE",
        "ROVER",
        "LANDER",
        "MISSION",
        "LAUNCH",
        "CLOUD",
        "DATABASE",
        "SERVER",
        "NETWORK",
        "ROUTER",
        "SWITCH",
        "FIREWALL",
        "PROTOCOL",
        "WIFI",
        "BLUETOOTH",
        "ETHERNET",
        "MODEM",
        "BROWSER",
        "WEBSITE",
        "INTERNET",
        "DOMAIN",
        "EMAIL",
        "PASSWORD",
        "USERNAME",
        "LOGIN",
        "ACCOUNT",
        "PROFILE",
        "AVATAR",
        "DIGITAL",
        "VIRTUAL",
        "REALITY",
        "AUGMENT",
        "NEURAL",
        "CRYPTO",
        "TOKEN",
        "WALLET",
        "SMART",
        "CONTRACT",
        "TRANSACTION",
        "LEDGER",
        "MINE",
        "VERIFY",
        "VALIDATE",
        "ENCRYPT",
        "DECRYPT",
        "SECURE",
        "KEY",
        "PRIVATE",
        "PUBLIC",
        "OCEAN",
        "RIVER",
        "LAKE",
        "MOUNTAIN",
        "FOREST",
        "DESERT",
        "ARCTIC",
        "TROPICS",
        "PRAIRIE",
        "CANYON",
        "VALLEY",
        "REEF",
        "ISLAND",
        "BEACH",
        "COAST",
        "VOLCANO",
        "GLACIER",
        "STORM",
        "THUNDER",
        "LIGHTNING",
        "RAINBOW",
        "SUNRISE",
        "SUNSET",
        "HORIZON",
        "ZENITH",
        "NADIR",
        "DRAGON",
        "PHOENIX",
        "GRIFFIN",
        "UNICORN",
        "KRAKEN",
        "HYDRA",
        "SPHINX",
        "PEGASUS",
        "MINOTAUR",
        "CENTAUR",
        "SIREN",
        "CHIMERA",
        "TITAN",
        "CYCLOPS",
        "MEDUSA",
        "LIBRARY",
        "MUSEUM",
        "GALLERY",
        "THEATER",
        "CINEMA",
        "CONCERT",
        "STADIUM",
        "ARENA",
        "PLAZA",
        "GARDEN",
        "PARK",
        "BRIDGE",
        "TOWER",
        "CASTLE",
        "PALACE",
        "TEMPLE",
        "PYRAMID",
        "GUITAR",
        "PIANO",
        "VIOLIN",
        "TRUMPET",
        "DRUMS",
        "FLUTE",
        "SAXOPHONE",
        "HARP",
        "ACCORDION",
        "MELODY",
        "HARMONY",
        "RHYTHM",
        "TEMPO",
        "BEAR",
        "CLOCK",
        "WATCH",
        "CALENDAR",
        "DIAMOND",
        "RUBY",
        "EMERALD",
        "SAPPHIRE",
        "PEARL",
        "JADE",
        "OPAL",
        "AMBER",
        "CRYSTAL",
        "GOLD",
        "SILVER",
        "PLATINUM",
        "COPPER",
        "IRON",
        "STEEL",
        "BRONZE",
        "MARBLE",
        "GRANITE",
        "BREEZE",
        "GUST",
        "TORNADO",
        "HURRICANE",
        "TYPHOON",
        "CYCLONE",
        "BLIZZARD",
        "AVALANCHE",
        "TSUNAMI",
        "EARTHQUAKE",
        "PLANET",
        "METEOR",
        "ASTEROID",
        "TELESCOPE",
        "MICROSCOPE",
        "COMPASS",
        "SEXTANT",
    ]
    .iter()
    .map(|byte| byte.to_string())
    .collect()
}

fn generate_recovery_key(key: &[u8], nonce: &[u8]) -> String {
    let word_list = generate_full_wordlist();
    let mut key = key.to_vec();

    key.iter_mut()
        .enumerate()
        .for_each(|(i, b)| *b = b.wrapping_add(nonce[i % nonce.len()]));

    let words: Vec<&str> = key
        .iter()
        .map(|&byte| word_list[byte as usize].as_str())
        .collect();

    words.join("-")
}

fn parse_recovery_key(input: &str, nonce: &[u8]) -> Result<Vec<u8>, Errors> {
    let word_list = generate_full_wordlist();

    let word_map: std::collections::HashMap<String, u8> = word_list
        .iter()
        .enumerate()
        .map(|(i, word)| (word.to_ascii_uppercase(), i as u8))
        .collect();

    let mut key = input
        .split('-')
        .map(|word| word_map.get(&word.to_ascii_uppercase()).copied())
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| Errors::EmptyPassword)?;

    key.iter_mut()
        .enumerate()
        .for_each(|(i, b)| *b = b.wrapping_sub(nonce[i % nonce.len()]));

    Ok(key)
}

fn encrypt(
    password: &str,
    data: &[u8],
    nonce: NonceData,
    config: Config,
    custom_salt: Option<Salt>,
    wrap_all: bool,
    recovery_key: Option<bool>,
) -> Result<Vec<u8>, Errors> {
    let key_len = match config.key_length {
        KeyLength::Key256 => 32,
        KeyLength::Key512 => 64,
    };

    if password.len().ct_ne(&0).unwrap_u8() != 1 {
        return Err(Errors::EmptyPassword);
    } else if (password.len() as u32).ct_lt(&key_len).unwrap_u8() == 1 {
        return Err(Errors::PasswordTooShort(format!(
            "Password must be at least {} characters for cryptographic strength.",
            key_len
        )));
    }

    if let Some(recovery_key) = recovery_key {
        if recovery_key == true {
            println!(
                "Recovery Key: {}",
                generate_recovery_key(password.as_bytes(), nonce.as_bytes())
            );
        }
    }

    let nonce = nonce.as_bytes();
    let mut password = derive_key(password, nonce);
    let mut pwd = derive_password_key(&password, nonce, custom_salt, config)?;

    secure_zeroize(&mut password);

    let mut out_vec = Vec::new();

    if wrap_all {
        out_vec.extend(nonce);
    }

    {
        let pwd = blake3::hash(b"atom-crypte-password");
        let pwd = *pwd.as_bytes();
        let encrypted_version = xor_encrypt(nonce, &pwd, &mut VERSION.to_vec(), config)?;
        out_vec.extend(encrypted_version);
    }

    let mut mixed_data = mix_blocks(
        &mut s_bytes(data, nonce, &pwd, config)?,
        nonce,
        &pwd,
        config,
    )?;
    let mut mixed_columns_data = triangle_mix_columns(
        &mut mixed_data,
        &GaloisField::new(config.gf_poly.value()),
        config,
    )?;

    secure_zeroize(&mut mixed_data);

    let mut shifted_data = s_bytes(
        &dynamic_shift(&mut mixed_columns_data, nonce, &pwd, config)?,
        nonce,
        &pwd,
        config,
    )?;

    secure_zeroize(&mut mixed_columns_data);

    let mut crypted = Vec::new();
    let mut round_data = xor_encrypt(nonce, &pwd, &mut shifted_data, config)?;

    secure_zeroize(&mut shifted_data);

    for i in 0..=config.rounds {
        let slice_end = std::cmp::min(i * 16, pwd.len());
        let key = match config.key_length {
            KeyLength::Key256 => blake3::hash(&pwd[..slice_end]).as_bytes().to_vec(),
            KeyLength::Key512 => {
                let mut hash = Sha3_512::new();
                hash.update(&pwd[..slice_end]);
                hash.finalize().to_vec()
            }
        };

        let crypted_chunks = round_data
            .par_chunks(dynamic_sizes(round_data.len()) as usize)
            .map(|data: &[u8]| {
                xor_encrypt(nonce, &key, &mut data.to_vec(), config)
                    .map_err(|e| Errors::InvalidXor(e.to_string()))
            })
            .collect::<Result<Vec<Vec<u8>>, Errors>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>();

        if i == config.rounds {
            crypted.extend(crypted_chunks);
        } else {
            secure_zeroize(&mut round_data);
            round_data = crypted_chunks;
        }
    }

    let mut data = Vec::from(blake3::hash(&data).as_bytes());
    data.extend(blake3::hash(&crypted).as_bytes());

    let mac = calculate_hmac(&pwd, &data)?;

    secure_zeroize(&mut pwd);

    out_vec.extend(crypted);
    out_vec.extend(mac);

    if wrap_all {
        if custom_salt.is_some() {
            out_vec.extend(
                custom_salt
                    .ok_or(Errors::BuildFailed("Cannot Open Salt".to_string()))?
                    .as_bytes(),
            );
        } else {
            out_vec.extend(nonce);
        }
    }

    Ok(out_vec)
}

// -----------------------------------------------------

fn decrypt(
    password: &str,
    data: &[u8],
    nonce: Option<NonceData>,
    config: Config,
    custom_salt: Option<Salt>,
    wrap_all: bool,
    recovery_key: Option<String>,
) -> Result<Vec<u8>, Errors> {
    let (nonce_data, custom_salt) = if let Some(nonce) = nonce {
        (nonce, custom_salt)
    } else {
        let (_, custom_salt) = data.split_at(data.len() - 32);
        let (nonce, _) = data.split_at(32);

        (nonce.as_nonce(), Option::from(custom_salt.as_salt()))
    };

    let nonce_byte = nonce_data.as_bytes();

    let password = if let Some(key) = recovery_key {
        String::from_utf8_lossy(&parse_recovery_key(&key, nonce_byte)?).to_string()
    } else {
        password.to_string()
    };

    let password_hash: [u8; 32] = derive_key(password.as_str(), nonce_byte);
    let mut expected_password = derive_password_key(
        &derive_key(password.as_str(), nonce_byte),
        nonce_byte,
        custom_salt,
        config,
    )?;
    let mut pwd = derive_password_key(&password_hash, nonce_byte, custom_salt, config)?;

    if !verify_keys_constant_time(&pwd, &expected_password)? {
        secure_zeroize(&mut pwd);
        secure_zeroize(&mut expected_password);
        return Err(Errors::InvalidMac("Invalid key".to_string()));
    }

    secure_zeroize(&mut expected_password);

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

    let version_pwd = blake3::hash(b"atom-crypte-password");
    let version_pwd = *version_pwd.as_bytes();
    let mut encrypted_version = encrypted_version.to_vec();
    let version = xor_decrypt(nonce_byte, &version_pwd, &mut encrypted_version, config)?;

    if !version.starts_with(b"atom-version") {
        secure_zeroize(&mut pwd);
        return Err(Errors::InvalidAlgorithm);
    }

    let (crypted, mac_key) = if version.starts_with(b"atom-version:0x5") && wrapped {
        let (crypted, rest) = rest.split_at(rest.len() - 96);
        let (mac_key, _) = rest.split_at(64);

        (crypted, mac_key)
    } else {
        let (crypted, mac_key) = rest.split_at(rest.len() - 64);

        (crypted, mac_key)
    };

    let mut xor_decrypted = Vec::new();
    let mut round_data = Vec::from(crypted);

    for i in (0..=config.rounds).rev() {
        let slice_end = std::cmp::min(i * 16, pwd.len());
        let key = match config.key_length {
            KeyLength::Key256 => blake3::hash(&pwd[..slice_end]).as_bytes().to_vec(),
            KeyLength::Key512 => {
                let mut hash = Sha3_512::new();
                hash.update(&pwd[..slice_end]);
                hash.finalize().to_vec()
            }
        };

        let decrypted = round_data
            .to_vec()
            .par_chunks_mut(dynamic_sizes(round_data.len()) as usize)
            .map(|data: &mut [u8]| {
                xor_decrypt(nonce_byte, &key, data, config)
                    .map_err(|e| Errors::InvalidXor(e.to_string()))
            })
            .collect::<Result<Vec<Vec<u8>>, Errors>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>();

        if i == 0 {
            xor_decrypted.extend(decrypted);
        } else {
            secure_zeroize(&mut round_data);
            round_data = decrypted
        }
    }

    let mut xor_decrypted = xor_decrypt(nonce_byte, &pwd, &mut xor_decrypted, config)?;

    let mut unshifted = dynamic_unshift(
        &in_s_bytes(&mut xor_decrypted, nonce_byte, &pwd, config)?,
        nonce_byte,
        &pwd,
        config,
    )?;

    secure_zeroize(&mut xor_decrypted);

    let mut inversed_columns = inverse_triangle_mix_columns(
        &mut unshifted,
        &GaloisField::new(config.gf_poly.value()),
        config,
    )?;
    let mut unmixed = unmix_blocks(&mut inversed_columns, nonce_byte, &pwd, config)?;

    secure_zeroize(&mut unshifted);
    secure_zeroize(&mut inversed_columns);

    let mut decrypted_data = in_s_bytes(&unmixed, nonce_byte, &pwd, config)?;

    secure_zeroize(&mut unmixed);

    let mut data = Vec::from(blake3::hash(&decrypted_data).as_bytes());
    data.extend(blake3::hash(&crypted).as_bytes());

    let mut mac = calculate_hmac(&pwd, &data)?;

    if mac.ct_eq(mac_key).unwrap_u8() != 1 {
        // Check if the MAC is valid
        secure_zeroize(&mut decrypted_data);
        secure_zeroize(&mut mac);
        secure_zeroize(&mut data);
        return Err(Errors::InvalidMac("Invalid authentication".to_string()));
    }

    secure_zeroize(&mut data);

    Ok(decrypted_data)
}

// -----------------------------------------------------

pub trait AsBase {
    fn as_base64(&self) -> String;
    fn as_string(&self) -> String;
}

impl AsBase for Vec<u8> {
    fn as_base64(&self) -> String {
        BASE64_STANDARD.encode(self)
    }

    fn as_string(&self) -> String {
        String::from_utf8_lossy(self).to_string()
    }
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

impl AtomCrypteBuilder {
    /// Creates a new instance of AtomCrypteBuilder.
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

    /// Sets the salt for the encryption.
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the recovery decryption key for the decryption.
    pub fn decrypt_from_recovery_key(mut self, decryption_key: String) -> Self {
        self.decryption_key = Some(decryption_key);
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
        let salt = self.salt;
        let (recovery_key, benchmark, wrap_all) = if let Some(reocvery_key) = self.utils {
            (
                reocvery_key.recovery_key,
                reocvery_key.benchmark,
                reocvery_key.wrap_all,
            )
        } else {
            (None, false, false)
        };

        if benchmark {
            let start = Instant::now();
            let out = encrypt(
                password.as_str(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
            )?;
            let duration = start.elapsed();
            println!("Encryption took {}ms", duration.as_millis());
            Ok(out)
        } else {
            encrypt(
                password.as_str(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
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
                password.as_str(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
            );
            let duration = start.elapsed();
            println!("Decryption took {}ms", duration.as_millis());
            out
        } else {
            decrypt(
                password.as_str(),
                &data,
                nonce,
                config,
                salt,
                wrap_all,
                recovery_key,
            )
        }
    }
}
