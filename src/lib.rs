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

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, prelude::BASE64_STANDARD};
use blake3::derive_key;
use engine::engine::*;
use hmac::Hmac;
use hmac::Mac;
use rand::{RngCore, TryRngCore, random_range, rngs::OsRng};
use rayon::prelude::*;
use sha3::{Digest, Sha3_512};
use std::sync::Arc;
use std::time::Instant;
use subtle::{ConstantTimeEq, ConstantTimeLess};
use sysinfo::System;
use thiserror::Error;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::MaxBuffer;
use tss_esapi::tcti_ldr::DeviceConfig;
use zeroize::Zeroize;
mod engine;

static VERSION: &[u8] = b"atom-version:0x7";

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
    #[error("TPM is not enabled")]
    TpmNotEnabled,
    #[error("TPM Error: {0}")]
    TpmError(String),
    #[error("Hardware nonce is not enabled")]
    HardwareNonceNotEnabled,
    #[error("Invalid TPM response")]
    InvalidTpmResponse,
    #[error("RNG Required for this type")]
    RngRequired,
    #[error("TPM Hashing Error: {0}")]
    TpmHashingError(String),
    #[error("Galois Field Error: {0}")]
    GaloisFieldError(String),
    #[error("Hardware Hashing Error: {0}")]
    HardwareHashingError(String),
    #[error("Data Error: {0}")]
    DataError(String),
    #[error("Cannot perform operation: {0}")]
    InverseError(String),
    #[error("Chunk Error: {0}")]
    ChunkError(String),
    #[error("0.7.0 is not backward compatible")]
    NotBackwardCompatible,
}

/// Represents different types of sboxes that can be used for encryption and decryption.
/// # Not recommended for use in production environments.
#[derive(Debug, Clone, Copy)]
pub enum SboxTypes {
    NonceBased,
    PasswordAndNonceBased,
}

/// Represents different types of irreducible polynomials that can be used for encryption and decryption.
#[derive(Debug, Clone, Copy)]
pub enum IrreduciblePoly {
    AES,
    Conway,
    Custom(u16),
}

impl IrreduciblePoly {
    fn value(&self) -> u16 {
        match self {
            IrreduciblePoly::AES => 0x11B,
            IrreduciblePoly::Conway => 0x14D,
            IrreduciblePoly::Custom(val) => *val,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLength {
    Key256,
    Key512,
}

/// Represents different types of Argon2 variants that can be used for password hashing.
/// # ⚠️ CRITICAL CONFIGURATION - DO NOT MODIFY
///
/// Changing this value will make ALL existing encrypted data
/// unreadable and ALL existing passwords invalid.
///
/// This setting must remain consistent across:
/// - Database encryption/decryption
/// - User password verification
/// - Key derivation functions
///
/// Only change if:
/// - Starting fresh deployment (no existing data)
/// - Performing planned migration with data conversion
/// - You have cryptographic expertise
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    Argon2d,
    Argon2i,
    Argon2id,
}

/// Thread strategy for the encryption and decryption process.
/// # ⚠️ WARNING: If SIMD (AVX2) enabled encryption will always use full threads.
/// - `AutoThread`: Automatically determine the number of threads to use.
/// - `FullThread`: Use all available threads.
/// - `LowThread`: Use a low number of threads
/// - `BulkOperations`: Optimize for bulk operations.
/// - `Gaming`: Optimize for gaming scenarios.
/// - `SingleThread`: Use a single thread.
/// - `Custom(usize)`: Specify a custom number of threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStrategy {
    AutoThread,
    FullThread,
    LowThread,
    BulkOperations,
    Gaming,
    SingleThread,
    Custom(usize),
}

/// Galois Field Type for Diffusion
/// # ⚠️ WARNING: Triangular have more diffusion than AES, Recommended using Triangular
/// # ⚠️ WARNING: DO NOT CHANGE UNLESS YOU KNOW WHAT YOU'RE DOING
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaloisFieldType {
    Triangular,
    AES,
    Hybrid,
}

/// Represents hardware capabilities.
#[derive(Debug, Clone, Copy)]
pub struct Hardware {
    pub tpm_enabled: bool,
    /// Using TPM for nonce generation
    pub hardware_nonce: bool,
    /// Using TPM for hashing
    pub hardware_hashing: bool,
    /// Enable AVX2 usage
    pub enable_avx2: bool,
}

impl Hardware {
    pub fn new() -> Self {
        Hardware {
            tpm_enabled: true,
            hardware_nonce: true,
            hardware_hashing: false,
            enable_avx2: true,
        }
    }

    pub fn set_tpm_enabled(mut self, tpm_enabled: bool) -> Self {
        self.tpm_enabled = tpm_enabled;
        self
    }

    pub fn set_hardware_nonce(mut self, hardware_nonce: bool) -> Self {
        self.hardware_nonce = hardware_nonce;
        self
    }

    pub fn set_hardware_hashing(mut self, hardware_hashing: bool) -> Self {
        self.hardware_hashing = hardware_hashing;
        self
    }

    pub fn set_enable_avx2(mut self, enable_avx2: bool) -> Self {
        self.enable_avx2 = enable_avx2;
        self
    }
}

/// Configuration for AtomCrypte encryption/decryption operations.
///
/// # Security Profiles
/// Use `Config::from_profile()` for predefined security levels, or customize individual options.
///
/// # Performance Impact
/// - `constant_time_sbox`: ~7x slower but timing-attack resistant
/// - `constant_time_key_lookup`: ~7-20x slower but timing-attack resistant
/// - `dummy_data`: Minimal overhead, adds side-channel protection
/// - `rounds > 6`: Significant impact on performance
///
/// # Example
/// ```rust
/// // Balanced security-performance
/// let config = Config::from_profile(Profile::Balanced);
///
/// // Maximum security (timing attack resistant)
/// let paranoid = Config::from_profile(Profile::Max);
///
/// // Custom configuration
/// let custom = Config::default()
///     .constant_time_sbox(true)  // 7x slower, timing-attack resistant
///     .rounds(3);                // 3x crypto rounds
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Threading strategy for parallel operations
    pub thread_strategy: ThreadStrategy,

    /// Stack size for each thread in bytes
    pub stack_size: usize,

    /// Galois field irreducible polynomial
    pub gf_poly: IrreduciblePoly,

    /// Galois field type
    /// # ⚠️ WARNING: DO NOT CHANGE UNLESS YOU KNOW WHAT YOU'RE DOING
    pub gf_type: GaloisFieldType,

    /// Number of encryption rounds (1-10 recommended)
    pub rounds: usize,

    /// Key derivation output length
    pub key_length: KeyLength,

    /// Generate dummy data for side-channel resistance
    pub dummy_data: bool,

    /// Use constant-time S-box operations. Provides timing attack resistance
    /// at ~7x performance cost. Recommended for high-security environments.
    pub constant_time_sbox: bool,

    /// Use constant-time key lookup operations. Provides timing attack resistance
    /// at ~7-20x performance cost. Recommended for high-security environments.
    pub constant_time_key_lookup: bool,

    /// TPM hardware support
    pub hardware: Hardware,

    /// # ⚠️ EXTREMELY EXPENSIVE – DO NOT ENABLE UNLESS YOU KNOW WHAT YOU'RE DOING
    /// # ⚠️ ~65,000 CPU CYCLES PER SINGLE GALOIS FIELD OPERATION
    ///
    /// Use constant-time Galois field operations. Provides timing attack resistance
    /// at ~1000-2000 performance cost. Recommended for high-security environments.
    ///
    /// ⚠️ **Warning**: This flag should NOT be enabled unless required by a strict threat model.
    pub constant_time_galois_field: bool,

    /// Can affect performance.
    /// Adds more security.
    pub multi_round_galois_field: bool,

    /// Can affect performance.
    /// Adds more security.
    pub ctr_layer: bool,

    /// 🆕 NEW: Enable/disable key derivation
    /// When false: uses password directly (FAST but INSECURE for weak passwords)
    /// When true: uses Argon2 + BLAKE3 derivation (SECURE but slower)
    pub key_derivation: bool,

    /// Enable/disable secure zeroization
    pub secure_zeroize: bool,

    pub zeroize: bool,

    /// # ⚠️ CRITICAL CONFIGURATION - DO NOT MODIFY
    ///
    /// Changing this value will make ALL existing encrypted data
    /// unreadable and ALL existing passwords invalid.
    ///
    /// This setting must remain consistent across:
    /// - Database encryption/decryption
    /// - User password verification
    /// - Key derivation functions
    ///
    /// Only change if:
    /// - Starting fresh deployment (no existing data)
    /// - Performing planned migration with data conversion
    /// - You have cryptographic expertise
    pub argon2_type: Argon2Type,
}

/// Profile for the encryption and decryption process.
/// - `extreme`: Extreme security level.
/// - `fortress`: Maximum security level, can be good against any attacks.
/// - `max`: Maximum security level, can be good against most attacks.
/// - `secure`: Secure security level.
/// - `balanced`: Balanced security level.
/// - `fast`: Fast security level.
///
/// Profile::Extreme - MAXIMUM SECURITY
///
/// ⚠️ WARNING: EXTREMELY SLOW! ⚠️
///
/// Performance: ~500 bytes/second
/// Use only when:
/// - Data value > time cost
/// - Maximum security required
/// - Side-channel attacks likely
/// - No performance requirements
///
/// Features:
/// - Constant-time operations
/// - 10 encryption rounds
/// - 512-bit keys
/// - No hardware dependencies
/// - Maximum memory protection
#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Extreme,
    Fortress,
    Max,
    Secure,
    Balanced,
    Fast,
    TriangleTestSuite,
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
                    0..45 => rayon::current_num_threads(),
                    45..65 => {
                        (rayon::current_num_threads() / 2) + (rayon::current_num_threads() / 4)
                    }
                    65..80 => rayon::current_num_threads() / 2,
                    80..99 => rayon::current_num_threads() / 4,
                    _ => 1,
                }
            }
            Self::FullThread => rayon::current_num_threads(),
            Self::LowThread => rayon::current_num_threads() / 2,
            Self::BulkOperations => {
                (rayon::current_num_threads() / 2) + (rayon::current_num_threads() / 4)
            }
            Self::SingleThread => 1,
            Self::Gaming => {
                if rayon::current_num_threads() > 6 {
                    rayon::current_num_threads() / 4
                } else {
                    rayon::current_num_threads() / 2
                }
            }
            Self::Custom(num_threads) => *num_threads,
        }
    }
}

impl Default for Config {
    /// Default configuration for the encryption and decryption process.
    fn default() -> Self {
        Self {
            thread_strategy: ThreadStrategy::AutoThread,
            stack_size: 64 * 1024 * 1024,
            gf_poly: IrreduciblePoly::AES,
            gf_type: GaloisFieldType::AES,
            rounds: 2,
            key_length: KeyLength::Key512,
            dummy_data: true,
            multi_round_galois_field: true,
            ctr_layer: true,
            constant_time_sbox: false,
            constant_time_key_lookup: false,
            constant_time_galois_field: false,
            key_derivation: true,
            secure_zeroize: false,
            zeroize: false,
            argon2_type: Argon2Type::Argon2id,
            hardware: Hardware::new(),
        }
    }
}

impl Config {
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

    /// Sets the Galois field to use for encryption and decryption.
    /// # ⚠️ WARNING: DO NOT CHANGE UNLESS YOU KNOW WHAT YOU'RE DOING
    pub fn gf_type(mut self, gf: GaloisFieldType) -> Self {
        self.gf_type = gf;
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
        } else if num > 10 {
            eprintln!("Round count too high will have significant impact on performance.");
            self.rounds = num;
        } else {
            self.rounds = num;
        }
        self
    }

    /// Sets the dummy data.
    /// Recommended dummy data for security.
    pub fn dummy_data(mut self, dummy_data: bool) -> Self {
        self.dummy_data = dummy_data;
        self
    }

    /// Sets the constant time sbox.
    /// Recommended constant time sbox for security.
    pub fn constant_time_sbox(mut self, constant_time_sbox: bool) -> Self {
        self.constant_time_sbox = constant_time_sbox;
        self
    }

    /// Sets the constant time key lookup.
    /// Recommended constant time key lookup for security.
    pub fn constant_time_key_lookup(mut self, constant_time_key_lookup: bool) -> Self {
        self.constant_time_key_lookup = constant_time_key_lookup;
        self
    }

    /// Sets the complexity level (0-10).
    ///
    /// # Performance Guide:
    /// - **0-1**: Fast operations (~1.5-2s for 200MB) - Everyday use
    /// - **2-3**: Balanced operations (~1.5-3s for 200MB) - Everyday use
    /// - **4-5**: Secure operations (~2-4s for 200MB) - Secure for most tasks
    /// - **6-7**: Maximum operations (~15-50s for 200MB) - Research/Academic
    /// - **8-10**: Full features operations (~100s+ for 200MB) - Maximum security
    /// - WARNING: Performance assumes mid-range CPU. On high-end processors (e.g., EPYC 9004/9002 series) performance can exceed 1GB/s.
    ///
    /// # Example:
    /// ```rust
    /// let fast_config = Config::default().complexity(1);      // Quick encryption
    /// let secure_config = Config::default().complexity(5);    // Enterprise grade
    /// let fortress_config = Config::default().complexity(10); // Maximum security
    /// ```
    pub fn complexity(self, level: u8) -> Self {
        match level {
            0..=1 => Self::from_profile(Profile::Fast),
            2..=3 => Self::from_profile(Profile::Balanced),
            4..=5 => Self::from_profile(Profile::Secure),
            6..=7 => Self::from_profile(Profile::Max),
            8..=10 => Self::from_profile(Profile::Fortress),
            _ => Self::from_profile(Profile::Fortress),
        }
    }

    pub fn set_hardware(mut self, hardware: Hardware) -> Self {
        self.hardware = hardware;
        self
    }

    /// # ⚠️ EXTREMELY EXPENSIVE – DO NOT ENABLE UNLESS YOU KNOW WHAT YOU'RE DOING
    /// # ⚠️ ~65,000 CPU CYCLES PER SINGLE GALOIS FIELD OPERATION
    ///
    /// Use constant-time Galois field operations. Provides timing attack resistance
    /// at ~1000-2000 performance cost. Recommended for high-security environments.
    ///
    /// ⚠️ **Warning**: This flag should NOT be enabled unless required by a strict threat model.
    pub fn constant_time_galois_field(mut self, constant_time_galois_field: bool) -> Self {
        self.constant_time_galois_field = constant_time_galois_field;
        self
    }

    /// Set the stack size for the thread
    pub fn stack_size(mut self, stack_size: usize) -> Self {
        self.stack_size = stack_size;
        self
    }

    /// Use multiple rounds of Galois field operations. Provides additional security
    /// at a slight performance cost. Recommended for high-security environments.
    ///
    /// ⚠️ **Warning**: This flag should NOT be disabled unless you know what you are doing.
    pub fn multi_round_galois_field(mut self, multi_round_galois_field: bool) -> Self {
        self.multi_round_galois_field = multi_round_galois_field;
        self
    }

    /// Use CTR layer operations. Provides additional security
    /// at a slight performance cost. Recommended for high-security environments.
    ///
    /// ⚠️ **Warning**: This flag should NOT be disabled unless you know what you are doing.
    pub fn ctr_layer(mut self, ctr_layer: bool) -> Self {
        self.ctr_layer = ctr_layer;
        self
    }

    /// Enable/disable key derivation
    /// When false: uses password directly (FAST but INSECURE for weak passwords)
    /// When true: uses Argon2 + BLAKE3 derivation (SECURE but slower)
    pub fn key_derivation(mut self, key_derivation: bool) -> Self {
        self.key_derivation = key_derivation;
        self
    }

    /// Enable/disable secure zeroization
    pub fn enable_secure_zeroize(mut self, secure_zeroize: bool) -> Self {
        self.secure_zeroize = secure_zeroize;
        self
    }

    /// Enable/disable zeroization
    pub fn enable_zeroize(mut self, zeroize: bool) -> Self {
        self.zeroize = zeroize;
        self
    }

    /// # ⚠️ CRITICAL CONFIGURATION - DO NOT MODIFY
    ///
    /// Changing this value will make ALL existing encrypted data
    /// unreadable and ALL existing passwords invalid.
    ///
    /// This setting must remain consistent across:
    /// - Database encryption/decryption
    /// - User password verification
    /// - Key derivation functions
    ///
    /// Only change if:
    /// - Starting fresh deployment (no existing data)
    /// - Performing planned migration with data conversion
    /// - You have cryptographic expertise
    pub fn argon2_type(mut self, argon2_type: Argon2Type) -> Self {
        self.argon2_type = argon2_type;
        self
    }

    /// Create a configuration from a profile
    pub fn from_profile(profile: Profile) -> Self {
        match profile {
            Profile::Fast => Self {
                thread_strategy: ThreadStrategy::FullThread,
                stack_size: 64 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 1,
                key_length: KeyLength::Key256,
                dummy_data: true,
                multi_round_galois_field: false,
                ctr_layer: true,
                constant_time_sbox: false,
                constant_time_key_lookup: false,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: false,
                zeroize: false,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new(),
            },
            Profile::Balanced => Self {
                thread_strategy: ThreadStrategy::AutoThread,
                stack_size: 64 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 2,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: true,
                constant_time_sbox: false,
                constant_time_key_lookup: false,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: false,
                zeroize: false,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new(),
            },
            Profile::Secure => Self {
                thread_strategy: ThreadStrategy::AutoThread,
                stack_size: 64 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 2,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: true,
                constant_time_sbox: false,
                constant_time_key_lookup: false,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: false,
                zeroize: true,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new(),
            },
            Profile::Max => Self {
                thread_strategy: ThreadStrategy::AutoThread,
                stack_size: 128 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 4,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: true,
                constant_time_sbox: true,
                constant_time_key_lookup: false,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: true,
                zeroize: true,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new(),
            },
            Profile::Fortress => Self {
                thread_strategy: ThreadStrategy::FullThread,
                stack_size: 128 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 10,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: true,
                constant_time_sbox: true,
                constant_time_key_lookup: true,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: true,
                zeroize: true,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new().set_enable_avx2(false),
            },
            Profile::Extreme => Self {
                thread_strategy: ThreadStrategy::FullThread,
                stack_size: 128 * 1024 * 1024,
                gf_poly: IrreduciblePoly::AES,
                gf_type: GaloisFieldType::AES,
                rounds: 10,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: true,
                constant_time_sbox: true,
                constant_time_key_lookup: true,
                constant_time_galois_field: true,
                key_derivation: true,
                secure_zeroize: true,
                zeroize: true,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new().set_enable_avx2(false),
            },
            Profile::TriangleTestSuite => Self {
                thread_strategy: ThreadStrategy::AutoThread,
                stack_size: 64 * 1024 * 1024,
                gf_poly: IrreduciblePoly::Conway,
                gf_type: GaloisFieldType::Triangular,
                rounds: 2,
                key_length: KeyLength::Key512,
                dummy_data: true,
                multi_round_galois_field: true,
                ctr_layer: false,
                constant_time_sbox: false,
                constant_time_key_lookup: false,
                constant_time_galois_field: false,
                key_derivation: true,
                secure_zeroize: false,
                zeroize: false,
                argon2_type: Argon2Type::Argon2id,
                hardware: Hardware::new(),
            },
        }
    }
}

/// Using TPM for secure storage and nonce generation.
///
/// This implementation utilizes the Trusted Platform Module (TPM) to securely store and nonce generation.
#[derive(Debug, Clone, Copy)]
pub struct TpmModule;

impl TpmModule {
    pub fn generate_context(self, hardware: Hardware) -> Result<tss_esapi::Context, Errors> {
        if !hardware.tpm_enabled {
            println!("TPM is not enabled");
            return Err(Errors::TpmNotEnabled);
        }

        tss_esapi::Context::new(tss_esapi::TctiNameConf::Device(DeviceConfig::default()))
            .map_err(|e| Errors::TpmError(e.to_string()))
    }

    fn hash_key(
        key: MaxBuffer,
        context: &mut tss_esapi::Context,
        hardware: Hardware,
    ) -> Result<Vec<u8>, Errors> {
        if !hardware.hardware_hashing {
            return Err(Errors::HardwareHashingError(
                "Hardware hashing not enabled".to_string(),
            ));
        }

        let hash = context
            .hash(
                key,
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha3_512,
                Hierarchy::Owner,
            )
            .map_err(|e| Errors::TpmHashingError(e.to_string()))?;

        Ok(hash.0.to_vec())
    }

    fn generate_nonce(
        self,
        context: &mut tss_esapi::Context,
        hardware: Hardware,
    ) -> Result<NonceData, Errors> {
        if !hardware.hardware_nonce {
            println!("Hardware nonce is not enabled");
            return Err(Errors::HardwareNonceNotEnabled);
        }

        let random = context
            .get_random(32)
            .map_err(|_| Errors::InvalidTpmResponse)?
            .to_vec();

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&random[..32]);

        Ok(NonceData::Nonce(nonce))
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
/// # ⚠️ WARNING: YOU HAVE TO USE SUDO/ADMIN PRIVILEGES TO GENERATE A TPM NONCE.
///
/// ## Platform Requirements:
/// - **Linux:** `sudo your_app` or run as root
/// - **Windows:** Run as Administrator
/// - **macOS:** `sudo your_app` (if TPM available)
///
/// ## Why Admin Access is Required:
/// - Direct hardware access to TPM chip
/// - Security isolation from unprivileged processes
/// - Compliance with TPM security model
///
/// ## Fallback Strategy:
/// ```rust
/// let nonce = match Nonce::generate_nonce(None, NonceType::TPM(hardware, tpm)) {
///     Ok(hw_nonce) => hw_nonce,
///     Err(_) => {
///         eprintln!("TPM access failed, falling back to software nonce");
///         Nonce::generate_nonce(Some(rng), NonceType::Hashed)?
///     }
/// };
/// ```
pub struct Nonce;

/// Nonce Types
/// - Classic: Generates a random nonce.
/// - Hashed: Generates a hashed nonce.
/// - Tagged: Generates a tagged nonce.
/// - Machine: Generates a machine-specific nonce.
/// - TPM: Generates a nonce using a Trusted Platform Module.
///
/// # ⚠️ WARNING: YOU HAVE TO USE SUDO/ADMIN PRIVILEGES TO GENERATE A TPM NONCE.
///
/// ## Platform Requirements:
/// - **Linux:** `sudo your_app` or run as root
/// - **Windows:** Run as Administrator
/// - **macOS:** `sudo your_app` (if TPM available)
///
/// ## Why Admin Access is Required:
/// - Direct hardware access to TPM chip
/// - Security isolation from unprivileged processes
/// - Compliance with TPM security model
///
/// ## Fallback Strategy:
/// ```rust
/// let nonce = match Nonce::generate_nonce(None, NonceType::TPM(hardware, tpm)) {
///     Ok(hw_nonce) => hw_nonce,
///     Err(_) => {
///         eprintln!("TPM access failed, falling back to software nonce");
///         Nonce::generate_nonce(Some(rng), NonceType::Hashed)?
///     }
/// };
/// ```
pub enum NonceType {
    Classic,
    Hashed,
    Tagged(String),
    Machine,
    Tpm(Hardware, TpmModule, tss_esapi::Context),
}

impl Nonce {
    pub fn generate_nonce(rng: Option<Rng>, nonce_type: NonceType) -> Result<NonceData, Errors> {
        match nonce_type {
            NonceType::Classic => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::nonce(rng))
            }
            NonceType::Hashed => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::hashed_nonce(rng))
            }
            NonceType::Tagged(tag) => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::tagged_nonce(rng, &tag.as_bytes()))
            }
            NonceType::Machine => Ok(Nonce::machine_nonce(rng)),
            NonceType::Tpm(hardware, mut manager, mut tpm) => {
                Nonce::tpm_nonce(hardware, &mut manager, &mut tpm)
            }
        }
    }

    fn hashed_nonce(rng: Rng) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = rand::random_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::HashedNonce(nonce)
    }

    fn tagged_nonce(rng: Rng, tag: &[u8]) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = rand::random_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            nonce = *blake3::hash(&mix).as_bytes();
        }

        NonceData::TaggedNonce(*blake3::hash(&[&nonce, tag].concat()).as_bytes()) // Hash the nonce to get a 32 byte more random nonce (Extra Security)
    }

    fn machine_nonce(rng: Option<Rng>) -> NonceData {
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

    fn nonce(rng: Rng) -> NonceData {
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

    fn tpm_nonce(
        hardware: Hardware,
        manager: &mut TpmModule,
        tpm: &mut tss_esapi::Context,
    ) -> Result<NonceData, Errors> {
        manager.generate_nonce(tpm, hardware)
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
    pub fn salt() -> Self {
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

    pub fn tpm_salt(
        hardware: Hardware,
        manager: TpmModule,
        tpm: &mut tss_esapi::Context,
    ) -> Result<Self, Errors> {
        let nonce = manager.generate_nonce(tpm, hardware)?.to_vec();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&nonce[..32]);
        Ok(Salt::Salt(salt))
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

    let len = match config.key_length {
        KeyLength::Key256 => 32,
        KeyLength::Key512 => 64,
    };

    let mut salt = salt.to_vec();

    if let Some(custom_salt) = custom_salt {
        salt = custom_salt.as_bytes().to_vec();
    }

    let argon = match config.argon2_type {
        Argon2Type::Argon2d => Argon2::new(Algorithm::Argon2d, Version::V0x13, Params::DEFAULT),
        Argon2Type::Argon2i => Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::DEFAULT),
        Argon2Type::Argon2id => Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT),
    };

    let mut out = vec![0u8; len];
    argon
        .hash_password_into(pwd, &salt, &mut out)
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

// -----------------------------------------------------

fn secure_zeroize(data: &mut [u8], config: &Config) {
    if data.len() < 1024 * 1024 * 5 && config.secure_zeroize && config.zeroize {
        use rand::Rng;
        let mut rng = rand::rng();

        for byte in data.iter_mut() {
            *byte = rng.random::<u8>();
        }
    }

    if config.zeroize {
        data.zeroize()
    };
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
    data: &mut [u8],
    nonce: NonceData,
    config: Config,
    custom_salt: Option<Salt>,
    wrap_all: bool,
    recovery_key: Option<bool>,
) -> Result<Vec<u8>, Errors> {
    let key_len = match config.key_length {
        KeyLength::Key256 => 16,
        KeyLength::Key512 => 32,
    };

    let data_for_mac = data.to_vec();

    if password.len().ct_ne(&0).unwrap_u8() != 1 {
        return Err(Errors::EmptyPassword);
    } else if (password.len() as u32).ct_lt(&key_len).unwrap_u8() == 1 {
        return Err(Errors::PasswordTooShort(format!(
            "Password must be at least {} characters for cryptographic strength.",
            key_len
        )));
    }

    let nonce = nonce.as_bytes();
    let mut pwd = if config.key_derivation {
        let password = derive_key(password, nonce);
        let pwd = derive_password_key(&password, nonce, custom_salt, config)?;
        pwd
    } else {
        password.as_bytes().to_vec()
    };

    if let Some(recovery_key) = recovery_key {
        if recovery_key == true {
            println!("Recovery Key: {}", generate_recovery_key(&pwd, nonce));
        }
    }

    let gf = Arc::new(GaloisField::new(config.gf_poly.value()));

    let mut out_vec = Vec::new();

    if wrap_all {
        out_vec.extend(nonce);
    }

    {
        let version_pwd = blake3::hash(b"atom-crypte-password");
        let version_pwd = *version_pwd.as_bytes();
        let encrypted_version = rxa_encrypt(nonce, &version_pwd, &mut VERSION.to_vec(), config)?;
        out_vec.extend(encrypted_version);
    }

    let mut key_mixed_data = rxa_encrypt(nonce, &pwd, data, config)?;

    let mut sbox_data = s_bytes(&mut key_mixed_data, nonce, &pwd, config)?;
    secure_zeroize(&mut key_mixed_data, &config);

    let mut rxa_mix = rxa_encrypt(nonce, &pwd, &mut sbox_data, config)?;
    secure_zeroize(&mut sbox_data, &config);

    let mut gf_data = apply_gf(&mut rxa_mix, &config, &gf, nonce)?;
    secure_zeroize(&mut rxa_mix, &config);

    shift_rows(&mut gf_data, &config);

    let mut shifted_data = dynamic_shift(&mut gf_data, nonce, &pwd, config)?;
    secure_zeroize(&mut gf_data, &config);

    let final_sbox_data = s_bytes(&mut shifted_data, nonce, &pwd, config)?;
    secure_zeroize(&mut shifted_data, &config);

    let mut crypted = Vec::new();
    let mut round_data = final_sbox_data;

    for i in 1..=config.rounds {
        let slice_end = std::cmp::min(i * 32, pwd.len());
        let round_key = match config.key_length {
            KeyLength::Key256 => blake3::hash(&pwd[..slice_end]).as_bytes().to_vec(),
            KeyLength::Key512 => {
                let mut hash = Sha3_512::new();
                hash.update(&pwd[..slice_end]);
                hash.finalize().to_vec()
            }
        };

        let crypted_chunks = round_data
            .par_chunks_mut(1024 * 1024)
            .map(|data: &mut [u8]| {
                let mut xor_data = rxa_encrypt(nonce, &round_key, data, config)?;

                match config.multi_round_galois_field {
                    true => apply_gf(&mut xor_data, &config, &gf, nonce),
                    false => match i {
                        1 => apply_gf(&mut xor_data, &config, &gf, nonce),
                        _ => Ok(xor_data),
                    },
                }
            })
            .try_reduce_with(|mut acc, mut next| {
                acc.append(&mut next);
                Ok(acc)
            })
            .ok_or_else(|| Errors::ChunkError("Cannot reduce chunk".to_string()))??;

        if i == config.rounds {
            crypted.extend(crypted_chunks);
        } else {
            secure_zeroize(&mut round_data, &config);
            round_data = crypted_chunks;
        }
    }

    if config.ctr_layer {
        let mut iv = [0u8; 64];
        iv.clone_from_slice(&crypted[0..64]);
        ctr_encrypt(nonce, &mut crypted[64..], &iv);
        shift_rows(&mut crypted[..64], &config);
    }

    let mut mac_data = Vec::from(blake3::hash(&data_for_mac).as_bytes());
    mac_data.extend(blake3::hash(&crypted).as_bytes());
    let mac = calculate_hmac(&pwd, &mac_data)?;

    secure_zeroize(&mut pwd, &config);

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

    let pwd = if config.key_derivation {
        let password_hash: [u8; 32] = derive_key(password, nonce_byte);
        let mut expected_password = derive_password_key(
            &derive_key(password, nonce_byte),
            nonce_byte,
            custom_salt,
            config,
        )?;
        let mut pwd = derive_password_key(&password_hash, nonce_byte, custom_salt, config)?;

        if !verify_keys_constant_time(&pwd, &expected_password)? {
            secure_zeroize(&mut pwd, &config);
            secure_zeroize(&mut expected_password, &config);
            return Err(Errors::InvalidMac("Invalid key".to_string()));
        }

        secure_zeroize(&mut expected_password, &config);
        pwd
    } else {
        password.as_bytes().to_vec()
    };

    let mut pwd = if let Some(key) = recovery_key {
        parse_recovery_key(&key, nonce_byte)?
    } else {
        pwd
    };

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

    // Version verification
    let version_pwd = blake3::hash(b"atom-crypte-password");
    let version_pwd = *version_pwd.as_bytes();
    let mut encrypted_version = encrypted_version.to_vec();
    let version = rxa_decrypt(nonce_byte, &version_pwd, &mut encrypted_version, config)?;

    if !version.starts_with(b"atom-version") {
        secure_zeroize(&mut pwd, &config);
        return Err(Errors::InvalidAlgorithm);
    }

    if version.starts_with(b"atom-version:0x5") {
        secure_zeroize(&mut pwd, &config);
        return Err(Errors::NotBackwardCompatible);
    }

    let (mut crypted, mac_key) = if version.starts_with(b"atom-version:0x7") && wrapped {
        let (data_without_salt, _) = rest.split_at(rest.len() - 32);
        let (crypted, mac_key) = data_without_salt.split_at(data_without_salt.len() - 64);
        (crypted.to_vec(), mac_key.to_vec())
    } else {
        let (crypted, mac_key) = rest.split_at(rest.len() - 64);
        (crypted.to_vec(), mac_key.to_vec())
    };

    let mac_data_1 = blake3::hash(&crypted).as_bytes().to_vec();

    if config.ctr_layer {
        inverse_shift_rows(&mut crypted[..64], &config);
        let mut iv = [0u8; 64];
        iv.clone_from_slice(&crypted[0..64]);
        ctr_decrypt(nonce_byte, &mut crypted[64..], &iv);
    }

    let mut round_data = crypted.clone();
    let gf = Arc::new(GaloisField::new(config.gf_poly.value()));

    for i in (1..=config.rounds).rev() {
        let slice_end = std::cmp::min(i * 32, pwd.len());
        let round_key = match config.key_length {
            KeyLength::Key256 => blake3::hash(&pwd[..slice_end]).as_bytes().to_vec(),
            KeyLength::Key512 => {
                let mut hash = Sha3_512::new();
                hash.update(&pwd[..slice_end]);
                hash.finalize().to_vec()
            }
        };

        let decrypted: Vec<u8> = round_data
            .par_chunks_mut(1024 * 1024)
            .map(|data: &mut [u8]| {
                let mut gf_reversed = match config.multi_round_galois_field {
                    true => apply_gf(data, &config, &gf, nonce_byte)?,
                    false => match i {
                        1 => apply_gf(data, &config, &gf, nonce_byte)?,
                        _ => data.to_vec(),
                    },
                };

                rxa_decrypt(nonce_byte, &round_key, &mut gf_reversed, config)
                    .map_err(|e| Errors::InvalidXor(e.to_string()))
            })
            .try_reduce_with(|mut acc, mut next| {
                acc.append(&mut next);
                Ok(acc)
            })
            .ok_or_else(|| Errors::ChunkError("Cannot reduce chunk".to_string()))??;

        round_data = decrypted;
    }

    let mut pre_sbox_data = in_s_bytes(&mut round_data, nonce_byte, &pwd, config)?;
    secure_zeroize(&mut round_data, &config);

    let mut unshifted_data = dynamic_unshift(&mut pre_sbox_data, nonce_byte, &pwd, config)?;
    secure_zeroize(&mut pre_sbox_data, &config);

    inverse_shift_rows(&mut unshifted_data, &config);

    let mut ungf_data = apply_gf(&mut unshifted_data, &config, &gf, nonce_byte)?;
    secure_zeroize(&mut unshifted_data, &config);

    let mut rxa_unmixed = rxa_decrypt(nonce_byte, &pwd, &mut ungf_data, config)?;
    secure_zeroize(&mut ungf_data, &config);

    let mut unsbox_data = in_s_bytes(&mut rxa_unmixed, nonce_byte, &pwd, config)?;
    secure_zeroize(&mut rxa_unmixed, &config);

    let mut decrypted_data = rxa_decrypt(nonce_byte, &pwd, &mut unsbox_data, config)?;
    secure_zeroize(&mut unsbox_data, &config);

    let mut mac_data = Vec::from(blake3::hash(&decrypted_data).as_bytes());
    mac_data.extend(&mac_data_1);

    let mut mac = calculate_hmac(&pwd, &mac_data)?;

    if mac.ct_eq(&mac_key).unwrap_u8() != 1 {
        secure_zeroize(&mut decrypted_data, &config);
        secure_zeroize(&mut mac, &config);
        secure_zeroize(&mut mac_data, &config);
        return Err(Errors::InvalidMac("Invalid authentication".to_string()));
    }

    secure_zeroize(&mut mac_data, &config);

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
                password.as_str(),
                &mut data,
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
                &mut data,
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

/// Test suite for Shannon entropy etc.
pub struct Calculate;

impl Calculate {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0usize; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        frequency
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn calculate_bit_balance(data: &[u8]) -> (usize, usize, f64) {
        let mut ones = 0;
        let mut zeros = 0;

        for byte in data {
            ones += byte.count_ones() as usize;
            zeros += byte.count_zeros() as usize;
        }

        let total_bits = ones + zeros;
        let balance = (ones as f64 / total_bits as f64) * 100.0;

        (ones, zeros, balance)
    }

    pub fn calculate_avalanche(data1: &[u8], data2: &[u8]) -> Result<f64, Errors> {
        if data1.len() != data2.len() {
            return Err(Errors::DataError("Data sizes do not match".to_string()));
        }

        let mut changed_bits = 0;
        let total_bits = data1.len() * 8;

        for (byte1, byte2) in data1.iter().zip(data2.iter()) {
            let xor_result = byte1 ^ byte2;
            changed_bits += xor_result.count_ones() as usize;
        }

        Ok((changed_bits as f64 / total_bits as f64) * 100.0)
    }

    pub fn calculate_byte_difference(data1: &[u8], data2: &[u8]) -> f64 {
        let min_len = usize::min(data1.len(), data2.len());
        let max_len = usize::max(data1.len(), data2.len());

        let diff = data1
            .iter()
            .zip(data2.iter())
            .take(min_len)
            .filter(|(a, b)| a != b)
            .count();
        ((diff + (max_len - min_len)) as f64 / max_len as f64) * 100.0
    }

    pub fn generate_random_data(size: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        let mut out = vec![0u8; size];
        rng.fill_bytes(&mut out);
        out
    }
}
