/*! # CRYSTALYST – High-Performance Encryption
[![Crates.io](https://img.shields.io/crates/v/crystalyst-rs)](https://crates.io/crates/crystalyst-rs)
[![Downloads](https://img.shields.io/crates/d/crystalyst-rs)](https://crates.io/crates/crystalyst-rs)
[![License](https://img.shields.io/crates/l/crystalyst-rs)](LICENSE)


> Latest Version: 0.8.0 - "When Things Get Real", [Changelogs](CHANGELOGS.md)

> **Where does the name come from?**
> Inspired by the fusion of **CRYSTAL** (clarity, structure) and **CATALYST** (accelerator). Thus: **CRYSTAL** + catal**YST** = **CRYSTALYST**.

- [Pre-Release Testing](PRERELEASE-TESTING.md)
- [Known Issues](KNOWN-ISSUES.md)
- [Threat Model](THREAT-MODEL.md)

---

## ⚠️ Disclaimer

- **This project is experimental and not production-ready.**
- While CRYSTALYST offers strong multi-layered cryptography with post-quantum primitives, it has **not been formally audited**.
- Use at your own risk — especially in high-security or production environments.

## NOT BACKWARD COMPATIBLE WITH AtomCrypte

---

## Statistical Test Results

This implementation has been tested using official and widely recognized randomness testing suites:

- ✅ NIST SP 800-22
- ✅ Dieharder

**[Click here to view full test results](TEST_SUITES/OVERALL_SCORE.md)**
All tests passed with strong or perfect ratings. A few tests flagged as “weak” due to extremely uniform results, which is acceptable.

\> Note: Tests were conducted on encrypted output of a 50MB all-zero input using CRYSTALYST with Argon2d. See `output.bin` for reproducibility.

---

## Features at a Glance

- Offers strong multi-layered cryptography and post-quantum primitives.
- No formal third-party audits have been conducted.
- Built for **research**, **experimentation**, and **educational use**.
- TPM integration provides secure Nonce + Salt generation and secure hardware-backed hashing.
- **Zeroize is disabled by default** for performance — enable via `Secure`, `Fortress`, or `Extreme` profiles for memory hygiene.

| Feature                      | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| Key512 Support           | True 512-bit key support, no shrink hacks                                   |
| SHA3 Hashing             | Unified SHA3-256/SHA3-512 across MAC, S-Box, Hashing                        |
| Dynamic S-Box Engine     | Golden ratio powered, per-encryption randomness                            |
| Secure Key Cache         | SecretBox-backed, auto-zeroing cache                                        |
| Counter Mode Encryption  | GCM-like stream cipher for high entropy                                     |
| TPM Integration          | Hardware-backed hashing, nonce, and salt generation                         |
| Entropy Analyzer         | Avalanche, balance, and Shannon tests built-in                             |
| Hybrid MixColumns        | AES + Triangle Galois Field transforms                                      |
| Configurable Complexity  | Profiles: `Fast`, `Secure`, `Extreme`, etc. or build your own                   |
| Constant-Time Ops        | Constant-time key lookup, S-Box ops, and MAC comparisons                    |
| SIMD Acceleration        | Full AVX2-backed XOR, ADD, SUB                                         |

---

## Dynamic S-Box generation:
- \> CRYSTALYST introduces a novel approach to Dynamic S-Box generation, ensuring each encryption operation uses a unique, unpredictable S-Box. This dynamic generation enhances security by preventing precomputed attacks and reducing the effectiveness of statistical analysis.
### How much entropy does it provide?
- \> It's providing 8.0000 shanon entropy, which is the maximum possible entropy, because always it has 256 bytes (0..255).
### How unique is it?
- \>%99.99 (Almost never generates same S-Box), its not perfect because of the nature of the algorithm, and never can generate fully unique S-Box, but it's close to it.
### How is that even possible on real time?:
- 1. **Key X Nonce combination**: Combining Key and Nonce using a secure hash function (If computed before using precomputed values), ensuring aperiodic distribution and unpredictability.
- 2. **Golden Ratio**: Irrational number properties, ensuring aperiodic distribution and unpredictability.
- 3. **Fisher-Yates Shuffle**: Randomizes the order of elements in the S-Box, ensuring each permutation is unique and unpredictable.
- 4. **Pregenerate S-Box, after swapping**: Swapping Pregenerated S-Box, this is lightweight and efficient.
- 5. **Cache Optimization**: Getting pre-generated Key X Nonce combination from cache, no computation power needed.
### Test Results:
- Tested through static key, different nonce values
- Generation **repeated over 10 million times**, **no duplicates found**

\> If same key (if you used Salt, same Salt needed as well) + nonce it will generate same S-Box, it's how it should be.

---

## Why CRYSTALYST?

- Combines modern cryptographic primitives like SHA3, Argon2, and AVX2 for next-gen security.
- Fully configurable — from chunk size to Galois field type.
- Built-in statistical analysis tools for dev-time confidence.
- Sane defaults, crazy flexibility.

---

## 📦 Installation

```bash
cargo add crystalyst
```

## Quick Example

```rust
use crystalyst::{CrystalystBuilder, Config, Nonce, Utils, NonceType};

let nonce = Nonce::generate_nonce(None, NonceType::Classic);
let utils = Utils::new().wrap_all(true);
let config = Config::default();

let encrypted = CrystalystBuilder::new()
    .data(b"Hello, world!")
    .password("super_secret_password")
    .nonce(nonce)
    .config(config)
    .encrypt()
    .expect("encryption failed");

let decrypted = CrystalystBuilder::new()
    .data(&encrypted)
    .password("super_secret_password")
    .config(config)
    .decrypt()
    .expect("decryption failed");

assert_eq!(decrypted, b"Hello, world!");
```

---

## Key Features
- **Testing**: Local entropy/avalanche/bit balance testing modules included.
- **Recovery Key**: Generates recovery key based on your main Password and Nonce.
- **Counter Mode**: Securely manages encryption and decryption using a counter mode.
- **SIMD Support**: Processing through single instruction but multiple data. (Performance boost)
- **TPM Operations**: Securely manages cryptographic operations using Trusted Platform Module (TPM).
- **512-bit Key Support**: Supports keys of up to 512 bits for enhanced security.
- **Constant-Time Execution (Locally Verified)**: All critical operations are implemented to run in constant time, minimizing timing side-channel risks. While extensive local testing confirms stability across various inputs, third-party validation is recommended for formal assurance.
- **Salt Support**: Cryptographic salt generation using `Salt::new()` to prevent rainbow table attacks.
- **Infinite Rounds**: User-defined encryption round count.
- **Wrap-All Support**: Seamlessly wraps salt, nonce, version, etc. into final output.
- **MAC with SHA3-512**: Strong integrity validation and quantum resistance.
- **Benchmark Support**: Time encryption/decryption operations with `.benchmark()`.
- **Secure Key Derivation**: Argon2 for password hashing.
- **Dynamic S-boxes**: Based on password, nonce, or both.
- **Finite Field Arithmetic**: Galois Field operations similar to AES MixColumns and you can use AES MixColumns.
- **Dummy Data**:
  - **Input Shield:** If input is empty, generates 1 B–8 KB of random “junk.”
  - **Output Decoys:** Appends up to 10 KB of extra random bytes post-encryption to confuse size-based analysis.
- **Parallel Processing**: Uses Rayon for multicore CPU support.
- **Zeroized Memory**: Automatic clearing of sensitive data in RAM.
- **Perfect Distribution**:
  - Exhaustive statistical tests confirms near-theoretical perfection:
    - Shannon Entropy: `8.0000`, which we reach 7.99999+ (Perfect randomness, Max, Normal: 7.99999+, Min: 7.98)
    - Bit Balance: `1.0000`, which we reach 0.999+ (Perfect bit distribution, Max, Normal: 0.99-1, Min: 0.98)
    - Avalanche Effect: `0.5000`, which we reach 0.499+ (Ideal avalanche ratio, Max, Normal: 0.5, Min: 0.49)
  - Verified over 10,000 independent test runs.
- **Memory Hard**: Algorithm is designed to be memory-hard, making it resistant to brute-force attacks even with large amounts of memory.
- **Zero Memory Leak (Verified in Local Testing)**:
  Extensive `Valgrind` testing under multiple stress scenarios (including 25x repeat encryption) shows zero **definite** or **indirect** memory leaks.
  (Note: Not yet validated by third-party audits or formal verification tools.)

---

## Cryptographic Components

- **Argon2**: Memory-hard password hashing
- **SHA-3**: Default MAC function & HASH function with post-quantum resilience
- **Custom S-box**: Deterministic but unique per configuration
- **Shift Rows**: Using similar algorithm to AES
- **Galois Field**: MixColumns transformation layer
- **Dynamic Chunk Shifting**: Adaptive chunk size adjustment based on nonce, password, data length
- **Block Mix**: Efficiently Mixing data
- **RXA Layer**: Rotate + XOR + Add in one operation (If it seems basic; no it's provides HIGH security)
- **MAC Validation**: Ensures authenticity and tamper-resistance
- **TPM Operations**: Securely manages cryptographic operations using Trusted Platform Module (TPM)

---

### How to use TPM:
```rust
let manager = TpmModule;
let nonce = Nonce::generate_nonce(
    None,
    NonceType::Tpm(
        config.hardware,
        manager,
        manager.generate_context(config.hardware).unwrap(),
    ),
)
.unwrap();

let salt = Salt::tpm_salt(
    config.hardware,
    manager,
    &mut manager.generate_context(config.hardware).unwrap(),
)
.unwrap();

// How to enable TPM hashing (EXAMPLE):
let config = Config::default().set_hardware(Hardware::new().set_hardware_hashing(true));
```

### Custom Configuration
- 🚧 If you forget your configuration, you won't be able to decrypt the data. (Especially important if you changed round count, Key Length, or polynomial.)
```rust
use crystalyst::{CrystalystBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

let config = Config::default()
    .set_thread(ThreadStrategy::Custom(4))
    .gf_poly(IrreduciblePoly::Custom(0x14d))
    .rounds(6); // 6 ~ 8 Rounds recommended
```

### Using Predefined Profiles
```rust
use crystalyst::{Config, Profile};

let config = Config::from_profile(Profile::Secure);
```

### Machine-specific Encryption
```rust
use crystalyst::{CrystalystBuilder, Config, Nonce};

let nonce = Nonce::generate_nonce(None, NonceType::Machine); // You can generate via Machine info + Rng
let password = "your_password_here".machine_rng(false); // False means no distro lock
```

---

## 💡 Roadmap

- Test Suite
- Machine-level access controls (Kind of done via AVX2 support)

---

## 📄 License

Licensed under the [MIT license](LICENSE).

---

## ✍️ Author

Developed by **Metehan Eyyub Zaferoğlu**
Contact: [metehanzafer@proton.me](mailto:metehanzafer@proton.me) !*/

#[cfg(feature = "key_derivation")]
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use hmac::Mac;
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretBox};
use sha3::Sha3_512;
#[cfg(feature = "key_derivation")]
use subtle::ConstantTimeLess;
use sysinfo::System;
use thiserror::Error;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::MaxBuffer;
use tss_esapi::tcti_ldr::DeviceConfig;
use zeroize::Zeroize;

use crate::rng_utils::nonce::NonceData;
#[cfg(feature = "key_derivation")]
use crate::rng_utils::salt::Salt;
#[cfg(feature = "machine_rng")]
use crate::utils::base_utils::AsBase;

/// Ciphers; Blocker Cipher, Stream Cipher
pub mod cipher;
mod engine;
/// Utils such as RNG, Nonce, Salt...
pub mod rng_utils;
/// Utils such as RNG, Kyber...
pub mod utils;

pub mod profiles {
    use super::*;

    pub const DEFAULT: Config = Config::DEFAULT;
    /// Constant Time Default Profile
    pub const CT_DEFAULT: Config = Config::CT_DEFAULT;
    pub const FAST: Config = Config::FAST;
    pub const BALANCED: Config = Config::BALANCED;
    pub const SECURE: Config = Config::SECURE;
    /// Constant Time Secure Profile
    pub const CT_SECURE: Config = Config::CT_SECURE;
    pub const MAX: Config = Config::MAX;
    pub const FORTRESS: Config = Config::FORTRESS;
    pub const EXTREME: Config = Config::EXTREME;
    pub const REALTIME: Config = Config::REALTIME;
    /// Constant Time Realtime Profile
    pub const CT_REALTIME: Config = Config::CT_REALTIME;
}

pub struct KeyBuffer(SecretBox<[u8]>);

impl KeyBuffer {
    pub fn new(key: Vec<u8>) -> Self {
        KeyBuffer(SecretBox::new(key.into_boxed_slice()))
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0.expose_secret()
    }
}

pub struct RoundKeyBuffer(Vec<u8>);

impl RoundKeyBuffer {
    pub fn new(key: Vec<u8>) -> Self {
        RoundKeyBuffer(key)
    }
}

impl Drop for RoundKeyBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

static VERSION: &[u8] = b"CRYSTALYST-version:0x9";

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
    #[error("CRYSTALYST is not backward compatible with CRYSTALYST 0.8.0")]
    NotBackwardCompatible,
    #[error("Kyber Error: {0}")]
    KyberError(String),
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
    Key512,
}

#[cfg(feature = "key_derivation")]
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
    /// Warm up Cache
    /// # PROVIDING RESISTANCE AGAINST SIDE-CHANNEL ATTACKS
    /// # ⚠️⚠️⚠️ DO NOT DISABLE THIS OPTION UNLESS YOU KNOW WHAT YOU ARE DOING ⚠️⚠️⚠️
    pub warmup_cache: bool,
}

impl Hardware {
    pub const DEFAULT: Hardware = Hardware {
        tpm_enabled: true,
        hardware_nonce: true,
        hardware_hashing: false,
        enable_avx2: false,
        warmup_cache: true,
    };

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

    /// # PROVIDING RESISTANCE AGAINST SIDE-CHANNEL ATTACKS
    /// # ⚠️⚠️⚠️ DO NOT DISABLE THIS OPTION UNLESS YOU KNOW WHAT YOU ARE DOING ⚠️⚠️⚠️
    pub fn warmup_cache(mut self, warmup_cache: bool) -> Self {
        self.warmup_cache = warmup_cache;
        self
    }
}

/// Configuration for CRYSTALYST encryption/decryption operations.
/// # If you want Real CT protection, use single thread.
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

    pub dummy_data_size: usize,

    /// Provides timing attack resistance
    /// Recommended for high-security environments
    pub subtle_sbox: bool,

    /// Provides timing attack resistance
    /// Recommended for high-security environments
    pub subtle_key_lookup: bool,

    /// TPM hardware support
    pub hardware: Hardware,

    /// Can affect performance.
    /// Adds more security.
    pub multi_round_galois_field: bool,

    /// Can affect performance.
    /// Adds more security.
    pub ctr_layer: bool,

    #[cfg(feature = "key_derivation")]
    /// When false: uses password directly (FAST but INSECURE for weak passwords)
    /// When true: uses Argon2 + BLAKE3 derivation (SECURE but slower)
    pub key_derivation: bool,

    /// Enable/disable secure zeroization
    pub secure_zeroize: bool,

    pub zeroize: bool,

    #[cfg(feature = "key_derivation")]
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

impl Config {
    pub const DEFAULT: Config = Config {
        thread_strategy: ThreadStrategy::AutoThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 10,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Default configuration for constant-time operations.
    ///
    /// # Details
    /// - This configuration is optimized for constant-time operations and is suitable for use in security-sensitive contexts.
    /// - It is recommended to use this configuration when performing cryptographic operations that require constant-time execution.
    /// - AVX2 can be enabled if needed.
    pub const CT_DEFAULT: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 10,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    pub const FAST: Config = Config {
        thread_strategy: ThreadStrategy::FullThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 1,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 10,
        multi_round_galois_field: false,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    pub const BALANCED: Config = Config {
        thread_strategy: ThreadStrategy::AutoThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 10,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    pub const SECURE: Config = Config {
        thread_strategy: ThreadStrategy::AutoThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 20,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: true,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Constant time implementation of Secure profile.
    ///
    /// This configuration is optimized for constant time execution and is suitable for secure applications.
    pub const CT_SECURE: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 20,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: true,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Constant time by default.
    pub const MAX: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 4,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 50,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: true,
        zeroize: true,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Constant time by default.
    pub const FORTRESS: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 32 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 10,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 100,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: true,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: true,
        zeroize: true,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Constant time by default.
    pub const EXTREME: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 32 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 10,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 1024,
        multi_round_galois_field: true,
        ctr_layer: true,
        subtle_sbox: true,
        subtle_key_lookup: true,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: true,
        zeroize: true,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    pub const TRIANGLE_TEST_SUITE: Config = Config {
        thread_strategy: ThreadStrategy::AutoThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::Conway,
        gf_type: GaloisFieldType::Triangular,
        rounds: 2,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 10,
        multi_round_galois_field: true,
        ctr_layer: false,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: true,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Config for realtime encryption and decryption.
    /// Key derivation disabled by default.
    pub const REALTIME: Config = Config {
        thread_strategy: ThreadStrategy::BulkOperations,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 1,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 25,
        multi_round_galois_field: false,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: false,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

    /// Optimized for constant time operations.
    ///
    /// # Details
    /// - This configuration is optimized for constant time operations, which is important for security-sensitive applications.
    /// - AVX2 can be enabled if needed.
    pub const CT_REALTIME: Config = Config {
        thread_strategy: ThreadStrategy::SingleThread,
        stack_size: 16 * 1024 * 1024,
        gf_poly: IrreduciblePoly::AES,
        gf_type: GaloisFieldType::AES,
        rounds: 1,
        key_length: KeyLength::Key512,
        dummy_data: true,
        dummy_data_size: 1024 * 25,
        multi_round_galois_field: false,
        ctr_layer: true,
        subtle_sbox: false,
        subtle_key_lookup: false,
        #[cfg(feature = "key_derivation")]
        key_derivation: false,
        secure_zeroize: false,
        zeroize: false,
        #[cfg(feature = "key_derivation")]
        argon2_type: Argon2Type::Argon2id,
        hardware: Hardware::DEFAULT,
    };

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
    pub fn subtle_sbox(mut self, constant_time_sbox: bool) -> Self {
        self.subtle_sbox = constant_time_sbox;
        self
    }

    /// Sets the constant time key lookup.
    /// Recommended constant time key lookup for security.
    pub fn subtle_key_lookup(mut self, constant_time_key_lookup: bool) -> Self {
        self.subtle_key_lookup = constant_time_key_lookup;
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
            0..=1 => Self::FAST,
            2..=3 => Self::BALANCED,
            4..=5 => Self::SECURE,
            6..=7 => Self::MAX,
            8..=10 => Self::FORTRESS,
            _ => Self::FORTRESS,
        }
    }

    pub fn set_hardware(mut self, hardware: Hardware) -> Self {
        self.hardware = hardware;
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

    #[cfg(feature = "key_derivation")]
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

    #[cfg(feature = "key_derivation")]
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

// -----------------------------------------------------

#[cfg(feature = "key_derivation")]
fn derive_password_key(
    pwd: &[u8],
    salt: &[u8],
    custom_salt: Option<Salt>,
    config: Config,
    needed_len: u64,
) -> Result<Vec<u8>, Errors> {
    if (pwd.len() as u64).ct_lt(&needed_len).unwrap_u8() != 0 {
        return Err(Errors::Argon2Failed("Invalid Password".to_string()));
    }

    let mut salt = salt.to_vec();

    if let Some(custom_salt) = custom_salt {
        salt = custom_salt.as_bytes().to_vec();
    }

    let argon = match config.argon2_type {
        Argon2Type::Argon2d => Argon2::new(Algorithm::Argon2d, Version::V0x13, Params::DEFAULT),
        Argon2Type::Argon2i => Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::DEFAULT),
        Argon2Type::Argon2id => Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT),
    };

    let mut out = vec![0u8; 64];
    argon
        .hash_password_into(pwd, &salt, &mut out)
        .map_err(|e| Errors::Argon2Failed(e.to_string()))?; // Hashing Password VIA Argon2

    Ok(out)
}

// -----------------------------------------------------

fn secure_zeroize(data: &mut [u8], config: &Config) {
    if data.len() < 1024 * 1024 * 5 && config.secure_zeroize && config.zeroize {
        use rand::Rng;
        let mut rng = thread_rng();

        for byte in data.iter_mut() {
            *byte = rng.gen_range(0..=1) as u8;
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
