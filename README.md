# CRYSTALYST – High-Performance Encryption
[![Crates.io](https://img.shields.io/crates/v/crystalyst)](https://crates.io/crates/crystalyst)
[![Downloads](https://img.shields.io/crates/d/crystalyst)](https://crates.io/crates/crystalyst)
[![License](https://img.shields.io/crates/l/crystalyst)](LICENSE)

> **Note:** CRYSTALYST was formerly known as **AtomCrypte**.

> **Where does the name come from?**
> Inspired by the fusion of **CRYSTAL** (clarity, structure) and **CATALYST** (accelerator). Thus: **CRYSTAL** + catal**YST** = **CRYSTALYST**.

- CRYSTALYST formally known as AtomCrypte
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
- **SHA3**: Default MAC function & HASH function with post-quantum resilience
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
Contact: [metehanzafer@proton.me](mailto:metehanzafer@proton.me)
