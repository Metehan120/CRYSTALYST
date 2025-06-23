# AtomCrypte
📢 Latest Major Release: [v0.7.0 - Configuration Revolution](CHANGELOGS.md)
[![Crates.io](https://img.shields.io/crates/v/atomcrypte)](https://crates.io/crates/atomcrypte)
[![Crates.io](https://img.shields.io/crates/d/atomcrypte)](https://crates.io/crates/atomcrypte)
[![Crates.io](https://img.shields.io/crates/l/atomcrypte)](https://crates.io/crates/atomcrypte)

- OFFICIAL SITE & DOCUMENTATION: [SITE](https://atomcrypte.zaferoglu.me/main) / Currently not available
- A high-performance, multi-layered encryption library designed for flexibility, security, and speed.
- Secured with TPM operations and cryptographic algorithms.
- You can find the Threat Model here: [Threat Model](THREAT-MODEL.md)
- You can find changelogs here: [Changelogs](CHANGELOGS.md)
- You can find Pre-Release steps testing here: [Pre-Release Testing](PRERELEASE-TESTING.md)
- Known Issues: [Known Issues](KNOWN-ISSUES.md)

---

## ⚠️ WARNING: Make sure your configuration (rounds, key length, etc.) matches exactly during decryption. If not, decryption will fail silently or return garbage data.

## 🚧 Disclaimer
- This project is currently experimental and is not recommended for production environments.
- While it offers strong multi-layered security, including quantum-resilient techniques, it has not undergone formal third-party audits.
- It has been developed for academic research, cryptographic experimentation, and educational purposes.
- **Use at your own discretion, and apply additional caution in critical systems.**
- \+ Use TPM operations for secure Nonce + Salt generation and Secure Hashing
- \> In future, Tirangle MixColumns will be optimized if exceed AES results will switch to Triangle MixColumns.
- \> Zeroize now disabled by default, you can choose: Secure, Fortress, Extreme profiles for zeroize or you can enable it by your own.

## 🚧 Version 0.7 Disclaimer
- If you're upgrading from v0.6.x:
   - Encrypted files with previous configs **will not be decryptable**.
   - Regenerate data or migrate configs manually.
---

## Overview

AtomCrypte is a robust encryption library that combines multiple cryptographic techniques to provide state-of-the-art security with configurable parameters.
It supports parallel processing, and modular cryptographic components, enabling both performance and advanced customization.

---

## Dynamic S-Box generation:
- \> AtomCrypte introduces a novel approach to Dynamic S-Box generation, ensuring each encryption operation uses a unique, unpredictable S-Box. This dynamic generation enhances security by preventing precomputed attacks and reducing the effectiveness of statistical analysis.
### How good entrop is it providing?:
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
- **Secure Key Derivation**: Argon2 + Blake3 for password hashing.
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
- **Blake3**: Fast cryptographic hash for key derivation
- **SHA3-512**: Default MAC function with post-quantum resilience
- **Custom S-box**: Deterministic but unique per configuration
- **Shift Rows**: Using similar algorithm to AES
- **Galois Field**: MixColumns transformation layer
- **Dynamic Chunk Shifting**: Adaptive chunk size adjustment based on nonce, password, data length
- **Block Mix**: Efficiently Mixing data
- **RXA Layer**: Rotate + XOR + Add in one operation (If it seems basic; no it's provides HIGH security)
- **MAC Validation**: Ensures authenticity and tamper-resistance
- **TPM Operations**: Securely manages cryptographic operations using Trusted Platform Module (TPM)

---

## Configuration Options

### Galois Field Polynomial
```rust
pub enum IrreduciblePoly {
    AES,
    Conway,
    Custom(u8),
}
```

### Predefined Profiles
```rust
pub enum Profile {
    Extreme,
    Fortress,
    Max,
    Secure,
    Balanced,
    Fast,
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
// TPM Nonce are using Nonce Enum tuple, you can find how to use down.
```

## Usage Examples

### Basic Encryption/Decryption
```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile, Rng, Nonce};

let nonce = Nonce::generate_nonce(Some(Rng::os_rng()), NonceType::Classic);
let config = Config::default();
let utils = Utils::new().wrap_all(true).benchmark(true);

let encrypted = AtomCrypteBuilder::new()
    .data("Hello, world!".as_bytes())
    .password("secure_password")
    .nonce(nonce)
    .config(config)
    .utils(utils)
    .encrypt()
    .expect("Encryption failed");

let decrypted = AtomCrypteBuilder::new()
    .data(&encrypted)
    .password("secure_password")
    .config(config)
    .utils(utils)
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
    .nonce(nonce)
    .config(Config::default())
    .utils(utils)
    .salt(salt) // Optional but recommended
    .encrypt()
    .expect("Encryption failed");

// Or you can turn byte slice into Salt
```

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
use atom_crypte::{AtomCrypteBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

let config = Config::default()
    .set_thread(ThreadStrategy::Custom(4))
    .gf_poly(IrreduciblePoly::Custom(0x14d))
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

let nonce = Nonce::generate_nonce(None, NonceType::Machine); // You can generate via Machine info + Rng
let password = "your_password_here".machine_rng(false); // False means no distro lock
```

## Performance

- **CPU**: Parallelized via Rayon
- **Benchmarks**: ~100MB ≈ 1s encryption/decryption on average device
- **Benchmarks**: ~20MB ≈ 1s encryption/decryption on low-end device
- **Theoretical Benchmarks**: On HIGH-END server CPUs (e.g. AMD EPYC, Intel Xeon): 600MB/s theoretical speed.

## Security Considerations

- Constant-time comparisons
- All critical operations are constant-time
- Memory zeroization
- Authenticated encryption with SHA3 MAC
- Configurable number of layers and rounds
- Defense-in-depth: multiple cryptographic operations layered

---

## 💡 Roadmap

- Test Suite
- Kyber (PQC) integration
- Recovery key fallback
- Machine-level access controls (Kind of done via AVX2 support)

## License

[MIT License](LICENSE)

## Credits

- **Developer**: Metehan Eyyub Zaferoğlu
- **E-Mail**: metehanzafer@proton.me
- **Special thanks** to the Rust community, cryptography researchers, and open-source contributors inspiring robust, future-ready designs.
