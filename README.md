# AtomCrypte
📢 Latest Major Release: [v0.6.0 - Stage 2](CHANGELOGS.md)

- OFFICIAL SITE & DOCUMENTATION: [SITE](https://atomcrypte.zaferoglu.me/main)
- A high-performance, multi-layered encryption library designed for flexibility, security, and speed.
- You can find the Threat Model here: [Threat Model](THREAT-MODEL.md)
- You can find changelogs here: [Changelogs](CHANGELOGS.md)
- You can find Pre-Release steps testing here: [Pre-Release Testing](PRERELEASE-TESTING.md)
- Known Issues: [Known Issues](KNOWN-ISSUES.md)
---

## 🚧 Disclaimer
- This project is currently experimental and is not recommended for production environments.
- While it offers strong multi-layered security, including quantum-resilient techniques, it has not undergone formal third-party audits.
- It has been developed for academic research, cryptographic experimentation, and educational purposes.
- **Use at your own discretion, and apply additional caution in critical systems.**

## 🚧 Version 0.6 Disclaimer
- **Not backward-compatible with v0.5.x** due to engine changes.

---

## Overview

AtomCrypte is a robust encryption library that combines multiple cryptographic techniques to provide state-of-the-art security with configurable parameters.
It supports parallel processing, and modular cryptographic components, enabling both performance and advanced customization.

---

## Key Features
- **Recovery Key**: Generates recovery key based on your main Password and Nonce.
- **SIMD Support**: Processing through single instruction but mutliple data. (Performance boost)
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
- **Dummy Data**:
  - **Input Shield:** If input is empty, generates 1 B–8 KB of random “junk.”
  - **Output Decoys:** Appends up to 1 MB of extra random bytes post-encryption to confuse size-based analysis.
- **Parallel Processing**: Uses Rayon for multicore CPU support.
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
    .nonce(Nonce::nonce(Rng::osrng()))
    .config(Config::default())
    .utils(utils)
    .salt(salt) // Optional but recommended
    .encrypt()
    .expect("Encryption failed");

// Or you can turn byte slice into Salt
```

### Custom Configuration
- 🚧 If you forget your configuration, you won't be able to decrypt the data. (Especially important if you changed round count, S-box type, Key Length, or polynomial.)
```rust
use atom_crypte::{AtomCrypteBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

let config = Config::default()
    .with_sbox(SboxTypes::PasswordAndNonceBased)
    .set_thread(ThreadStrategy::AutoThread)
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
- **Benchmarks**: ~100MB ≈ 1s encryption/decryption on average device
- **Benchmarks**: ~20MB ≈ 1s encryption/decryption on low-end device

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

- Developer: Metehan
- E-Mail: metehanzafer@proton.me
- Special thanks to the Rust community, cryptography researchers, and open-source contributors inspiring robust, future-ready designs.
