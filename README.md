# AtomCrypte
📢 Latest Major Release: [v0.3.0 - Secure Evolution](CHANGELOGS.md)

- A high-performance, multi-layered encryption library designed for flexibility, security, and speed.
- You can find the Threat Model here: [Threat Model](atomcrypte_threat_model.md)
- You can find changelogs here: [Changelogs](CHANGELOGS.md)

---

## 🚧 Disclaimer
This project is experimental and should not be used in production systems. It is created for academic research, cryptographic experimentation, and learning purposes. Use at your own discretion.

---

## Overview

AtomCrypte is a robust encryption library that combines multiple cryptographic techniques to provide state-of-the-art security with configurable parameters. It supports parallel processing, GPU acceleration, and modular cryptographic components, enabling both performance and advanced customization.

## Key Features

- **Salt Support**: Cryptographic salt generation using `Salt::new()` to prevent rainbow table attacks
- **Infinite Rounds**: User-defined encryption round count
- **Wrap-All Support**: Seamlessly wraps salt, nonce, version, etc. into final output
- **MAC with SHA3-512**: Strong integrity validation and quantum resistance
- **Benchmark Support**: Time encryption/decryption operations with `.benchmark()`
- **Secure Key Derivation**: Argon2 + Blake3 for password hashing
- **Dynamic S-boxes**: Based on password, nonce or both
- **Finite Field Arithmetic**: Galois Field operations similar to AES MixColumns
- **Parallel Processing**: Uses Rayon for multicore CPU support
- **GPU Acceleration**: OpenCL backend for fast encryption/decryption
- **Zeroized Memory**: Automatic clearing of sensitive data in RAM

## Cryptographic Components

AtomCrypte integrates the following primitives and concepts:

- **Argon2**: Memory-hard password hashing
- **Blake3**: Fast cryptographic hash for key derivation
- **SHA3-512**: Default MAC function with post-quantum resilience
- **Custom S-box**: Deterministic but unique per configuration
- **Galois Field**: MixColumns-like transformation layer
- **MAC Validation**: Ensures authenticity and tamper-resistance

## Configuration Options

AtomCrypte is highly configurable. Below are common customization options:

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
- 🚧 - 🚧 If you forget your configuration, you won't be able to decrypt the data. (Especially important if you changed round count, S-box type, or polynomial.)
```rust
use atom_crypte::{AtomCrypteBuilder, Config, DeviceList, SboxTypes, IrreduciblePoly};

let config = Config::default()
    .with_device(DeviceList::Gpu)
    .with_sbox(SboxTypes::PasswordAndNonceBased)
    .set_thread(4)
    .gf_poly(IrreduciblePoly::Custom(0x4d))
    .rounds(6); // 4 Rounds recommended
```

### Using Predefined Profiles
```rust
use atom_crypte::{AtomCrypteBuilder, Config, Profile};

let config = Config::from_profile(Profile::Fast);
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
- **Benchmarks**: ~100MB ≈ 1s encryption/decryption on avarage device

## Security Considerations

- Constant-time comparisons
- Memory zeroization
- Authenticated encryption with SHA3 MAC
- Configurable number of layers and rounds
- Defense-in-depth: multiple cryptographic operations layered

---

## 💡 Roadmap

- Kyber (PQC) integration
- Recovery key fallback
- Machine-level access controls

## License

[MIT License](LICENSE)

## Credits

- Developer: Metehan
- E-Mail: metehanzafer@proton.me
