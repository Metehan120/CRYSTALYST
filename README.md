# AtomCrypte

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
- Multiple cryptographic layers provide defense in depth

---

## 💡 Roadmap (Planned Features)

- Recovery key fallback
- Machine-level access controls

## License

[`MIT License`](LICENSE). This project is for research and educational use. Not recommended for production environments without a formal audit.

## Credits

- Developer: Metehan
- E-Mail: metehan@zaferoglu.me
