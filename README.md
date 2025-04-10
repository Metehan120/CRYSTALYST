## Security Disclaimer

While this implementation incorporates multiple security techniques, no custom cryptographic implementation should be used in production without thorough review by security experts. The algorithm has not undergone formal cryptanalysis or standardization.

# Atom Encryption

A high-security, potentially post-quantum resistant encryption implementation in Rust.

## Overview

Atom Encryption is a multi-layered encryption system that employs multiple transformations, dynamic S-boxes, and parallel processing to create a robust cryptographic solution. The algorithm combines several techniques to potentially resist both classical and quantum attacks.

## Features

- **Multiple Security Layers**: XOR-based encryption, dynamic S-boxes, block mixing, and data reversal
- **Strong Cryptographic Primitives**: Blake3 hashing, Argon2 key derivation, and MAC authentication
- **Memory Safety**: All sensitive data is zeroed after use
- **Side-Channel Protection**: Constant-time comparisons for critical operations
- **Performance Optimized**: Parallel processing with Rayon for high throughput
- **Dynamic Processing**: Chunk sizes adjusted based on data length for optimal performance
- **Potential Post-Quantum Resistance**: Multiple independent security layers may provide resistance against quantum attacks

## Security Considerations

The security of this implementation relies on:

- 256-bit encryption keys
- 32-byte random nonces
- Multiple transformation layers (XOR, rotate, add, S-box, chunk mixing)
- Data reversal operations for enhanced entropy
- MAC authentication for integrity verification

## Usage

```rust
use atomcrypte::{AtomCrypte, Nonce, NonceData, AsNonce};

fn main() -> Result<(), atomcrypte::Errors> {
    let password = "SuperSecretPassword";

    // Example 1: Random Nonce
    let nonce1 = Nonce::nonce()?; // Random 32-byte Nonce
    let data = b"Hello, AtomCrypte World!";
    let encrypted1 = AtomCrypte::encrypt(password, data, nonce1)?;
    let decrypted1 = AtomCrypte::decrypt(password, &encrypted1, nonce1)?;
    println!("Random Nonce Decrypted: {}", String::from_utf8_lossy(&decrypted1));

    // Example 2: Hashed Nonce (Extra Security)
    let nonce2 = Nonce::hashed_nonce()?; 
    let encrypted2 = AtomCrypte::encrypt(password, data, nonce2)?;
    let decrypted2 = AtomCrypte::decrypt(password, &encrypted2, nonce2)?;
    println!("Hashed Nonce Decrypted: {}", String::from_utf8_lossy(&decrypted2));

    // Example 3: Tagged Nonce (Nonce based on tag)
    let nonce3 = Nonce::tagged_nonce(b"custom-tag")?;
    let encrypted3 = AtomCrypte::encrypt(password, data, nonce3)?;
    let decrypted3 = AtomCrypte::decrypt(password, &encrypted3, nonce3)?;
    println!("Tagged Nonce Decrypted: {}", String::from_utf8_lossy(&decrypted3));

    // Example 4: Vec<u8> to NonceData Conversion
    let raw_nonce_vec = nonce1.to_vec();
    let nonce_from_vec = raw_nonce_vec.as_nonce()?; // Safe conversion
    let decrypted4 = AtomCrypte::decrypt(password, &encrypted1, nonce_from_vec)?;
    println!("Vec to NonceData Decrypted: {}", String::from_utf8_lossy(&decrypted4));

    // Example 5: &[u8] to NonceData Conversion
    let raw_nonce_slice = nonce1.as_bytes();
    let nonce_from_slice = raw_nonce_slice.as_nonce()?; // Safe conversion
    let decrypted5 = AtomCrypte::decrypt(password, &encrypted1, nonce_from_slice)?;
    println!("Slice to NonceData Decrypted: {}", String::from_utf8_lossy(&decrypted5));

    Ok(())
}
```

## Advanced Security

For maximum security, consider:
- Storing the nonce on a separate system from the encrypted data
- Using a password of appropriate entropy (the system requires a 32-byte key after derivation)
- Implementing secure key management practices

## Technical Details

The encryption process follows these steps:

1. Password key derivation using Argon2 and Blake3
2. Version information encryption
3. Data transformation through dynamic S-boxes
4. Block mixing with rotation and XOR operations
5. Chunk-based processing with dynamic sizing
6. Data reversal for additional security
7. Final XOR encryption pass
8. MAC generation for authentication

The decryption process reverses these steps in the correct order to recover the original data.

## Dependencies

- `argon2`: For secure password hashing
- `blake3`: For fast cryptographic hashing
- `rand`: For secure random number generation
- `rayon`: For parallel processing
- `subtle`: For constant-time equality comparison
- `thiserror`: For error handling
- `zeroize`: For secure memory cleanup
- `num_cpus`: For optimal thread management

## License

MIT License. See [`LICENSE`](LICENSE) file for details