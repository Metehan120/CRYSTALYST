## ⚠️ Security Notice
 - WARNING: AtomCrypte is an experimental encryption library and has not yet passed formal security audits or NCC Group testing.
It is provided as-is for research, educational, and experimental purposes only.
Do not use AtomCrypte in production environments or for sensitive data until it has been properly reviewed and verified by professional cryptographers.

# AtomCrypte

- AtomCrypte is a high-performance, security-focused encryption library built in Rust that employs multiple layers of cryptographic operations to provide robust data protection.

## Features

- **Multi-layered Encryption**: Combines XOR operations, dynamic S-boxes, block mixing, and MAC verification
- **High Performance**: Utilizes Rayon for parallel processing to optimize encryption and decryption speeds
- **Security-first Design**: Implements constant-time comparisons and secure key derivation
- **Memory Safety**: Automatically zeroizes sensitive data after use
- **Flexible Nonce Management**: Supports regular, hashed, and tagged nonces for different use cases

## Security Properties

- **Dynamic S-Box Generation**: Creates unique substitution boxes based on nonce and password
- **Dynamic Chunk Processing**: Varies chunk sizes and operations based on data length and cryptographic inputs
- **Message Authentication**: Implements BLAKE3-based MAC for integrity verification
- **Strong Key Derivation**: Uses Argon2 for password-based key derivation with salting
- **Side-channel Resistance**: Employs constant-time operations for sensitive comparisons

## Usage

### Basic Encryption and Decryption

```rust
use atom_crypte::{AtomCrypte, Nonce, NonceData};

// Generate a secure nonce
let nonce = Nonce::nonce()?;

// Encrypt data
let encrypted = AtomCrypte::encrypt("password123", "Hello, world!".as_bytes(), nonce)?;

// Decrypt data
let decrypted = AtomCrypte::decrypt("password123", &encrypted, nonce)?;
assert_eq!(decrypted, "Hello, world!".as_bytes());
```

### Using Different Nonce Types

```rust
// Standard nonce
let standard_nonce = Nonce::nonce()?;

// Hashed nonce (Blake3 hashed for additional randomness)
let hashed_nonce = Nonce::hashed_nonce()?;

// Tagged nonce (combines randomness with application-specific tag)
let tagged_nonce = Nonce::tagged_nonce(b"user-data")?;
```

### Advanced Usage Example

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

## Technical Details

### Encryption Process

1. **Key Derivation**: Password is derived using Argon2 with the nonce as salt
2. **S-Box Generation**: Dynamic substitution box created from nonce and password
3. **Block Mixing**: Data is transformed with rotation, XOR, and addition operations
4. **Dynamic Chunking**: Data is split into variably sized chunks based on nonce and key
5. **Chunk Shifting**: Chunks undergo byte-level transformations and are reversed
6. **XOR Encryption**: Final encryption layer with key and nonce
7. **MAC Generation**: BLAKE3-based MAC is computed for authentication
### Decryption Process

The decryption process reverses all operations in the exact opposite order, with constant-time verification of both the version marker and authentication code.

## Dependencies

- **argon2**: Password hashing
- **blake3**: Fast cryptographic hashing
- **rand**: Secure random number generation
- **rayon**: Parallel computation
- **subtle**: Constant-time comparison operations
- **thiserror**: Error handling
- **zeroize**: Secure memory clearing
- **num_cpus**: CPU core detection for optimal threading

## Security Considerations

- **Password Strength**: The security of encrypted data ultimately depends on password entropy
- **Nonce Reuse**: Never reuse a nonce with the same password
- **Memory Protection**: While sensitive data is zeroized after use, physical memory attacks remain a consideration
- **Implementation Verification**: This library would benefit from formal security auditing

## Performance

AtomCrypte automatically scales its operations based on input size and available CPU cores:

- Small data (<1KB): Optimized for minimal overhead
- Medium data (1KB-100MB): Balanced security and performance
- Large data (>100MB): Maximized parallelism with larger chunk sizes

## Flow Diagram
![FLOW_DIAGRAM](flow_diagram.svg)

## License

MIT License. See [`MIT`](LICENSE) file for details.