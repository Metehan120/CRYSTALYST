# AtomCrypte

**AtomCrypte** is an experimental, multi-layered, and modular encryption library written in Rust, designed for high-security research environments and advanced cryptographic exploration. It is not intended for production use, but rather as a platform for testing, understanding, and advancing modern encryption mechanisms.

---

## 🚧 Disclaimer

This project is **experimental** and should not be used in production systems. It is created for academic research, cryptographic experimentation, and learning purposes. Use at your own discretion.

---

## 🔐 Key Features

- **Multi-layered Encryption Process**: Each encryption pass includes dynamic S-box substitution, chunk-based transformations, and XOR-based processing.
- **Blake3 Hashing**: Fast and secure hashing for nonce derivation and MAC (Message Authentication Code) generation.
- **Argon2 Key Derivation**: Secure and memory-hard password hashing.
- **Dynamic S-Boxes**: S-boxes are generated based on password, nonce, or both.
- **Authenticated Encryption**: Includes MAC generation and validation using keyed Blake3.
- **GPU Acceleration**: Supports OpenCL-based chunk processing for high-performance environments.
- **Machine-Bound Identity**: Ability to generate device-specific nonces and passwords.
- **Secure Memory Handling**: Uses `zeroize` for wiping sensitive data from memory.
- **Highly Configurable**: Fully customizable `Config` struct allowing device selection and S-box tuning.

---

## 📦 Nonce Types

- `Nonce`: Randomly generated 32-byte nonce
- `TaggedNonce`: Random nonce combined with user-supplied tag
- `HashedNonce`: Random nonce repeatedly hashed
- `MachineNonce`: Derived from device information like username, OS, and hostname

---

## ⚙️ Configuration Options

Use the `Config` struct to control algorithm behavior:

```rust
let config = Config::default()
    .with_device(DeviceList::Gpu)
    .with_sbox(SboxTypes::PasswordAndNonceBased);
```

- `DeviceList::Auto` — Auto-detects GPU support
- `DeviceList::Gpu` — Enforces GPU acceleration
- `DeviceList::Cpu` — Uses only CPU
- `SboxTypes::PasswordBased`, `NonceBased`, `PasswordAndNonceBased`

---

## 🔧 Usage

### Encryption

```rust
let nonce = Nonce::hashed_nonce(Rng::osrng());
let config = Config::default().with_device(DeviceList::Auto);

let encrypted = AtomCrypte::encrypt("my-password", b"secret-data", nonce, config)?;
```

### Decryption

```rust
let decrypted = AtomCrypte::decrypt("my-password", &encrypted, nonce, config)?;
```

---

## 📌 Advanced Features

- **Thread-pool parallelism** with Rayon for faster processing
- **Dynamic Chunk Sizes** based on data length and cryptographic parameters
- **Custom Rng System** including tagged and machine-based options
- **MachineRng Trait** to derive device-bound passwords via `"password".machine_rng()`

---

## 🔬 Security Notes

- All encryption operations include version tagging, MAC checks, and constant-time comparisons.
- MAC is generated using Blake3 keyed-hash with encrypted data and XORed plaintext.
- Device-bound security is available via machine-specific nonce and password derivation.

---

## 📚 Recommended For

- Cryptographic research and education
- Advanced users exploring encryption customization
- Low-level system-level security experiments

---

## 💡 Roadmap (Planned Features)

- Builder pattern API (e.g. `Builder.encrypt().build()`)
- GF(2^8) arithmetic support
- Recovery key fallback
- More nonce and S-box strategies
- Machine-level access controls

---

📄 License

MIT License. This project is for research and educational use. Not recommended for production environments without a formal audit.

---
**Note**: AtomCrypte is not a replacement for industry-standard ciphers like AES or ChaCha20. Instead, it demonstrates what is possible when encryption is treated as an extendable, modular system.

Made with love (and zero sleep).
