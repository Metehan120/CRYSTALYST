# AtomCrypte

> **Warning:** AtomCrypte is a work-in-progress experimental encryption algorithm. It is **not** intended for production use, and has not undergone formal cryptanalysis or external security auditing. Use at your own risk.

## Overview

AtomCrypte is a custom symmetric encryption algorithm built with multiple transformation layers, memory safety, and obfuscation-focused design. It is implemented in Rust and designed to explore layered cryptographic techniques such as dynamic S-box substitution, chunk-level mutations, Argon2-based key derivation, and authenticated encryption.

The goal of AtomCrypte is to serve as a research and educational platform for cryptographic design, rather than a direct replacement for established algorithms such as AES or ChaCha20.

---

## Features

- 🔒 Memory-hard password-based key derivation using **Argon2**
- 🔀 Non-linear **S-box transformation** unique to each key/nonce pair
- 🧩 **Chunk-based rotation and XOR obfuscation**
- ⚡ **Parallel encryption** using the `rayon` crate
- 🔐 **MAC authentication** using keyed **BLAKE3**
- 🧼 Secure memory cleanup with `zeroize`
- 📦 Constant-time key and MAC verification via `subtle`

---

## Warning

AtomCrypte is experimental. It has **not** been vetted by security professionals, and no formal proof of security is available. There may be flaws or weaknesses in both the algorithmic design and implementation.

Do **not** use AtomCrypte to protect sensitive or real-world data.

This project is for:
- Educational use
- Cryptographic prototyping
- Obfuscation research
- Personal experimentation

---

## Security Assumptions

- Secrecy depends entirely on the strength of the password and the uniqueness of the nonce.
- Replay attacks must be mitigated at a higher protocol level.
- The algorithm assumes a Dolev-Yao style attacker (has full access to messages and source code).
- Cryptographic primitives used (Argon2, Blake3) are assumed secure.

---

## How It Works

Encryption process includes:
1. Key derivation using `derive_key` + Argon2
2. Version tag encryption and inclusion
3. Dynamic S-box creation and substitution
4. Block mixing using nonce-based transformations
5. Chunk-level data mutation (rotation + XOR)
6. XOR-based encryption with nonce/password stream
7. MAC generation for integrity

Decryption reverses the above steps and verifies both version and MAC tags before revealing data.

---

## Disclaimer

AtomCrypte is provided “as-is” for academic and experimental purposes.  
The author makes no guarantees regarding its security, correctness, or fitness for any purpose.  
You are solely responsible for how you use this code.

---

## License

MIT License. See `LICENSE` file for details.