# AtomCrypte Threat Model (v0.7.0)

## Purpose

AtomCrypte is a high-performance, multi-layered, highly-configurable encryption library written in Rust. It provides robust data confidentiality and integrity through modern cryptographic primitives, dynamic S-boxes, multi-round transformations, full parallelism, and optional SIMD support. Version 0.7.0 introduces constant-time configurable cryptographic operations, TPM-backed entropy, and an enhanced configuration system.

---

## Scope & Limitations

* Designed for **file or data-at-rest encryption**
* **Not optimized for streaming** or real-time traffic (planned for v0.8.0)
* **Key, nonce, and salt management** must be handled by user unless `.wrap_all(true)` is enabled
* **Not backward compatible** with earlier versions (e.g., v0.6.x and below)
* **Experimental**, under active development — **formal audits pending**

---

## Threat Types

| Threat Type                  | Mitigation Strategy                                                   |
| ---------------------------- | --------------------------------------------------------------------- |
| Brute Force Attack           | Argon2id + Blake3                                                     |
| Known-Plaintext Attack (KPA) | Unique nonce + dynamic S-box + RXA layer + multi-round structure      |
| Ciphertext-only Attack (COA) | Entropy-maximized counter mode + high-diffusion transformations       |
| Timing Attack                | Configurable constant-time S-boxes and key lookups                    |
| Side-channel Attack          | Constant-time config, TPM entropy, optional zeroize + stack hardening |
| Replay Attack                | Nonce uniqueness + MAC binding                                        |
| Key Reuse                    | Prevented via key derivation and config binding                       |
| Data Tampering               | HMAC-SHA3-512 authenticated encryption                                |
| Weak Key Derivation          | Argon2id with user-configurable parameters                            |

---

## Defense Mechanisms

| Component         | Security Feature                                                         |
| ----------------- | ------------------------------------------------------------------------ |
| Key Derivation    | Argon2id + Blake3                                                        |
| TPM Integration   | TPM 2.0 backed salt, nonce, and hashing (hardware-based entropy)         |
| Constant-time Ops | Configurable constant-time S-box, key lookup, and Galois operations      |
| Data Integrity    | HMAC-SHA3-512 for tamper detection                                       |
| Memory Safety     | Secure zeroize (random overwrite + zero pass)                            |
| S-box Dynamics    | Password-, Nonce-, or Hybrid-based S-box generation + golden ratio logic |
| Parallelism       | Rayon-powered parallelism + AVX2 SIMD acceleration                       |
| Obfuscation       | Dummy data + dynamic chunk sizing                                        |
| Recovery Key      | Recovery derived from password and nonce                                 |

---

## Assumptions

* A **strong, unique password** is used per session
* **Salt** is securely generated or provided
* **Nonce** is unique and never reused with the same key
* **Configuration** is preserved during decryption
* **TPM or OS entropy** is trusted if used
* **Environment is secure** during encryption/decryption

---

## Example Attack Scenarios

| Scenario                   | Expected Outcome                      |
| -------------------------- | ------------------------------------- |
| Same plaintext + password  | Different ciphertext (via nonce/salt) |
| Modified ciphertext or MAC | Decryption fails with error           |
| Reused nonce + password    | Warning issued; may weaken security   |
| Incorrect configuration    | Decryption fails gracefully           |
| Corrupted encrypted data   | Returns decryption error, not panic   |

---

## Recommendations

* Use **Profile::Fortress** or **Extreme** for maximum security
* Use `.wrap_all(true)` to preserve decryption parameters
* Avoid key/nonce reuse at all costs
* Store configuration or embed using `.wrap_all()`
* Use TPM features if available for best entropy
* Use **Key512 + >=5 rounds** for long-term encryption

---

## Summary

AtomCrypte (v0.7.0) offers:

* **Dynamic, configurable cryptographic layers**
* **TPM-backed entropy and constant-time logic**
* **Comprehensive configuration system and recovery support**
* **Not yet audited** but built with best practices in mind

---

Made by [Metehan120](https://github.com/Metehan120)
