# AtomCrypte Threat Model (v0.3.0)

## 🛡️ Purpose

AtomCrypte is a high-performance, multi-layered, configurable encryption library written in Rust.
It aims to provide robust data confidentiality and integrity using modern and custom cryptographic techniques, including quantum-resilient MAC generation and GPU acceleration.

---

## ⚠️ Scope & Limitations

- Intended for file or data-at-rest encryption
- Not yet optimized for streaming or network-level encryption
- Key, nonce, and salt management is delegated to the user (unless wrapped)
- Not compatible with legacy versions due to evolving structure and MAC changes
- Experimental — not production-ready without formal audit

---

## 🧨 Threat Types

| Threat                          | Mitigation Strategy |
|----------------------------------|----------------------|
| Brute Force Attack              | Argon2 + Blake3-based key derivation with salt support |
| Known-Plaintext Attack (KPA)    | Nonce and round structure disrupts pattern matching |
| Ciphertext-only Attack (COA)    | Dynamic multi-round XOR with key rotation |
| Timing Attack                   | Constant-time comparisons used (`ct_eq`) |
| Side-channel Attack             | Software-level only; hardware not mitigated |
| Replay Attack                   | Prevented via nonce uniqueness and MAC binding |
| Key Reuse                       | Secure if nonce and salt are unique; user responsibility |
| Data Tampering                  | SHA3-512 |
| Weak Key Derivation             | Argon2 ensures high computational cost for attackers |

---

## 🛡️ Defense Mechanisms

| Component             | Security Feature |
|------------------------|-------------------|
| Key Derivation         | Argon2 + Blake3 with optional salt |
| Data Integrity         | SHA3-512 (v0.3) MAC for post-quantum resilience |
| Memory Safety          | Uses `zeroize` to wipe secrets from memory |
| Nonce Generation       | Multiple nonce types (machine, tagged, hashed) |
| S-box Security         | Dynamic S-box generated per session using password & nonce |
| Round Logic            | Round-based XOR with rolling keys and mix-columns-like layers |
| Configuration Handling | User-defined Config, must match for decryption |

---

## 🧪 Assumptions

- Unique, strong password is used per encryption
- Salt is securely generated and wrapped or stored
- Nonce is never reused for the same key
- Decryption environment is trusted and local
- Config is retained correctly by the user (wrap_all recommended)

---

## 📊 Example Attack Scenarios

| Scenario                      | Outcome |
|-------------------------------|---------|
| Same data + same password     | Unique ciphertext due to nonce/salt |
| Tampered MAC                 | Decryption fails with InvalidMac error |
| Nonce reuse                  | Can weaken security under specific conditions |
| Incorrect Config on decrypt  | Fails — Config-dependent structure |
| Skipped rounds               | Breaks decryption logic and fails |

---

## ✅ Recommendations

- Use at least 3–6 rounds for secure mode
- Prefer SHA3 MAC (enabled by default in v0.3)
- Always use `.wrap_all(true)` in production-like tests
- Never reuse nonce + password + salt combinations
- Securely store or wrap the Config if custom settings are used

---

## 🔚 Summary

AtomCrypte (v0.3) is:

- Secure-by-design with strong KDF and MAC structure
- Modular, parallelized, and optionally GPU-accelerated
- Configurable for various use cases and layered encryption needs
- Post-quantum aware thanks to SHA3 and future Kyber integration

**Note:** This library is experimental. Improper configuration or reuse of sensitive values (e.g., nonce, salt) may significantly degrade security.

---

Maintained by [Metehan120](https://github.com/Metehan120)
