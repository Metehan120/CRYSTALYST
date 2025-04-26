# AtomCrypte Threat Model (v0.4.0)

## Purpose

AtomCrypte is a high-performance, multi-layered, highly-configurable encryption library written in Rust.
It provides strong data confidentiality and integrity using modern cryptographic primitives, dynamic S-boxes, and GPU-accelerated operations, with support for 512-bit key sizes for enhanced post-quantum resilience.

---

## Scope & Limitations

- Designed for **file or data-at-rest encryption**
- **Not optimized for streaming** or live network traffic encryption yet
- **Key, nonce, and salt management** is user's responsibility (unless `.wrap_all(true)`)
- **Backward incompatible** across major versions due to evolving structures
- **Experimental** — not production-ready without formal third-party audits

---

## Threat Types

| Threat Type                   | Mitigation Strategy |
|---------------------------------|----------------------|
| Brute Force Attack             | Argon2 + Blake3 (+ optional SHA3-512) key derivation |
| Known-Plaintext Attack (KPA)    | Nonce uniqueness + multi-round dynamic transformations |
| Ciphertext-only Attack (COA)    | Randomized multi-layer XOR + MixColumns-like shifts |
| Timing Attack                  | `ct_eq` constant-time comparisons everywhere |
| Side-channel Attack            | Software-only countermeasures; hardware leaks not mitigated |
| Replay Attack                  | Nonce uniqueness and MAC binding |
| Key Reuse                      | Nonce+salt uniqueness enforced by user or `.wrap_all` |
| Data Tampering                 | Enforced via SHA3-512 MAC verification |
| Weak Key Derivation            | Argon2 hardness + optional SHA3 hardening step |

---

## Defense Mechanisms

| Component             | Security Feature |
|------------------------|-------------------|
| Key Derivation         | Argon2 + Blake3, optional SHA3-512 strengthening |
| 512-bit Key Support    | Maximum entropy, post-quantum resilience |
| Data Integrity         | SHA3-512 MAC validation |
| Memory Safety          | Full `zeroize` memory cleansing |
| Nonce Handling         | Random, Hashed, Machine-based nonces |
| Salt Security          | Salt is cryptographically randomized and recommended to wrap |
| S-box Dynamics         | Dynamic per-session S-box from password+nonce |
| Parallelism            | Multi-threaded (Rayon) and optional GPU acceleration (OpenCL) |
| Config Control         | Strict Config-Data dependency (rounds, S-box type, poly, key length) |

---

## Assumptions

- A **unique, strong password** is provided for each encryption
- **Salt** is securely generated per session and salt must be saved or wrapped securely
- **Nonce** is always fresh and unique
- **Config** (especially rounds, S-box type, GF polynomial, key length) is preserved accurately
- Decryption occurs in a **trusted environment**

---

## Example Attack Scenarios

| Scenario                        | Expected Outcome |
|----------------------------------|------------------|
| Same plaintext + password       | Different ciphertext (nonce & salt randomness) |
| Tampered ciphertext or MAC       | Decryption fails immediately (InvalidMac) |
| Nonce or Salt reuse              | Security degraded; unpredictable (user mistake) |
| Wrong Config parameters          | Decryption fails gracefully (InvalidMac) |
| Partial or malformed input       | Fails without panic (returns error) |

---

## Recommendations

- Use **Key512** (512-bit) for maximum security when possible
- Set **rounds ≥ 5** for "Secure" profiles
- Always call `.wrap_all(true)` to embed salt/nonce safely
- Never reuse **(password + nonce + salt)** combinations
- Save **Config** alongside ciphertext if you modify default settings

---

## Summary

AtomCrypte (v0.4.0) is:

- Secure encryption engine
- Multithreaded and GPU-accelerated
- Highly configurable with dynamic security layers
- Still experimental — misconfiguration risks remain

---

Maintained with ✨ by [Metehan120](https://github.com/Metehan120)
