# AtomCrypte Threat Model (v0.5.0)

## Purpose

AtomCrypte is a high-performance, multi-layered, highly-configurable encryption library written in Rust.
It provides robust data confidentiality and integrity through modern cryptographic primitives, dynamic S-boxes, multi-round transformations, and full parallelism with optional SIMD support. Now with 512-bit key support and HMAC-SHA3 authentication, AtomCrypte is engineered for post-quantum resilience and high-throughput security.

---

## Scope & Limitations

- Designed for **file or data-at-rest encryption**
- **Not yet optimized for streaming** or real-time traffic (planned for v0.6.0)
- **Key, nonce, and salt management** must be handled by user unless `.wrap_all(true)` is enabled
- **Not backward compatible** with earlier versions (e.g., v0.4.x to v0.5.x)
- **Experimental**, under active development — audits are pending

---

## Threat Types

| Threat Type                   | Mitigation Strategy |
|------------------------------|----------------------|
| Brute Force Attack           | Argon2 + Blake3 + optional SHA3-512 key derivation |
| Known-Plaintext Attack (KPA) | Unique nonce + dynamic block transformations |
| Ciphertext-only Attack (COA) | Multi-round XOR + MixColumns-like + S-box shifts |
| Timing Attack                | Constant-time comparisons (`ct_eq`) + randomized flow |
| Side-channel Attack          | Limited software mitigation; hardware-based leakage not mitigated |
| Replay Attack                | Unique nonce + HMAC binding |
| Key Reuse                    | Enforced via user config or `.wrap_all()` |
| Data Tampering               | Verified using HMAC-SHA3-512 |
| Weak Key Derivation          | Argon2id with optional SHA3 hardening and key cache reuse prevention |

---

## Defense Mechanisms

| Component              | Security Feature |
|------------------------|------------------|
| Key Derivation         | Argon2id + Blake3 + optional SHA3-512 |
| Key Caching            | Thread-safe RwLock with cache eviction coming (future) |
| Data Integrity         | HMAC-SHA3-512 (authenticated encryption) |
| Memory Safety          | Secure zeroization with random overwrite pass + zero pass |
| Nonce Handling         | Unique nonce per session; supports machine ID and random fallback |
| Salt Security          | Optional per-session cryptographic salt, embeddable via wrap_all |
| S-box Dynamics         | Password-, Nonce-, or Hybrid-based dynamic generation |
| Parallelism            | Full multithreading via Rayon, AVX2 planned (v0.6.0) |
| Chunk Obfuscation      | Dynamic chunk sizing + dummy data injection |

---

## Assumptions

- **Strong, unique password** is used per session
- **Salt** is generated randomly or securely derived per session
- **Nonce** is not reused within the same password context
- **Config** is preserved and correctly restored during decryption
- **Environment is trusted** for decryption (no remote unverified input)

---

## Example Attack Scenarios

| Scenario                       | Expected Outcome |
|--------------------------------|------------------|
| Same plaintext + password      | Different ciphertext (nonce/salt randomness) |
| Modified ciphertext/MAC        | Decryption fails (InvalidMac error) |
| Reused nonce/salt/password     | Security degrades; user warning recommended |
| Incorrect config during decrypt| Decryption fails cleanly |
| Partially corrupted input      | Graceful error return, not panic |

---

## Recommendations

- Prefer **Key512** with **≥5 rounds** for sensitive or long-term storage
- Use `.wrap_all(true)` to ensure proper metadata embedding
- Avoid reusing **(password + salt + nonce)** combinations
- Persist **Config** alongside encrypted data for accurate decryption
- For maximum performance, run on multi-core CPUs and prepare for AVX2 upgrade in v0.6

---

## Summary

AtomCrypte (v0.5.0) offers:

- **Potentially Quantum-ready, multithreaded encryption engine**
- **Dynamic, layered transformations with MAC authentication**
- **Optional dummy data and chunk obfuscation**
- **Cleaner and safer key handling via cache layer**
- **Not yet audited**, but engineered with future audits in mind

---

Made by [Metehan120](https://github.com/Metehan120)
