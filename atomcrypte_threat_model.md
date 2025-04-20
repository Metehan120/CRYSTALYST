# AtomCrypte Threat Model (v0.2.1)

## 🛡️ Purpose

AtomCrypte is a high-performance, multi-layered, configurable encryption library written in Rust.
It aims to provide robust data confidentiality and integrity using custom cryptographic techniques.

---

## ⚠️ Scope & Limitations

- Intended for file or text-based data encryption
- Not designed for direct network-level encryption
- Key and nonce management is left to the user
- Not compatible with legacy versions due to changing encryption structure
- Not recommended for production use — experimental and research-focused

---

## 🧨 Threat Types

| Threat                          | Description |
|----------------------------------|-------------|
| Brute Force Attack              | Mitigated by Argon2 + Blake3 KDF |
| Known-Plaintext Attack (KPA)    | Dynamic nonce usage makes block correlation very difficult |
| Ciphertext-only Attack (COA)    | Encryption rounds + dynamic keys prevent analysis |
| Timing Attack                   | Constant-time operations used (`ct_eq`) |
| Side-channel Attack             | No hardware mitigation; constant-time software level only |
| Replay Attack                   | Prevented via nonce and MAC |
| Key Reuse                       | Can be risky if the same nonce is used with same key |
| Data Tampering                  | Detected via Blake3 MAC |
| Weak Key Derivation             | Argon2 with salt ensures high entropy |

---

## 🛡️ Defense Mechanisms

| Area                  | Strategy |
|------------------------|----------|
| Key Derivation         | Argon2 + Blake3 with salt |
| Data Integrity         | Blake3 keyed MAC |
| Memory Safety          | `zeroize` crate used to clear sensitive data |
| Nonce Generation       | OS RNG, thread RNG, tagged and machine-based |
| S-box Security         | Dynamic S-box generated per encryption session |
| Round Logic            | Each round uses different derived keys |
| Configuration          | Controlled via user-defined `Config` struct |

---

## 🧪 Assumptions

- Strong, unique password is used
- Nonce is different for every encryption
- Salt is securely stored or embedded safely
- Code is executed in a trusted environment
- Experimental — not production-ready

---

## 📊 Example Attack Scenarios

| Scenario                  | Outcome |
|----------------------------|---------|
| Same data + same password | Different output (due to nonce) |
| Missing MAC               | Decryption fails |
| Nonce reuse               | Repeated encryption is susceptible |
| Incorrect GF polynomial   | May reduce diffusion efficiency |
| Tampering with rounds     | Skipping rounds breaks decryption |

---

## ✅ Recommendations

- Use at least 3 rounds
- Always use 32-byte passwords
- Never reuse a nonce
- Verify MAC on decryption
- Do not use in production unless externally audited

---

## 🔚 Summary

AtomCrypte is:

- A secure-by-design experimental encryption engine
- Highly configurable, nonce/key sensitive
- Best suited for cryptography enthusiasts, researchers, and custom systems

**Note:** Misuse of configurations (e.g., low rounds, reused nonce) can weaken security drastically.

---

Maintained by [Metehan120](https://github.com/Metehan120)
