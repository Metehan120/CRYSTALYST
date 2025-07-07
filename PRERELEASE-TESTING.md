# CRYSTALYST Pre-Release Testing Checklist (v0.8.5)

This document outlines all critical testing procedures that must be completed before publishing a new version of CRYSTALYST.

---

## Test Categories

| Category | Status | Notes |
|:--|:--|:--|
| **Memory Leak Testing** | ✅ | Tested with Valgrind; must show 0 definite/indirect leaks. |
| **Shannon Entropy Testing** | ✅ | Minimum required: 7.99999 entropy (perfect randomness) on 1MB+ Data. |
| **Bit Balance Testing** | ✅ | Minimum required: 0.99999 (perfect bit distribution). |
| **Avalanche Effect Testing** | ✅ | Target: 0.5000 avalanche ratio (ideal). |
| **Fuzzing Test** | ✅ | Randomly generate inputs and check for crashes or unexpected behavior. |
| **Stress Testing (Encrypt/Decrypt Loops)** | ✅ | At least 25 consecutive encryption/decryption cycles. |
| **Side-Channel (Cache) Shifting Validation** | ✅ | Confirm cache instruction randomization between encryptions. |
| **Salt & Nonce Correctness Check** | ✅ | Ensure proper uniqueness and secure generation every session. |
| **Multi-threaded Consistency Testing** | ✅ | Run with Rayon on multiple cores; check output consistency. |
| **Key Derivation Hardness Check** | ✅ | Test Argon2 + Blake3 output randomness and resistance. |
| **MAC Validation (Tamper Resistance)** | ✅ | Corrupt ciphertext and verify decryption fails (InvalidMac). |
| **Malformed Input Handling** | ✅ | Feed incorrect/partial inputs and expect safe error handling. |
| **Documentation Synchronization** | ✅ | Ensure README, Threat Model, and Changelogs match implementation. |
| **Performance Benchmarking** | ✅ | Measure encrypt/decrypt speed for 20MB and 100MB data on different devices. |
| **Attack Simulation (Replay, KPA, COA)** | ✅ | Simulate attacks and confirm mitigations work as described. |
| **Configuration Error Handling** | ✅ | Verify decryption fails cleanly on wrong config attempts. |

---

## Minimum Release Conditions

- **All tests must be completed and passed without critical issues.**
- **If any test fails, a fix must be applied and the entire checklist re-executed.**
- **No "definite" or "indirect" memory leaks allowed in release builds.**
- **No partial feature releases; only fully validated features can be included.**

---

## Notes

- Future releases will aim to introduce automatic test pipelines and formal test coverage reports.

---

## Maintainer

**Metehan**

E-Mail: *metehanzafer@proton.me*
