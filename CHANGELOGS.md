# AtomCrypte v0.3.0 - "Secure Evolution"
## New Features

### 1. Salt Support
- Added `Salt::new()` to generate cryptographic salt.
- Prevents rainbow table attacks effectively.
- If no salt is provided, `nonce` will be used as fallback.

### 2. Infinite Rounds Support
- You can now configure unlimited encryption rounds via `Config::rounds(n)`.
- Increased round = increased complexity, at your control.

### 3. Wrap-All Support
- Wrap `salt`, `nonce`, `version`, etc. into the encrypted output with a single option.
- Enabled via `.wrap_all(true)` in builder.
- Makes encryption process simpler, safer.

### 4. SHA3-512 as MAC Generator
- New default MAC algorithm: SHA3-512
- Post-quantum resistant: Effective brute-force complexity ≈ 2²⁵⁶ (even against Grover's algorithm)

### 5. Benchmark Option
- Easily measure encryption/decryption performance.
- Use `.benchmark(true)` on the builder.

### 6. Improved MachineRng
- `machine_rng(distro_locked: bool)` now supports optional OS-level entropy lock.

### 7. Trait Improvements
- Traits are now separated into Safe and Non-Safe usage groups.
- Simplifies implementation and increases clarity.

## Fixes & Improvements

1. Fixed an issue where MAC wasn't validating correctly in some edge cases.
2. Improved overall encryption performance.
3. Codebase refactored for modularity and maintainability.

---

Note:
v0.3.0 marks the start of **quantum-resilient design shift**.
The next version (v0.4+) will focus on further optimizations, better abstraction, and Kyber integration.
