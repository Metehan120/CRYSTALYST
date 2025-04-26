# AtomCrypte v0.4.0 - "Steps Toward"
## New Features

### 1. 512-bit Key Support
- Maximum entropy, post-quantum resilience
- You can generate 512-bit keys using `Config::/*Your Config*/.key_length(KeyLength::Key512)` or `Config::from_profile(Profile::Secure) / Config::from_profile(Profile::Max)`.

### 2. New Profile Setting:
- Added `Profile::Max` to Maximize encryption parameters.
- Using `Key512` and `20 Rounds` for Maximum security.
- This option will be `very heavy`.

### 3. Password Length Checking (Non User-Important)
- Checking if length is 0;
- Prevents weak passwords from being used.

### 4. AsBase64 Encoding
- Converts encrypted data to Base64 format for easier handling and transmission.
- You can convert via `.as_base64()`.

### 5. AsString Encoding
- Converts encrypted data to String format for easier look.
- You can convert via `.as_string()`.
- `Intended for debugging and visual inspection only. Not for saving data`.

### 6. Better Seeds via Key512
- Utilizes the full 512-bit key for generating seeds, ensuring a more secure and unpredictable seed generation process.
- Improved seed generation algorithm for better randomness and security.

### Fixes and Improvements
1. Small performance improvements.
2. Fixed benchmarks on Encrypt and Decrypt named same (`Encryption took...`).
3. Code base refactored.

---

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
v0.4.0 marks the start of **quantum-resilient design shift**.

The next version (v0.5+) will focus on further optimizations, better abstraction, and Kyber integration.
