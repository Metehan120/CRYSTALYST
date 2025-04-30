# AtomCrypte v0.5.0 – "Stage 1"

## Overview
> The 0.5.0 update marks the **largest internal refactor and performance leap** in AtomCrypte's history. With a redesigned encryption engine, this release delivers unmatched parallel performance, cleaner abstractions, and even better resistance against side-channel analysis.

---

## New Core Features

### 1. **Smart Key Caching (Thread-Safe)**
- Introduced a thread-safe, read-write locked `HashMap` cache to store derived keys.
- Avoids redundant key derivations across multiple operations, especially during multi-round encryption.
- Greatly reduces CPU cycles spent on hashing during repeated operations.
- Fully thread-safe using `RwLock<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>`.

### 2. **Parallel XOR & S-Box Processing**
- All XOR operations now use custom `par_chunks_mut` processing.
- S-box transformations fully parallelized using Rayon, allowing operations to scale with CPU threads.

### 3. **Dynamic Chunk Sizes (Data-Length Aware)**
- Internal chunk sizes adjust based on input data size.
- Provides best balance between performance and memory locality.
- Enables seamless encryption across files from **512 bytes to multi-GB ranges**.

---

## Algorithm Improvements
### 1. **New S-Box Generation Paths**
- Password-based, Nonce-based, and Combined-mode available.
- S-boxes are now derived using full entropy of Blake3/SHA3-512 hashed seed.
- S-box and inverse s-box computations now follow a deterministic yet dynamic path per config.

---

## Security Upgrades
### 1. **HMAC-SHA3 Authentication**
- MAC now computed via **HMAC-SHA3-512**, enhancing integrity verification.
- Ensures message tampering detection using a key-bound secure hash.

### 2. **MAC Binding Strategy**
- MACs now bind not just to output, but to the original **plaintext + ciphertext** pair.
- Defeats chosen-ciphertext attacks and tampering during transmission.

---

## Performance

### Ryzen 5 3600 Benchmarks (100MB File):
- **Encryption Speed:** ~20.8 MB/s
- **Decryption Speed:** ~40.4 MB/s
- **Compared to v0.4.x:** ~4–6x faster

### On High-End Server (EPYC/Threadripper expected):
- **Estimated Encryption:** 200–400 MB/s
- **Estimated Decryption:** 300–700 MB/s

Performance varies based on thread count and data size.

---

## Compatibility
- **Not backward-compatible with v0.4.x** due to engine and MAC structure changes.
- Encrypted files in 0.5.0 must be decrypted using 0.5.0 and above.

A migration tool is **under consideration** for future patch releases.

---

## Roadmap After v0.5.0

### v0.6.0 → Faster but Better
- **AVX2** Support: SIMD acceleration.
- **AVX512** Support: Further SIMD acceleration.

### v0.8.0 → Networked Mode / Remote Secret Key Injection

---

# AtomCrypte v0.4.1 – “Dummy Data”

## New Features

### 1. Dummy Data Generator
- **Timing‐Attack Shield:**
  - If someone feeds you an empty input, AtomCrypte now auto‐generates a random “junk” payload (1 BYTE – 8 KB by default).
  - General‐purpose decoy bytes: after any encryption call, AtomCrypte can sprinkle in up to **1 MB** of extra random data.
- **Analysis‐Attack Confusion:**
  - Any attempt to profile your ciphertext size or pattern gets thrown off by these decoy bytes.

### 2. Secure Zeroize
- **Two‐Pass Memory Wipe:**
  1. **Overwrite** all sensitive buffers with random bytes.
  2. **Zero‐out** every single byte.
- **Balanced Performance:**
  - No significant performance degradation observed — your data stays safe without slowing you down.


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
