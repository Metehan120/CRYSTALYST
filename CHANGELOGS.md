# CRYSTALYST v0.8.0 - "When Things Get Real"
## Overview

Major leap on CRYSTALYST history, introducing Real Key512 support, full SHA-3 support, and more.

## New Features
### 1. Real Key512 Support
- **Full Key Expansion**: Supports 512-bit keys for enhanced security.
- **Key Derivation**: Utilizes only Argon2 for secure key derivation.
- **Removed BLAKE3 Key Derivation Support**: Key never shrunk to 32bytes, but rather expanded to Key512.

### 2. Enhanced HMAC Support:
- **Full MAC Restructure**: The HMAC calculation now includes the version, cryptographic metadata, and SHA3-512 hashed ciphertext to ensure robust integrity.
- **Extended Metadata Layer**: Appends [0xAC, 0x07, 0x13, 0x00] control bytes to strengthen tamper detection.
- **Encrypt-then-MAC**: Implements a secure HMAC scheme after encryption to ensure both confidentiality and message integrity.
- **Improved Digest Composition**: Introduces layered hash input (plaintext, ciphertext, nonce, metadata and version) for enhanced cryptographic binding.

### 3. Full SHA3 Integration
- **Blake3 Replaced**: Transitioned from Blake3 to SHA3-256 and SHA3-512 for cryptographic consistency and post-quantum readiness.
- **Unified Digest Layer**: All MAC, hashing, and S-box generation now rely solely on SHA3 algorithms.

### 4. Post-Quantum Key Exchange Support (Kyber Integration)
- Integrated NIST-standard Kyber512 algorithm as an optional key exchange mechanism.
- New KyberModule API: Enables secure, passwordless shared secret generation between two parties.
- Provides built-in support for:
  - client_init → initializes ephemeral shared key generation
  - server_receive → receives and finalizes the shared secret
  - shared_secret() → exports derived key for use in CRYSTALYST
- Drop-in compatible with CrystalystBuilder::password(...), allowing seamless encryption using post-quantum shared keys.
- Resistant to both classical and quantum key recovery attacks.

### 5. Eliminated internal key caching from RXA:
- Eliminated internal key caching in the RXA encryption/decryption layer to reduce memory footprint and avoid unnecessary allocations.
- Enhanced security by preventing sensitive key material from being stored in long-lived memory structures (e.g. HashMap with RwLock), reducing the attack surface for side-channel or memory scraping attacks.

### 6. More secure S-BOX generation:
- Replaced the previous cast_slice::<u8, u32> usage with a safe and explicit mapping using .map(|b| *b as u32) to prevent potential alignment issues and ensure full seed length preservation.

### 7. Secure Key Cache management:
- Implemented a secure key cache management system to prevent sensitive key material from being stored in long-lived memory structures, reducing the attack surface for side-channel or memory scraping attacks.
- Keys are stored in SecretBox<[u8]>, ensuring they’re automatically zeroed out when dropped.

### 8. Better Chunk Generation on Dynamic Shift:
- Harmonized with Golden Ratio and key_cache using the formula: chunk_size = dynamic_size + seed[pos] ^ (pos * GOLDEN_RATIO)
- Implemented a more efficient chunk generation algorithm that dynamically adjusts the shift based on the input data size, ensuring optimal performance and security.
- This ensures non-uniform chunk sizes across data segments, making pattern analysis and ciphertext structure inference significantly harder.
- Golden Ratio multiplier (0x9E3779B97F4A7C15) introduces high-entropy, non-repeating patterns in chunk boundaries.

# CRYSTALYST v0.7.0 - "Configuration Revolution"

## Overview
The most significant update due to the introduction of constant-time configurable cryptography and hardware-backed security features.
- \> Total 1000+ Lines changed/added.

## Major New Features
### Removed S-Box types.

## Important Feature, Counter Mode (GCM-like but without MAC, algorithm already using HMAC):
### Counter Mode Benefits
- **Higher Entropy**: Achieves 7.999+ Shannon entropy in single round, on most cases 7.9999+ entropy
- **Attack Resistance**: Better protection against pattern-based attacks
- **Stream Cipher Behavior**: Eliminates block cipher weaknesses
- **No Performance Cost**: Almost zero overhead when enabled

### Implementation Details
- **Keystream Generation**: Golden ratio + cross-byte mixing
- **AES Matrix Integration**: Standard MixColumns on counter keystream
- **Parallel Processing**: Thread-safe atomic operations

### Security Properties
- **GCM Compliance**: Counter starts at 1 (NIST standard)
- **Perfect Balance**: ~50% bit distribution
- **Excellent Avalanche**: ~50% bit change propagation
- **High Diffusion**: 99.6%+ byte difference percentage, 7.999+ Shannon entropy, on most cases 7.99999+ entropy

### Entropy Results
- **50MB Zero Data**: Shannon 7.999996+
- **Real Data (Tested with 170MB .exe)**: Shannon 7.999999+ (even better!), On my tests, Reached Maximum: 7.9999992+
- **Avalanche Effect**: ~50% (theoretical ideal)
- **Bit Balance**: ~50% distribution
- **Byte Difference**: 99.6%+ unique output

### Usage
- **Test Suites**: `ctr_layer: false` (pure performance)
- **Production**: `ctr_layer: true` (enhanced security)
- **Backwards Compatible**: Existing configs unchanged

### Performance
- **Throughput**: 40.8 MB/s maintained
- **Memory**: Minimal additional usage
- **CPU**: Efficient golden ratio operations

## 2nd Important Feature, Golden Ratio S-Box:
### Bio-Inspired S-Box Generation
- **Nature-Derived Mathematics**: Uses the golden ratio (φ = 1.618...) for S-box creation, inspired by natural patterns found in sunflowers, nautilus shells, and Fibonacci sequences
- **Irrational Number Security**: Each Seed value undergoes golden ratio transformation, creating mathematically irreversible substitutions
- **Position-Dependent Chaos**: Every byte position gets unique φ multiplication using 32-bit precision

### Implementation Details
- **Triple Entropy Sources**: Combines password/nonce derivation + golden ratio enhancement + Fisher-Yates shuffling
- **Perfect Distribution**: Fisher-Yates algorithm ensures uniform S-box permutation
- **Dynamic Generation**: Every encryption creates a unique S-box based on key and nonce

### Security Properties
- **Cryptanalysis Resistance**: Linear and differential analysis become impossible due to irrational coefficients
- **Pattern Breaking**: Golden ratio multiplication destroys all mathematical patterns and relationships
- **Infinite Variations**: Astronomical number of possible S-boxes (256! × φ^seed_length)
- **Attack Immunity**: Statistical analysis, algebraic attacks, and brute force become computationally impossible

### 1. **Hardware-Backed Security (TPM 2.0 Integration)**
- **Complete TPM Nonce Generation Integration on Linux**: Securely integrates TPM 2.0 chips for enhanced security
- **TPM Nonce Generation**: Hardware-backed entropy using Trusted Platform Module
- **TPM Hardware Hashing**: Offloads cryptographic hashing to dedicated TPM chip for enhanced security
- **Intelligent Hash Fallback**: Automatically falls back to software SHA3-512 when TPM algorithms are unsupported
- **`TpmModule`**: Direct TPM chip integration for maximum security
- **`NonceType::Tpm`**: Hardware-generated nonces using cryptographic chips
- **Hardware Key Derivation**: Uses TPM 2.0 for secure key generation and derivation
- **True Random Number Generation**: Leverages TRNG in TPM 2.0 compliant chips
- **Enterprise-Grade Security**: Hardware-backed entropy for high-security operations

#### ⚠️ TPM Requirements:
- Requires TPM 2.0 and enabled firmware support
- **Administrator/Sudo privileges required** for TPM access
- Available on modern motherboards with TPM chips
- **Note**: Some TPM implementations (like AMD fTPM) may have limited algorithm support - automatic fallback ensures compatibility

### 2. **Revolutionary Configuration System**
- `Profile::Fortress`:
    - `constant_time_sbox(true)` - Timing attack resistant S-box operations
    - `constant_time_key_lookup(true)` - Secure key access patterns
    - `.constant_time_galois_field(true)` - Secure Galois field operations \ EXTREMELY EXPENSIVE (~65.000 CYCLES PER GF TRANSFORMATION)
    - `10 Rounds` - Number of rounds for cryptographic operations

### 3. **Configurable Constant-Time Operations**
- `constant_time_sbox(true)` - Timing attack resistant S-box operations
- `constant_time_key_lookup(true)` - Secure key access patterns
- Configurable per security profile
- Side-channel attack resistance

### 4. **Unified Nonce System**
- **`NonceType` Enum**: Centralized nonce type selection
  - `NonceType::Classic` - Fast software-generated nonces
  - `NonceType::Hashed` - Hash-based nonce generation
  - `NonceType::Machine` - Machine-bound nonces
  - `NonceType::TPM` - Hardware TPM-generated nonces
- **`Nonce::generate_nonce()`**: Unified interface for all nonce types
- **Flexible RNG Support**: Optional custom RNG for software nonces

### 5. TPM generated Salt:
- **`.tpm_salt()`**: Generate a TPM-generated salt for more secure cryptographic operations.
- **Randomness Verification**: Ensure entropy sources meet cryptographic requirements

### 6. **Enhanced Hardware Support**
- **`Hardware` Configuration**: Complete hardware capability control
  - `set_tmp_enabled()` - Enable/disable TPM features
  - `set_hardware_nonce()` - Control hardware nonce generation
  - `set_hardware_hashing()` - Control hardware hashing generation
  - `set_enable_avx2()` - Enable vector instruction optimization
- **Builder Pattern**: Fluent hardware configuration interface

### 7. **Complexity Slider API**
- `Config::default().complexity(0-10)` - Simple security level selection
- Automatic profile mapping based on complexity level
- User-friendly security configuration

### 8. **Enhanced Threading Options**
- `ThreadStrategy::Gaming` - Gaming-optimized threading
- `ThreadStrategy::BulkOperations` - Server workload optimization
- `ThreadStrategy::AutoThread` - CPU usage-aware threading
- `ThreadStrategy::FullThread` - Maximum threading utilization
- `.stack_size(usize)` - Configure stack size for threads, may needed on high computentional works (Default: 64MB)

### 9. **Advanced Security Primitives**
- Uses industry-standard `subtle` crate for timing-safe operations
- Constant-time S-box lookups when security profile demands
- Memory-safe operations with configurable security levels
- Protection against timing-based side-channel attacks

## 10. **Complete SIMD XOR, SIMD ADD and SIMD SUB Operations**
- **Added AVX2 vectorized implementations** for core arithmetic operations
- **32x parallel processing** with `_mm256_xor_si256`, `_mm256_add_epi8`, `_mm256_sub_epi8` intrinsics
- **Automatic fallback** to scalar operations on non-AVX2 CPUs
- **Perfect memory alignment** with 32-byte chunks for optimal SIMD utilization
- **Cross-platform compatibility** with runtime CPU feature detection
- **Significant performance boost** on modern x86_64 processors
- **Zero overhead** remainder handling for non-aligned data sizes

## 11. **Better Ordering**
- **SIMD call optimization for better performance**
- **Reduced memory allocations in core encryption pipeline**
- **Enhanced parallel processing efficiency in dynamic shift operations**

## 12. **Multi Round Galois Field Operations**
- **Multi Round Galois Field Operations**: Enhanced security.
- **Can be disabled through configuration BUT ⚠️ do not disable unless you know what you are doing and understand the security implications.**

## 13. **New Golios Field Operations (Only AES Added, Triangle was there)**
## 13.1.1 Triangle MixColumns (Custom)
- Chunk size: 3 bytes with remainder handling
- Operations: Custom polynomial mixing with multi-layer diffusion
- Advantage: Higher diffusion, superior entropy generation on repeated data
- \> Optimized for Conway GF operations, perform better on >40kb data

## 13.1.2 AES-inspired MixColumns
- Chunk size: 4 bytes (standard AES state)
- Operations: Fixed polynomial matrix multiplication
- Advantage: Proven security, faster processing

## 13.1.3 Hybrid Mode
- Process: AES → Triangle (encryption), Triangle⁻¹ → AES⁻¹ (decryption)
- Advantage: Combined security properties
- Use case: For research/test purposes

## 13.2 Performance (Ryzen 5 3600):
| Algorithm  | Processing Time | Throughput |
|------------|----------------|-----------------|
| Triangle   | 5.5s          | 25.4 MB/s  |
| AES        | 3.4s          | 50.9 MB/s  |

## 13.3 Recommendations
- **⚠️ WARNING:** DO NOT CHANGE unless you understand the security implications

## 14 Shift Rows:
- **Using similar algorithm to AES**
- Providing Confusion and Diffusion

## 15. Corrected Ordering:
- **RXA First Design**: Provides Rotate + XOR + Add, maybe it seems basic, but its provides HIGH security.

## 16. Controlable key derivation:
- **Enable/Disable via Config**: Allows for custom key derivation functions and variable key lengths
- **Disabled = Fast Operations**: Optimized for speed and efficiency

## 17. Small Testing unit:
- **Calculate shanon entropy**: Provides basic metrics to analyze the cryptographic quality of encrypted output. Useful for testing randomness, diffusion, and avalanche effects.
- **Calculate bit balance**: Checks the balance of 1 and 0 bits.
- **Calculate avalanche**: Calculates how much the output changes when a small change is made to the input.
- **Calculate byte difference**: Calculates percentage of bytes that differ between two slices.

## 18. Optimized for Real-Time work by default:
- Achieves 50MB/s+ on Ryzen 5 3600
- **Zeroize Disabled By Default**: Zeroize Disabled by Default: Optimized for speed; can be manually enabled or toggled via Secure, Fortress, or Extreme profiles.
- **AVX2**: 32 Bytes/cycle: Good on big packets, 2x performance improvements most times

## 19. Complete Argon2 implementation:
- **Argon2id (Recommended)**:
 - Hybrid of Argon2i and Argon2d.
 - Resistant to side-channel and GPU attacks.
 - Best overall balance of speed and security.
 - Recommended for most use-cases.
- **Argon2i**:
 - Prioritizes side-channel resistance.
 - Memory access is data-independent.
 - Ideal for password storage or environments vulnerable to timing attacks.
- **Argon2d**:
 - Focuses on GPU/hardware attack resistance.
 - Memory access is data-dependent.
 - Not safe for password hashing due to side-channel risks.
 - Useful for key derivation in controlled environments.
### ⚠️ Warning: Changing Argon2 variant affects key derivation. Make sure it matches on both encryption and decryption.

## Security Enhancements

- **Hardware-Backed Entropy**: TPM integration provides true hardware randomness
- **Timing Attack Resistance**: Configurable constant-time operations
- **Side-Channel Protection**: Memory-safe cryptographic primitives
- **Extra Mix Columns on Rounds**: Enhanced diffusion and confusion
- **Fixed Remainder on Galois Field Operations**: Ensures consistent results across platforms
- **Fixed AES Irreducible Polynomial**: Ensures secure and consistent results across platforms
- **Removed Mix Blocks**: Using RXA instead: Faster and Secure
# Note: Fortress profile is designed for maximum security and compliance, not speed.

## Performance (Default settings)

### Performance Range (340MB File):
- Way faster (2-3x) but on different configurations 1.5-2X Slower when compared to default setting

### Hardware Benchmarks:
- **Ryzen 5 3600:** ~50-100 MB/s
- **EPYC 9965 series:** 600MB/s+ theoretical throughput

---

# CRYSTALYST v0.6.0 - "Stage 2"

## Overview
- CRYSTALYST now comes with AVX2 Hardware Support, Fully Rewritten Engine, and Enhanced Security Features.

## Removed:
- Removed GPU Backend Support
- Removed Legacy Thread Strategy

## Added:

### 1. **AVX2 Hardware Support**
- Utilizes AVX2 instructions for optimized encryption and decryption operations.
- Enhances performance by leveraging SIMD (Single Instruction, Multiple Data) capabilities.
- Supports modern CPUs with AVX2 instruction set.

### 2. **Fully parallel XOR, Sub, Add**
- Implements fully parallel operations for XOR, Sub, Add, Shift, and Rotate.
- Optimizes memory access patterns for improved cache utilization.
- Gives near performance to AVX2 instructions.

### 3. **Chunk Based Hybrid Encryption**
- Utilizes chunk-based hybrid encryption for improved security and performance.
- Enhances security by combining symmetric and asymmetric encryption.
- Optimizes memory access patterns for improved cache utilization.

### 4. **Fully Rewritten Engine**
- Redesigned encryption engine with improved parallelism and memory locality.
- Enhanced security features and resistance against side-channel analysis.
- Faster execution, improved maintainability

### 5. **Advanced Thread Strategy**
- AutoThread, FullThread, LowThread, or Custom thread configs
- Automatically adapts based on CPU load and core count
- Preserves thermal headroom and maximizes parallel performance

### 6. Recovery Key
- Generates a unique recovery key for each encryption operation.
- Using your main Password and Nonce.
- Recovery Key option (.recovery_key(true))

## 7. Utils and Builder Separated

### 8.1. Utils
- Benchmark option (.benchmark(true))
- Recovery Key option (.recovery_key(true))
- Wrapping option (.wrap_all(true))

### 8.2. Builder
- Same as before. (CrystalystBuilder::new())
- Benchmark and Wrap All moved to Utils

## Fixes and Enhancements
1. Overflow Errors
2. Thread Strategy Improvements
3. Memory Access Patterns Optimized
4. Faster Encryption
5. Faster Decryption

## Performance

### Ryzen 5 3600 Benchmarks (100MB File):
- **Encryption Speed:** ~50.2 MB/s
- **Decryption Speed:** ~50.1 MB/s
- **Compared to v0.5.x:** ~2–3x faster

### On High-end Devices (Ryzen 7-9 7000 - Ryzen 7-9 9000)
- **Estimated  Encryption Speed:** ~120 MB/s
- **Estimated Decryption Speed:** ~120 MB/s
- **Compared to v0.5.x:** ~2–3x faster

### On High-End Server (EPYC/Threadripper expected):
- **Estimated Encryption:** 300–600 MB/s
- **Estimated Decryption:** 300–600 MB/s
- **Compared to v0.5.x:** ~2–3x faster

Performance varies based on thread count and data size.

## Compatibility
- **Not backward-compatible with v0.5.x** due to engine structure changes.

---

# CRYSTALYST v0.5.0 – "Stage 1"

## Overview
> The 0.5.0 update marks the **largest internal refactor and performance leap until 0.5.0** in CRYSTALYST's history. With a redesigned encryption engine, this release delivers unmatched parallel performance, cleaner abstractions, and even better resistance against side-channel analysis.

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
- **Decryption Speed:** ~20.4 MB/s
- **Compared to v0.4.x:** ~4–6x faster

### On High-End Server (EPYC/Threadripper expected):
- **Estimated Encryption:** 200–300 MB/s
- **Estimated Decryption:** 200–300 MB/s

Performance varies based on thread count and data size.

---

## Compatibility
- **Not backward-compatible with v0.4.x** due to engine and MAC structure changes.
---

## Roadmap After v0.5.0

### v0.6.0 → Faster but Better
- **AVX2** Support: SIMD acceleration.
- **ARM NEON** Support: SIMD acceleration.

---

# CRYSTALYST v0.4.1 – “Dummy Data”

## New Features

### 1. Dummy Data Generator
- **Timing‐Attack Shield:**
  - If someone feeds you an empty input, CRYSTALYST now auto‐generates a random “junk” payload (1 BYTE – 8 KB by default).
  - General‐purpose decoy bytes: after any encryption call, CRYSTALYST can sprinkle in up to **1 MB** of extra random data.
- **Analysis‐Attack Confusion:**
  - Any attempt to profile your ciphertext size or pattern gets thrown off by these decoy bytes.

### 2. Secure Zeroize
- **Two‐Pass Memory Wipe:**
  1. **Overwrite** all sensitive buffers with random bytes.
  2. **Zero‐out** every single byte.
- **Balanced Performance:**
  - No significant performance degradation observed — your data stays safe without slowing you down.


# CRYSTALYST v0.4.0 - "Steps Toward"
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

# CRYSTALYST v0.3.0 - "Secure Evolution"
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
