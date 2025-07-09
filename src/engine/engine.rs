use crate::{
    Config, Errors, GaloisFieldType, TpmModule,
    engine::{
        cache_warmup::{CacheWarmup, CacheWarmup64},
        simd::{avx2_add_inplace, avx2_sub_inplace, avx2_xor_inplace},
    },
};
use dashmap::DashMap;
use rand::Rng;
use rayon::{ThreadPool, prelude::*};
use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Sha3_512};
use std::{
    arch::x86_64::{__m128i, _mm_loadu_si128, _mm_set_epi8, _mm_shuffle_epi8, _mm_storeu_si128},
    hint::black_box,
    sync::OnceLock,
    thread,
    time::Duration,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use tss_esapi::structures::MaxBuffer;
use zeroize::Zeroize;

type SecretKey = SecretBox<[u8]>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KeyBuffer(Vec<u8>);

impl Drop for KeyBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub const RATIO: u64 = 0x9E3779B97F4A7C15;
pub const ROTATIONS: [u32; 10] = [8, 2, 3, 1, 4, 5, 12, 9, 11, 4];
pub const POS_DEPENT: [u32; 10] = [1, 8, 3, 1, 8, 3, 1, 9, 1, 4];
static THREAD_POOL: OnceLock<ThreadPool> = OnceLock::new();
static KEY_CACHE_MAP: OnceLock<DashMap<KeyBuffer, SecretKey>> = OnceLock::new();

fn choose_key(nonce: &[u8], key: &[u8], config: &Config) -> Result<Vec<u8>, Errors> {
    match config.hardware.hardware_hashing {
        true => {
            let manager = TpmModule;
            let mut context = manager.generate_context(config.hardware)?;
            let tpm_key = MaxBuffer::try_from([nonce, key].concat())
                .map_err(|e| Errors::TpmHashingError(e.to_string()))?;
            match TpmModule::hash_key(tpm_key, &mut context, config.hardware) {
                Ok(hash) => {
                    thread::sleep(Duration::from_micros(50));
                    Ok(hash)
                }
                Err(_) => {
                    println!("TPM SHA3-512 NOT SUPPORTED, FALLBACK TO SOFTWARE SHA3-512");
                    let mut hash = Sha3_512::new();
                    hash.update(nonce);
                    hash.update(key);
                    Ok(hash.finalize().to_vec())
                }
            }
        }
        false => {
            let mut hash = Sha3_512::new();
            hash.update(nonce);
            hash.update(key);
            Ok(hash.finalize().to_vec())
        }
    }
}

fn get_thread_pool(thread_num: usize, stack_size: usize) -> &'static ThreadPool {
    THREAD_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_num)
            .stack_size(stack_size)
            .build()
            .expect("Failed to build thread pool")
    })
}

pub fn key_cache(nonce: &mut [u8], key: &[u8], config: &Config) -> Result<Vec<u8>, Errors> {
    let cache = KEY_CACHE_MAP.get_or_init(|| DashMap::new());

    let key_pair = [key, nonce].concat();

    if cache.len() > 4 {
        cache.clear();
    }

    if let Some(value_entry) = cache.get(&KeyBuffer(key_pair.to_vec())) {
        let value = value_entry.value();
        return Ok(value.expose_secret().to_vec());
    }

    let value = choose_key(nonce, key, config)?;

    cache.insert(
        KeyBuffer(key_pair.to_vec()),
        SecretBox::new(value.clone().into_boxed_slice()),
    );

    Ok(value)
}

#[repr(align(64))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GaloisField {
    mul_table: [[u8; 256]; 256],
    inv_table: [u8; 256],
    irreducible_poly: u16,
}

impl GaloisField {
    pub fn new(irreducible_poly: u16) -> Self {
        let mut gf = Self {
            mul_table: [[0; 256]; 256],
            inv_table: [0; 256],
            irreducible_poly,
        };

        gf.initialize_tables();
        gf
    }

    fn initialize_tables(&mut self) {
        for i in 0..256 {
            for j in 0..256 {
                self.mul_table[i][j] = self.multiply(i as u8, j as u8);
            }
        }
        for i in 1..256 {
            for j in 1..256 {
                if self.mul_table[i][j] == 1 {
                    self.inv_table[i] = j as u8;
                }
            }
        }
    }

    fn multiply(&self, a: u8, b: u8) -> u8 {
        let mut p = 0;
        let mut a_val = a as u16;
        let mut b_val = b as u16;

        while a_val != 0 && b_val != 0 {
            if b_val & 1 != 0 {
                p ^= a_val as u8;
            }

            let high_bit_set = a_val & 0x80;
            a_val <<= 1;

            if high_bit_set != 0 {
                a_val ^= self.irreducible_poly as u16;
            }

            b_val >>= 1;
        }

        p as u8
    }

    fn fast_multiply(&self, a: u8, b: u8) -> u8 {
        black_box(self.mul_table[a as usize][b as usize])
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    pub fn warm_cache(&self) {
        use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
        unsafe {
            for i in (0..256).step_by(64) {
                _mm_prefetch(self.mul_table[i].as_ptr() as *const i8, _MM_HINT_T0);
            }

            _mm_prefetch(self.inv_table.as_ptr() as *const i8, _MM_HINT_T0);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline(always)]
    pub fn warm_cache(&self) {
        for i in (0..256).step_by(64) {
            unsafe {
                core::ptr::read_volatile(&self.mul_table[i][0]);
            }
        }

        unsafe {
            core::ptr::read_volatile(&self.inv_table[0]);
        }
    }
}

fn parallel_xor_inplace(data: &mut [u8], key: &CacheWarmup64, pool: &ThreadPool, config: &Config) {
    pool.install(|| {
        let remainder_len = data.len() % 32;
        let chunks = data.par_chunks_exact_mut(32);

        chunks.enumerate().for_each(|(chunk_index, chunk)| {
            for (i, byte) in chunk.iter_mut().enumerate() {
                let global_pos = ((chunk_index * 32 + i) % 64) as u8;
                *byte ^= key_lookup(key, global_pos, config);
            }
        });

        if remainder_len != 0 {
            let start = data.len() - remainder_len;
            data[start..].par_iter_mut().enumerate().for_each(|(i, b)| {
                *b ^= key_lookup(key, (start + i) as u8, config);
            });
        }
    });
}

fn parallel_add_inplace(data: &mut [u8], key: &CacheWarmup64, pool: &ThreadPool, config: &Config) {
    pool.install(|| {
        let remainder_len = data.len() % 32;
        let chunks = data.par_chunks_exact_mut(32);

        chunks.enumerate().for_each(|(chunk_index, chunk)| {
            for (i, byte) in chunk.iter_mut().enumerate() {
                let global_pos = ((chunk_index * 32 + i) & 63) as u8;
                *byte = byte.wrapping_add(key_lookup(key, global_pos, config));
            }
        });

        if remainder_len != 0 {
            let start = data.len() - remainder_len;
            data[start..].par_iter_mut().enumerate().for_each(|(i, b)| {
                *b = b.wrapping_add(key_lookup(key, (start + i) as u8, config));
            });
        }
    });
}

fn parallel_sub_inplace(data: &mut [u8], key: &CacheWarmup64, pool: &ThreadPool, config: &Config) {
    pool.install(|| {
        let remainder_len = data.len() % 32;
        let chunks = data.par_chunks_exact_mut(32);

        chunks.enumerate().for_each(|(chunk_index, chunk)| {
            for (i, byte) in chunk.iter_mut().enumerate() {
                let global_pos = ((chunk_index * 32 + i) % 64) as u8;
                *byte = byte.wrapping_sub(key_lookup(key, global_pos, config));
            }
        });

        if remainder_len != 0 {
            let start = data.len() - remainder_len;
            data[start..].par_iter_mut().enumerate().for_each(|(i, b)| {
                *b = b.wrapping_sub(key_lookup(key, (start + i) as u8, config));
            });
        }
    });
}

fn xor(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_xor_inplace(data, key, &config) }
    } else {
        parallel_xor_inplace(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

fn add(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_add_inplace(data, key, config) }
    } else {
        parallel_add_inplace(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

fn sub(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_sub_inplace(data, key, config) }
    } else {
        parallel_sub_inplace(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

#[inline]
pub fn constant_time_key_lookup(key: &[u8], value: u8) -> u8 {
    let mut result = 0u8;

    for i in 0u8..=255u8 {
        let mask = value.ct_eq(&i);
        result.conditional_assign(&key[i as usize % key.len()], mask);
    }

    result
}

#[inline(always)]
pub fn key_lookup(key: &CacheWarmup64, value: u8, config: &Config) -> u8 {
    match config.subtle_key_lookup {
        true => constant_time_key_lookup(&key.key, value),
        false => key.cache_key_lookup(value),
    }
}

#[inline]
pub fn generate_counter_keystream(nonce: u64, block_counter: u64, chunk_idx: usize) -> [u8; 3] {
    let unique_counter = nonce
        .wrapping_add(block_counter)
        .wrapping_add(chunk_idx as u64)
        .wrapping_mul(RATIO);

    let bytes = unique_counter.to_le_bytes();
    [
        bytes[0] ^ bytes[3],
        bytes[1] ^ bytes[4],
        bytes[2] ^ bytes[5],
    ]
}

pub fn triangle_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    nonce: &[u8],
    config: &Config,
) -> Result<(), Errors> {
    gf.warm_cache();
    let mut _dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=config.dummy_data_size) {
                _dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    if data.is_empty() {
        return Err(Errors::GaloisFieldError("Empty Data".to_string()));
    }

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    pool.install(|| {
        data.par_chunks_exact_mut(3)
            .enumerate()
            .for_each(|(idx, chunk)| {
                let block_counter = ((idx / 512) as u64) + 1;
                let mut key_stream = generate_counter_keystream(
                    (nonce[idx % nonce.len()]) as u64,
                    block_counter,
                    idx,
                );

                let [a, b, c] = [key_stream[0], key_stream[1], key_stream[2]];
                key_stream[0] = gf.fast_multiply(3, a) ^ gf.fast_multiply(4, b) ^ c;
                key_stream[1] = gf.fast_multiply(4, b) ^ c;
                key_stream[2] = gf.fast_multiply(6, c);

                for (i, byte) in chunk.iter_mut().enumerate() {
                    *byte ^= black_box(key_stream[i]);
                }
            });
    });

    Ok(())
}

#[inline]
pub fn generate_counter_keystream_aes(nonce: u64, block_counter: u64, chunk_idx: usize) -> [u8; 4] {
    let unique_counter = nonce
        .wrapping_add(block_counter)
        .wrapping_add(chunk_idx as u64)
        .wrapping_mul(RATIO);

    let bytes = unique_counter.to_le_bytes();
    [
        bytes[0] ^ bytes[3],
        bytes[1] ^ bytes[4],
        bytes[2] ^ bytes[5],
        bytes[3] ^ bytes[6],
    ]
}

pub fn aes_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    config: &Config,
    nonce: &[u8],
) -> Result<(), Errors> {
    gf.warm_cache();
    let mut _dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=config.dummy_data_size) {
                _dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    if data.is_empty() {
        return Err(Errors::GaloisFieldError("Empty Data".to_string()));
    }

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    pool.install(|| {
        data.par_chunks_exact_mut(4)
            .enumerate()
            .for_each(|(idx, chunk)| {
                let block_counter = ((idx / 512) as u64) + 1;

                let mut key_stream = generate_counter_keystream_aes(
                    (nonce[idx % nonce.len()]) as u64,
                    block_counter,
                    idx,
                );

                let [s0, s1, s2, s3] = [key_stream[0], key_stream[1], key_stream[2], key_stream[3]];
                key_stream[0] = gf.fast_multiply(2, s0) ^ gf.fast_multiply(3, s1) ^ s2 ^ s3;
                key_stream[1] = s0 ^ gf.fast_multiply(2, s1) ^ gf.fast_multiply(3, s2) ^ s3;
                key_stream[2] = s0 ^ s1 ^ gf.fast_multiply(2, s2) ^ gf.fast_multiply(3, s3);
                key_stream[3] = gf.fast_multiply(3, s0) ^ s1 ^ s2 ^ gf.fast_multiply(2, s3);

                for (i, byte) in chunk.iter_mut().enumerate() {
                    *byte ^= black_box(key_stream[i]);
                }
            });
    });

    Ok(())
}

pub fn apply_gf(
    data: &mut [u8],
    config: &Config,
    gf: &GaloisField,
    nonce: &[u8],
) -> Result<(), Errors> {
    match config.gf_type {
        GaloisFieldType::Triangular => triangle_mix_columns(data, gf, nonce, config),
        GaloisFieldType::AES => aes_mix_columns(data, gf, config, nonce),
        GaloisFieldType::Hybrid => {
            aes_mix_columns(data, gf, config, nonce)?;
            triangle_mix_columns(data, gf, nonce, config)
        }
    }
}

pub fn inverse_shift_rows(data: &mut [u8], config: &Config) {
    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        data.par_chunks_exact_mut(16).for_each(|chunk| unsafe {
            let mask = _mm_set_epi8(15, 2, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12);
            let shuffled =
                _mm_shuffle_epi8(_mm_loadu_si128(chunk.as_ptr() as *const __m128i), mask);
            _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, shuffled);
        });
    } else {
        pool.install(|| {
            data.par_chunks_exact_mut(16).for_each(|chunk| {
                chunk.swap(11, 7);
                chunk.swap(15, 11);
                chunk.swap(3, 15);
                chunk.swap(6, 14);
                chunk.swap(2, 10);
                chunk.swap(9, 13);
                chunk.swap(5, 9);
                chunk.swap(1, 5);
            });
        })
    }
}

pub fn shift_rows(data: &mut [u8], config: &Config) {
    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        data.par_chunks_exact_mut(16).for_each(|chunk| unsafe {
            let mask = _mm_set_epi8(11, 6, 1, 12, 7, 2, 13, 8, 3, 14, 9, 4, 15, 10, 5, 0);
            let shuffled =
                _mm_shuffle_epi8(_mm_loadu_si128(chunk.as_ptr() as *const __m128i), mask);
            _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, shuffled);
        });
    } else {
        pool.install(|| {
            data.par_chunks_exact_mut(16).for_each(|chunk| {
                chunk.swap(1, 5);
                chunk.swap(5, 9);
                chunk.swap(9, 13);
                chunk.swap(2, 10);
                chunk.swap(6, 14);
                chunk.swap(3, 15);
                chunk.swap(15, 11);
                chunk.swap(11, 7);
            });
        });
    }
}

pub fn rxa_encrypt(pwd: &CacheWarmup64, input: &mut [u8], config: Config) -> Result<(), Errors> {
    let mut dummy_vec;
    let input: &mut [u8] = if input.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        input
    };

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    pool.install(|| {
        input
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = b.rotate_left(ROTATIONS[i % 8]));
    });
    xor(input, &pwd, &config);
    add(input, &pwd, &config);

    Ok(())
}

pub fn rxa_decrypt(pwd: &CacheWarmup64, input: &mut [u8], config: Config) -> Result<(), Errors> {
    let mut dummy_vec;
    let input: &mut [u8] = if input.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        input
    };

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    sub(input, &pwd, &config);
    xor(input, &pwd, &config);
    pool.install(|| {
        input
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = b.rotate_right(ROTATIONS[i % 8]));
    });

    Ok(())
}

#[inline]
fn constant_time_sbox_lookup(sbox: &[u8; 256], input: u8) -> u8 {
    let mut result = 0u8;

    for i in 0u8..=255u8 {
        let mask = input.ct_eq(&i);
        result.conditional_assign(&sbox[i as usize], mask);
    }

    result
}

pub fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
    let mut inv_s_box = [0u8; 256];

    for (i, &val) in s_box.iter().enumerate() {
        inv_s_box[val as usize] = i as u8;
    }

    inv_s_box
}

pub fn generate_dynamic_sbox(nonce: &[u8], key: &[u8], cfg: Config) -> Result<[u8; 256], Errors> {
    let mut sbox: [u8; 256] = [0; 256];
    for i in 0..256 {
        sbox[i] = i as u8;
    }

    let mut nonce = nonce.to_vec();
    let seed_base = key_cache(&mut nonce, key, &cfg)?;
    let mut seed = seed_base.iter().map(|b| *b as u32).collect::<Vec<u32>>();

    seed.iter_mut().enumerate().for_each(|(i, byte)| {
        *byte ^= (i as u64 + 1).wrapping_mul(RATIO) as u32;
    });

    for i in (1..256).rev() {
        let pos_factor = POS_DEPENT[i % 10];

        let seed1_enhanced = (black_box(seed[i % seed.len()]) as u32).wrapping_mul(pos_factor);
        let seed2_enhanced = (black_box(seed[(i * 7) % seed.len()]) as u32)
            .wrapping_mul(pos_factor.wrapping_add(i as u32));

        let index = (seed1_enhanced.wrapping_add(seed2_enhanced) as usize) % (i + 1);
        sbox.swap(i, index);
    }

    Ok(sbox)
}

pub fn in_s_bytes(data: &mut [u8], inv_sbox: &CacheWarmup64, cfg: Config) -> Result<(), Errors> {
    let pool = get_thread_pool(cfg.thread_strategy.get_cpu_count(), cfg.stack_size);
    if cfg.hardware.warmup_cache {
        inv_sbox.pre_sbox_warmup();
    }

    match cfg.subtle_sbox {
        true => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = constant_time_sbox_lookup(&inv_sbox.inv_sbox, *b));
        })),
        false => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = inv_sbox.cache_inverse_lookup(*b));
        })),
    }
}

pub fn s_bytes(data: &mut [u8], sbox: &CacheWarmup64, cfg: Config) -> Result<(), Errors> {
    let pool = get_thread_pool(cfg.thread_strategy.get_cpu_count(), cfg.stack_size);
    if cfg.hardware.warmup_cache {
        sbox.pre_sbox_warmup();
    }

    match cfg.subtle_sbox {
        true => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = constant_time_sbox_lookup(&sbox.sbox, *b));
        })),
        false => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = sbox.cache_time_lookup(*b));
        })),
    }
}

pub fn generate_keystream_32(nonce: &[u8], block_counter: u64, chunk_idx: usize) -> [u8; 32] {
    let mut keystream = [0u8; 32];

    for (i, b) in nonce.iter().enumerate() {
        let unique_counter = (*b as u64)
            .wrapping_add(block_counter)
            .wrapping_add(chunk_idx as u64)
            .wrapping_add(i as u64)
            .wrapping_mul(RATIO);

        keystream[i] = unique_counter as u8;
    }

    keystream
}

pub fn ctr_encrypt(nonce: &[u8], data: &mut [u8], iv: &[u8]) {
    let mut current_iv = iv;

    for (idx, chunk) in data.chunks_exact_mut(64).enumerate() {
        let block_counter = ((idx / 32) as u64) + 1;
        let keystream = generate_keystream_32(nonce, block_counter, idx);

        chunk
            .iter_mut()
            .zip(current_iv.iter())
            .enumerate()
            .for_each(|(i, (b, iv_byte))| {
                *b = *b ^ (iv_byte.wrapping_mul(keystream[i % 8]));
            });

        current_iv = &chunk[..iv.len().min(64)];
    }
}

pub fn ctr_decrypt(nonce: &[u8], data: &mut [u8], iv: &[u8]) {
    let mut current_iv = iv.to_vec();

    for (idx, chunk) in data.chunks_exact_mut(64).enumerate() {
        let block_counter = ((idx / 32) as u64) + 1;
        let keystream = generate_keystream_32(nonce, block_counter, idx);

        let next_iv = chunk[..current_iv.len().min(64)].to_vec();

        chunk
            .iter_mut()
            .zip(current_iv.iter())
            .enumerate()
            .for_each(|(i, (b, iv_byte))| {
                *b = *b ^ (iv_byte.wrapping_mul(keystream[i % 8]));
            });

        current_iv = next_iv;
    }
}
