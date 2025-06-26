use crate::{Config, Errors, GaloisFieldType, KeyLength, TpmModule};
use rand::Rng;
use rayon::{ThreadPool, prelude::*};
use secrecy::{ExposeSecret, SecretBox};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use tss_esapi::structures::MaxBuffer;
use zeroize::Zeroize;

use super::simd::{avx2_add, avx2_sub, avx2_xor};

type SecretKey = SecretBox<[u8]>;

static THREAD_POOL: OnceLock<ThreadPool> = OnceLock::new();
static KEY_CACHE_MAP: OnceLock<RwLock<HashMap<Vec<u8>, SecretKey>>> = OnceLock::new();

fn choose_key(nonce: &[u8], key: &[u8], config: &Config) -> Result<Vec<u8>, Errors> {
    match config.key_length {
        KeyLength::Key256 => {
            let mut hash = Sha3_256::new();
            hash.update(nonce);
            hash.update(key);
            Ok(hash.finalize().to_vec())
        }
        KeyLength::Key512 => match config.hardware.hardware_hashing {
            true => {
                let manager = TpmModule;
                let mut context = manager.generate_context(config.hardware)?;
                let tpm_key = MaxBuffer::try_from([nonce, key].concat())
                    .map_err(|e| Errors::TpmHashingError(e.to_string()))?;
                match TpmModule::hash_key(tpm_key, &mut context, config.hardware) {
                    Ok(hash) => Ok(hash),
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
        },
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
    let cache = KEY_CACHE_MAP.get_or_init(|| RwLock::new(HashMap::new()));
    let key_pair = nonce
        .iter()
        .enumerate()
        .map(|(i, b)| b.wrapping_add(key[i % key.len()]))
        .collect::<Vec<u8>>();

    {
        let map = cache
            .read()
            .map_err(|_| Errors::BuildFailed("Cannot read cache data".to_string()))?;
        if let Some(value) = map.get(&key_pair) {
            let value = value.expose_secret();
            return Ok(value.to_vec());
        }
    }

    let value = choose_key(nonce, key, config)?;

    let mut map = cache
        .write()
        .map_err(|_| Errors::BuildFailed("Cannot write cache data".to_string()))?;
    map.insert(key_pair, SecretBox::new(value.clone().into_boxed_slice()));

    Ok(value)
}

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
        self.mul_table[a as usize][b as usize]
    }

    fn constant_time_fast_multiply(&self, a: u8, b: u8) -> u8 {
        let mut result = 0u8;

        for i in 0u8..=255u8 {
            for j in 0u8..=255u8 {
                let mask = a.ct_eq(&i) & b.ct_eq(&j);
                result.conditional_assign(&self.mul_table[i as usize][j as usize], mask);
            }
        }

        result
    }
}

fn parallel_xor(data: &[u8], key: &[u8], pool: &ThreadPool, config: &Config) -> Vec<u8> {
    let mut output = vec![0u8; 0];
    output.resize(data.len(), 0u8);
    pool.install(|| {
        let size = data.len() as usize;
        output
            .par_chunks_mut(dynamic_sizes(size) as usize)
            .zip(data.par_chunks(dynamic_sizes(size) as usize))
            .enumerate()
            .for_each(|(chunk_index, (out_chunk, in_chunk))| {
                let chunk_size = dynamic_sizes(size) as usize;
                for (i, &byte) in in_chunk.iter().enumerate() {
                    let global_index = (chunk_index * chunk_size + i) as u8;
                    out_chunk[i] = byte ^ key_lookup(key, global_index, config);
                }
            });
    });

    output
}

fn parallel_add(data: &[u8], key: &[u8], pool: &ThreadPool, config: &Config) -> Vec<u8> {
    let mut output = vec![0u8; 0];
    output.resize(data.len(), 0u8);
    pool.install(|| {
        let size = data.len() as usize;
        output
            .par_chunks_mut(dynamic_sizes(size) as usize)
            .zip(data.par_chunks(dynamic_sizes(size) as usize))
            .enumerate()
            .for_each(|(chunk_index, (out_chunk, in_chunk))| {
                let chunk_size = dynamic_sizes(size) as usize;
                for (i, &byte) in in_chunk.iter().enumerate() {
                    let global_index = (chunk_index * chunk_size + i) as u8;
                    out_chunk[i] = byte.wrapping_add(key_lookup(key, global_index, config));
                }
            });
    });

    output
}

fn parallel_sub(data: &[u8], key: &[u8], pool: &ThreadPool, config: &Config) -> Vec<u8> {
    let mut output = vec![0u8; 0];
    output.resize(data.len(), 0u8);
    pool.install(|| {
        let size = data.len() as usize;
        output
            .par_chunks_mut(dynamic_sizes(size) as usize)
            .zip(data.par_chunks(dynamic_sizes(size) as usize))
            .enumerate()
            .for_each(|(chunk_index, (out_chunk, in_chunk))| {
                let chunk_size = dynamic_sizes(size) as usize;
                for (i, &byte) in in_chunk.iter().enumerate() {
                    let global_index = (chunk_index * chunk_size + i) as u8;
                    out_chunk[i] = byte.wrapping_sub(key_lookup(key, global_index, config));
                }
            });
    });

    output
}

fn xor(data: &mut [u8], key: &[u8], config: &Config) -> Vec<u8> {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_xor(data, key, &config) }
    } else {
        parallel_xor(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

fn add(data: &mut [u8], key: &[u8], config: &Config) -> Vec<u8> {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_add(data, key, config) }
    } else {
        parallel_add(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

fn sub(data: &mut [u8], key: &[u8], config: &Config) -> Vec<u8> {
    if is_x86_feature_detected!("avx2") && config.hardware.enable_avx2 {
        unsafe { avx2_sub(data, key, config) }
    } else {
        parallel_sub(
            data,
            key,
            get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size),
            &config,
        )
    }
}

pub fn constant_time_key_lookup(key: &[u8], value: u8) -> u8 {
    let mut result = 0u8;

    for i in 0u8..=255u8 {
        let mask = value.ct_eq(&i);
        result.conditional_assign(&key[i as usize % key.len()], mask);
    }

    result
}

pub fn key_lookup(key: &[u8], value: u8, config: &Config) -> u8 {
    match config.constant_time_key_lookup {
        true => constant_time_key_lookup(key, value),
        false => key[value as usize % key.len()],
    }
}

pub fn generate_counter_keystream(nonce: u64, block_counter: u64, chunk_idx: usize) -> [u8; 3] {
    let unique_counter = nonce
        .wrapping_add(block_counter)
        .wrapping_add(chunk_idx as u64)
        .wrapping_mul(0x9E3779B97F4A7C15);

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
) -> Result<Vec<u8>, Errors> {
    let mut _dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=1024 * 10) {
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
                match config.constant_time_galois_field {
                    true => {
                        key_stream[0] = gf.constant_time_fast_multiply(3, a)
                            ^ gf.constant_time_fast_multiply(4, b)
                            ^ c;
                        key_stream[1] = gf.constant_time_fast_multiply(4, b) ^ c;
                        key_stream[2] = gf.constant_time_fast_multiply(6, c);
                    }
                    false => {
                        key_stream[0] = gf.fast_multiply(3, a) ^ gf.fast_multiply(4, b) ^ c;
                        key_stream[1] = gf.fast_multiply(4, b) ^ c;
                        key_stream[2] = gf.fast_multiply(6, c);
                    }
                }

                for (i, byte) in chunk.iter_mut().enumerate() {
                    *byte ^= key_stream[i];
                }
            });
    });

    Ok(data.to_vec())
}

pub fn generate_counter_keystream_aes(nonce: u64, block_counter: u64, chunk_idx: usize) -> [u8; 4] {
    let unique_counter = nonce
        .wrapping_add(block_counter)
        .wrapping_add(chunk_idx as u64)
        .wrapping_mul(0x9E3779B97F4A7C15);

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
) -> Result<Vec<u8>, Errors> {
    let mut _dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=1024 * 10) {
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
                match config.constant_time_galois_field {
                    true => {
                        key_stream[0] = gf.constant_time_fast_multiply(2, s0)
                            ^ gf.constant_time_fast_multiply(3, s1)
                            ^ s2
                            ^ s3;
                        key_stream[1] = s0
                            ^ gf.constant_time_fast_multiply(2, s1)
                            ^ gf.constant_time_fast_multiply(3, s2)
                            ^ s3;
                        key_stream[2] = s0
                            ^ s1
                            ^ gf.constant_time_fast_multiply(2, s2)
                            ^ gf.constant_time_fast_multiply(3, s3);
                        key_stream[3] = gf.constant_time_fast_multiply(3, s0)
                            ^ s1
                            ^ s2
                            ^ gf.constant_time_fast_multiply(2, s3);
                    }
                    false => {
                        key_stream[0] = gf.fast_multiply(2, s0) ^ gf.fast_multiply(3, s1) ^ s2 ^ s3;
                        key_stream[1] = s0 ^ gf.fast_multiply(2, s1) ^ gf.fast_multiply(3, s2) ^ s3;
                        key_stream[2] = s0 ^ s1 ^ gf.fast_multiply(2, s2) ^ gf.fast_multiply(3, s3);
                        key_stream[3] = gf.fast_multiply(3, s0) ^ s1 ^ s2 ^ gf.fast_multiply(2, s3);
                    }
                }

                for (i, byte) in chunk.iter_mut().enumerate() {
                    *byte ^= key_stream[i];
                }
            });
    });

    Ok(data.to_vec())
}

pub fn apply_gf(
    data: &mut [u8],
    config: &Config,
    gf: &GaloisField,
    nonce: &[u8],
) -> Result<Vec<u8>, Errors> {
    match config.gf_type {
        GaloisFieldType::Triangular => triangle_mix_columns(data, gf, nonce, config),
        GaloisFieldType::AES => aes_mix_columns(data, gf, config, nonce),
        GaloisFieldType::Hybrid => {
            let mut mix = aes_mix_columns(data, gf, config, nonce)?;
            triangle_mix_columns(&mut mix, gf, nonce, config)
        }
    }
}

pub fn inverse_shift_rows(data: &mut [u8], config: &Config) {
    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

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

pub fn shift_rows(data: &mut [u8], config: &Config) {
    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

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

pub fn rxa_encrypt(pwd: &[u8], input: &mut [u8], config: Config) -> Result<Vec<u8>, Errors> {
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
            .for_each(|(i, b)| *b = b.rotate_left(key_lookup(&pwd, i as u8, &config) as u32));
    });
    let mut input = xor(input, &pwd, &config);
    let out = add(&mut input, &pwd, &config);

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(out),
    }
}

pub fn rxa_decrypt(pwd: &[u8], input: &mut [u8], config: Config) -> Result<Vec<u8>, Errors> {
    let mut dummy_vec;
    let input: &mut [u8] = if input.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        input
    };

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    let mut input = sub(input, &pwd, &config);
    let mut input = xor(&mut input, &pwd, &config);
    pool.install(|| {
        input
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = b.rotate_right(key_lookup(&pwd, i as u8, &config) as u32));
    });

    match input.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(input),
    }
}

fn constant_time_sbox_lookup(sbox: &[u8; 256], input: u8) -> u8 {
    let mut result = 0u8;

    for i in 0u8..=255u8 {
        let mask = input.ct_eq(&i);
        result.conditional_assign(&sbox[i as usize], mask);
    }

    result
}

fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
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
        *byte ^= (i as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15) as u32;
    });

    for i in (1..256).rev() {
        let index = (seed[i % seed.len()] as usize + seed[(i * 7) % seed.len()] as usize) % (i + 1); // Generate a random index
        sbox.swap(i, index); // Swap the values in the sbox
    }

    Ok(sbox)
}

pub fn in_s_bytes(
    data: &mut [u8],
    nonce: &[u8],
    pwd: &[u8],
    cfg: Config,
) -> Result<Vec<u8>, Errors> {
    let mut sbox = generate_dynamic_sbox(nonce, pwd, cfg)?; // Generate the sbox
    let inv_sbox = generate_inv_s_box(&sbox); // Generate the inverse sbox

    sbox.zeroize();

    let pool = get_thread_pool(cfg.thread_strategy.get_cpu_count(), cfg.stack_size);

    match cfg.constant_time_sbox {
        true => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = constant_time_sbox_lookup(&inv_sbox, *b));
            data.to_vec()
        })),
        false => Ok(pool.install(|| {
            data.par_iter_mut().for_each(|b| *b = inv_sbox[*b as usize]);
            data.to_vec()
        })),
    }
}

pub fn s_bytes(data: &mut [u8], nonce: &[u8], pwd: &[u8], cfg: Config) -> Result<Vec<u8>, Errors> {
    let sbox = generate_dynamic_sbox(nonce, pwd, cfg)?;
    let pool = get_thread_pool(cfg.thread_strategy.get_cpu_count(), cfg.stack_size);

    match cfg.constant_time_sbox {
        true => Ok(pool.install(|| {
            data.par_iter_mut()
                .for_each(|b| *b = constant_time_sbox_lookup(&sbox, *b));
            data.to_vec()
        })),
        false => Ok(pool.install(|| {
            data.par_iter_mut().for_each(|b| *b = sbox[*b as usize]);
            data.to_vec()
        })),
    }
}

pub fn dynamic_sizes(data_len: usize) -> u32 {
    match data_len {
        0..1_000 => 14,
        1_000..10_000 => 24,
        10_000..100_000 => 64,
        100_000..1_000_000 => 2048,
        1_000_000..10_000_000 => 16384,
        10_000_000..100_000_000 => 32768,
        100_000_000..1_000_000_000 => 65536,
        1_000_000_000..10_000_000_000 => 131072,
        10_000_000_000..100_000_000_000 => 131072,
        100_000_000_000..1_000_000_000_000 => 262144,
        1_000_000_000_000..10_000_000_000_000 => 262144,
        10_000_000_000_000..100_000_000_000_000 => 524288,
        100_000_000_000_000..1_000_000_000_000_000 => 524288,
        1_000_000_000_000_000..10_000_000_000_000_000 => 1048576,
        10_000_000_000_000_000..100_000_000_000_000_000 => 1048576,
        100_000_000_000_000_000..1_000_000_000_000_000_000 => 2097152,
        1_000_000_000_000_000_000..10_000_000_000_000_000_000 => 2097152,
        _ => unreachable!(),
    }
}

pub fn get_chunk_sizes(
    data_len: usize,
    nonce: &[u8],
    key: &[u8],
    config: Config,
) -> Result<Vec<usize>, Errors> {
    let mut sizes_table = Vec::new();
    let mut pos = 0;

    let mut nonce = nonce.to_vec();
    let seed = key_cache(&mut nonce, key, &config)?;

    let data_size = dynamic_sizes(data_len) as usize;

    while pos < data_len {
        let size = data_size + (seed[pos % seed.len()] as usize % 16)
            ^ (pos.wrapping_mul(0x9E3779B97F4A7C15));
        let size = if size == 0 { 1 } else { size % (256 * 256) };
        sizes_table.push(size.min(data_len - pos));

        pos += size;
    }

    Ok(sizes_table)
}

pub fn dynamic_shift(
    data: &mut [u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let mut nonce = nonce.to_vec();
    let key = key_cache(&mut nonce, password, &config)?;
    let chunk_sizes = get_chunk_sizes(data.len(), &nonce, &key, config)?;

    let mut offsets = Vec::with_capacity(chunk_sizes.len());
    let mut cursor = 0;
    for size in &chunk_sizes {
        offsets.push((cursor, *size));
        cursor += *size;
    }

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=1024 * 10) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    pool.install(|| {
        let mut rotated: Vec<u8> = offsets
            .par_iter()
            .enumerate()
            .flat_map(|(i, (start, size))| {
                let mut chunk = data[*start..(*start + *size)].to_vec();
                let rotate_by = (nonce[i % nonce.len()] % 8) as u32;

                chunk
                    .par_iter_mut()
                    .for_each(|b| *b = b.rotate_left(rotate_by));

                chunk
            })
            .collect();

        let result = xor(&mut rotated, &key, &config);

        Ok(result.par_iter().rev().cloned().collect::<Vec<u8>>())
    })
}

pub fn dynamic_unshift(
    data: &mut [u8],
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let mut data = data.par_iter().rev().cloned().collect::<Vec<u8>>();
    let mut nonce = nonce.to_vec();
    let key = key_cache(&mut nonce, password, &config)?;

    let chunk_sizes = get_chunk_sizes(data.len(), &nonce, &key, config)?;

    let mut offsets = Vec::with_capacity(chunk_sizes.len());
    let mut cursor = 0;
    for size in &chunk_sizes {
        offsets.push((cursor, *size));
        cursor += *size;
    }

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::thread_rng().gen_range(0..=1024 * 10) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_strategy.get_cpu_count(), config.stack_size);

    pool.install(|| {
        let data = xor(&mut data, &key, &config);

        let result: Vec<u8> = offsets
            .par_iter()
            .enumerate()
            .flat_map(|(i, (start, size))| {
                let mut chunk = data[*start..(*start + *size)].to_vec();
                let rotate_by = (nonce[i % nonce.len()] % 8) as u32;

                chunk
                    .par_iter_mut()
                    .for_each(|b| *b = b.rotate_right(rotate_by));

                chunk
            })
            .collect();

        Ok(result)
    })
}

pub fn generate_keystream_32(nonce: &[u8], block_counter: u64, chunk_idx: usize) -> [u8; 32] {
    let mut keystream = [0u8; 32];

    for (i, b) in nonce.iter().enumerate() {
        let unique_counter = (*b as u64)
            .wrapping_add(block_counter)
            .wrapping_add(chunk_idx as u64)
            .wrapping_add(i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15);

        keystream[i] = unique_counter as u8;
    }

    keystream
}

pub fn ctr_encrypt(nonce: &[u8], data: &mut [u8], iv: &[u8]) {
    let mut current_iv = iv.to_vec();

    for (idx, chunk) in data.chunks_exact_mut(64).enumerate() {
        let block_counter = ((idx / 64) as u64) + 1;
        let keystream = generate_keystream_32(nonce, block_counter, idx);

        chunk
            .iter_mut()
            .zip(current_iv.iter())
            .enumerate()
            .for_each(|(i, (b, iv_byte))| {
                *b = *b ^ (iv_byte.wrapping_mul(keystream[i % 8]));
            });

        current_iv = chunk[..iv.len().min(64)].to_vec();
    }
}

pub fn ctr_decrypt(nonce: &[u8], data: &mut [u8], iv: &[u8]) {
    let mut current_iv = iv.to_vec();

    for (idx, chunk) in data.chunks_exact_mut(64).enumerate() {
        let block_counter = ((idx / 64) as u64) + 1;
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
