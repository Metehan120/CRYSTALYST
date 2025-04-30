use crate::{Config, Errors, KeyLength, SboxTypes};
use rayon::{ThreadPool, prelude::*};
use sha3::{Digest, Sha3_512};
use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

static THREAD_POOL: OnceLock<ThreadPool> = OnceLock::new();
static KEY_CACHE_MAP: OnceLock<RwLock<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>> = OnceLock::new();

fn choose_key(nonce: &[u8], key: &[u8], config: &Config) -> Vec<u8> {
    match config.key_length {
        KeyLength::Key256 => blake3::hash(&[nonce, key].concat()).as_bytes().to_vec(),
        KeyLength::Key512 => {
            let mut hash = Sha3_512::new();
            hash.update(nonce);
            hash.update(key);
            hash.finalize().to_vec()
        }
    }
}

fn get_thread_pool(thread_num: usize) -> &'static ThreadPool {
    THREAD_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_num)
            .build()
            .expect("Failed to build thread pool")
    })
}

fn key_cache(nonce: &[u8], key: &[u8], config: &Config) -> Vec<u8> {
    let cache = KEY_CACHE_MAP.get_or_init(|| RwLock::new(HashMap::new()));
    let key_pair = (nonce.to_vec(), key.to_vec());

    {
        let map = cache.read().unwrap();
        if let Some(value) = map.get(&key_pair) {
            return value.clone();
        }
    }

    let value = choose_key(nonce, key, config);

    let mut map = cache.write().unwrap();
    map.insert(key_pair, value.clone());

    value
}

pub struct GaloisField {
    mul_table: [[u8; 256]; 256],
    inv_table: [u8; 256],
    irreducible_poly: u8,
}

impl GaloisField {
    pub fn new(irreducible_poly: u8) -> Self {
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

    fn inverse(&self, a: u8) -> Option<u8> {
        if a == 0 {
            None
        } else {
            Some(self.inv_table[a as usize])
        }
    }
}

pub fn parallel_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()]; // içi dolu olsun

    let size = data.len() as usize;
    output
        .par_chunks_mut(dynamic_sizes(size) as usize)
        .zip(data.par_chunks(dynamic_sizes(size) as usize))
        .for_each(|(out_chunk, in_chunk)| {
            for (i, &byte) in in_chunk.iter().enumerate() {
                out_chunk[i] = byte ^ key[i % key.len()];
            }
        });

    output
}

pub fn triangle_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let mut dummy_vec;
    let data: &mut [u8] = if data.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        data
    };

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::random_range(0..1048576) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_num);

    pool.install(|| {
        data.par_chunks_exact_mut(3).for_each(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            let c = chunk[2];

            chunk[0] = gf.fast_multiply(3, a) ^ gf.fast_multiply(2, b) ^ c;
            chunk[1] = gf.fast_multiply(4, b) ^ c;
            chunk[2] = gf.fast_multiply(5, c);
        })
    });

    Ok(data.to_vec())
}

pub fn inverse_triangle_mix_columns(
    data: &mut [u8],
    gf: &GaloisField,
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let mut dummy_vec;
    let data: &mut [u8] = if data.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        data
    };

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::random_range(0..1048576) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_num);

    pool.install(|| {
        data.par_chunks_exact_mut(3).for_each(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            let c = chunk[2];

            let inv_5 = gf.inverse(5).unwrap_or(1);
            let c_prime = gf.fast_multiply(inv_5, c);

            let inv_4 = gf.inverse(4).unwrap_or(1);
            let b_prime = gf.fast_multiply(inv_4, b ^ gf.fast_multiply(1, c_prime));

            let inv_3 = gf.inverse(3).unwrap_or(1);
            let a_prime = gf.fast_multiply(inv_3, a ^ gf.fast_multiply(2, b_prime) ^ c_prime);

            chunk[0] = a_prime;
            chunk[1] = b_prime;
            chunk[2] = c_prime;
        })
    });

    Ok(data.to_vec())
}

pub fn xor_encrypt(nonce: &[u8], pwd: &[u8], input: &mut [u8]) -> Result<Vec<u8>, Errors> {
    let mut dummy_vec;
    let input: &mut [u8] = if input.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        input
    };

    let out = input
        .into_par_iter()
        .enumerate()
        .map(|(i, b)| {
            let mut masked =
                b.rotate_left((nonce[i % nonce.len()] ^ pwd[i % pwd.len()] % 8) as u32); // Rotate the byte left by the nonce value

            masked = masked.wrapping_add(pwd[i % pwd.len()]); // Add the password to the byte
            masked = masked.wrapping_add(nonce[i % nonce.len()]); // Add the nonce to the byte

            masked
        })
        .collect::<Vec<u8>>();

    let key = parallel_xor(nonce, pwd);
    let out = parallel_xor(&out, &key);

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())),
        false => Ok(out),
    }
}

pub fn xor_decrypt(nonce: &[u8], pwd: &[u8], input: &mut [u8]) -> Result<Vec<u8>, Errors> {
    let mut dummy_vec;
    let input: &mut [u8] = if input.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        input
    };

    let key = parallel_xor(nonce, pwd);
    let input = parallel_xor(&input, &key);

    let out = input
        .into_par_iter()
        .enumerate()
        .map(|(i, b)| {
            let masked = b.wrapping_sub(nonce[i % nonce.len()]); // Subtract the nonce from the byte
            let masked = masked.wrapping_sub(pwd[i % pwd.len()]); // Subtract the password from the byte

            let masked =
                masked.rotate_right((nonce[i % nonce.len()] ^ pwd[i % pwd.len()] % 8) as u32); // Rotate the byte right by the nonce value

            masked
        })
        .collect::<Vec<u8>>();

    match out.is_empty() {
        true => return Err(Errors::InvalidXor("Empty vector".to_string())), // If out vector is empty then returns an Error
        false => Ok(out),
    }
}

pub fn mix_blocks(
    data: &mut [u8],
    nonce: &[u8],
    pwd: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let key = key_cache(nonce, pwd, &config);

    let mut dummy_vec;
    let data: &mut [u8] = if data.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        data
    };

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::random_range(0..1048576) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_num);

    if data.len().ct_eq(&3).unwrap_u8() == 1 {
        return Ok(data.to_vec()); // If data len <
    }

    let pool = pool.install(|| {
        let chunk_size = dynamic_sizes(data.len()) as usize;

        data.par_chunks_mut(chunk_size)
            .enumerate()
            .flat_map(|(chunk_index, chunk)| {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(i, &byte)| {
                        let global_index = chunk_index * chunk_size + i;
                        let n = key[global_index % key.len()];
                        let mut byte = byte;
                        byte = byte.wrapping_add(n);
                        byte = byte.rotate_right((n % 8) as u32);
                        byte ^= n;
                        byte = byte.wrapping_add(n);
                        byte
                    })
                    .collect::<Vec<u8>>()
            })
            .collect::<Vec<u8>>()
    });

    Ok(pool)
}

pub fn unmix_blocks(
    data: &mut [u8],
    nonce: &[u8],
    pwd: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let key = key_cache(nonce, pwd, &config);

    let mut dummy_vec;
    let data: &mut [u8] = if data.is_empty() {
        dummy_vec = (0..7642).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        &mut dummy_vec
    } else {
        data
    };

    let mut dummy_data: Vec<u8> = Vec::new();

    match config.dummy_data {
        true => {
            for _i in 0..rand::random_range(0..1048576) {
                dummy_data.push(rand::random::<u8>());
            }
        }
        false => {}
    }

    let pool = get_thread_pool(config.thread_num);

    if data.len().ct_eq(&3).unwrap_u8() == 1 {
        return Ok(data.to_vec());
    }

    let pool = pool.install(|| {
        let chunk_size = dynamic_sizes(data.len()) as usize;

        data.par_chunks_mut(chunk_size)
            .enumerate()
            .flat_map(|(chunk_index, chunk)| {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(i, &byte)| {
                        let global_index = chunk_index * chunk_size + i;
                        let n = key[global_index % key.len()];
                        let mut byte = byte;
                        byte = byte.wrapping_sub(n);
                        byte ^= n;
                        byte = byte.rotate_left((n % 8) as u32);
                        byte = byte.wrapping_sub(n);
                        byte
                    })
                    .collect::<Vec<u8>>()
            })
            .collect::<Vec<u8>>()
    });

    Ok(pool)
}

fn generate_inv_s_box(s_box: &[u8; 256]) -> [u8; 256] {
    let mut inv_s_box = [0u8; 256];
    for (i, &val) in s_box.iter().enumerate() {
        // Iterate over the s_box
        inv_s_box[val as usize] = i as u8; // Inverse the s_box
    }

    inv_s_box
}

pub fn generate_dynamic_sbox(nonce: &[u8], key: &[u8], cfg: Config) -> [u8; 256] {
    let mut sbox: [u8; 256] = [0; 256];
    for i in 0..256 {
        sbox[i] = i as u8;
    }

    let seed_base = key_cache(nonce, key, &cfg);
    let seed = match cfg.sbox {
        SboxTypes::PasswordBased => blake3::hash(&[key].concat()).as_bytes().to_vec(),
        SboxTypes::NonceBased => blake3::hash(&[nonce].concat()).as_bytes().to_vec(),
        SboxTypes::PasswordAndNonceBased => seed_base.clone(),
    };

    for i in (1..256).rev() {
        let index = (seed[i % seed.len()] as usize + seed[(i * 7) % seed.len()] as usize) % (i + 1); // Generate a random index
        sbox.swap(i, index); // Swap the values in the sbox
    }

    sbox
}

pub fn in_s_bytes(data: &[u8], nonce: &[u8], pwd: &[u8], cfg: Config) -> Result<Vec<u8>, Errors> {
    let mut sbox = generate_dynamic_sbox(nonce, pwd, cfg); // Generate the sbox
    let inv_sbox = generate_inv_s_box(&sbox); // Generate the inverse sbox

    sbox.zeroize();

    let pool = get_thread_pool(cfg.thread_num);

    Ok(pool.install(|| data.par_iter().map(|b| inv_sbox[*b as usize]).collect())) // Inverse the sbox
}

pub fn s_bytes(data: &[u8], nonce: &[u8], pwd: &[u8], cfg: Config) -> Result<Vec<u8>, Errors> {
    let sbox = generate_dynamic_sbox(nonce, pwd, cfg); // Generate the sbox
    let pool = get_thread_pool(cfg.thread_num);

    Ok(pool.install(|| data.par_iter().map(|b| sbox[*b as usize]).collect())) // Apply the sbox
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

// TODO: Better chunk generation
pub fn get_chunk_sizes(data_len: usize, nonce: &[u8], key: &[u8], config: Config) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut pos = 0;
    let seed = key_cache(nonce, key, &config);

    let data_size = dynamic_sizes(data_len) as usize;

    while pos < data_len {
        let size = data_size + (seed[pos % seed.len()] as usize % 8); // Generate a random size for the chunk via Pos % Seed Lenght
        sizes.push(size.min(data_len - pos)); // Prevents code from unexpected errors and pushing data to sizes Vector
        pos += size;
    }

    sizes
}

pub fn dynamic_shift(
    data: &Vec<u8>,
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let key = key_cache(nonce, password, &config);

    let pool = get_thread_pool(config.thread_num);

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key, config);

    let mut dummy_data: Vec<u8> = Vec::new();

    for _i in 0..rand::random_range(0..1048576) {
        dummy_data.push(rand::random::<u8>());
    }

    let mut shifted = Vec::with_capacity(data.len());
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let mut chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value

        pool.install(|| {
            chunk.par_iter_mut().for_each(|b| {
                *b = b.rotate_left(rotate_by); // Rotate the byte left by the nonce value
            });

            let chunk = parallel_xor(&chunk, &key);

            shifted.par_extend(chunk);
            cursor += size; // Move the cursor to the next chunk
        })
    }

    shifted = shifted.iter().rev().cloned().collect::<Vec<u8>>();
    Ok(shifted)
}

pub fn dynamic_unshift(
    data: &Vec<u8>,
    nonce: &[u8],
    password: &[u8],
    config: Config,
) -> Result<Vec<u8>, Errors> {
    let data = data.iter().rev().cloned().collect::<Vec<u8>>();
    let key = key_cache(nonce, password, &config);

    let pool = get_thread_pool(config.thread_num);

    let chunk_sizes = get_chunk_sizes(data.len(), nonce, &key, config);

    let mut dummy_data: Vec<u8> = Vec::new();

    for _i in 0..rand::random_range(0..1048576) {
        dummy_data.push(rand::random::<u8>());
    }

    let mut original = Vec::with_capacity(data.len());
    let mut cursor = 0;

    for (i, size) in chunk_sizes.iter().enumerate() {
        let chunk = data[cursor..cursor + size].to_vec();

        let rotate_by = (nonce[i % nonce.len()] % 8) as u32; // Rotate the byte left by the nonce value

        pool.install(|| {
            let mut chunk = parallel_xor(&chunk, &key);

            chunk.par_iter_mut().for_each(|b| {
                *b = b.rotate_right(rotate_by); // Rotate the byte right by the nonce value
            });

            original.par_extend(chunk);
            cursor += size; // Move the cursor to the next chunk
        })
    }

    Ok(original)
}
