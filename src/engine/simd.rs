use rayon::prelude::*;
use std::arch::x86_64::*;

use crate::{
    Config,
    engine::{cache_warmup::CacheWarmup64, engine::key_lookup},
};

#[target_feature(enable = "avx2")]
pub unsafe fn avx2_xor_inplace(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    let remainder_len = data.len() % 32;
    let chunks = data.par_chunks_exact_mut(32);

    chunks.enumerate().for_each(|(chunk_index, chunk)| {
        let mut key_block = [0u8; 32];
        let key_start = (chunk_index * 32) % 64;

        match key_start + 32 <= 64 {
            true => {
                key_block.copy_from_slice(&key.key[key_start..key_start + 32]);
            }
            false => {
                let first_part = 64 - key_start;
                key_block[..first_part].copy_from_slice(&key.key[key_start..]);
                key_block[first_part..].copy_from_slice(&key.key[..32 - first_part]);
            }
        };

        unsafe {
            let data_vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let key_vec = _mm256_loadu_si256(key_block.as_ptr() as *const __m256i);
            let xor_vec = _mm256_xor_si256(data_vec, key_vec);

            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, xor_vec);
        }
    });

    if remainder_len != 0 {
        let start = data.len() - remainder_len;
        data[start..].par_iter_mut().enumerate().for_each(|(i, b)| {
            *b ^= key_lookup(key, (start + i) as u8, config);
        });
    }
}

#[target_feature(enable = "avx2")]
pub unsafe fn avx2_add_inplace(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    let remainder_len = data.len() % 32;
    let chunks = data.par_chunks_exact_mut(32);

    chunks.enumerate().for_each(|(chunk_index, chunk)| {
        let mut key_block = [0u8; 32];
        let key_start = (chunk_index * 32) % 64;

        match key_start + 32 <= 64 {
            true => {
                key_block.copy_from_slice(&key.key[key_start..key_start + 32]);
            }
            false => {
                let first_part = 64 - key_start;
                key_block[..first_part].copy_from_slice(&key.key[key_start..]);
                key_block[first_part..].copy_from_slice(&key.key[..32 - first_part]);
            }
        };

        unsafe {
            let data_vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let key_vec = _mm256_loadu_si256(key_block.as_ptr() as *const __m256i);
            let add_vec = _mm256_add_epi8(data_vec, key_vec);

            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, add_vec);
        }
    });

    if remainder_len != 0 {
        let start = data.len() - remainder_len;
        data[start..]
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = b.wrapping_add(key_lookup(key, (start + i) as u8, config)));
    }
}

#[target_feature(enable = "avx2")]
pub unsafe fn avx2_sub_inplace(data: &mut [u8], key: &CacheWarmup64, config: &Config) {
    let remainder_len = data.len() % 32;
    let chunks = data.par_chunks_exact_mut(32);

    chunks.enumerate().for_each(|(chunk_index, chunk)| {
        let mut key_block = [0u8; 32];
        let key_start = (chunk_index * 32) % 64;

        match key_start + 32 <= 64 {
            true => {
                key_block.copy_from_slice(&key.key[key_start..key_start + 32]);
            }
            false => {
                let first_part = 64 - key_start;
                key_block[..first_part].copy_from_slice(&key.key[key_start..]);
                key_block[first_part..].copy_from_slice(&key.key[..32 - first_part]);
            }
        };

        unsafe {
            let data_vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let key_vec = _mm256_loadu_si256(key_block.as_ptr() as *const __m256i);
            let sub_vec = _mm256_sub_epi8(data_vec, key_vec);

            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, sub_vec);
        }
    });

    if remainder_len != 0 {
        let start = data.len() - remainder_len;
        data[start..]
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = b.wrapping_sub(key_lookup(key, (start + i) as u8, config)));
    }
}
