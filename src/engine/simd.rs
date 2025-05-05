use bytemuck::cast_slice;
use rayon::prelude::*;
use std::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn avx2_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()];
    let chunks = data.par_chunks(32);
    let out_chunks = output.par_chunks_mut(32);

    out_chunks.zip(chunks).into_par_iter().enumerate().for_each(
        |(chunk_index, (out_chunk, in_chunk))| {
            let mut key_block = [0u8; 32];
            for i in 0..in_chunk.len() {
                key_block[i] = key[(chunk_index * 32 + i) % key.len()];
            }

            let mut in_block = [0u8; 32];
            in_block[..in_chunk.len()].copy_from_slice(in_chunk);

            unsafe {
                let data_vec = cast_slice::<u8, __m256i>(&in_block)[0];
                let key_vec = cast_slice::<u8, __m256i>(&key_block)[0];
                let xor_vec = _mm256_xor_si256(data_vec, key_vec);

                let mut out_block = [0u8; 32];
                _mm256_storeu_si256(out_block.as_mut_ptr() as *mut __m256i, xor_vec);
                out_chunk.copy_from_slice(&out_block[..in_chunk.len()]);
            }
        },
    );

    output
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub fn avx2_add(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()];
    let chunks = data.par_chunks(32);
    let out_chunks = output.par_chunks_mut(32);

    out_chunks.zip(chunks).into_par_iter().enumerate().for_each(
        |(chunk_index, (out_chunk, in_chunk))| {
            let mut key_block = [0u8; 32];
            for i in 0..in_chunk.len() {
                key_block[i] = key[(chunk_index * 32 + i) % key.len()];
            }

            let mut in_block = [0u8; 32];
            in_block[..in_chunk.len()].copy_from_slice(in_chunk);

            unsafe {
                let data_vec = cast_slice::<u8, __m256i>(&in_block)[0];
                let key_vec = cast_slice::<u8, __m256i>(&key_block)[0];
                let add_vec = _mm256_add_epi8(data_vec, key_vec);

                let mut out_block = [0u8; 32];
                _mm256_storeu_si256(out_block.as_mut_ptr() as *mut __m256i, add_vec);
                out_chunk.copy_from_slice(&out_block[..in_chunk.len()]);
            }
        },
    );

    output
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub fn avx2_sub(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()];
    let chunks = data.par_chunks(32);
    let out_chunks = output.par_chunks_mut(32);

    out_chunks.zip(chunks).into_par_iter().enumerate().for_each(
        |(chunk_index, (out_chunk, in_chunk))| {
            let mut key_block = [0u8; 32];
            for i in 0..in_chunk.len() {
                key_block[i] = key[(chunk_index * 32 + i) % key.len()];
            }

            let mut in_block = [0u8; 32];
            in_block[..in_chunk.len()].copy_from_slice(in_chunk);

            unsafe {
                let data_vec = cast_slice::<u8, __m256i>(&in_block)[0];
                let key_vec = cast_slice::<u8, __m256i>(&key_block)[0];
                let sub_vec = _mm256_sub_epi8(data_vec, key_vec);

                let mut out_block = [0u8; 32];
                _mm256_storeu_si256(out_block.as_mut_ptr() as *mut __m256i, sub_vec);
                out_chunk.copy_from_slice(&out_block[..in_chunk.len()]);
            }
        },
    );

    output
}
