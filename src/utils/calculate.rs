use rand::RngCore;

use crate::Errors;

/// Test suite for Shannon entropy etc.
pub struct Calculate;

impl Calculate {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0usize; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        frequency
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn calculate_bit_balance(data: &[u8]) -> (usize, usize, f64) {
        let mut ones = 0;
        let mut zeros = 0;

        for byte in data {
            ones += byte.count_ones() as usize;
            zeros += byte.count_zeros() as usize;
        }

        let total_bits = ones + zeros;
        let balance = (ones as f64 / total_bits as f64) * 100.0;

        (ones, zeros, balance)
    }

    pub fn calculate_avalanche(data1: &[u8], data2: &[u8]) -> Result<f64, Errors> {
        if data1.len() != data2.len() {
            return Err(Errors::DataError("Data sizes do not match".to_string()));
        }

        let mut changed_bits = 0;
        let total_bits = data1.len() * 8;

        for (byte1, byte2) in data1.iter().zip(data2.iter()) {
            let xor_result = byte1 ^ byte2;
            changed_bits += xor_result.count_ones() as usize;
        }

        Ok((changed_bits as f64 / total_bits as f64) * 100.0)
    }

    pub fn calculate_byte_difference(data1: &[u8], data2: &[u8]) -> f64 {
        let min_len = usize::min(data1.len(), data2.len());
        let max_len = usize::max(data1.len(), data2.len());

        let diff = data1
            .iter()
            .zip(data2.iter())
            .take(min_len)
            .filter(|(a, b)| a != b)
            .count();
        ((diff + (max_len - min_len)) as f64 / max_len as f64) * 100.0
    }

    pub fn generate_random_data(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut out = vec![0u8; size];
        rng.fill_bytes(&mut out);
        out
    }
}
