use std::hint::black_box;
use zeroize::Zeroize;

#[cfg(target_arch = "x86_64")]
#[repr(align(64))]
#[repr(C)]
pub struct CacheWarmup64 {
    pub key: [u8; 64],
    pub sbox: [u8; 256],
    pub inv_sbox: [u8; 256],
}

#[cfg(target_arch = "aarch64")]
#[repr(align(128))]
#[repr(C)]
pub struct CacheWarmup64 {
    pub key: [u8; 64],
    pub sbox: [u8; 256],
    pub inv_sbox: [u8; 256],
}

impl CacheWarmup64 {
    pub fn new(key: [u8; 64], sbox: [u8; 256], inv_sbox: [u8; 256]) -> Self {
        Self {
            key,
            sbox,
            inv_sbox,
        }
    }
}

impl Drop for CacheWarmup64 {
    fn drop(&mut self) {
        self.inv_sbox.zeroize();
        self.key.zeroize();
        self.sbox.zeroize();
    }
}

pub trait CacheWarmup {
    fn warm_cache(&self);
    fn cache_time_lookup(&self, key: u8) -> u8;
    fn cache_inverse_lookup(&self, value: u8) -> u8;
    fn cache_key_lookup(&self, key: u8) -> u8;
    fn pre_sbox_warmup(&self);
}

#[cfg(target_arch = "x86_64")]
impl CacheWarmup for CacheWarmup64 {
    #[inline(always)]
    fn warm_cache(&self) {
        use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};

        unsafe {
            _mm_prefetch(self.key.as_ptr() as *const i8, _MM_HINT_T0);

            for i in (0..256).step_by(64) {
                _mm_prefetch(self.sbox.as_ptr().add(i) as *const i8, _MM_HINT_T0);
                _mm_prefetch(self.inv_sbox.as_ptr().add(i) as *const i8, _MM_HINT_T0);
            }
        }
    }

    #[inline(always)]
    fn pre_sbox_warmup(&self) {
        use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};

        unsafe {
            for i in (0..256).step_by(64) {
                _mm_prefetch(self.sbox.as_ptr().add(i) as *const i8, _MM_HINT_T0);
                _mm_prefetch(self.inv_sbox.as_ptr().add(i) as *const i8, _MM_HINT_T0);
            }
        }
    }

    #[inline(always)]
    fn cache_time_lookup(&self, value: u8) -> u8 {
        black_box(self.sbox[value as usize])
    }

    #[inline(always)]
    fn cache_inverse_lookup(&self, value: u8) -> u8 {
        black_box(self.inv_sbox[value as usize])
    }

    #[inline(always)]
    fn cache_key_lookup(&self, key: u8) -> u8 {
        black_box(self.key[(key as usize) % 64])
    }
}

#[cfg(target_arch = "aarch64")]
impl CacheWarmup for CacheWarmup64 {
    #[inline(always)]
    fn warm_cache(&self) {
        unsafe {
            core::ptr::read_volatile(&self.key[0]);

            for i in (0..256).step_by(128) {
                core::ptr::read_volatile(&self.sbox[i]);
                core::ptr::read_volatile(&self.inv_sbox[i]);
            }
        }
    }

    #[inline(always)]
    fn pre_sbox_warmup(&self) {
        unsafe {
            for i in (0..256).step_by(128) {
                core::ptr::read_volatile(&self.sbox[i]);
                core::ptr::read_volatile(&self.inv_sbox[i]);
            }
        }
    }

    #[inline(always)]
    fn cache_time_lookup(&self, value: u8) -> u8 {
        black_box(self.sbox[value as usize])
    }

    #[inline(always)]
    fn cache_inverse_lookup(&self, value: u8) -> u8 {
        black_box(self.inv_sbox[value as usize])
    }

    #[inline(always)]
    fn cache_key_lookup(&self, key: u8) -> u8 {
        black_box(self.key[(key as usize) % 64])
    }
}
