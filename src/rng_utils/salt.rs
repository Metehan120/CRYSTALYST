use crate::{Errors, Hardware, TpmModule, rng_utils::rng::RNG};

/// Generator for a new salt
/// - You can save this salt to a file or database, or you can add directly to encrypted data.
///
/// /// ⚠️ Warning:
/// If you lose this salt, decryption will fail. Keep it safe like your password.
#[derive(Debug, Copy, Clone)]
pub enum Salt {
    Salt([u8; 32]),
}

impl Salt {
    /// Generate a new salt
    /// Generates a new salt using a combination of random bytes from the thread and OS random number generators.
    /// - You have to save this salt to a file or database, or you can add directly to encrypted data.
    pub fn salt() -> Self {
        let rng = *RNG::thread_rng().as_bytes();
        let mix_rng = *RNG::osrng().as_bytes();
        let hash_rng = vec![rng, mix_rng].concat();
        let mut out = Vec::new();

        for (i, b) in hash_rng.iter().enumerate() {
            let b = *b;
            let add = (mix_rng[i % mix_rng.len()] as usize) % (i + 1);
            let add = add as u8;
            let new_b = b.wrapping_add(add.wrapping_add(rng[i % rng.len()] % 8));
            out.push(new_b);
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&out[..32]);

        Salt::Salt(salt)
    }

    pub fn tpm_salt(
        hardware: Hardware,
        manager: TpmModule,
        tpm: &mut tss_esapi::Context,
    ) -> Result<Self, Errors> {
        let nonce = manager.generate_nonce(tpm, hardware)?.to_vec();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&nonce[..32]);
        Ok(Salt::Salt(salt))
    }

    /// Returns the salt as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Salt::Salt(bytes) => bytes,
        }
    }

    /// Returns the salt as a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Returns vector or byte slice as a salt data.
/// You can use this to turn a vector or byte slice into a salt.
pub trait AsSalt {
    fn as_salt(&self) -> Salt;
    fn as_salt_safe(&self) -> Result<Salt, String>;
}

impl AsSalt for &[u8] {
    fn as_salt(&self) -> Salt {
        assert!(self.len() == 32, "Salt input must be exactly 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self[..32]);
        Salt::Salt(arr)
    }

    fn as_salt_safe(&self) -> Result<Salt, String> {
        if self.len() != 32 {
            Err("Salt input must be exactly 32 bytes".to_string())
        } else {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self[..32]);
            Ok(Salt::Salt(arr))
        }
    }
}
