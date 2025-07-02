use rand::RngCore;
use rand_core::OsRng;
#[cfg(feature = "machine_rng")]
use sha3::{Digest, Sha3_256};

#[cfg(feature = "machine_rng")]
use crate::AsBase;

/// Generates a random nonce using the operating system's random number generator.
pub enum RNG {
    OsRngNonce([u8; 32]),
    TaggedOsRngNonce([u8; 32]),
    ThreadRngNonce([u8; 32]),
}

impl RNG {
    /// Generates a random nonce using the machine's random number generator.
    pub fn thread_rng() -> Self {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self::ThreadRngNonce(nonce)
    }

    /// Generates a random nonce using the operating system's random number generator.
    pub fn osrng() -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Self::OsRngNonce(nonce)
    }

    /// Generates a random nonce using the operating system's random number generator, with a tag.
    pub fn tagged_osrng(tag: &[u8]) -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let new_nonce: Vec<u8> = nonce
            .iter()
            .enumerate()
            .map(|(i, b)| b.wrapping_add(tag[i % tag.len()] ^ i as u8))
            .collect();

        let mut final_nonce = [0u8; 32];
        final_nonce.copy_from_slice(&new_nonce[..32]);

        Self::TaggedOsRngNonce(final_nonce)
    }

    /// Returns the RNG as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match &self {
            Self::OsRngNonce(a) | Self::TaggedOsRngNonce(a) | Self::ThreadRngNonce(a) => a,
        }
    }

    /// Returns the RNG as a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Generates a unique identifier based on the machine's configuration.
#[cfg(feature = "machine_rng")]
pub trait MachineRng {
    fn machine_rng(&self, distro_lock: bool) -> String;
}

/// Generates a unique identifier based on the machine's configuration.
/// Heads up:
/// If you're migrating from version 2.2 or used machine_rng with distribution lock enabled,
/// make sure to decrypt your data before changing or reinstalling your OS.
/// The OS distribution is a part of the key derivation process when distro_lock is set to true.
/// Failing to do so may permanently prevent access to your encrypted data.
#[cfg(feature = "machine_rng")]
impl MachineRng for str {
    fn machine_rng(&self, distro_lock: bool) -> String {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();

        let mut data = Vec::new();
        data.extend_from_slice(user_name.as_bytes());
        data.extend_from_slice(device_name.as_bytes());
        data.extend_from_slice(real_name.as_bytes());
        if distro_lock == true {
            let distro = whoami::distro();
            data.extend_from_slice(distro.as_bytes());
        }
        data.extend_from_slice(self.as_bytes());

        let mut hash = Sha3_256::new();
        hash.update(&data);
        let hash = hash.finalize();
        hash.to_vec().as_base64()
    }
}
