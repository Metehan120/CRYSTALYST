use rand::{Rng, thread_rng};
use sha3::{Digest, Sha3_256};

use crate::{Errors, Hardware, TpmModule, rng_utils::rng::RNG};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NonceData {
    TaggedNonce([u8; 32]),
    HashedNonce([u8; 32]),
    Nonce([u8; 32]),
    MachineNonce([u8; 32]),
} // Multiple data types for future usage

impl NonceData {
    /// Converts the nonce data into a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            NonceData::Nonce(n)
            | NonceData::HashedNonce(n)
            | NonceData::TaggedNonce(n)
            | NonceData::MachineNonce(n) => n,
        }
    }
    /// Converts the nonce data into a vector of bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            NonceData::Nonce(n)
            | NonceData::HashedNonce(n)
            | NonceData::TaggedNonce(n)
            | NonceData::MachineNonce(n) => n.to_vec(),
        }
    }
}

/// Converts bytes or vector of bytes into a NonceData.
pub trait AsNonce {
    fn as_nonce(&self) -> NonceData;
    fn as_nonce_safe(&self) -> Result<NonceData, String>;
}

fn slice_to_nonce(input: &[u8]) -> Result<NonceData, String> {
    if input.len() != 32 {
        Err("Nonce length must be 32 bytes".to_string())
    } else {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(input);
        Ok(NonceData::Nonce(arr))
    }
}

/// Converts the bytes into a nonce data.
impl AsNonce for [u8] {
    fn as_nonce(&self) -> NonceData {
        slice_to_nonce(self).expect("Nonce length must be 32 bytes")
    }

    fn as_nonce_safe(&self) -> Result<NonceData, String> {
        slice_to_nonce(self)
    }
}

/// Converts the bytes vector into a nonce data.
impl AsNonce for Vec<u8> {
    fn as_nonce(&self) -> NonceData {
        slice_to_nonce(self).expect("Nonce length must be 32 bytes")
    }

    fn as_nonce_safe(&self) -> Result<NonceData, String> {
        slice_to_nonce(self)
    }
}

pub struct Nonce;

/// Nonce Types
/// - Classic: Generates a random nonce.
/// - Hashed: Generates a hashed nonce.
/// - Tagged: Generates a tagged nonce.
/// - Machine: Generates a machine-specific nonce.
/// - TPM: Generates a nonce using a Trusted Platform Module.
///
/// # ⚠️ WARNING: YOU HAVE TO USE SUDO/ADMIN PRIVILEGES TO GENERATE A TPM NONCE.
///
/// ## Platform Requirements:
/// - **Linux:** `sudo your_app` or run as root
/// - **Windows:** Run as Administrator
/// - **macOS:** `sudo your_app` (if TPM available)
///
/// ## Why Admin Access is Required:
/// - Direct hardware access to TPM chip
/// - Security isolation from unprivileged processes
/// - Compliance with TPM security model
///
/// ## Fallback Strategy:
/// ```rust
/// let nonce = match Nonce::generate_nonce(None, NonceType::TPM(hardware, tpm)) {
///     Ok(hw_nonce) => hw_nonce,
///     Err(_) => {
///         eprintln!("TPM access failed, falling back to software nonce");
///         Nonce::generate_nonce(Some(rng), NonceType::Hashed)?
///     }
/// };
/// ```
pub enum NonceType {
    Classic,
    Hashed,
    Tagged(String),
    #[cfg(feature = "base_coding")]
    Machine,
    Tpm(Hardware, TpmModule, tss_esapi::Context),
}

impl Nonce {
    pub fn generate_nonce(rng: Option<RNG>, nonce_type: NonceType) -> Result<NonceData, Errors> {
        match nonce_type {
            NonceType::Classic => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::nonce(rng))
            }
            NonceType::Hashed => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::hashed_nonce(rng))
            }
            NonceType::Tagged(tag) => {
                let rng = rng.ok_or(Errors::RngRequired)?;
                Ok(Nonce::tagged_nonce(rng, &tag.as_bytes()))
            }
            #[cfg(feature = "base_coding")]
            NonceType::Machine => Ok(Nonce::machine_nonce(rng)),
            NonceType::Tpm(hardware, mut manager, mut tpm) => {
                Nonce::tpm_nonce(hardware, &mut manager, &mut tpm)
            }
        }
    }

    fn hashed_nonce(rng: RNG) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = thread_rng().gen_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            let mut out = [0u8; 32];
            let mut hash = Sha3_256::new();
            hash.update(&mix);
            out.copy_from_slice(hash.finalize().to_vec().as_slice());
            nonce = out;
        }

        NonceData::HashedNonce(nonce)
    }

    fn tagged_nonce(rng: RNG, tag: &[u8]) -> NonceData {
        let mut nonce = *rng.as_bytes();
        let number: u8 = thread_rng().gen_range(0..255);

        for i in 0..=number {
            let mut mix = nonce.to_vec();
            mix.push(i as u8);
            let mut out = [0u8; 32];
            let mut hash = Sha3_256::new();
            hash.update(&mix);
            out.copy_from_slice(hash.finalize().to_vec().as_slice());
            nonce = out;
        }

        let mut output = [0u8; 32];
        let mut hash = Sha3_256::new();
        hash.update(nonce);
        hash.update(tag);
        let out = hash.finalize().to_vec();
        output.copy_from_slice(&out);

        NonceData::TaggedNonce(output) // Hash the nonce to get a 32 byte more random nonce (Extra Security)
    }

    #[cfg(feature = "base_coding")]
    fn machine_nonce(rng: Option<RNG>) -> NonceData {
        let user_name = whoami::username();
        let device_name = whoami::devicename();
        let real_name = whoami::realname();
        let distro = whoami::distro();

        let mut all_data = Vec::new();

        all_data.extend_from_slice(user_name.as_bytes());
        all_data.extend_from_slice(device_name.as_bytes());
        all_data.extend_from_slice(real_name.as_bytes());
        all_data.extend_from_slice(distro.as_bytes());

        if let Some(rng) = rng {
            all_data.extend_from_slice(rng.as_bytes());
        }

        let mut out = [0u8; 32];
        let mut hash = Sha3_256::new();
        hash.update(&all_data);
        let hash = hash.finalize().to_vec();
        out.copy_from_slice(hash.as_slice());

        NonceData::MachineNonce(out)
    }

    fn nonce(rng: RNG) -> NonceData {
        let nonce = *rng.as_bytes();
        let number: u8 = thread_rng().gen_range(0..255);

        let new_nonce_vec = nonce
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let add = (rng.as_bytes()[i % rng.as_bytes().len()] as usize) % (i + 1);
                let add = add as u8;
                b.wrapping_add(add.wrapping_add(number))
            })
            .collect::<Vec<u8>>();

        let mut new_nonce = [0u8; 32];
        new_nonce.copy_from_slice(&new_nonce_vec[..32]);

        NonceData::Nonce(new_nonce)
    }

    fn tpm_nonce(
        hardware: Hardware,
        manager: &mut TpmModule,
        tpm: &mut tss_esapi::Context,
    ) -> Result<NonceData, Errors> {
        manager.generate_nonce(tpm, hardware)
    }
}
