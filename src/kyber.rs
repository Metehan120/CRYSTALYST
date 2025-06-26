use crate::Errors;
use pqc_kyber::Uake;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct KyberModule {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
    pub uake: Uake,
}

impl KyberModule {
    pub fn new() -> Result<Self, Errors> {
        let key = pqc_kyber::keypair(&mut OsRng).map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok(Self {
            public: key.public.to_vec(),
            secret: key.secret.to_vec(),
            uake: Uake::new(),
        })
    }

    pub fn new_from_existed(
        public: &[u8],
        secret: &[u8],
        uake: Option<Uake>,
    ) -> Result<Self, Errors> {
        if public.len() != Self::PUBLIC_KEY_SIZE || secret.len() != Self::SECRET_KEY_SIZE {
            return Err(Errors::KyberError(format!(
                "Public key must be {} bytes, got {}",
                Self::PUBLIC_KEY_SIZE,
                public.len()
            )));
        }

        let uake = uake.unwrap_or_else(|| Uake::new());

        Ok(Self {
            public: public.to_vec(),
            secret: secret.to_vec(),
            uake: uake,
        })
    }

    pub fn client_init(&mut self, public: Vec<u8>) -> Result<Vec<u8>, Errors> {
        if public.len() != Self::PUBLIC_KEY_SIZE {
            return Err(Errors::KyberError(
                "Public key must be 800 bytes long".to_string(),
            ));
        }
        let mut public_result = [0u8; 800];
        public_result.copy_from_slice(&public);
        Ok(self
            .uake
            .client_init(&public_result, &mut OsRng)
            .map_err(|e| Errors::KyberError(e.to_string()))?
            .to_vec())
    }

    pub fn server_receive(&mut self, send_a: Vec<u8>) -> Result<Vec<u8>, Errors> {
        if send_a.len() != Self::UAKE_SEND_A_SIZE {
            return Err(Errors::KyberError(
                "send_a must be 1568 bytes long".to_string(),
            ));
        }
        let mut send_a_result = [0u8; 1568];
        send_a_result.copy_from_slice(&send_a);
        let mut secret_result = [0u8; 1632];
        secret_result.copy_from_slice(&self.secret);
        Ok(self
            .uake
            .server_receive(send_a_result, &secret_result, &mut OsRng)
            .map_err(|e| Errors::KyberError(e.to_string()))?
            .to_vec())
    }

    pub fn client_confirm(&mut self, server_send: Vec<u8>) -> Result<(), Errors> {
        if server_send.len() != Self::SERVER_SEND_KEY_SIZE {
            return Err(Errors::KyberError(
                "server_send must be 768 bytes long".to_string(),
            ));
        }

        let mut server_end_result = [0u8; 768];
        server_end_result.copy_from_slice(&server_send);

        Ok(self
            .uake
            .client_confirm(server_end_result)
            .map_err(|e| Errors::KyberError(e.to_string()))?)
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), Errors> {
        let (ciphertext, shared_secret) = pqc_kyber::encapsulate(&self.public, &mut OsRng)
            .map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    pub fn decapsulate(&self, cipher: &[u8]) -> Result<Vec<u8>, Errors> {
        let shared_secret = pqc_kyber::decapsulate(cipher, &self.secret)
            .map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok(shared_secret.to_vec())
    }
}

impl KyberModule {
    pub const PUBLIC_KEY_SIZE: usize = 800;
    pub const UAKE_SEND_A_SIZE: usize = 1568;
    pub const SECRET_KEY_SIZE: usize = 1632;
    pub const SHARED_SECRET_SIZE: usize = 32;
    pub const SERVER_SEND_KEY_SIZE: usize = 768;

    pub fn shared_secret(&self) -> [u8; 32] {
        self.uake.shared_secret
    }

    pub fn is_valid(&self) -> bool {
        self.public.len() == Self::PUBLIC_KEY_SIZE && self.secret.len() == Self::SECRET_KEY_SIZE
    }
}

impl Drop for KyberModule {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
