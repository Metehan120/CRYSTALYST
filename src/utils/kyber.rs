//! # Kyber Post-Quantum Cryptography Module
//!
//! This module provides a safe wrapper around the Kyber post-quantum key encapsulation mechanism (KEM).
//! It implements both basic KEM operations and the Unilaterally Authenticated Key Exchange (UAKE) protocol.
//!
//! ## Features
//! - Post-quantum secure key encapsulation
//! - Unilaterally authenticated key exchange
//! - Memory-safe secret handling using `secrecy` crate
//! - Support for both fresh key generation and importing existing keys
//!
//! ## Example Usage
//!
//! ### Basic Key Encapsulation
//! ```rust
//! use crystalyst_rs::KyberModule;
//!
//! // Generate a new Kyber keypair
//! let alice = KyberModule::new()?;
//! let bob = KyberModule::new()?;
//!
//! // Alice encapsulates a secret using Bob's public key
//! let (shared_secret, ciphertext) = alice.encapsulate()?;
//!
//! // Bob decapsulates to get the same shared secret
//! let bob_secret = bob.decapsulate(&ciphertext)?;
//! ```
//!
//! ### UAKE Protocol
//! ```rust
//! let mut client = KyberModule::new()?;
//! let mut server = KyberModule::new()?;
//!
//! // Step 1: Client initiates
//! let send_a = client.client_init(server.public)?;
//!
//! // Step 2: Server responds
//! let server_send = server.server_receive(send_a)?;
//!
//! // Step 3: Client confirms
//! client.client_confirm(server_send)?;
//!
//! // Both parties now have shared secret
//! let client_secret = client.shared_secret();
//! let server_secret = server.shared_secret();
//! ```
#[cfg(feature = "kyber")]
use crate::Errors;
#[cfg(feature = "kyber")]
use pqc_kyber::Uake;
#[cfg(feature = "kyber")]
use rand::rngs::OsRng;
#[cfg(feature = "kyber")]
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

#[cfg(feature = "kyber")]
/// A securely wrapped shared secret derived from Kyber operations.
///
/// The secret is stored in a `SecretBox` to prevent accidental exposure
/// and ensure it's properly zeroized when dropped.
pub struct SharedSecret(SecretBox<[u8]>);

#[cfg(feature = "kyber")]
/// Kyber ciphertext used for key encapsulation transport.
///
/// This contains the encapsulated key material that can be sent over
/// an insecure channel to the recipient.
pub struct KyberCipherText(Vec<u8>);

#[cfg(feature = "kyber")]
/// Kyber public key for key encapsulation.
///
/// This is safe to share publicly and is used by others to encapsulate
/// secrets that only the corresponding private key holder can decrypt.
pub struct KyberPublicKey(Vec<u8>);

#[cfg(feature = "kyber")]
/// Kyber private key stored securely.
///
/// The private key is wrapped in a `SecretBox` to prevent accidental
/// exposure and ensure secure memory handling.
pub struct KyberPrivateKey(SecretBox<[u8]>);

#[cfg(feature = "kyber")]
impl KyberPublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// # Arguments
    /// * `public` - Raw public key bytes (should be 800 bytes for Kyber)
    pub fn new(public: Vec<u8>) -> Self {
        Self(public)
    }

    /// Returns the public key as a byte slice.
    ///
    /// This is safe to expose as public keys are meant to be shared.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "kyber")]
impl KyberPrivateKey {
    /// Creates a new private key from raw bytes.
    ///
    /// The key material is immediately wrapped in a `SecretBox` for security.
    ///
    /// # Arguments
    /// * `secret` - Raw private key bytes (should be 1632 bytes for Kyber)
    pub fn new(secret: Vec<u8>) -> Self {
        Self(SecretBox::new(secret.into_boxed_slice()))
    }

    /// Exposes the secret key bytes.
    ///
    /// ⚠️ **Warning**: This exposes sensitive key material. Use with caution
    /// and ensure the returned slice is not copied unnecessarily.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0.expose_secret()
    }
}

#[cfg(feature = "kyber")]
impl SharedSecret {
    /// Creates a new shared secret from raw bytes.
    ///
    /// The secret is immediately wrapped in a `SecretBox` for security.
    ///
    /// # Arguments
    /// * `secret` - Raw secret bytes (typically 32 bytes for Kyber)
    pub fn new(secret: Vec<u8>) -> Self {
        Self(SecretBox::new(secret.into_boxed_slice()))
    }

    /// Exposes the shared secret bytes.
    ///
    /// ⚠️ **Warning**: This exposes sensitive cryptographic material.
    /// Use immediately for key derivation and avoid storing the result.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0.expose_secret()
    }
}

#[cfg(feature = "kyber")]
impl KyberCipherText {
    /// Creates a new ciphertext from raw bytes.
    ///
    /// # Arguments
    /// * `ciphertext` - Encapsulated key material
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self(ciphertext)
    }

    /// Returns the ciphertext as a byte slice.
    ///
    /// This is safe to expose as ciphertext is meant to be transmitted.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "kyber")]
/// Main Kyber cryptographic module supporting both KEM and UAKE operations.
///
/// This struct maintains a Kyber keypair and UAKE state for performing
/// post-quantum secure key exchanges. All sensitive material is stored
/// in `SecretBox` wrappers for memory safety.
///
/// # Thread Safety
/// This struct is not thread-safe due to mutable UAKE state. Create separate
/// instances for concurrent operations.
pub struct KyberModule {
    /// The public key component of the Kyber keypair
    pub public: KyberPublicKey,
    /// The private key component, securely wrapped
    pub secret: KyberPrivateKey,
    /// UAKE protocol state, securely wrapped
    pub uake: SecretBox<Uake>,
}

#[cfg(feature = "kyber")]
impl KyberModule {
    /// Standard Kyber public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 800;
    /// Size of UAKE client initial message in bytes
    pub const UAKE_SEND_A_SIZE: usize = 1568;
    /// Standard Kyber private key size in bytes
    pub const SECRET_KEY_SIZE: usize = 1632;
    /// Size of derived shared secret in bytes
    pub const SHARED_SECRET_SIZE: usize = 32;
    /// Size of UAKE server response in bytes
    pub const SERVER_SEND_KEY_SIZE: usize = 768;

    /// Creates a new Kyber module with a freshly generated keypair.
    ///
    /// This generates a new random Kyber keypair using the system's
    /// cryptographically secure random number generator.
    ///
    /// # Returns
    /// * `Ok(KyberModule)` - Successfully created module with new keypair
    /// * `Err(Errors)` - Key generation failed
    ///
    /// # Example
    /// ```rust
    /// let kyber = KyberModule::new()?;
    /// assert!(kyber.is_valid());
    /// ```
    pub fn new() -> Result<Self, Errors> {
        let key = pqc_kyber::keypair(&mut OsRng).map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok(Self {
            public: KyberPublicKey::new(key.public.to_vec()),
            secret: KyberPrivateKey::new(key.secret.to_vec()),
            uake: SecretBox::new(Box::new(Uake::new())),
        })
    }

    /// Creates a Kyber module from existing key material.
    ///
    /// This is useful for restoring a keypair from storage or using
    /// keys generated elsewhere. The UAKE state is always initialized fresh.
    ///
    /// # Arguments
    /// * `public` - Public key bytes (must be exactly 800 bytes)
    /// * `secret` - Private key bytes (must be exactly 1632 bytes)
    /// * `uake` - Optional existing UAKE state, creates new if None
    ///
    /// # Returns
    /// * `Ok(KyberModule)` - Successfully created module
    /// * `Err(Errors)` - Invalid key sizes or creation failed
    ///
    /// # Example
    /// ```rust
    /// let public_bytes = [0u8; 800]; // Your actual public key
    /// let secret_bytes = [0u8; 1632]; // Your actual private key
    /// let kyber = KyberModule::new_from_existed(&public_bytes, &secret_bytes, None)?;
    /// ```
    pub fn new_from_existed(
        public: &[u8],
        secret: &[u8],
        uake: Option<Uake>,
    ) -> Result<Self, Errors> {
        if public.len() != Self::PUBLIC_KEY_SIZE || secret.len() != Self::SECRET_KEY_SIZE {
            return Err(Errors::KyberError(format!(
                "Invalid key sizes: public must be {} bytes (got {}), secret must be {} bytes (got {})",
                Self::PUBLIC_KEY_SIZE,
                public.len(),
                Self::SECRET_KEY_SIZE,
                secret.len()
            )));
        }

        let uake = uake.unwrap_or_else(|| Uake::new());

        Ok(Self {
            public: KyberPublicKey(public.to_vec()),
            secret: KyberPrivateKey(SecretBox::new(secret.to_vec().into_boxed_slice())),
            uake: SecretBox::new(Box::new(uake)),
        })
    }

    /// Initiates UAKE protocol as a client.
    ///
    /// This is the first step in the UAKE protocol where the client
    /// sends an initial message to the server using the server's public key.
    ///
    /// # Arguments
    /// * `public` - Server's public key for the exchange
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Client's initial message (1568 bytes) to send to server
    /// * `Err(Errors)` - Invalid public key size or protocol error
    ///
    /// # Example
    /// ```rust
    /// let mut client = KyberModule::new()?;
    /// let server_public = server.public.clone(); // Get server's public key
    /// let client_message = client.client_init(server_public)?;
    /// // Send client_message to server
    /// ```
    pub fn client_init(&mut self, public: KyberPublicKey) -> Result<Vec<u8>, Errors> {
        if public.as_bytes().len() != Self::PUBLIC_KEY_SIZE {
            return Err(Errors::KyberError(format!(
                "Public key must be {} bytes long, got {}",
                Self::PUBLIC_KEY_SIZE,
                public.as_bytes().len()
            )));
        }

        let mut public_result = [0u8; Self::PUBLIC_KEY_SIZE];
        public_result.copy_from_slice(public.as_bytes());

        Ok(self
            .uake
            .expose_secret_mut()
            .client_init(&public_result, &mut OsRng)
            .map_err(|e| Errors::KyberError(e.to_string()))?
            .to_vec())
    }

    /// Processes client's UAKE message as a server.
    ///
    /// This is the second step in the UAKE protocol where the server
    /// receives the client's initial message and generates a response.
    ///
    /// # Arguments
    /// * `send_a` - Client's initial message (must be exactly 1568 bytes)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Server's response message (768 bytes) to send back to client
    /// * `Err(Errors)` - Invalid message size or protocol error
    ///
    /// # Example
    /// ```rust
    /// let mut server = KyberModule::new()?;
    /// let client_message = receive_from_client(); // Get client's message
    /// let server_response = server.server_receive(client_message)?;
    /// // Send server_response back to client
    /// ```
    pub fn server_receive(&mut self, send_a: Vec<u8>) -> Result<Vec<u8>, Errors> {
        if send_a.len() != Self::UAKE_SEND_A_SIZE {
            return Err(Errors::KyberError(format!(
                "Client message must be {} bytes long, got {}",
                Self::UAKE_SEND_A_SIZE,
                send_a.len()
            )));
        }

        let mut send_a_result = [0u8; Self::UAKE_SEND_A_SIZE];
        send_a_result.copy_from_slice(&send_a);
        let mut secret_result = [0u8; Self::SECRET_KEY_SIZE];
        secret_result.copy_from_slice(&self.secret.expose_secret());

        Ok(self
            .uake
            .expose_secret_mut()
            .server_receive(send_a_result, &secret_result, &mut OsRng)
            .map_err(|e| Errors::KyberError(e.to_string()))?
            .to_vec())
    }

    /// Completes UAKE protocol as a client.
    ///
    /// This is the final step in the UAKE protocol where the client
    /// processes the server's response to complete the key exchange.
    /// After this call succeeds, both parties have the same shared secret.
    ///
    /// # Arguments
    /// * `server_send` - Server's response message (must be exactly 768 bytes)
    ///
    /// # Returns
    /// * `Ok(())` - Protocol completed successfully, shared secret is available
    /// * `Err(Errors)` - Invalid message size or protocol error
    ///
    /// # Example
    /// ```rust
    /// let server_response = receive_from_server(); // Get server's response
    /// client.client_confirm(server_response)?;
    /// let shared_secret = client.shared_secret(); // Now available
    /// ```
    pub fn client_confirm(&mut self, server_send: Vec<u8>) -> Result<(), Errors> {
        if server_send.len() != Self::SERVER_SEND_KEY_SIZE {
            return Err(Errors::KyberError(format!(
                "Server message must be {} bytes long, got {}",
                Self::SERVER_SEND_KEY_SIZE,
                server_send.len()
            )));
        }

        let mut server_end_result = [0u8; Self::SERVER_SEND_KEY_SIZE];
        server_end_result.copy_from_slice(&server_send);

        Ok(self
            .uake
            .expose_secret_mut()
            .client_confirm(server_end_result)
            .map_err(|e| Errors::KyberError(e.to_string()))?)
    }

    /// Performs Kyber key encapsulation.
    ///
    /// This generates a random shared secret and encapsulates it using
    /// this module's public key. The returned ciphertext can be sent
    /// to the holder of the corresponding private key.
    ///
    /// # Returns
    /// * `Ok((SharedSecret, KyberCipherText))` - Tuple containing:
    ///   - `SharedSecret`: 32-byte key for cryptographic operations
    ///   - `KyberCipherText`: Transport data to send to other party
    /// * `Err(Errors)` - Encapsulation failed
    ///
    /// # Example
    /// ```rust
    /// let alice = KyberModule::new()?;
    /// let (secret, ciphertext) = alice.encapsulate()?;
    /// // Send ciphertext to Bob, use secret for encryption
    /// ```
    pub fn encapsulate(&self) -> Result<(SharedSecret, KyberCipherText), Errors> {
        let (ciphertext, shared_secret) =
            pqc_kyber::encapsulate(&self.public.as_bytes(), &mut OsRng)
                .map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok((
            SharedSecret::new(shared_secret.to_vec()),
            KyberCipherText::new(ciphertext.to_vec()),
        ))
    }

    /// Performs Kyber key decapsulation.
    ///
    /// This decapsulates the shared secret from the given ciphertext
    /// using this module's private key. The returned secret should
    /// match the one used during encapsulation.
    ///
    /// # Arguments
    /// * `cipher` - Ciphertext containing the encapsulated key
    ///
    /// # Returns
    /// * `Ok(SharedSecret)` - The decapsulated shared secret (32 bytes)
    /// * `Err(Errors)` - Decapsulation failed (invalid ciphertext or key)
    ///
    /// # Example
    /// ```rust
    /// let ciphertext = receive_ciphertext(); // From encapsulating party
    /// let bob = KyberModule::new_from_existed(&public, &private, None)?;
    /// let secret = bob.decapsulate(&ciphertext)?;
    /// ```
    pub fn decapsulate(&self, cipher: &KyberCipherText) -> Result<SharedSecret, Errors> {
        let shared_secret = pqc_kyber::decapsulate(cipher.as_bytes(), &self.secret.expose_secret())
            .map_err(|e| Errors::KyberError(e.to_string()))?;
        Ok(SharedSecret(SecretBox::new(
            shared_secret.to_vec().into_boxed_slice(),
        )))
    }

    /// Retrieves the shared secret from completed UAKE exchange.
    ///
    /// This returns the shared secret established through the UAKE protocol.
    /// Only call this after successfully completing the UAKE handshake
    /// (all three steps: client_init, server_receive, client_confirm).
    ///
    /// # Returns
    /// The 32-byte shared secret established by UAKE
    ///
    /// # Example
    /// ```rust
    /// // After completing UAKE protocol...
    /// let secret = client.shared_secret();
    /// // Use secret for symmetric encryption/authentication
    /// ```
    pub fn shared_secret(&self) -> SharedSecret {
        SharedSecret::new(self.uake.expose_secret().shared_secret.to_vec())
    }

    /// Validates that the module's keys have correct sizes.
    ///
    /// This checks that the public and private keys are the expected
    /// sizes for Kyber operations. Useful for debugging and validation.
    ///
    /// # Returns
    /// * `true` - Keys have correct sizes
    /// * `false` - One or more keys have incorrect sizes
    ///
    /// # Example
    /// ```rust
    /// let kyber = KyberModule::new()?;
    /// assert!(kyber.is_valid()); // Should always be true for new modules
    /// ```
    pub fn is_valid(&self) -> bool {
        self.public.as_bytes().len() == Self::PUBLIC_KEY_SIZE
            && self.secret.expose_secret().len() == Self::SECRET_KEY_SIZE
    }
}
