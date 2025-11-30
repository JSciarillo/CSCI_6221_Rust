//Cryptographic operations
// -Argon2id
// -AES-256-GCM
// -SecureString & MasterKey zeroed on drop

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type CryptoResult<T> = Result<T, CryptoError>;


//Error types
//Enum representing all possible cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    //Encryption operation failed
    EncryptionFailed(String),

    //Decryption operation failed
    DecryptionFailed(String),

    //Key derivation failed
    KeyDerivationFailed(String),

    //Data format is invalid
    InvalidData(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed(m) => write!(f, "Encryption failed: {}", m),
            CryptoError::DecryptionFailed(m) => write!(f, "Decryption failed: {}", m),
            CryptoError::KeyDerivationFailed(m) => write!(f, "Key derivation failed: {}", m),
            CryptoError::InvalidData(m) => write!(f, "Invalid data: {}", m),
        }
    }
}

impl std::error::Error for CryptoError {}


// Secure String Type

//A wrapper around String that automatically clears memory on drop.
//Purpose:
//Stores sensitive strings (passwords) and ensures they are wiped from memory when no longer needed

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    ///The actual string data, zeroed on drop
    data: String,
}

impl SecureString {
    /// Creates a new SecureString from a String.
    /// `data` is the string to secure
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Returns a reference to the contained string.
    
    pub fn as_str(&self) -> &str {
        &self.data
    }

    /// Consumes the SecureString and returns the inner String
    /// The returned String won't be automatically zeroized
    #[allow(dead_code)]
    pub fn into_string(self) -> String {
        self.data.clone()
    }
}


impl From<String> for SecureString {
    fn from(s: String) -> Self {
        SecureString::new(s)
    }
}


//The master encryption key created from the user's password
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct MasterKey {
    /// The 256-bit (32-byte) encryption key
    key: [u8; 32],
}

impl MasterKey {
    /// Derives a master key from a password and salt using Argon2id.
    /// #Process
    /// 1.Takes password and salt as input
    /// 2.Runs Argon2id with default parameters
    /// 3.Outputs 32 bytes of key material
    pub fn derive_from_password(password: &str, salt: &[u8]) -> CryptoResult<Self> {
        //Uses default Argon2 parameters
        let argon2 = Argon2::default();

        //Allocate buffer for the derived key
        let mut key = [0u8; 32];

        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self { key })
    }

    /// Returns a reference to the raw key bytes
    ///Only for passing to encryption/decryption functions
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// Password Hashing
///Stores a hashed password for verification, not encrypting data
///
/// #Hash Format
/// Stores the full Argon2id hash string which includes:
/// -Algorithm identifier (argon2id)
/// -Parameters (memory cost, time cost, parallelism)
/// -Salt (base64 encoded)
/// -Hash output (base64 encoded)
///Stored in vault to verify user knows the master password before trying to decrypt
pub struct StoredPasswordHash {
    ///The full Argon2id hash string (PHC format)
    hash: String,
}

impl StoredPasswordHash {
    /// Creates a new password hash from a plaintext password.
    
    pub fn new(password: &str) -> CryptoResult<Self> {
        //Generate a random salt for this password
        let salt = SaltString::generate(&mut thread_rng());

        //Use default Argon2 parameters
        let argon2 = Argon2::default();

        //Hash the password and get PHC format string
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?
            .to_string();

        Ok(Self { hash })
    }

    /// Verifies a password against this stored hash.
    //Returns:
    //true - Password matches the hash
    //false - Password does not match or hash is invalid
    pub fn verify(&self, password: &str) -> bool {
        // Parse the stored hash string
        match PasswordHash::new(&self.hash) {
            Ok(parsed) => {
                // Verify the password against the parsed hash
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            }
            Err(_) => false, // Invalid hash format
        }
    }

    ///Returns hash string for storage.
    pub fn as_str(&self) -> &str {
        &self.hash
    }

    ///Creates a StoredPasswordHash from an existing hash string.
    //
    //When loading a hash from the vault file
    pub fn from_string(hash: String) -> Self {
        Self { hash }
    }
}

// Encrypted Data Structure
/// Represents encrypted data using AES-256-GCM.
//Random value ensuring unique ciphertext
//Encrypted data + authentication tag

#[derive(Debug, Clone)]
pub struct EncryptedData {
    
    nonce: Vec<u8>,

    ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Encrypts plaintext data using AES-256-GCM.
    pub fn encrypt(plaintext: &[u8], key: &MasterKey) -> CryptoResult<Self> {
        //Create cipher instance from the key
        let cipher = Aes256Gcm::new(key.as_bytes().into());

        //Generate a random nonce 
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes); 

        //Create Nonce type from bytes
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);

        //Perform authenticated encryption
        //Returns ciphertext with authentication tag appended
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Decrypts encrypted data using AES-256-GCM.
    pub fn decrypt(&self, key: &MasterKey) -> CryptoResult<Vec<u8>> {
        // Create cipher instance from the key
        let cipher = Aes256Gcm::new(key.as_bytes().into());

        // Create Nonce from stored nonce bytes
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&self.nonce);

        // Perform authenticated decryption
        // Automatically verifies authentication tag
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    /// Encodes the encrypted data as a base64 string for storage.
    ///
    //Format:
    /// Concatenates nonce (12 bytes) + ciphertext (variable) and encodes as base64.
    /// This allows storing binary data in JSON files.
    //Returns:
    ///Base64-encoded string containing nonce + ciphertext
    pub fn to_base64(&self) -> String {
        // Combine nonce and ciphertext into single buffer
        let mut combined = Vec::with_capacity(12 + self.ciphertext.len());
        combined.extend_from_slice(&self.nonce);
        combined.extend_from_slice(&self.ciphertext);

        //Encode as base64
        general_purpose::STANDARD.encode(&combined)
    }

    /// Decodes encrypted data from a base64 string.
    pub fn from_base64(encoded: &str) -> CryptoResult<Self> {
        //Decode from base64
        let combined = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CryptoError::InvalidData(e.to_string()))?;

        //Verifies minimum length, must be 12 bytes
        if combined.len() < 12 {
            return Err(CryptoError::InvalidData("Data too short".into()));
        }

        //Split into nonce and ciphertext
        let (nonce, ciphertext) = combined.split_at(12);

        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

// Utility Functions

/// Generates a cryptographically secure random salt.

/// Creates unique salt for key derivation
/// Size:
/// Returns 32 bytes (256 bits) of random data
/// Source:
/// Uses thread_rng which takes from cryptographically secure random source
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    thread_rng().fill_bytes(&mut salt);  // CHANGED: OsRng -> thread_rng()
    salt
}

/// Generates random bytes of specified length.
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Returns
/// Vector of cryptographically secure random bytes
#[allow(dead_code)]
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    thread_rng().fill_bytes(&mut bytes);  // CHANGED: OsRng -> thread_rng()
    bytes
}

/// Computes SHA-256 hash of data.

#[allow(dead_code)]
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    // Create hasher instance using Default trait
    let mut hasher = Sha256::default();

    // Feed data into hasher
    hasher.update(data);

    // Finalize and return hash as Vec<u8>
    hasher.finalize().to_vec()
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    //Test that password hash verification works correctly
    #[test]
    fn test_password_hash_verification() {
        let pw = "test_password_123";

        //Create hash from password
        let hash = StoredPasswordHash::new(pw).unwrap();

        assert!(hash.verify(pw));

        assert!(!hash.verify("no"));
    }

    //Test that encryption and decryption roundtrip works
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pw = "master_pw";
        let salt = generate_salt();

        //Derive key from password
        let key = MasterKey::derive_from_password(pw, &salt).unwrap();

        //Test data
        let pt = b"Secret data";

        //Encrypt
        let enc = EncryptedData::encrypt(pt, &key).unwrap();

        //Decrypt
        let dec = enc.decrypt(&key).unwrap();

        //Verify plaintext matches original
        assert_eq!(pt, dec.as_slice());
    }

    //Tests base64 encoding/decoding roundtrip works
    #[test]
    fn test_b64_roundtrip() {
        let pw = "master_pw";
        let salt = generate_salt();

        //Derive key
        let key = MasterKey::derive_from_password(pw, &salt).unwrap();

        //Test data
        let pt = b"hello";

        //Encrypt
        let enc = EncryptedData::encrypt(pt, &key).unwrap();

        //Encode to base64
        let b64 = enc.to_base64();

        //Decode from base64
        let dec_enc = EncryptedData::from_base64(&b64).unwrap();

        //Decrypt
        let dec = dec_enc.decrypt(&key).unwrap();

        //Verify plaintext matches original
        assert_eq!(pt, dec.as_slice());
    }
}