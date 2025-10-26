// ============================================================================
// Cryptographic Operations
// - Argon2id for KDF
// - AES-256-GCM for authenticated encryption
// - SecureString & MasterKey zeroized on drop
// ============================================================================
// This module provides all cryptographic primitives used by the vault:
//
// Key Derivation:
//   - Argon2id: Memory-hard function that derives encryption keys from passwords
//   - Resistant to GPU/ASIC attacks through high memory requirements
//   - Configurable time/memory cost parameters
//
// Encryption:
//   - AES-256-GCM: Authenticated encryption providing confidentiality + integrity
//   - 256-bit key size for quantum-resistance planning
//   - GCM mode provides authentication tag to detect tampering
//
// Memory Safety:
//   - Zeroize: Ensures sensitive data is securely erased from memory
//   - Prevents data leakage via memory dumps, swap files, or core dumps
// ============================================================================

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type alias for crypto operation results
pub type CryptoResult<T> = Result<T, CryptoError>;

// ============================================================================
// Error Types
// ============================================================================

/// Enum representing all possible cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    /// Encryption operation failed (e.g., invalid key)
    EncryptionFailed(String),

    /// Decryption operation failed (e.g., wrong key, corrupted data)
    DecryptionFailed(String),

    /// Key derivation failed (e.g., invalid parameters)
    KeyDerivationFailed(String),

    /// Data format is invalid (e.g., malformed base64, wrong length)
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

// ============================================================================
// Secure String Type
// ============================================================================

/// A wrapper around String that automatically zeros memory on drop.
///
/// # Purpose
/// Stores sensitive strings (passwords) and ensures they are wiped from
/// memory when no longer needed, preventing:
/// - Memory dumps from revealing passwords
/// - Passwords persisting in swap files
/// - Passwords visible in core dumps after crashes
///
/// # Derive Macros
/// - Zeroize: Provides method to zero the memory
/// - ZeroizeOnDrop: Automatically calls zeroize when dropped
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    /// The actual string data (will be zeroed on drop)
    data: String,
}

impl SecureString {
    /// Creates a new SecureString from a String.
    ///
    /// # Arguments
    /// * `data` - The string to secure
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Returns a reference to the contained string.
    ///
    /// # Security Note
    /// The returned reference is still in memory - don't keep it longer than needed
    pub fn as_str(&self) -> &str {
        &self.data
    }

    /// Consumes the SecureString and returns the inner String.
    ///
    /// # Warning
    /// The returned String won't be automatically zeroized.
    /// Only use when you need ownership of the underlying data.
    #[allow(dead_code)]
    pub fn into_string(self) -> String {
        self.data.clone()
    }
}

/// Allow creating SecureString from String using .into()
impl From<String> for SecureString {
    fn from(s: String) -> Self {
        SecureString::new(s)
    }
}

// ============================================================================
// Master Key Type
// ============================================================================

/// The master encryption key derived from the user's password.
///
/// # Key Derivation
/// Uses Argon2id with these properties:
/// - Memory-hard: Resistant to GPU/ASIC attacks
/// - Time-cost: Configurable iterations (default: 3)
/// - Parallelism: Can utilize multiple cores
/// - Salt: Unique per vault to prevent rainbow tables
///
/// # Security
/// - 256-bit key size (32 bytes)
/// - Zeroized on drop to prevent memory leaks
/// - Never stored on disk (derived from password on demand)
///
/// # Derive Macros
/// - Zeroize: Enables zeroing of key material
/// - ZeroizeOnDrop: Automatically zeros key when dropped
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    /// The 256-bit (32-byte) encryption key
    key: [u8; 32],
}

impl MasterKey {
    /// Derives a master key from a password and salt using Argon2id.
    ///
    /// # Arguments
    /// * `password` - The user's master password
    /// * `salt` - Random salt (should be 32 bytes, stored in vault)
    ///
    /// # Process
    /// 1. Takes password and salt as input
    /// 2. Runs Argon2id with default parameters
    /// 3. Outputs 32 bytes of key material
    ///
    /// # Performance
    /// This is intentionally slow (100ms+) to make brute-force attacks impractical.
    /// On user devices this delay is acceptable for security benefit.
    ///
    /// # Returns
    /// * `Ok(MasterKey)` - Successfully derived key
    /// * `Err(CryptoError)` - If key derivation fails
    pub fn derive_from_password(password: &str, salt: &[u8]) -> CryptoResult<Self> {
        // Use default Argon2 parameters (balanced security/performance)
        let argon2 = Argon2::default();

        // Allocate buffer for the derived key
        let mut key = [0u8; 32];

        // Derive key material into the buffer
        // This is the CPU-intensive operation that provides security
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self { key })
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// # Usage
    /// Only for passing to encryption/decryption functions.
    /// Don't expose these bytes outside the crypto module.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// ============================================================================
// Password Hashing
// ============================================================================

/// Stores a hashed password for verification (not encryption).
///
/// # Purpose
/// Different from MasterKey - this is for *verifying* passwords, not encrypting data.
///
/// # Hash Format
/// Stores the full Argon2id hash string which includes:
/// - Algorithm identifier (argon2id)
/// - Parameters (memory cost, time cost, parallelism)
/// - Salt (base64 encoded)
/// - Hash output (base64 encoded)
///
/// # Use Case
/// Stored in vault to verify user knows the master password before
/// attempting decryption (prevents wasting time on wrong password).
pub struct StoredPasswordHash {
    /// The full Argon2id hash string (PHC format)
    hash: String,
}

impl StoredPasswordHash {
    /// Creates a new password hash from a plaintext password.
    ///
    /// # Arguments
    /// * `password` - The password to hash
    ///
    /// # Process
    /// 1. Generates a random salt using OsRng
    /// 2. Hashes password with Argon2id
    /// 3. Returns hash in PHC string format
    ///
    /// # Returns
    /// * `Ok(StoredPasswordHash)` - Hash created successfully
    /// * `Err(CryptoError)` - If hashing fails
    pub fn new(password: &str) -> CryptoResult<Self> {
        // Generate a random salt for this password
        let salt = SaltString::generate(&mut OsRng);

        // Use default Argon2 parameters
        let argon2 = Argon2::default();

        // Hash the password and get PHC format string
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?
            .to_string();

        Ok(Self { hash })
    }

    /// Verifies a password against this stored hash.
    ///
    /// # Arguments
    /// * `password` - The password to verify
    ///
    /// # Returns
    /// * `true` - Password matches the hash
    /// * `false` - Password does not match or hash is invalid
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

    /// Returns the hash string for storage.
    pub fn as_str(&self) -> &str {
        &self.hash
    }

    /// Creates a StoredPasswordHash from an existing hash string.
    ///
    /// # Use Case
    /// When loading a hash from the vault file
    pub fn from_string(hash: String) -> Self {
        Self { hash }
    }
}

// ============================================================================
// Encrypted Data Structure
// ============================================================================

/// Represents encrypted data using AES-256-GCM.
///
/// # Structure
/// Contains two parts:
/// 1. Nonce (12 bytes): Random value ensuring unique ciphertext
/// 2. Ciphertext: Encrypted data + authentication tag (16 bytes)
///
/// # AES-GCM Properties
/// - Authenticated Encryption with Associated Data (AEAD)
/// - Confidentiality: Data is encrypted
/// - Integrity: Authentication tag detects tampering
/// - Authentication: Only holder of key can decrypt
///
/// # Security
/// - Each encryption uses a unique random nonce
/// - Authentication tag prevents tampering
/// - Key must remain secret for security
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Nonce (Number used ONCE) - must be unique per encryption
    /// Always 12 bytes for AES-GCM
    nonce: Vec<u8>,

    /// Encrypted data + authentication tag
    /// Length = plaintext length + 16 bytes (auth tag)
    ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Encrypts plaintext data using AES-256-GCM.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `key` - The MasterKey to use for encryption
    ///
    /// # Process
    /// 1. Generates a random 12-byte nonce using OsRng
    /// 2. Creates AES-256-GCM cipher with the key
    /// 3. Encrypts plaintext with the cipher and nonce
    /// 4. Returns EncryptedData with nonce and ciphertext
    ///
    /// # Security Notes
    /// - Never reuse a nonce with the same key (catastrophic failure)
    /// - Nonce is random, not a counter, to avoid state management
    /// - Authentication tag is automatically appended to ciphertext
    ///
    /// # Returns
    /// * `Ok(EncryptedData)` - Successfully encrypted
    /// * `Err(CryptoError)` - If encryption fails
    pub fn encrypt(plaintext: &[u8], key: &MasterKey) -> CryptoResult<Self> {
        // Create cipher instance from the key
        let cipher = Aes256Gcm::new(key.as_bytes().into());

        // Generate a random nonce (must be unique for each encryption)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Create Nonce type from bytes
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Perform authenticated encryption
        // Returns ciphertext with authentication tag appended
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Decrypts this encrypted data using AES-256-GCM.
    ///
    /// # Arguments
    /// * `key` - The MasterKey to use for decryption
    ///
    /// # Process
    /// 1. Creates AES-256-GCM cipher with the key
    /// 2. Attempts decryption using stored nonce and ciphertext
    /// 3. Verifies authentication tag (detects tampering)
    /// 4. Returns plaintext if successful
    ///
    /// # Security
    /// - Authentication tag is verified automatically
    /// - Fails if data has been tampered with
    /// - Fails if wrong key is used
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(CryptoError)` - If decryption or authentication fails
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
    /// # Format
    /// Concatenates nonce (12 bytes) + ciphertext (variable) and encodes as base64.
    /// This allows storing binary data in JSON files.
    ///
    /// # Returns
    /// Base64-encoded string containing nonce + ciphertext
    pub fn to_base64(&self) -> String {
        // Combine nonce and ciphertext into single buffer
        let mut combined = Vec::with_capacity(12 + self.ciphertext.len());
        combined.extend_from_slice(&self.nonce);
        combined.extend_from_slice(&self.ciphertext);

        // Encode as base64
        general_purpose::STANDARD.encode(&combined)
    }

    /// Decodes encrypted data from a base64 string.
    ///
    /// # Arguments
    /// * `encoded` - Base64 string (nonce + ciphertext)
    ///
    /// # Format
    /// Expects: 12-byte nonce + variable-length ciphertext
    ///
    /// # Returns
    /// * `Ok(EncryptedData)` - Successfully decoded
    /// * `Err(CryptoError)` - If base64 invalid or data too short
    pub fn from_base64(encoded: &str) -> CryptoResult<Self> {
        // Decode from base64
        let combined = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| CryptoError::InvalidData(e.to_string()))?;

        // Verify minimum length (nonce must be 12 bytes)
        if combined.len() < 12 {
            return Err(CryptoError::InvalidData("Data too short".into()));
        }

        // Split into nonce and ciphertext
        let (nonce, ciphertext) = combined.split_at(12);

        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Generates a cryptographically secure random salt.
///
/// # Purpose
/// Creates unique salt for key derivation, preventing:
/// - Rainbow table attacks
/// - Parallel attacks across multiple vaults
/// - Dictionary attacks with precomputed hashes
///
/// # Size
/// Returns 32 bytes (256 bits) of random data
///
/// # Source
/// Uses OsRng which draws from OS entropy source:
/// - /dev/urandom on Linux
/// - BCryptGenRandom on Windows
/// - SecRandomCopyBytes on macOS
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);
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
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Computes SHA-256 hash of data.
///
/// # Purpose
/// General-purpose hashing for integrity checks or fingerprinting.
/// NOT suitable for password hashing (use Argon2id instead).
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte (256-bit) SHA-256 hash
#[allow(dead_code)]
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    // Create hasher instance using Default trait
    let mut hasher = Sha256::default();

    // Feed data into hasher
    hasher.update(data);

    // Finalize and return hash as Vec<u8>
    hasher.finalize().to_vec()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that password hash verification works correctly
    #[test]
    fn test_password_hash_verification() {
        let pw = "test_password_123";

        // Create hash from password
        let hash = StoredPasswordHash::new(pw).unwrap();

        // Verify correct password succeeds
        assert!(hash.verify(pw));

        // Verify incorrect password fails
        assert!(!hash.verify("nope"));
    }

    /// Test that encryption and decryption roundtrip works
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pw = "master_pw";
        let salt = generate_salt();

        // Derive key from password
        let key = MasterKey::derive_from_password(pw, &salt).unwrap();

        // Test data
        let pt = b"Secret data";

        // Encrypt
        let enc = EncryptedData::encrypt(pt, &key).unwrap();

        // Decrypt
        let dec = enc.decrypt(&key).unwrap();

        // Verify plaintext matches original
        assert_eq!(pt, dec.as_slice());
    }

    /// Test that base64 encoding/decoding roundtrip works
    #[test]
    fn test_b64_roundtrip() {
        let pw = "master_pw";
        let salt = generate_salt();

        // Derive key
        let key = MasterKey::derive_from_password(pw, &salt).unwrap();

        // Test data
        let pt = b"hello";

        // Encrypt
        let enc = EncryptedData::encrypt(pt, &key).unwrap();

        // Encode to base64
        let b64 = enc.to_base64();

        // Decode from base64
        let dec_enc = EncryptedData::from_base64(&b64).unwrap();

        // Decrypt
        let dec = dec_enc.decrypt(&key).unwrap();

        // Verify plaintext matches original
        assert_eq!(pt, dec.as_slice());
    }
}
