// ============================================================================
// Storage: vault file format + disk I/O
// ============================================================================
// This module handles all file system operations for the vault including:
// - Vault file structure and serialization (JSON format)
// - Reading/writing encrypted vault data
// - Audit log management
// - Cross-platform path resolution
// - Atomic file operations for data integrity
//
// File Format:
// The vault is stored as a JSON file with the following structure:
// {
//   "metadata": { version, created_at, modified_at, salt },
//   "master_password_hash": "...",  // Argon2id hash for verification
//   "encrypted_data": "...",         // Base64 AES-256-GCM encrypted credentials
//   "audit_log": [...]               // Array of audit entries
// }
// ============================================================================

use crate::crypto::{CryptoError, StoredPasswordHash};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Type alias for storage operation results
pub type StorageResult<T> = Result<T, StorageError>;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during storage operations
#[derive(Debug)]
pub enum StorageError {
    /// File system I/O error (read/write failures, permissions, etc.)
    IoError(std::io::Error),

    /// JSON serialization/deserialization error
    SerializationError(serde_json::Error),

    /// Cryptographic operation error
    CryptoError(CryptoError),

    /// Vault file not found at expected location
    VaultNotFound,

    /// Attempting to create vault when one already exists
    VaultAlreadyExists,

    /// Vault file exists but has invalid format/structure
    InvalidVaultFormat,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "I/O error: {}", e),
            StorageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            StorageError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            StorageError::VaultNotFound => write!(f, "Vault not found"),
            StorageError::VaultAlreadyExists => write!(f, "Vault already exists"),
            StorageError::InvalidVaultFormat => write!(f, "Invalid vault format"),
        }
    }
}

/// Implement Error trait for StorageError
impl std::error::Error for StorageError {}

/// Convert std::io::Error to StorageError
impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::IoError(e)
    }
}

/// Convert serde_json::Error to StorageError
impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::SerializationError(e)
    }
}

/// Convert CryptoError to StorageError
impl From<CryptoError> for StorageError {
    fn from(e: CryptoError) -> Self {
        StorageError::CryptoError(e)
    }
}

// ============================================================================
// Audit Entry Structure
// ============================================================================

/// Represents a single audit log entry tracking vault operations.
///
/// # Purpose
/// Provides accountability and security monitoring by recording:
/// - What operation was performed
/// - When it occurred
/// - Which service was affected
/// - Whether it succeeded or failed
///
/// # Security Benefits
/// - Detect unauthorized access attempts
/// - Track credential access patterns
/// - Investigate security incidents
/// - Comply with security policies
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// When the operation occurred (UTC timezone)
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Type of operation (e.g., "ADD", "GET", "REMOVE", "UPDATE", "INIT")
    pub operation: String,

    /// Service name affected by the operation (None for vault-level operations)
    pub service: Option<String>,

    /// Whether the operation completed successfully
    pub success: bool,
}

// ============================================================================
// Vault Metadata Structure
// ============================================================================

/// Metadata about the vault file.
///
/// # Fields
/// - version: Vault format version for compatibility
/// - created_at: When the vault was first initialized
/// - modified_at: Last modification timestamp
/// - salt: Random salt used for key derivation (base64-encoded)
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Vault file format version (for future compatibility)
    pub version: String,

    /// When the vault was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the vault was last modified
    pub modified_at: chrono::DateTime<chrono::Utc>,

    /// Base64-encoded salt for KDF (32 bytes raw)
    /// This salt is unique per vault and used in Argon2id key derivation
    pub salt: String,
}

// ============================================================================
// Vault File Structure
// ============================================================================

/// The complete vault file structure that is serialized to JSON.
///
/// # Structure
/// This represents the on-disk format of the vault containing:
/// - Metadata (version, timestamps, salt)
/// - Master password verification hash
/// - Encrypted credential data
/// - Audit log of operations
///
/// # Security Notes
/// - Only encrypted_data contains sensitive information (credentials)
/// - Master password hash is for verification only (not for encryption)
/// - Salt is stored in plaintext (not secret, just needs to be random)
/// - Audit log is unencrypted for accessibility
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    /// Vault metadata (version, timestamps, salt)
    pub metadata: VaultMetadata,

    /// Argon2id hash of master password (for verification)
    pub master_password_hash: String,

    /// Base64-encoded encrypted credential data (AES-256-GCM)
    pub encrypted_data: String,

    /// Audit log of vault operations
    pub audit_log: Vec<AuditEntry>,
}

impl VaultFile {
    /// Creates a new VaultFile structure for a freshly initialized vault.
    ///
    /// # Arguments
    /// * `password_hash` - Hashed master password for verification
    /// * `salt` - Random salt for key derivation (32 bytes)
    ///
    /// # Returns
    /// New VaultFile with:
    /// - Version set to "1.0.0"
    /// - Timestamps set to current time
    /// - Empty encrypted_data (no credentials yet)
    /// - Empty audit_log
    pub fn new(password_hash: StoredPasswordHash, salt: Vec<u8>) -> Self {
        let now = chrono::Utc::now();
        Self {
            metadata: VaultMetadata {
                version: "1.0.0".to_string(),
                created_at: now,
                modified_at: now,
                // Encode salt as base64 for JSON storage
                salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            },
            master_password_hash: password_hash.as_str().to_string(),
            encrypted_data: String::new(),
            audit_log: Vec::new(),
        }
    }

    /// Adds an entry to the audit log.
    ///
    /// # Arguments
    /// * `operation` - Type of operation (e.g., "ADD", "GET", "REMOVE")
    /// * `service` - Service affected (None for vault-level operations)
    /// * `success` - Whether operation succeeded
    ///
    /// # Log Rotation
    /// Automatically limits log to 1000 entries by removing oldest when full.
    /// This prevents unbounded growth while maintaining recent history.
    pub fn add_audit_entry(&mut self, operation: String, service: Option<String>, success: bool) {
        // Create and push new entry with current timestamp
        self.audit_log.push(AuditEntry {
            timestamp: chrono::Utc::now(),
            operation,
            service,
            success,
        });

        // Rotate log if it exceeds 1000 entries (remove oldest)
        if self.audit_log.len() > 1000 {
            self.audit_log.remove(0);
        }
    }

    /// Retrieves the decoded salt from metadata.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The 32-byte salt
    /// * `Err(StorageError)` - If base64 decoding fails
    pub fn get_salt(&self) -> StorageResult<Vec<u8>> {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.metadata.salt,
        )
        .map_err(|_| StorageError::InvalidVaultFormat)
    }
}

// ============================================================================
// Vault Storage Manager
// ============================================================================

/// Manages vault file system operations.
///
/// # Responsibilities
/// - Resolving vault file paths (default or custom)
/// - Reading and writing vault files
/// - Atomic operations to prevent corruption
/// - Platform-specific file permissions
/// - Backup/export operations
pub struct VaultStorage {
    /// Path to the vault file on disk
    vault_path: PathBuf,
}

impl VaultStorage {
    /// Creates a new VaultStorage using the default platform-specific path.
    ///
    /// # Default Paths
    /// - Linux: ~/.local/share/secure_password_vault/vault.json
    /// - macOS: ~/Library/Application Support/secure_password_vault/vault.json
    /// - Windows: C:\Users\<user>\AppData\Local\secure_password_vault\vault.json
    ///
    /// # Returns
    /// * `Ok(VaultStorage)` - Storage manager ready to use
    /// * `Err(StorageError)` - If path cannot be determined
    pub fn new() -> StorageResult<Self> {
        let vault_path = Self::get_default_vault_path()?;
        Ok(Self { vault_path })
    }

    /// Creates a VaultStorage with a custom path.
    ///
    /// # Arguments
    /// * `path` - Custom path for vault file
    ///
    /// # Use Cases
    /// - Testing with temporary paths
    /// - Multiple vaults in different locations
    /// - Custom backup locations
    pub fn with_path(path: PathBuf) -> Self {
        Self { vault_path: path }
    }

    /// Determines the default platform-specific vault path.
    ///
    /// Uses the `directories` crate to find appropriate data directories
    /// following OS conventions and standards.
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Default vault path for this platform
    /// * `Err(StorageError)` - If home directory cannot be determined
    pub fn get_default_vault_path() -> StorageResult<PathBuf> {
        // Get platform-specific project directories
        let proj_dirs = ProjectDirs::from("com", "securityteam", "secure_password_vault").ok_or(
            StorageError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine vault directory",
            )),
        )?;

        // Get data directory and ensure it exists
        let data_dir = proj_dirs.data_dir();
        fs::create_dir_all(data_dir)?;

        // Return path to vault.json in data directory
        Ok(data_dir.join("vault.json"))
    }

    /// Checks if the vault file exists at the configured path.
    ///
    /// # Returns
    /// * `true` - Vault file exists
    /// * `false` - Vault file does not exist
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Saves the vault to disk using atomic write operation.
    ///
    /// # Atomic Write Process
    /// 1. Serialize vault to JSON
    /// 2. Write to temporary file (.tmp extension)
    /// 3. Rename temp file to actual vault file (atomic operation)
    /// 4. Set restrictive permissions (Unix only)
    ///
    /// # Why Atomic?
    /// The rename operation is atomic on most filesystems, preventing:
    /// - Partial writes if process crashes
    /// - Corruption if power fails during write
    /// - Race conditions with concurrent access
    ///
    /// # Security
    /// On Unix systems, sets permissions to 0600 (owner read/write only)
    /// to prevent other users from accessing vault file.
    ///
    /// # Arguments
    /// * `vault` - VaultFile structure to save
    ///
    /// # Returns
    /// * `Ok(())` - Vault saved successfully
    /// * `Err(StorageError)` - If write or rename fails
    pub fn save(&self, vault: &VaultFile) -> StorageResult<()> {
        // Serialize vault to pretty-printed JSON
        let json = serde_json::to_string_pretty(vault)?;

        // Write to temporary file first
        let tmp = self.vault_path.with_extension("tmp");
        fs::write(&tmp, json)?;

        // Atomically rename temp to actual vault file
        fs::rename(&tmp, &self.vault_path)?;

        // Set restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.vault_path)?.permissions();
            // 0600 = owner read/write, no access for group or others
            perms.set_mode(0o600);
            fs::set_permissions(&self.vault_path, perms)?;
        }
        Ok(())
    }

    /// Loads the vault from disk.
    ///
    /// # Process
    /// 1. Check if vault exists
    /// 2. Read JSON file
    /// 3. Deserialize into VaultFile structure
    ///
    /// # Returns
    /// * `Ok(VaultFile)` - Loaded vault structure
    /// * `Err(StorageError)` - If file doesn't exist or parsing fails
    pub fn load(&self) -> StorageResult<VaultFile> {
        // Check existence first for better error message
        if !self.vault_exists() {
            return Err(StorageError::VaultNotFound);
        }

        // Read file contents
        let json = fs::read_to_string(&self.vault_path)?;

        // Deserialize JSON to VaultFile structure
        let vault: VaultFile = serde_json::from_str(&json)?;
        Ok(vault)
    }

    /// Deletes the vault file from disk.
    ///
    /// # Warning
    /// This permanently deletes the vault! All encrypted data will be lost
    /// if no backup exists.
    ///
    /// # Returns
    /// * `Ok(())` - Vault deleted or didn't exist
    /// * `Err(StorageError)` - If deletion fails (permissions, etc.)
    #[allow(dead_code)]
    pub fn delete(&self) -> StorageResult<()> {
        if self.vault_exists() {
            fs::remove_file(&self.vault_path)?;
        }
        Ok(())
    }

    /// Creates a backup copy of the vault file.
    ///
    /// # Arguments
    /// * `backup_path` - Where to save the backup
    ///
    /// # Security
    /// Backup file is still encrypted - still requires master password.
    /// Store backups in secure locations.
    ///
    /// # Returns
    /// * `Ok(())` - Backup created successfully
    /// * `Err(StorageError)` - If vault doesn't exist or copy fails
    pub fn backup(&self, backup_path: &Path) -> StorageResult<()> {
        if !self.vault_exists() {
            return Err(StorageError::VaultNotFound);
        }
        // Simple file copy for backup
        fs::copy(&self.vault_path, backup_path)?;
        Ok(())
    }

    /// Returns the vault file path.
    ///
    /// # Returns
    /// Reference to the vault file path
    pub fn get_path(&self) -> &Path {
        &self.vault_path
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::StoredPasswordHash;

    /// Test that VaultFile creation works correctly
    #[test]
    fn test_vault_file_creation() {
        let hash = StoredPasswordHash::new("pw").unwrap();
        let salt = vec![0u8; 32];
        let vault = VaultFile::new(hash, salt);

        // Verify initial state
        assert_eq!(vault.metadata.version, "1.0.0");
        assert!(vault.encrypted_data.is_empty());
    }

    /// Test that audit entries are added correctly
    #[test]
    fn test_audit_entries() {
        let hash = StoredPasswordHash::new("pw").unwrap();
        let salt = vec![0u8; 32];
        let mut vault = VaultFile::new(hash, salt);

        // Add an audit entry
        vault.add_audit_entry("ADD".into(), Some("svc".into()), true);

        // Verify entry was added
        assert_eq!(vault.audit_log.len(), 1);
        assert_eq!(vault.audit_log[0].operation, "ADD");
    }
}
