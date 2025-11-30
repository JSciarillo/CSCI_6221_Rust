// Storage: WASM/localStorage version

use crate::crypto::{CryptoError, StoredPasswordHash};
use serde::{Deserialize, Serialize};
use web_sys::window;

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug)]
pub enum StorageError {
    IoError(String),
    SerializationError(serde_json::Error),
    CryptoError(CryptoError),
    VaultNotFound,
    VaultAlreadyExists,
    InvalidVaultFormat,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "Storage error: {}", e),
            StorageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            StorageError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            StorageError::VaultNotFound => write!(f, "Vault not found"),
            StorageError::VaultAlreadyExists => write!(f, "Vault already exists"),
            StorageError::InvalidVaultFormat => write!(f, "Invalid vault format"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::SerializationError(e)
    }
}

impl From<CryptoError> for StorageError {
    fn from(e: CryptoError) -> Self {
        StorageError::CryptoError(e)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub operation: String,
    pub service: Option<String>,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultMetadata {
    pub version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub modified_at: chrono::DateTime<chrono::Utc>,
    pub salt: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultFile {
    pub metadata: VaultMetadata,
    pub master_password_hash: String,
    pub encrypted_data: String,
    pub audit_log: Vec<AuditEntry>,
}

impl VaultFile {
    pub fn new(password_hash: StoredPasswordHash, salt: Vec<u8>) -> Self {
        let now = chrono::Utc::now();
        Self {
            metadata: VaultMetadata {
                version: "1.0.0".to_string(),
                created_at: now,
                modified_at: now,
                salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            },
            master_password_hash: password_hash.as_str().to_string(),
            encrypted_data: String::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn add_audit_entry(&mut self, operation: String, service: Option<String>, success: bool) {
        self.audit_log.push(AuditEntry {
            timestamp: chrono::Utc::now(),
            operation,
            service,
            success,
        });

        if self.audit_log.len() > 1000 {
            self.audit_log.remove(0);
        }
    }

    pub fn get_salt(&self) -> StorageResult<Vec<u8>> {
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.metadata.salt,
        )
        .map_err(|_| StorageError::InvalidVaultFormat)
    }
}

#[derive(Clone)]
pub struct VaultStorage {
    storage_key: String,
}

impl VaultStorage {
    pub fn new() -> StorageResult<Self> {
        Ok(Self {
            storage_key: "secure_password_vault".to_string(),
        })
    }

    pub fn with_path(_path: std::path::PathBuf) -> Self {
        Self {
            storage_key: "secure_password_vault".to_string(),
        }
    }

    pub fn get_default_vault_path() -> StorageResult<std::path::PathBuf> {
        Ok(std::path::PathBuf::from("localStorage"))
    }

    pub fn vault_exists(&self) -> bool {
        self.get_local_storage()
            .and_then(|storage| storage.get_item(&self.storage_key).ok())
            .and_then(|item| item)
            .is_some()
    }

    pub fn save(&self, vault: &VaultFile) -> StorageResult<()> {
        let storage = self.get_local_storage()
            .ok_or_else(|| StorageError::IoError("localStorage not available".to_string()))?;

        let json = serde_json::to_string_pretty(vault)?;

        storage
            .set_item(&self.storage_key, &json)
            .map_err(|_| StorageError::IoError("Failed to save to localStorage".to_string()))?;

        Ok(())
    }

    pub fn load(&self) -> StorageResult<VaultFile> {
        if !self.vault_exists() {
            return Err(StorageError::VaultNotFound);
        }

        let storage = self.get_local_storage()
            .ok_or_else(|| StorageError::IoError("localStorage not available".to_string()))?;

        let json = storage
            .get_item(&self.storage_key)
            .map_err(|_| StorageError::IoError("Failed to read from localStorage".to_string()))?
            .ok_or(StorageError::VaultNotFound)?;

        let vault: VaultFile = serde_json::from_str(&json)?;
        Ok(vault)
    }

    #[allow(dead_code)]
    pub fn delete(&self) -> StorageResult<()> {
        if let Some(storage) = self.get_local_storage() {
            storage
                .remove_item(&self.storage_key)
                .map_err(|_| StorageError::IoError("Failed to delete from localStorage".to_string()))?;
        }
        Ok(())
    }

    pub fn backup(&self, _path: &std::path::Path) -> StorageResult<()> {
        Ok(())
    }

    pub fn get_path(&self) -> &std::path::Path {
        std::path::Path::new("localStorage")
    }

    fn get_local_storage(&self) -> Option<web_sys::Storage> {
        window()?.local_storage().ok()?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::StoredPasswordHash;

    #[test]
    fn test_vault_file_creation() {
        let hash = StoredPasswordHash::new("testpassword").unwrap();
        let salt = vec![0u8; 32];
        let vault = VaultFile::new(hash, salt);

        assert_eq!(vault.metadata.version, "1.0.0");
        assert!(vault.encrypted_data.is_empty());
        assert!(vault.audit_log.is_empty());
    }

    #[test]
    fn test_audit_entries() {
        let hash = StoredPasswordHash::new("testpassword").unwrap();
        let salt = vec![0u8; 32];
        let mut vault = VaultFile::new(hash, salt);

        vault.add_audit_entry("TEST".to_string(), Some("service".to_string()), true);

        assert_eq!(vault.audit_log.len(), 1);
        assert_eq!(vault.audit_log[0].operation, "TEST");
        assert_eq!(vault.audit_log[0].service, Some("service".to_string()));
        assert_eq!(vault.audit_log[0].success, true);
    }
}