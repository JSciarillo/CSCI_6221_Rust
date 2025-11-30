//Vault Module

use crate::crypto::{CryptoError, EncryptedData, MasterKey, SecureString, StoredPasswordHash};
use crate::storage::{StorageError, VaultFile, VaultStorage};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub type VaultResult<T> = Result<T, VaultError>;

#[derive(Debug)]
pub enum VaultError {
    StorageError(StorageError),
    CryptoError(CryptoError),
    CredentialNotFound(String),
    CredentialAlreadyExists(String),
    InvalidMasterPassword,
    VaultLocked,
    InvalidOperation(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::StorageError(e) => write!(f, "Storage error: {}", e),
            VaultError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            VaultError::CredentialNotFound(s) => write!(f, "Credential not found: {}", s),
            VaultError::CredentialAlreadyExists(s) => write!(f, "Credential already exists: {}", s),
            VaultError::InvalidMasterPassword => write!(f, "Invalid master password"),
            VaultError::VaultLocked => write!(f, "Vault is locked"),
            VaultError::InvalidOperation(s) => write!(f, "Invalid operation: {}", s),
        }
    }
}
impl std::error::Error for VaultError {}
impl From<StorageError> for VaultError {
    fn from(e: StorageError) -> Self {
        VaultError::StorageError(e)
    }
}
impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::CryptoError(e)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    pub id: String,
    pub service: String,
    pub username: String,
    #[serde(skip)]
    pub password: Option<SecureString>,
    pub encrypted_password: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub url: Option<String>,
}

impl Credential {
    pub fn new(
        service: String,
        username: String,
        password: SecureString,
        notes: Option<String>,
        key: &MasterKey,
    ) -> VaultResult<Self> {
        let encrypted = EncryptedData::encrypt(password.as_str().as_bytes(), key)?;
        let now = Utc::now();
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            service,
            username,
            password: Some(password),
            encrypted_password: encrypted.to_base64(),
            notes,
            created_at: now,
            modified_at: now,
            last_accessed: None,
            tags: Vec::new(),
            url: None,
        })
    }

    pub fn decrypt_password(&mut self, key: &MasterKey) -> VaultResult<SecureString> {
        let encrypted = EncryptedData::from_base64(&self.encrypted_password)?;
        let plaintext = encrypted.decrypt(key)?;
        let password = String::from_utf8(plaintext)
            .map_err(|e| VaultError::CryptoError(CryptoError::InvalidData(e.to_string())))?;
        self.last_accessed = Some(Utc::now());
        self.password = Some(SecureString::new(password.clone()));
        Ok(SecureString::new(password))
    }

    pub fn update_password(
        &mut self,
        new_password: SecureString,
        key: &MasterKey,
    ) -> VaultResult<()> {
        let encrypted = EncryptedData::encrypt(new_password.as_str().as_bytes(), key)?;
        self.encrypted_password = encrypted.to_base64();
        self.password = Some(new_password);
        self.modified_at = Utc::now();
        Ok(())
    }

    pub fn clear_password(&mut self) {
        self.password = None;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStore {
    credentials: HashMap<String, Credential>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn add(&mut self, credential: Credential) -> VaultResult<()> {
        if self.credentials.contains_key(&credential.service) {
            return Err(VaultError::CredentialAlreadyExists(
                credential.service.clone(),
            ));
        }
        self.credentials
            .insert(credential.service.clone(), credential);
        Ok(())
    }

    pub fn get(&self, service: &str) -> VaultResult<&Credential> {
        self.credentials
            .get(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    pub fn get_mut(&mut self, service: &str) -> VaultResult<&mut Credential> {
        self.credentials
            .get_mut(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    pub fn remove(&mut self, service: &str) -> VaultResult<Credential> {
        self.credentials
            .remove(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    #[allow(dead_code)]
    pub fn list_services(&self) -> Vec<&str> {
        self.credentials.keys().map(|s| s.as_str()).collect()
    }

    pub fn get_all(&self) -> Vec<&Credential> {
        self.credentials.values().collect()
    }

    pub fn search(&self, query: &str) -> Vec<&Credential> {
        let q = query.to_lowercase();
        self.credentials
            .values()
            .filter(|c| {
                c.service.to_lowercase().contains(&q)
                    || c.username.to_lowercase().contains(&q)
                    || c.notes
                        .as_ref()
                        .map_or(false, |n| n.to_lowercase().contains(&q))
            })
            .collect()
    }

    pub fn clear_all_passwords(&mut self) {
        for c in self.credentials.values_mut() {
            c.clear_password();
        }
    }
}

#[derive(Clone)]
pub struct Vault {
    storage: VaultStorage,
    master_key: Option<MasterKey>,
    credentials: Option<CredentialStore>,
    vault_file: Option<VaultFile>,
}

impl Vault {
    pub fn new() -> VaultResult<Self> {
        let storage = VaultStorage::new()?;
        Ok(Self {
            storage,
            master_key: None,
            credentials: None,
            vault_file: None,
        })
    }

    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            storage: VaultStorage::with_path(path),
            master_key: None,
            credentials: None,
            vault_file: None,
        }
    }

    pub fn exists(&self) -> bool {
        self.storage.vault_exists()
    }

    pub fn initialize(&mut self, master_password: &str) -> VaultResult<()> {
        if self.exists() {
            return Err(VaultError::StorageError(StorageError::VaultAlreadyExists));
        }
        let salt = crate::crypto::generate_salt();
        let password_hash = StoredPasswordHash::new(master_password)?;
        let mut vault_file = VaultFile::new(password_hash, salt.clone());
        vault_file.add_audit_entry("INIT".to_string(), None, true);

        let credentials = CredentialStore::new();
        let master_key = MasterKey::derive_from_password(master_password, &salt)?;

        let json = serde_json::to_string(&credentials)
            .map_err(|e| VaultError::InvalidOperation(e.to_string()))?;
        let encrypted = EncryptedData::encrypt(json.as_bytes(), &master_key)?;
        vault_file.encrypted_data = encrypted.to_base64();

        self.storage.save(&vault_file)?;
        self.vault_file = Some(vault_file);
        self.master_key = Some(master_key);
        self.credentials = Some(credentials);
        Ok(())
    }

    pub fn unlock(&mut self, master_password: &str) -> VaultResult<()> {
        let vault_file = self.storage.load()?;

        let pw_hash = StoredPasswordHash::from_string(vault_file.master_password_hash.clone());
        if !pw_hash.verify(master_password) {
            return Err(VaultError::InvalidMasterPassword);
        }

        let salt = vault_file.get_salt()?;
        let master_key = MasterKey::derive_from_password(master_password, &salt)?;

        let encrypted = EncryptedData::from_base64(&vault_file.encrypted_data)?;
        let plaintext = encrypted.decrypt(&master_key)?;
        let json = String::from_utf8(plaintext)
            .map_err(|e| VaultError::CryptoError(CryptoError::InvalidData(e.to_string())))?;
        let credentials: CredentialStore =
            serde_json::from_str(&json).map_err(|e| VaultError::InvalidOperation(e.to_string()))?;

        self.vault_file = Some(vault_file);
        self.master_key = Some(master_key);
        self.credentials = Some(credentials);
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(mut creds) = self.credentials.take() {
            creds.clear_all_passwords();
        }
        self.master_key = None;
    }

    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some() && self.credentials.is_some()
    }

    fn save(&mut self) -> VaultResult<()> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        let vault_file = self.vault_file.as_mut().ok_or(VaultError::VaultLocked)?;

        let json = serde_json::to_string(credentials)
            .map_err(|e| VaultError::InvalidOperation(e.to_string()))?;
        let encrypted = EncryptedData::encrypt(json.as_bytes(), master_key)?;
        vault_file.encrypted_data = encrypted.to_base64();
        vault_file.metadata.modified_at = Utc::now();

        self.storage.save(vault_file)?;
        Ok(())
    }

    pub fn add_credential(
        &mut self,
        service: String,
        username: String,
        password: SecureString,
        notes: Option<String>,
    ) -> VaultResult<()> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;

        let credential = Credential::new(service.clone(), username, password, notes, master_key)?;
        credentials.add(credential)?;

        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("ADD".to_string(), Some(service), true);
        }
        self.save()?;
        Ok(())
    }

    pub fn get_credential(&mut self, service: &str) -> VaultResult<Credential> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;

        let mut c = credentials.get(service)?.clone();
        c.decrypt_password(master_key)?;
        credentials.get_mut(service)?.last_accessed = Some(Utc::now());

        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("GET".to_string(), Some(service.to_string()), true);
        }
        self.save()?;
        Ok(c)
    }

    pub fn list_credentials(&self) -> VaultResult<Vec<Credential>> {
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(credentials.get_all().into_iter().cloned().collect())
    }

    pub fn remove_credential(&mut self, service: &str) -> VaultResult<()> {
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;
        credentials.remove(service)?;

        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("REMOVE".to_string(), Some(service.to_string()), true);
        }
        self.save()?;
        Ok(())
    }

    pub fn update_credential(
        &mut self,
        service: &str,
        username: Option<String>,
        password: Option<SecureString>,
        notes: Option<String>,
    ) -> VaultResult<()> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;
        let c = credentials.get_mut(service)?;

        if let Some(u) = username {
            c.username = u;
        }
        if let Some(pw) = password {
            c.update_password(pw, master_key)?;
        }
        if let Some(n) = notes {
            c.notes = Some(n);
        }

        c.modified_at = Utc::now();

        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("UPDATE".to_string(), Some(service.to_string()), true);
        }
        self.save()?;
        Ok(())
    }

    pub fn search_credentials(&self, query: &str) -> VaultResult<Vec<Credential>> {
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(credentials.search(query).into_iter().cloned().collect())
    }

    pub fn get_audit_log(&self) -> VaultResult<Vec<crate::storage::AuditEntry>> {
        let vf = self.vault_file.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(vf.audit_log.clone())
    }

    pub fn export(&self, path: &std::path::Path) -> VaultResult<()> {
        self.storage.backup(path)?;
        Ok(())
    }

    pub fn get_path(&self) -> &std::path::Path {
        self.storage.get_path()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}
