// ============================================================================
// Vault Module
// ============================================================================
// This is the core business logic module that orchestrates all vault operations.
// It ties together:
// - Crypto module (encryption/decryption)
// - Storage module (file I/O)
// - Credential management (CRUD operations)
//
// Architecture:
// - Vault: Main interface, manages locked/unlocked state
// - CredentialStore: In-memory collection of credentials
// - Credential: Individual password entry with metadata
//
// Security Model:
// - Vault starts in locked state (no keys in memory)
// - User must provide master password to unlock
// - Master key derived from password on unlock
// - Credentials decrypted on-demand
// - All sensitive data zeroized on lock/drop
// ============================================================================

use crate::crypto::{CryptoError, EncryptedData, MasterKey, SecureString, StoredPasswordHash};
use crate::storage::{StorageError, VaultFile, VaultStorage};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Type alias for vault operation results
pub type VaultResult<T> = Result<T, VaultError>;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during vault operations
#[derive(Debug)]
pub enum VaultError {
    /// Storage layer error (file I/O, serialization)
    StorageError(StorageError),

    /// Cryptographic operation error (encryption, decryption, key derivation)
    CryptoError(CryptoError),

    /// Requested credential not found in vault
    CredentialNotFound(String),

    /// Attempting to add credential that already exists
    CredentialAlreadyExists(String),

    /// Master password verification failed
    InvalidMasterPassword,

    /// Operation requires unlocked vault but vault is locked
    VaultLocked,

    /// Invalid operation or parameters
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

/// Implement Error trait for VaultError
impl std::error::Error for VaultError {}

/// Convert StorageError to VaultError
impl From<StorageError> for VaultError {
    fn from(e: StorageError) -> Self {
        VaultError::StorageError(e)
    }
}

/// Convert CryptoError to VaultError
impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::CryptoError(e)
    }
}

// ============================================================================
// Credential Structure
// ============================================================================

/// Represents a single credential (password) entry in the vault.
///
/// # Fields
/// - id: Unique identifier (UUID v4)
/// - service: Service name (e.g., "gmail", "github") - used as key
/// - username: Username or email for the account
/// - password: Decrypted password (only present when in memory)
/// - encrypted_password: Base64-encoded encrypted password (stored on disk)
/// - notes: Optional free-form notes
/// - created_at: Creation timestamp
/// - modified_at: Last modification timestamp
/// - last_accessed: Last time password was retrieved
/// - tags: Categories/labels for organization
/// - url: Optional website URL
///
/// # Security Design
/// - password field is #[serde(skip)] so never serialized to disk
/// - Only encrypted_password is persisted
/// - Password is SecureString (zeroized on drop)
/// - Passwords decrypted on-demand, not kept in memory
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    /// Unique identifier for this credential
    pub id: String,

    /// Service name (used as primary key)
    pub service: String,

    /// Username or email
    pub username: String,

    /// Decrypted password (in-memory only, not serialized)
    #[serde(skip)]
    pub password: Option<SecureString>,

    /// Encrypted password (base64-encoded, persisted to disk)
    pub encrypted_password: String,

    /// Optional notes field
    pub notes: Option<String>,

    /// When credential was created
    pub created_at: DateTime<Utc>,

    /// When credential was last modified
    pub modified_at: DateTime<Utc>,

    /// When password was last accessed (retrieved)
    pub last_accessed: Option<DateTime<Utc>>,

    /// Tags for categorization
    pub tags: Vec<String>,

    /// Associated URL
    pub url: Option<String>,
}

impl Credential {
    /// Creates a new credential with encrypted password.
    ///
    /// # Arguments
    /// * `service` - Service name (unique identifier)
    /// * `username` - Username for this service
    /// * `password` - Plaintext password (will be encrypted)
    /// * `notes` - Optional notes
    /// * `key` - Master key for encryption
    ///
    /// # Process
    /// 1. Encrypts password using AES-256-GCM
    /// 2. Generates unique ID (UUID v4)
    /// 3. Sets timestamps to current time
    /// 4. Initializes metadata fields
    ///
    /// # Returns
    /// * `Ok(Credential)` - New credential with encrypted password
    /// * `Err(VaultError)` - If encryption fails
    pub fn new(
        service: String,
        username: String,
        password: SecureString,
        notes: Option<String>,
        key: &MasterKey,
    ) -> VaultResult<Self> {
        // Encrypt the password
        let encrypted = EncryptedData::encrypt(password.as_str().as_bytes(), key)?;

        let now = Utc::now();
        Ok(Self {
            // Generate unique ID
            id: Uuid::new_v4().to_string(),
            service,
            username,
            // Keep password in memory initially
            password: Some(password),
            // Store encrypted version
            encrypted_password: encrypted.to_base64(),
            notes,
            created_at: now,
            modified_at: now,
            last_accessed: None,
            tags: Vec::new(),
            url: None,
        })
    }

    /// Decrypts and loads the password into memory.
    ///
    /// # Arguments
    /// * `key` - Master key for decryption
    ///
    /// # Side Effects
    /// - Updates last_accessed timestamp
    /// - Stores decrypted password in self.password field
    ///
    /// # Returns
    /// * `Ok(SecureString)` - Decrypted password
    /// * `Err(VaultError)` - If decryption fails or data corrupted
    pub fn decrypt_password(&mut self, key: &MasterKey) -> VaultResult<SecureString> {
        // Decode from base64
        let encrypted = EncryptedData::from_base64(&self.encrypted_password)?;

        // Decrypt using master key
        let plaintext = encrypted.decrypt(key)?;

        // Convert bytes to UTF-8 string
        let password = String::from_utf8(plaintext)
            .map_err(|e| VaultError::CryptoError(CryptoError::InvalidData(e.to_string())))?;

        // Update access timestamp
        self.last_accessed = Some(Utc::now());

        // Store in memory
        self.password = Some(SecureString::new(password.clone()));

        Ok(SecureString::new(password))
    }

    /// Updates the password for this credential.
    ///
    /// # Arguments
    /// * `new_password` - New plaintext password
    /// * `key` - Master key for encryption
    ///
    /// # Side Effects
    /// - Encrypts new password
    /// - Updates encrypted_password field
    /// - Stores new password in memory
    /// - Updates modified_at timestamp
    ///
    /// # Returns
    /// * `Ok(())` - Password updated successfully
    /// * `Err(VaultError)` - If encryption fails
    pub fn update_password(
        &mut self,
        new_password: SecureString,
        key: &MasterKey,
    ) -> VaultResult<()> {
        // Encrypt the new password
        let encrypted = EncryptedData::encrypt(new_password.as_str().as_bytes(), key)?;

        // Update encrypted field
        self.encrypted_password = encrypted.to_base64();

        // Update in-memory password
        self.password = Some(new_password);

        // Update modification timestamp
        self.modified_at = Utc::now();

        Ok(())
    }

    /// Clears the decrypted password from memory.
    ///
    /// # Purpose
    /// Security measure to minimize time sensitive data stays in memory.
    /// Called when:
    /// - Vault is locked
    /// - Credential is no longer needed
    /// - Before dropping the credential
    ///
    /// # Note
    /// Encrypted password remains intact on disk
    pub fn clear_password(&mut self) {
        self.password = None;
    }
}

// ============================================================================
// Credential Store
// ============================================================================

/// In-memory collection of credentials.
///
/// # Structure
/// Uses HashMap with service name as key for O(1) lookups.
///
/// # Lifecycle
/// - Created when vault is unlocked
/// - Destroyed when vault is locked
/// - All passwords cleared before destruction
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialStore {
    /// HashMap: service_name -> Credential
    credentials: HashMap<String, Credential>,
}

impl CredentialStore {
    /// Creates a new empty credential store.
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Adds a credential to the store.
    ///
    /// # Arguments
    /// * `credential` - Credential to add
    ///
    /// # Returns
    /// * `Ok(())` - Credential added successfully
    /// * `Err(VaultError)` - If credential with same service already exists
    pub fn add(&mut self, credential: Credential) -> VaultResult<()> {
        // Check for duplicate service name
        if self.credentials.contains_key(&credential.service) {
            return Err(VaultError::CredentialAlreadyExists(
                credential.service.clone(),
            ));
        }

        // Insert into HashMap
        self.credentials
            .insert(credential.service.clone(), credential);
        Ok(())
    }

    /// Gets an immutable reference to a credential.
    ///
    /// # Arguments
    /// * `service` - Service name to lookup
    ///
    /// # Returns
    /// * `Ok(&Credential)` - Reference to credential
    /// * `Err(VaultError)` - If credential not found
    pub fn get(&self, service: &str) -> VaultResult<&Credential> {
        self.credentials
            .get(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    /// Gets a mutable reference to a credential.
    ///
    /// # Arguments
    /// * `service` - Service name to lookup
    ///
    /// # Returns
    /// * `Ok(&mut Credential)` - Mutable reference to credential
    /// * `Err(VaultError)` - If credential not found
    pub fn get_mut(&mut self, service: &str) -> VaultResult<&mut Credential> {
        self.credentials
            .get_mut(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    /// Removes a credential from the store.
    ///
    /// # Arguments
    /// * `service` - Service name to remove
    ///
    /// # Returns
    /// * `Ok(Credential)` - The removed credential
    /// * `Err(VaultError)` - If credential not found
    pub fn remove(&mut self, service: &str) -> VaultResult<Credential> {
        self.credentials
            .remove(service)
            .ok_or_else(|| VaultError::CredentialNotFound(service.to_string()))
    }

    /// Returns list of all service names.
    ///
    /// # Returns
    /// Vector of service name strings
    #[allow(dead_code)]
    pub fn list_services(&self) -> Vec<&str> {
        self.credentials.keys().map(|s| s.as_str()).collect()
    }

    /// Returns references to all credentials.
    ///
    /// # Returns
    /// Vector of credential references
    pub fn get_all(&self) -> Vec<&Credential> {
        self.credentials.values().collect()
    }

    /// Searches credentials by query string.
    ///
    /// # Arguments
    /// * `query` - Search string (case-insensitive)
    ///
    /// # Search Scope
    /// Searches in:
    /// - Service name
    /// - Username
    /// - Notes field
    ///
    /// # Returns
    /// Vector of matching credentials
    pub fn search(&self, query: &str) -> Vec<&Credential> {
        let q = query.to_lowercase();
        self.credentials
            .values()
            .filter(|c| {
                // Check if query matches service, username, or notes
                c.service.to_lowercase().contains(&q)
                    || c.username.to_lowercase().contains(&q)
                    || c.notes
                        .as_ref()
                        .map_or(false, |n| n.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Clears all decrypted passwords from memory.
    ///
    /// # Purpose
    /// Security measure called when locking vault.
    /// Removes sensitive data from memory while keeping encrypted data intact.
    pub fn clear_all_passwords(&mut self) {
        for c in self.credentials.values_mut() {
            c.clear_password();
        }
    }
}

// ============================================================================
// Vault - Main Interface
// ============================================================================

/// The main vault interface managing encrypted credential storage.
///
/// # State Machine
/// - Locked: No keys in memory, cannot access credentials
/// - Unlocked: Master key derived, can access/modify credentials
///
/// # Lifecycle
/// 1. Create vault instance
/// 2. Initialize (new vault) or unlock (existing vault)
/// 3. Perform operations (add, get, update, remove)
/// 4. Lock when done (or automatic on drop)
///
/// # Security
/// - Master key never persisted
/// - Credentials encrypted at rest
/// - Passwords decrypted on-demand
/// - Automatic memory cleanup on drop
pub struct Vault {
    /// Storage manager for file operations
    storage: VaultStorage,

    /// Master encryption key (only present when unlocked)
    master_key: Option<MasterKey>,

    /// In-memory credential collection (only present when unlocked)
    credentials: Option<CredentialStore>,

    /// Vault file structure (loaded when unlocked)
    vault_file: Option<VaultFile>,
}

impl Vault {
    /// Creates a new Vault instance using default path.
    ///
    /// # Note
    /// Vault is created in locked state. Call unlock() or initialize() next.
    ///
    /// # Returns
    /// * `Ok(Vault)` - New locked vault instance
    /// * `Err(VaultError)` - If default path cannot be determined
    pub fn new() -> VaultResult<Self> {
        let storage = VaultStorage::new()?;
        Ok(Self {
            storage,
            master_key: None,
            credentials: None,
            vault_file: None,
        })
    }

    /// Creates a Vault instance with custom path.
    ///
    /// # Arguments
    /// * `path` - Custom path for vault file
    ///
    /// # Returns
    /// New locked vault instance
    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            storage: VaultStorage::with_path(path),
            master_key: None,
            credentials: None,
            vault_file: None,
        }
    }

    /// Checks if vault file exists.
    ///
    /// # Returns
    /// * `true` - Vault file exists
    /// * `false` - No vault file at this path
    pub fn exists(&self) -> bool {
        self.storage.vault_exists()
    }

    /// Initializes a new vault with a master password.
    ///
    /// # Arguments
    /// * `master_password` - User's chosen master password
    ///
    /// # Process
    /// 1. Verify vault doesn't already exist
    /// 2. Generate random salt
    /// 3. Hash master password for verification
    /// 4. Derive master key from password
    /// 5. Create empty credential store
    /// 6. Encrypt and save to disk
    /// 7. Add INIT audit entry
    ///
    /// # Returns
    /// * `Ok(())` - Vault initialized and ready to use
    /// * `Err(VaultError)` - If vault exists or initialization fails
    pub fn initialize(&mut self, master_password: &str) -> VaultResult<()> {
        // Prevent overwriting existing vault
        if self.exists() {
            return Err(VaultError::StorageError(StorageError::VaultAlreadyExists));
        }

        // Generate random salt for key derivation
        let salt = crate::crypto::generate_salt();

        // Hash password for verification (not for encryption)
        let password_hash = StoredPasswordHash::new(master_password)?;

        // Create vault file structure
        let mut vault_file = VaultFile::new(password_hash, salt.clone());
        vault_file.add_audit_entry("INIT".to_string(), None, true);

        // Create empty credential store
        let credentials = CredentialStore::new();

        // Derive encryption key from password
        let master_key = MasterKey::derive_from_password(master_password, &salt)?;

        // Encrypt empty credential store
        let json = serde_json::to_string(&credentials)
            .map_err(|e| VaultError::InvalidOperation(e.to_string()))?;
        let encrypted = EncryptedData::encrypt(json.as_bytes(), &master_key)?;
        vault_file.encrypted_data = encrypted.to_base64();

        // Save to disk
        self.storage.save(&vault_file)?;

        // Set vault to unlocked state
        self.vault_file = Some(vault_file);
        self.master_key = Some(master_key);
        self.credentials = Some(credentials);

        Ok(())
    }

    /// Unlocks an existing vault with the master password.
    ///
    /// # Arguments
    /// * `master_password` - User's master password
    ///
    /// # Process
    /// 1. Load vault file from disk
    /// 2. Verify master password against stored hash
    /// 3. Derive master key from password
    /// 4. Decrypt credential data
    /// 5. Deserialize credentials
    /// 6. Set vault to unlocked state
    ///
    /// # Returns
    /// * `Ok(())` - Vault unlocked successfully
    /// * `Err(VaultError)` - If password wrong or decryption fails
    pub fn unlock(&mut self, master_password: &str) -> VaultResult<()> {
        // Load vault file
        let vault_file = self.storage.load()?;

        // Verify master password
        let pw_hash = StoredPasswordHash::from_string(vault_file.master_password_hash.clone());
        if !pw_hash.verify(master_password) {
            return Err(VaultError::InvalidMasterPassword);
        }

        // Get salt and derive key
        let salt = vault_file.get_salt()?;
        let master_key = MasterKey::derive_from_password(master_password, &salt)?;

        // Decrypt credential data
        let encrypted = EncryptedData::from_base64(&vault_file.encrypted_data)?;
        let plaintext = encrypted.decrypt(&master_key)?;

        // Deserialize credentials
        let json = String::from_utf8(plaintext)
            .map_err(|e| VaultError::CryptoError(CryptoError::InvalidData(e.to_string())))?;
        let credentials: CredentialStore =
            serde_json::from_str(&json).map_err(|e| VaultError::InvalidOperation(e.to_string()))?;

        // Set unlocked state
        self.vault_file = Some(vault_file);
        self.master_key = Some(master_key);
        self.credentials = Some(credentials);

        Ok(())
    }

    /// Locks the vault, clearing sensitive data from memory.
    ///
    /// # Security
    /// - Clears all decrypted passwords
    /// - Drops master key (zeroized automatically)
    /// - Drops credential store
    ///
    /// # Note
    /// Encrypted data remains on disk, untouched
    pub fn lock(&mut self) {
        // Clear passwords before dropping
        if let Some(mut creds) = self.credentials.take() {
            creds.clear_all_passwords();
        }

        // Drop master key (zeroized automatically)
        self.master_key = None;
    }

    /// Checks if vault is currently unlocked.
    ///
    /// # Returns
    /// * `true` - Vault is unlocked
    /// * `false` - Vault is locked
    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some() && self.credentials.is_some()
    }

    /// Saves the current vault state to disk.
    ///
    /// # Process
    /// 1. Verify vault is unlocked
    /// 2. Serialize credential store
    /// 3. Encrypt with master key
    /// 4. Update vault file
    /// 5. Write to disk atomically
    ///
    /// # Returns
    /// * `Ok(())` - Vault saved successfully
    /// * `Err(VaultError)` - If vault locked or save fails
    fn save(&mut self) -> VaultResult<()> {
        // Ensure vault is unlocked
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        let vault_file = self.vault_file.as_mut().ok_or(VaultError::VaultLocked)?;

        // Serialize credentials
        let json = serde_json::to_string(credentials)
            .map_err(|e| VaultError::InvalidOperation(e.to_string()))?;

        // Encrypt
        let encrypted = EncryptedData::encrypt(json.as_bytes(), master_key)?;
        vault_file.encrypted_data = encrypted.to_base64();

        // Update modification timestamp
        vault_file.metadata.modified_at = Utc::now();

        // Write to disk
        self.storage.save(vault_file)?;
        Ok(())
    }

    /// Adds a new credential to the vault.
    ///
    /// # Arguments
    /// * `service` - Service name (must be unique)
    /// * `username` - Username for this service
    /// * `password` - Password (will be encrypted)
    /// * `notes` - Optional notes
    ///
    /// # Returns
    /// * `Ok(())` - Credential added successfully
    /// * `Err(VaultError)` - If vault locked, service exists, or save fails
    pub fn add_credential(
        &mut self,
        service: String,
        username: String,
        password: SecureString,
        notes: Option<String>,
    ) -> VaultResult<()> {
        // Ensure vault is unlocked
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;

        // Create encrypted credential
        let credential = Credential::new(service.clone(), username, password, notes, master_key)?;

        // Add to store
        credentials.add(credential)?;

        // Add audit entry
        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("ADD".to_string(), Some(service), true);
        }

        // Save to disk
        self.save()?;
        Ok(())
    }

    /// Retrieves a credential from the vault.
    ///
    /// # Arguments
    /// * `service` - Service name to retrieve
    ///
    /// # Process
    /// - Finds credential
    /// - Decrypts password
    /// - Updates last_accessed timestamp
    /// - Saves vault
    ///
    /// # Returns
    /// * `Ok(Credential)` - Credential with decrypted password
    /// * `Err(VaultError)` - If vault locked or credential not found
    pub fn get_credential(&mut self, service: &str) -> VaultResult<Credential> {
        // Ensure vault is unlocked
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;

        // Get and decrypt credential
        let mut c = credentials.get(service)?.clone();
        c.decrypt_password(master_key)?;

        // Update access timestamp in store
        credentials.get_mut(service)?.last_accessed = Some(Utc::now());

        // Add audit entry
        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("GET".to_string(), Some(service.to_string()), true);
        }

        // Save vault
        self.save()?;
        Ok(c)
    }

    /// Lists all credentials in the vault.
    ///
    /// # Returns
    /// * `Ok(Vec<Credential>)` - List of all credentials (passwords not decrypted)
    /// * `Err(VaultError)` - If vault locked
    pub fn list_credentials(&self) -> VaultResult<Vec<Credential>> {
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(credentials.get_all().into_iter().cloned().collect())
    }

    /// Removes a credential from the vault.
    ///
    /// # Arguments
    /// * `service` - Service name to remove
    ///
    /// # Returns
    /// * `Ok(())` - Credential removed successfully
    /// * `Err(VaultError)` - If vault locked or credential not found
    pub fn remove_credential(&mut self, service: &str) -> VaultResult<()> {
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;
        credentials.remove(service)?;

        // Add audit entry
        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("REMOVE".to_string(), Some(service.to_string()), true);
        }

        self.save()?;
        Ok(())
    }

    /// Updates an existing credential.
    ///
    /// # Arguments
    /// * `service` - Service name to update
    /// * `username` - New username (None = no change)
    /// * `password` - New password (None = no change)
    /// * `notes` - New notes (None = no change)
    ///
    /// # Returns
    /// * `Ok(())` - Credential updated successfully
    /// * `Err(VaultError)` - If vault locked or credential not found
    pub fn update_credential(
        &mut self,
        service: &str,
        username: Option<String>,
        password: Option<SecureString>,
        notes: Option<String>,
    ) -> VaultResult<()> {
        // Ensure vault is unlocked
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultLocked)?;
        let credentials = self.credentials.as_mut().ok_or(VaultError::VaultLocked)?;
        let c = credentials.get_mut(service)?;

        // Update fields if provided
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

        // Add audit entry
        if let Some(vf) = &mut self.vault_file {
            vf.add_audit_entry("UPDATE".to_string(), Some(service.to_string()), true);
        }

        self.save()?;
        Ok(())
    }

    /// Searches for credentials matching a query.
    ///
    /// # Arguments
    /// * `query` - Search string (case-insensitive)
    ///
    /// # Returns
    /// * `Ok(Vec<Credential>)` - Matching credentials
    /// * `Err(VaultError)` - If vault locked
    pub fn search_credentials(&self, query: &str) -> VaultResult<Vec<Credential>> {
        let credentials = self.credentials.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(credentials.search(query).into_iter().cloned().collect())
    }

    /// Retrieves the audit log.
    ///
    /// # Returns
    /// * `Ok(Vec<AuditEntry>)` - List of audit entries
    /// * `Err(VaultError)` - If vault locked
    pub fn get_audit_log(&self) -> VaultResult<Vec<crate::storage::AuditEntry>> {
        let vf = self.vault_file.as_ref().ok_or(VaultError::VaultLocked)?;
        Ok(vf.audit_log.clone())
    }

    /// Exports the vault to a backup file.
    ///
    /// # Arguments
    /// * `path` - Where to save the backup
    ///
    /// # Returns
    /// * `Ok(())` - Backup created successfully
    /// * `Err(VaultError)` - If backup fails
    pub fn export(&self, path: &std::path::Path) -> VaultResult<()> {
        self.storage.backup(path)?;
        Ok(())
    }

    /// Returns the vault file path.
    pub fn get_path(&self) -> &std::path::Path {
        self.storage.get_path()
    }
}

/// Automatically lock vault when dropped.
///
/// This ensures sensitive data is cleared from memory even if
/// the user forgets to explicitly lock the vault.
impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}
