// ============================================================================
// CLI helpers called from main.rs command handlers
// ============================================================================
// This module contains all command implementations for the CLI interface.
// Each public function corresponds to a user-facing command and handles:
// - User interaction (prompts, confirmations)
// - Vault operations (unlock, modify credentials)
// - Output formatting and user feedback
// ============================================================================

use crate::audit::AuditLogger;
use crate::crypto::SecureString;
use crate::password_generator::{PasswordGenerator, PasswordOptions, PasswordStrength};
use crate::vault::Vault;

use clipboard::{ClipboardContext, ClipboardProvider};
use colored::Colorize;
use dialoguer::{Confirm, Password};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Vault Initialization Command
// ============================================================================

/// Initializes a new password vault with encryption.
///
/// # Arguments
/// * `path` - Optional custom path for vault storage. If None, uses default location.
///
/// # Process Flow
/// 1. Creates a new Vault instance at the specified or default path
/// 2. Checks if vault already exists to prevent accidental overwrites
/// 3. Prompts user for master password with confirmation
/// 4. Assesses password strength and warns if weak
/// 5. Derives encryption key from password using Argon2id
/// 6. Creates encrypted vault file with initial metadata
///
/// # Security Features
/// - Password confirmation to prevent typos
/// - Strength assessment with color-coded feedback
/// - Optional cancellation for weak passwords
/// - Progress indicator during key derivation (CPU-intensive operation)
///
/// # Returns
/// * `Ok(())` - Vault successfully initialized
/// * `Err` - If vault exists, weak password rejected, or encryption fails
pub fn init_vault(path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Print initialization banner
    println!(
        "{}",
        "🔐 Initializing new password vault...".bright_blue().bold()
    );

    // Create vault instance with custom or default path
    let mut vault = if let Some(p) = path {
        Vault::with_path(PathBuf::from(p))
    } else {
        Vault::new()?
    };

    // Prevent overwriting existing vault - safety check
    if vault.exists() {
        return Err(
            "Vault already exists! Use a different path or delete the existing vault.".into(),
        );
    }

    // Display password requirements to guide user
    println!("{}", "Create a strong master password:".yellow());
    println!("  • ≥12 chars, mix of cases, numbers, symbols\n");

    // Prompt for master password with confirmation to prevent typos
    // This is critical as a typo would make the vault permanently inaccessible
    let master = Password::new()
        .with_prompt("Enter master password")
        .with_confirmation("Confirm master password", "Passwords don't match")
        .interact()?;

    // Assess the strength of the chosen password
    let strength = PasswordGenerator::assess_strength(&master);

    // Display strength assessment with color coding
    println!(
        "{}: {}",
        "Password strength".bright_blue(),
        strength.as_str().color(strength.color()).bold()
    );

    // Warn user about weak passwords and allow cancellation
    if matches!(
        strength,
        PasswordStrength::VeryWeak | PasswordStrength::Weak
    ) {
        let ok = Confirm::new()
            .with_prompt("Password is weak. Continue anyway?")
            .default(false)
            .interact()?;
        if !ok {
            return Err("Vault initialization cancelled.".into());
        }
    }

    // Show progress indicator during key derivation
    // Argon2id is intentionally slow (CPU-intensive) for security
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Setting up encrypted vault...");
    pb.enable_steady_tick(Duration::from_millis(100));

    // Perform actual vault initialization:
    // - Generates random salt
    // - Derives encryption key using Argon2id
    // - Creates encrypted vault structure
    // - Saves to disk
    vault.initialize(&master)?;

    // Update progress indicator to show completion
    pb.finish_with_message("✓ Vault initialized".green().to_string());

    // Display vault location for user reference
    println!("📁 {}", vault.get_path().display().to_string().cyan());

    // Critical warning: master password cannot be recovered
    println!(
        "{}",
        "⚠️  Keep your master password safe; it cannot be recovered!"
            .yellow()
            .bold()
    );
    Ok(())
}

// ============================================================================
// Add Credential Command
// ============================================================================

/// Adds a new credential to the vault.
///
/// # Arguments
/// * `service` - Name of the service (e.g., "gmail", "github")
/// * `username` - Username or email for the service
/// * `generate` - If true, generate a secure password; if false, prompt user
/// * `length` - Length of generated password (only used if generate=true)
/// * `notes` - Optional notes about the credential
///
/// # Process Flow
/// 1. Loads existing vault from disk
/// 2. Prompts for master password to unlock vault
/// 3. Either generates or prompts for the credential password
/// 4. Encrypts and stores the credential
/// 5. Updates audit log
///
/// # Security Notes
/// - Vault must be unlocked before adding credentials
/// - Password is encrypted using AES-256-GCM before storage
/// - Master password is never stored, only verified
///
/// # Returns
/// * `Ok(())` - Credential successfully added
/// * `Err` - If vault locked, service exists, or encryption fails
pub fn add_credential(
    service: String,
    username: String,
    generate: bool,
    length: usize,
    notes: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load the vault from disk
    let mut vault = Vault::new()?;

    // Prompt for master password to unlock vault (verifies user identity)
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Obtain password: either generate or prompt user
    let password = if generate {
        // Generate a secure random password
        let mut opts = PasswordOptions::default();
        if length > 0 {
            opts.length = length;
        }
        SecureString::new(PasswordGenerator::generate(&opts)?)
    } else {
        // Prompt user to enter password with confirmation
        SecureString::new(
            Password::new()
                .with_prompt("Password for the credential")
                .with_confirmation("Confirm", "Passwords don't match")
                .interact()?,
        )
    };

    // Add credential to vault (encrypts password and stores)
    vault.add_credential(service.clone(), username, password, notes)?;

    // Confirm success to user
    println!("{}", format!("✓ Added '{}'", service).green());
    Ok(())
}

// ============================================================================
// Get Credential Command
// ============================================================================

/// Retrieves a credential from the vault.
///
/// # Arguments
/// * `service` - Name of the service to retrieve
/// * `copy` - If true, copy password to clipboard
/// * `show` - If true, display password in terminal (security risk)
///
/// # Process Flow
/// 1. Unlocks vault with master password
/// 2. Retrieves and decrypts the requested credential
/// 3. Displays service name and username
/// 4. Optionally shows or copies password based on flags
/// 5. Updates last_accessed timestamp
///
/// # Security Considerations
/// - Showing password in terminal is a security risk (shoulder surfing, logs)
/// - Clipboard access may expose password to other applications
/// - Password is decrypted in memory only when needed
///
/// # Returns
/// * `Ok(())` - Credential retrieved successfully
/// * `Err` - If vault locked, service not found, or decryption fails
pub fn get_credential(
    service: String,
    copy: bool,
    show: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Retrieve credential (decrypts password)
    let cred = vault.get_credential(&service)?;

    // Display basic credential information (always safe to show)
    println!(
        "Service: {}\nUsername: {}",
        cred.service.cyan(),
        cred.username.cyan()
    );

    // Get reference to decrypted password
    let pw_opt = cred.password.as_ref();

    // Show password in terminal if requested
    // WARNING: This is a security risk - password visible on screen
    if show {
        if let Some(pw) = pw_opt {
            println!("Password: {}", pw.as_str().bold());
        }
    }

    // Copy password to system clipboard if requested
    // More secure than showing, but still exposes to clipboard-monitoring apps
    if copy {
        if let Some(pw) = pw_opt {
            let mut ctx: ClipboardContext = ClipboardProvider::new()?;
            ctx.set_contents(pw.as_str().to_string())?;
            println!("{}", "✓ Password copied to clipboard".green());
        }
    }
    Ok(())
}

// ============================================================================
// List Credentials Command
// ============================================================================

/// Lists all credentials stored in the vault.
///
/// # Arguments
/// * `verbose` - If true, show detailed info (username, creation date)
///
/// # Display Modes
/// - Normal mode: Shows only service names
/// - Verbose mode: Shows service, username, and creation date
///
/// # Security
/// - Does not decrypt or display passwords
/// - Only shows metadata about credentials
///
/// # Returns
/// * `Ok(())` - List displayed successfully
/// * `Err` - If vault locked or read fails
pub fn list_credentials(verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Get list of all credentials (without decrypting passwords)
    let list = vault.list_credentials()?;

    // Handle empty vault case
    if list.is_empty() {
        println!("{}", "No credentials stored.".yellow());
        return Ok(());
    }

    // Display header
    println!("{}", "Stored credentials:".bright_blue().bold());

    // Iterate and display each credential
    for c in list {
        if verbose {
            // Verbose mode: show service, username, and creation date
            println!(
                "- {}  ({})  created: {}",
                c.service.cyan(),
                c.username,
                c.created_at.format("%Y-%m-%d")
            );
        } else {
            // Normal mode: show only service name
            println!("- {}", c.service.cyan());
        }
    }
    Ok(())
}

// ============================================================================
// Remove Credential Command
// ============================================================================

/// Removes a credential from the vault.
///
/// # Arguments
/// * `service` - Name of the service to remove
/// * `force` - If true, skip confirmation prompt
///
/// # Safety Features
/// - Requires confirmation by default to prevent accidental deletion
/// - Force flag allows automation/scripting
/// - Updates audit log with removal operation
///
/// # Returns
/// * `Ok(())` - Credential removed successfully
/// * `Err` - If vault locked, service not found, or deletion fails
pub fn remove_credential(service: String, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Prompt for confirmation unless force flag is set
    if !force {
        let ok = Confirm::new()
            .with_prompt(format!("Delete '{}' ?", service))
            .default(false)
            .interact()?;
        if !ok {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Remove credential from vault
    vault.remove_credential(&service)?;

    // Confirm deletion to user
    println!("{}", format!("✓ Removed '{}'", service).green());
    Ok(())
}

// ============================================================================
// Update Credential Command
// ============================================================================

/// Updates an existing credential in the vault.
///
/// # Arguments
/// * `service` - Name of the service to update
/// * `username` - Optional new username (None = no change)
/// * `generate` - If true, generate new password
/// * `notes` - Optional new notes (None = no change)
///
/// # Update Behavior
/// - Only specified fields are updated
/// - Password only updated if generate=true
/// - Updates modified_at timestamp
/// - Updates audit log
///
/// # Returns
/// * `Ok(())` - Credential updated successfully
/// * `Err` - If vault locked, service not found, or update fails
pub fn update_credential(
    service: String,
    username: Option<String>,
    generate: bool,
    notes: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Generate new password if requested
    let new_pw = if generate {
        Some(SecureString::new(PasswordGenerator::generate(
            &PasswordOptions::default(),
        )?))
    } else {
        None
    };

    // Update credential with provided fields
    vault.update_credential(&service, username, new_pw, notes)?;

    // Confirm update to user
    println!("{}", format!("✓ Updated '{}'", service).green());
    Ok(())
}

// ============================================================================
// Change Master Password Command
// ============================================================================

/// Changes the master password for the vault.
///
/// # Implementation Status
/// This feature is currently not implemented. When implemented, it will:
/// 1. Verify current master password
/// 2. Prompt for new master password
/// 3. Re-derive encryption key with new password
/// 4. Re-encrypt all credential data
/// 5. Update vault file with new key
///
/// # Complexity
/// This operation requires:
/// - Decrypting all credentials with old key
/// - Deriving new key from new password
/// - Re-encrypting all credentials with new key
/// - Atomic update to prevent data loss
///
/// # Returns
/// * `Ok(())` - Always (as it's not implemented)
pub fn change_master_password() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        "Change master password is not implemented yet.".yellow()
    );
    Ok(())
}

// ============================================================================
// Generate Password Utility Command
// ============================================================================

/// Generates one or more secure passwords without storing them.
///
/// # Arguments
/// * `length` - Length of generated password(s)
/// * `special` - Include special characters
/// * `numbers` - Include numeric digits
/// * `uppercase` - Include uppercase letters
/// * `count` - Number of passwords to generate
///
/// # Features
/// - Configurable character sets (uppercase, numbers, special)
/// - Cryptographically secure random generation
/// - Displays strength assessment for each password
/// - Color-coded strength indicators
///
/// # Use Cases
/// - Quick password generation without storing
/// - Testing password strength
/// - Generating passwords for external use
///
/// # Returns
/// * `Ok(())` - Passwords generated and displayed
/// * `Err` - If generation fails (invalid parameters)
pub fn generate_password(
    length: usize,
    special: bool,
    numbers: bool,
    uppercase: bool,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Configure password generation options
    let mut opts = PasswordOptions::default();
    if length > 0 {
        opts.length = length;
    }
    opts.include_special = special;
    opts.include_numbers = numbers;
    opts.include_uppercase = uppercase;

    // Generate and display requested number of passwords
    for i in 0..count.max(1) {
        // Generate a single password
        let pw = PasswordGenerator::generate(&opts)?;

        // Assess its strength
        let strength = PasswordGenerator::assess_strength(&pw);

        // Display password with numbering (if count > 1) and strength indicator
        println!(
            "{} {}  [{}]",
            if count > 1 {
                format!("{:>2}.", i + 1) // Numbered list
            } else {
                "  ".to_string() // No numbering for single password
            },
            pw.bold(),
            strength.as_str().color(strength.color()).bold()
        );
    }
    Ok(())
}

// ============================================================================
// Audit Log Command
// ============================================================================

/// Displays the audit log of vault operations.
///
/// # Arguments
/// * `limit` - Maximum number of recent entries to display
///
/// # Audit Log Contents
/// For each operation, logs:
/// - Timestamp of operation
/// - Type of operation (ADD, GET, REMOVE, UPDATE, INIT)
/// - Service name affected (if applicable)
/// - Success/failure status
///
/// # Security Value
/// - Helps detect unauthorized access attempts
/// - Tracks when credentials were accessed
/// - Provides accountability for vault operations
///
/// # Returns
/// * `Ok(())` - Audit log displayed successfully
/// * `Err` - If vault locked or log read fails
pub fn view_audit_log(limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Retrieve audit log entries
    let entries = vault.get_audit_log()?;

    // Display formatted audit log table
    AuditLogger::print(&entries, limit);
    Ok(())
}

// ============================================================================
// Export Vault Command
// ============================================================================

/// Exports the vault to a backup file.
///
/// # Arguments
/// * `output` - Path for the backup file (defaults to vault.backup.json)
///
/// # Export Details
/// - Creates an exact copy of the encrypted vault file
/// - Backup file is still encrypted (master password required to restore)
/// - Includes all credentials, metadata, and audit log
/// - Does not decrypt any data during export
///
/// # Use Cases
/// - Creating backups before major changes
/// - Transferring vault to another machine
/// - Archiving vault state
///
/// # Security
/// - Exported file maintains encryption
/// - Still requires master password to access
/// - Should be stored securely
///
/// # Returns
/// * `Ok(())` - Vault exported successfully
/// * `Err` - If vault not found or write fails
pub fn export_vault(output: String) -> Result<(), Box<dyn std::error::Error>> {
    // Get vault instance
    let vault = Vault::new()?;

    // Determine output path (use default if empty string provided)
    let default = vault.get_path().to_path_buf();
    let out = if output.trim().is_empty() {
        default.with_file_name("vault.backup.json")
    } else {
        PathBuf::from(output)
    };

    // Perform the export (copies encrypted file)
    vault.export(&out)?;

    // Confirm export to user
    println!("{}", format!("✓ Exported to {}", out.display()).green());
    Ok(())
}

// ============================================================================
// Import Vault Command
// ============================================================================

/// Imports a vault from a backup file.
///
/// # Arguments
/// * `input` - Path to the backup file to import
///
/// # Import Process
/// - Verifies source file exists
/// - Creates vault directory if needed
/// - Copies backup file to vault location
/// - Overwrites existing vault (be careful!)
///
/// # Warnings
/// - This will overwrite the current vault
/// - Imported vault uses its own master password
/// - No password verification during import (encryption prevents tampering)
///
/// # Returns
/// * `Ok(())` - Vault imported successfully
/// * `Err` - If source file not found or write fails
pub fn import_vault(input: String) -> Result<(), Box<dyn std::error::Error>> {
    // Verify source file exists
    let src = PathBuf::from(input);
    if !src.exists() {
        return Err("Input file does not exist".into());
    }

    // Get destination path
    let vault = Vault::new()?;
    let dst = vault.get_path().to_path_buf();

    // Ensure parent directory exists
    std::fs::create_dir_all(dst.parent().unwrap())?;

    // Copy backup to vault location
    std::fs::copy(&src, &dst)?;

    // Confirm import to user
    println!("{}", format!("✓ Imported into {}", dst.display()).green());
    Ok(())
}

// ============================================================================
// Search Credentials Command
// ============================================================================

/// Searches for credentials matching a query.
///
/// # Arguments
/// * `query` - Search string to match against credentials
///
/// # Search Scope
/// Searches in:
/// - Service names
/// - Usernames
/// - Notes field
///
/// # Search Behavior
/// - Case-insensitive matching
/// - Partial string matching (substring search)
/// - Returns all matching credentials
/// - Does not decrypt passwords
///
/// # Returns
/// * `Ok(())` - Search completed and results displayed
/// * `Err` - If vault locked or search fails
pub fn search_credentials(query: String) -> Result<(), Box<dyn std::error::Error>> {
    // Load and unlock vault
    let mut vault = Vault::new()?;
    let master = Password::new().with_prompt("Master password").interact()?;
    vault.unlock(&master)?;

    // Perform search
    let results = vault.search_credentials(&query)?;

    // Handle no results case
    if results.is_empty() {
        println!("{}", "No matches.".yellow());
        return Ok(());
    }

    // Display search results
    println!(
        "{}",
        format!("Matches for '{}':", query).bright_blue().bold()
    );
    for c in results {
        println!("- {} ({})", c.service.cyan(), c.username);
    }
    Ok(())
}
