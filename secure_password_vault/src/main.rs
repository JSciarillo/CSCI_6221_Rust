// ============================================================================
// Secure Password Vault - Main Entry Point
// ============================================================================
// A local password manager built with Rust for maximum security
// Authors: Owen Chibanda, Jasmine Sciarillo, Aryan Bhosale
// Course: CSCI 6221 - Advanced Software Paradigms
// ============================================================================
//
// This is the main entry point for the Secure Password Vault CLI application.
// It handles:
// - Command-line argument parsing using clap
// - Routing commands to appropriate handlers in cli module
// - Error handling and user-friendly error messages
// - Application banner display
//
// Architecture:
// - main.rs: Entry point, CLI structure, command routing
// - cli.rs: Command implementations (user interaction)
// - vault.rs: Core vault operations (business logic)
// - crypto.rs: Cryptographic primitives (security)
// - storage.rs: Disk I/O and serialization
// - audit.rs: Audit log formatting
// - password_generator.rs: Password generation utilities
// ============================================================================

// Module declarations - tells Rust about other source files
mod audit; // Audit log display utilities
mod cli; // CLI command implementations
mod crypto; // Cryptographic operations
mod password_generator; // Password generation and strength assessment
mod storage; // Vault file I/O and serialization
mod vault; // Core vault business logic

// External crate imports
use clap::{Parser, Subcommand}; // Command-line argument parsing
use colored::*; // Terminal color output
use std::process; // Process control (exit codes)

// ============================================================================
// CLI Structure Definitions
// ============================================================================
// These structs define the command-line interface using clap's derive macros.
// The structure mirrors the actual CLI: vault <command> [options]
// ============================================================================

/// Main CLI structure representing the entire application.
///
/// # Derive Macros
/// - Parser: Generates CLI parser from struct definition
///
/// # Attributes
/// - command(name): Sets the program name shown in help text
/// - command(author): Sets author information
/// - command(version): Sets version number
/// - command(about): Short description for --help
/// - command(long_about): Detailed description (currently None)
#[derive(Parser)]
#[command(name = "Secure Password Vault")]
#[command(author = "Owen Chibanda, Jasmine Sciarillo, Aryan Bhosale")]
#[command(version = "1.0.0")]
#[command(about = "A secure local password manager", long_about = None)]
struct Cli {
    /// The subcommand to execute (init, add, get, etc.)
    #[command(subcommand)]
    command: Commands,
}

// ============================================================================
// Command Definitions
// ============================================================================
// Each variant represents a subcommand with its specific options.
//
// Common patterns:
// - #[arg(short, long)]: Creates both short (-x) and long (--xxx) flags
// - #[arg(default_value = "...")]: Provides default if not specified
// - Option<T>: Optional arguments that may not be provided
// ============================================================================

/// Enum defining all available subcommands.
///
/// Each variant corresponds to a command the user can run:
/// - vault init: Create new vault
/// - vault add: Add credential
/// - vault get: Retrieve credential
/// - etc.
#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    ///
    /// # Usage
    /// vault init [--path /custom/path]
    ///
    /// # Process
    /// 1. Prompts for master password
    /// 2. Derives encryption key using Argon2id
    /// 3. Creates encrypted vault file
    /// 4. Sets up audit log
    Init {
        /// Path to store the vault (optional, uses default location if not specified)
        ///
        /// Default location varies by OS:
        /// - Linux: ~/.local/share/secure_password_vault/vault.json
        /// - macOS: ~/Library/Application Support/secure_password_vault/vault.json
        /// - Windows: C:\Users\<user>\AppData\Local\secure_password_vault\vault.json
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Add a new credential to the vault
    ///
    /// # Usage
    /// vault add <service> --username <user> [options]
    ///
    /// # Examples
    /// - vault add gmail --username user@gmail.com
    /// - vault add github --username myuser --generate
    /// - vault add server --username admin --generate --length 20 --notes "Production server"
    Add {
        /// Service name (e.g., "gmail", "github")
        ///
        /// This is a positional argument (required, not a flag).
        /// Used as the unique identifier for this credential.
        service: String,

        /// Username or email
        ///
        /// The username/email associated with this service.
        /// Required field that identifies the account.
        #[arg(short, long)]
        username: String,

        /// Generate a secure password instead of providing one
        ///
        /// If set, automatically generates a cryptographically secure
        /// random password instead of prompting the user.
        #[arg(short, long)]
        generate: bool,

        /// Password length for generation (default: 16)
        ///
        /// Only used when --generate is set.
        /// Specifies how many characters the generated password should have.
        #[arg(short, long, default_value = "16")]
        length: usize,

        /// Additional notes (optional)
        ///
        /// Free-form text field for storing additional information
        /// such as security questions, account numbers, etc.
        #[arg(short, long)]
        notes: Option<String>,
    },

    /// Retrieve a credential from the vault
    ///
    /// # Usage
    /// vault get <service> [--copy] [--show]
    ///
    /// # Security Warning
    /// Using --show displays the password in terminal which is a security risk:
    /// - Visible to anyone looking at screen (shoulder surfing)
    /// - May be saved in terminal scrollback buffer
    /// - Could be in terminal logs
    ///
    /// Prefer using --copy to copy to clipboard instead.
    Get {
        /// Service name to retrieve
        ///
        /// Must match exactly the service name used when adding.
        service: String,

        /// Copy password to clipboard
        ///
        /// More secure than --show as password is not displayed.
        /// Password is placed in system clipboard for pasting.
        #[arg(short, long)]
        copy: bool,

        /// Show password in terminal (security risk!)
        ///
        /// WARNING: Displays password in plaintext on screen.
        /// Only use in secure, private environments.
        #[arg(short, long)]
        show: bool,
    },

    /// List all stored credentials
    ///
    /// # Usage
    /// vault list [--verbose]
    ///
    /// # Display
    /// - Normal: Shows only service names
    /// - Verbose: Shows service, username, and creation date
    ///
    /// Note: Passwords are never displayed in list output
    List {
        /// Show detailed information
        ///
        /// When set, displays:
        /// - Service name
        /// - Username
        /// - Creation timestamp
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove a credential from the vault
    ///
    /// # Usage
    /// vault remove <service> [--force]
    ///
    /// # Safety
    /// By default, prompts for confirmation before deleting.
    /// Use --force to skip confirmation (for scripts/automation).
    Remove {
        /// Service name to remove
        service: String,

        /// Skip confirmation prompt
        ///
        /// Dangerous: Immediately deletes without asking.
        /// Use with caution, especially in scripts.
        #[arg(short, long)]
        force: bool,
    },

    /// Update an existing credential
    ///
    /// # Usage
    /// vault update <service> [options]
    ///
    /// # Behavior
    /// Only specified fields are updated.
    /// Omitted fields remain unchanged.
    Update {
        /// Service name to update
        service: String,

        /// New username (optional)
        ///
        /// If provided, replaces the existing username.
        /// If omitted, username remains unchanged.
        #[arg(short, long)]
        username: Option<String>,

        /// Generate new password
        ///
        /// If set, generates and sets a new random password.
        /// Replaces the existing password.
        #[arg(short, long)]
        generate: bool,

        /// New notes (optional)
        ///
        /// If provided, replaces existing notes.
        /// If omitted, notes remain unchanged.
        #[arg(short, long)]
        notes: Option<String>,
    },

    /// Change the master password
    ///
    /// # Status
    /// Currently not implemented.
    ///
    /// # Future Implementation
    /// When implemented, will:
    /// 1. Verify current master password
    /// 2. Prompt for new master password
    /// 3. Re-derive encryption key
    /// 4. Re-encrypt all credentials with new key
    /// 5. Update vault file atomically
    ChangeMaster,

    /// Generate a secure password
    ///
    /// # Usage
    /// vault generate [options]
    ///
    /// # Use Case
    /// Generates passwords without storing them in the vault.
    /// Useful for:
    /// - Quick password generation
    /// - Testing password strength
    /// - Generating passwords for external use
    Generate {
        /// Length of the password
        ///
        /// Number of characters in generated password.
        /// Longer passwords are more secure.
        #[arg(short, long, default_value = "16")]
        length: usize,

        /// Include special characters
        ///
        /// Adds symbols like !@#$%^&*() to character set.
        /// Increases entropy and meets most password requirements.
        #[arg(short, long, default_value = "true")]
        special: bool,

        /// Include numbers
        ///
        /// Adds digits 0-9 to character set.
        /// Most services require at least one number.
        #[arg(short, long, default_value = "true")]
        numbers: bool,

        /// Include uppercase letters
        ///
        /// Adds A-Z to character set.
        /// Most services require mixed case.
        #[arg(short, long, default_value = "true")]
        uppercase: bool,

        /// Number of passwords to generate
        ///
        /// Generates multiple passwords at once.
        /// Useful for comparing options or batch generation.
        #[arg(short, long, default_value = "1")]
        count: usize,
    },

    /// View audit log of vault operations
    ///
    /// # Usage
    /// vault audit [--limit 10]
    ///
    /// # Purpose
    /// Shows history of vault operations including:
    /// - Timestamp of each operation
    /// - Type of operation (ADD, GET, REMOVE, etc.)
    /// - Service affected
    /// - Success/failure status
    ///
    /// # Security Value
    /// Helps detect:
    /// - Unauthorized access attempts
    /// - Suspicious activity patterns
    /// - When credentials were last accessed
    Audit {
        /// Number of recent entries to show
        ///
        /// Limits output to most recent N entries.
        /// Useful for quick checks without scrolling through entire log.
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Export vault (encrypted backup)
    ///
    /// # Usage
    /// vault export --output /path/to/backup.json
    ///
    /// # Security
    /// - Exported file remains encrypted
    /// - Still requires master password to restore
    /// - Creates exact copy of vault file
    ///
    /// # Use Cases
    /// - Regular backups
    /// - Transferring to another machine
    /// - Archiving vault state before changes
    Export {
        /// Output file path
        ///
        /// Where to save the backup file.
        /// Recommended: Use .json extension
        #[arg(short, long)]
        output: String,
    },

    /// Import vault from backup
    ///
    /// # Usage
    /// vault import --input /path/to/backup.json
    ///
    /// # Warning
    /// This OVERWRITES the current vault!
    /// Make sure to backup current vault first if needed.
    ///
    /// # Process
    /// Copies the backup file to the vault location.
    /// The imported vault uses its own master password.
    Import {
        /// Input file path
        ///
        /// Path to the backup file to import.
        /// Must be a valid encrypted vault file.
        #[arg(short, long)]
        input: String,
    },

    /// Search for credentials
    ///
    /// # Usage
    /// vault search <query>
    ///
    /// # Search Scope
    /// Searches in:
    /// - Service names
    /// - Usernames  
    /// - Notes field
    ///
    /// # Behavior
    /// - Case-insensitive
    /// - Partial matching (substring search)
    /// - Returns all matches
    /// - Does not display passwords
    Search {
        /// Search query
        ///
        /// Text to search for across credentials.
        /// Example: "google" matches "google.com", "google-cloud", etc.
        query: String,
    },
}

// ============================================================================
// Main Function
// ============================================================================

/// Application entry point.
///
/// # Process Flow
/// 1. Parse command-line arguments using clap
/// 2. Display application banner
/// 3. Route to appropriate command handler
/// 4. Execute command and capture result
/// 5. Handle errors gracefully with user-friendly messages
/// 6. Exit with appropriate status code
///
/// # Error Handling
/// - Success: Exits with code 0
/// - Error: Prints error message in red and exits with code 1
fn main() {
    // Parse command-line arguments
    // If parsing fails (e.g., invalid arguments), clap handles error display
    // and exits automatically with usage information
    let cli = Cli::parse();

    // Print banner - visual identifier for the application
    print_banner();

    // Execute the appropriate command based on parsed arguments
    // Pattern matching on Commands enum routes to correct handler
    let result = match cli.command {
        // Vault initialization
        Commands::Init { path } => cli::init_vault(path),

        // Add new credential
        Commands::Add {
            service,
            username,
            generate,
            length,
            notes,
        } => cli::add_credential(service, username, generate, length, notes),

        // Retrieve credential
        Commands::Get {
            service,
            copy,
            show,
        } => cli::get_credential(service, copy, show),

        // List all credentials
        Commands::List { verbose } => cli::list_credentials(verbose),

        // Remove credential
        Commands::Remove { service, force } => cli::remove_credential(service, force),

        // Update credential
        Commands::Update {
            service,
            username,
            generate,
            notes,
        } => cli::update_credential(service, username, generate, notes),

        // Change master password (not implemented)
        Commands::ChangeMaster => cli::change_master_password(),

        // Generate password
        Commands::Generate {
            length,
            special,
            numbers,
            uppercase,
            count,
        } => cli::generate_password(length, special, numbers, uppercase, count),

        // View audit log
        Commands::Audit { limit } => cli::view_audit_log(limit),

        // Export vault
        Commands::Export { output } => cli::export_vault(output),

        // Import vault
        Commands::Import { input } => cli::import_vault(input),

        // Search credentials
        Commands::Search { query } => cli::search_credentials(query),
    };

    // Handle errors gracefully
    // If command returns an error, print it in red and exit with failure code
    if let Err(e) = result {
        // Print error message with red "Error:" prefix
        eprintln!("{} {}", "Error:".red().bold(), e);

        // Exit with non-zero status code to indicate failure
        // This allows scripts to detect command failures
        process::exit(1);
    }

    // If we reach here, command succeeded
    // Implicit exit with code 0 (success)
}

// ============================================================================
// Banner Display
// ============================================================================

/// Print application banner
///
/// # Purpose
/// Displays visual branding and application information when running commands.
/// Uses Unicode box-drawing characters for professional appearance.
///
/// # Design
/// - Cyan color scheme for visibility
/// - Emoji icons for visual appeal (🔐 = security, 🦀 = Rust)
/// - Contains title, tagline, and author credits
fn print_banner() {
    // Top border
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );

    // Title with emoji icons
    println!(
        "{}",
        "║        🔐 Secure Password Vault - Rust Edition 🦀          ║"
            .cyan()
            .bold()
    );

    // Spacing line
    println!(
        "{}",
        "║                                                              ║".cyan()
    );

    // Tagline describing application purpose
    println!(
        "{}",
        "║  A local password manager with military-grade encryption    ║".cyan()
    );

    // Author credits
    println!(
        "{}",
        "║  Authors: Owen Chibanda, Jasmine Sciarillo, Aryan Bhosale   ║".cyan()
    );

    // Bottom border
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );

    // Empty line for spacing before command output
    println!();
}
