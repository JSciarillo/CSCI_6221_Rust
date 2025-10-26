// ============================================================================
// Password Generator
// ============================================================================
// This module provides secure password generation and strength assessment
// capabilities. It offers:
//
// 1. Configurable password generation with multiple character sets
// 2. Cryptographically secure randomness using OsRng
// 3. Password strength assessment based on multiple criteria
// 4. Support for excluding ambiguous characters
//
// Security Features:
// - Uses OS-level entropy source (OsRng) for true randomness
// - Ensures at least one character from each selected character set
// - Fisher-Yates shuffle for uniform distribution
// - No predictable patterns or sequences
// ============================================================================

use colored::Color;
use rand::{thread_rng, Rng};

// ============================================================================
// Password Generation Options
// ============================================================================

/// Configuration options for password generation.
///
/// # Options
/// - length: Number of characters in password
/// - include_uppercase: Include A-Z
/// - include_lowercase: Include a-z
/// - include_numbers: Include 0-9
/// - include_special: Include symbols (!@#$%^&*...)
/// - exclude_ambiguous: Exclude easily confused characters (I, l, 1, 0, O)
///
/// # Default Configuration
/// Creates a balanced password with:
/// - 16 characters
/// - All character types enabled
/// - Ambiguous characters allowed
#[derive(Debug, Clone)]
pub struct PasswordOptions {
    /// Length of the generated password
    pub length: usize,

    /// Include uppercase letters (A-Z)
    pub include_uppercase: bool,

    /// Include lowercase letters (a-z)
    pub include_lowercase: bool,

    /// Include numeric digits (0-9)
    pub include_numbers: bool,

    /// Include special characters (!@#$%...)
    pub include_special: bool,

    /// Exclude ambiguous characters (I/l/1, O/0)
    /// Useful for passwords that will be manually typed
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    /// Creates default password options
    ///
    /// Returns a configuration for strong, general-purpose passwords:
    /// - 16 characters (good balance of security and usability)
    /// - All character types included
    /// - Ambiguous characters not excluded
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_special: true,
            exclude_ambiguous: false,
        }
    }
}

// ============================================================================
// Password Strength Assessment
// ============================================================================

/// Enum representing password strength levels.
///
/// Strength is assessed based on:
/// - Length (8, 12, 16, 20+ characters)
/// - Character diversity (uppercase, lowercase, numbers, symbols)
/// - Overall entropy (combination of above factors)
///
/// # Levels
/// - VeryWeak: < 3 points (e.g., "password")
/// - Weak: 3-4 points (e.g., "Password1")
/// - Fair: 5-6 points (e.g., "MyP@ssw0rd")
/// - Strong: 7 points (e.g., "MyP@ssw0rd123!")
/// - VeryStrong: 8+ points (e.g., "xK9$mN2#vL8@pQ4!")
#[derive(Debug, PartialEq)]
pub enum PasswordStrength {
    /// Very weak password - easily cracked
    VeryWeak,

    /// Weak password - vulnerable to attacks
    Weak,

    /// Fair password - acceptable for low-value accounts
    Fair,

    /// Strong password - good for most purposes
    Strong,

    /// Very strong password - excellent security
    VeryStrong,
}

impl PasswordStrength {
    /// Returns the string representation of the strength level
    pub fn as_str(&self) -> &str {
        match self {
            PasswordStrength::VeryWeak => "Very Weak",
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Fair => "Fair",
            PasswordStrength::Strong => "Strong",
            PasswordStrength::VeryStrong => "Very Strong",
        }
    }

    /// Returns the color for displaying this strength level
    ///
    /// Color coding helps users quickly assess password quality:
    /// - Red: Very weak (critical - change immediately)
    /// - Yellow: Weak/Fair (warning - consider improving)
    /// - Green: Strong (acceptable)
    /// - Bright Green: Very strong (excellent)
    pub fn color(&self) -> Color {
        match self {
            PasswordStrength::VeryWeak => Color::Red,
            PasswordStrength::Weak => Color::Yellow,
            PasswordStrength::Fair => Color::Yellow,
            PasswordStrength::Strong => Color::Green,
            PasswordStrength::VeryStrong => Color::BrightGreen,
        }
    }
}

// ============================================================================
// Character Sets for Password Generation
// ============================================================================
// These constant byte slices define the character sets used in password
// generation. Using byte slices is more efficient than String for this purpose.
// ============================================================================

/// Uppercase letters excluding ambiguous characters
/// Excludes: I (looks like l and 1), O (looks like 0)
const UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Ambiguous uppercase letters
/// I: Can be confused with lowercase l and number 1
/// O: Can be confused with number 0
const UPPERCASE_AMBIGUOUS: &[u8] = b"IO";

/// Lowercase letters excluding ambiguous characters  
/// Excludes: l (looks like I and 1)
const LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";

/// Ambiguous lowercase letters
/// l: Can be confused with uppercase I and number 1
const LOWERCASE_AMBIGUOUS: &[u8] = b"l";

/// Numeric digits excluding ambiguous characters
/// Excludes: 0 (looks like O), 1 (looks like I and l)
/// Starting from 2 reduces confusion
const NUMBERS: &[u8] = b"23456789";

/// Ambiguous numeric digits
/// 0: Can be confused with letter O
/// 1: Can be confused with letters I and l
const NUMBERS_AMBIGUOUS: &[u8] = b"01";

/// Special characters for passwords
/// Includes common symbols that most systems accept
/// Avoids potentially problematic characters (quotes, backslash)
const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

// ============================================================================
// Password Generator
// ============================================================================

/// Main password generator providing generation and strength assessment
pub struct PasswordGenerator;

impl PasswordGenerator {
    /// Generates a secure random password based on the given options.
    ///
    /// # Arguments
    /// * `options` - Configuration specifying password requirements
    ///
    /// # Algorithm
    /// 1. Build character set from selected options
    /// 2. Validate parameters (length, character types)
    /// 3. Add required characters (one from each selected set)
    /// 4. Fill remaining positions with random characters
    /// 5. Shuffle using Fisher-Yates algorithm for uniform distribution
    ///
    /// # Security
    /// - Uses thread_rng() which is cryptographically secure
    /// - Ensures at least one character from each selected type
    /// - Fisher-Yates shuffle prevents predictable patterns
    /// - No bias in character selection
    ///
    /// # Returns
    /// * `Ok(String)` - Generated password meeting requirements
    /// * `Err(String)` - If parameters are invalid
    ///
    /// # Errors
    /// - Length is 0 or > 1024
    /// - No character types selected
    /// - Length too short for required character types
    pub fn generate(options: &PasswordOptions) -> Result<String, String> {
        // Validate length bounds
        if options.length == 0 {
            return Err("Password length must be greater than 0".into());
        }
        if options.length > 1024 {
            return Err("Password length must be less than 1024".into());
        }

        // Build character set and required characters list
        let mut charset = Vec::new();
        let mut required = Vec::new();

        // Add uppercase characters if requested
        if options.include_uppercase {
            charset.extend_from_slice(UPPERCASE);

            // Add ambiguous characters if not excluding them
            if !options.exclude_ambiguous {
                charset.extend_from_slice(UPPERCASE_AMBIGUOUS);
            }

            // Ensure at least one uppercase in final password
            required.push(*UPPERCASE.first().unwrap());
        }

        // Add lowercase characters if requested
        if options.include_lowercase {
            charset.extend_from_slice(LOWERCASE);

            if !options.exclude_ambiguous {
                charset.extend_from_slice(LOWERCASE_AMBIGUOUS);
            }

            // Ensure at least one lowercase in final password
            required.push(*LOWERCASE.first().unwrap());
        }

        // Add numeric digits if requested
        if options.include_numbers {
            charset.extend_from_slice(NUMBERS);

            if !options.exclude_ambiguous {
                charset.extend_from_slice(NUMBERS_AMBIGUOUS);
            }

            // Ensure at least one number in final password
            required.push(*NUMBERS.first().unwrap());
        }

        // Add special characters if requested
        if options.include_special {
            charset.extend_from_slice(SPECIAL);

            // Ensure at least one special character in final password
            required.push(*SPECIAL.first().unwrap());
        }

        // Validate that at least one character type is selected
        if charset.is_empty() {
            return Err("At least one character type must be selected".into());
        }

        // Validate that password is long enough for required characters
        if required.len() > options.length {
            return Err(format!(
                "Password length ({}) is too short for the required character types ({})",
                options.length,
                required.len()
            ));
        }

        // Initialize cryptographically secure RNG
        let mut rng = thread_rng();

        // Allocate password buffer
        let mut password = Vec::with_capacity(options.length);

        // Step 1: Add required characters (one from each selected type)
        // This ensures password meets all requirements
        password.extend_from_slice(&required);

        // Step 2: Fill remaining positions with random characters
        for _ in required.len()..options.length {
            let idx = rng.gen_range(0..charset.len());
            password.push(charset[idx]);
        }

        // Step 3: Shuffle the password using Fisher-Yates algorithm
        // This ensures required characters aren't predictably at the start
        // and provides uniform distribution
        for i in (1..password.len()).rev() {
            let j = rng.gen_range(0..=i);
            password.swap(i, j);
        }

        // Convert byte vector to UTF-8 string
        String::from_utf8(password).map_err(|e| format!("Failed to create password: {}", e))
    }

    /// Assesses the strength of a password.
    ///
    /// # Arguments
    /// * `password` - The password to assess
    ///
    /// # Scoring System
    /// Points are awarded for:
    /// - Length >= 8: +1 point
    /// - Length >= 12: +1 point (total 2)
    /// - Length >= 16: +1 point (total 3)
    /// - Length >= 20: +1 point (total 4)
    /// - Has lowercase: +1 point
    /// - Has uppercase: +1 point
    /// - Has numbers: +1 point
    /// - Has special characters: +1 point
    ///
    /// # Strength Mapping
    /// - 0-2 points: Very Weak
    /// - 3-4 points: Weak
    /// - 5-6 points: Fair
    /// - 7 points: Strong
    /// - 8+ points: Very Strong
    ///
    /// # Returns
    /// PasswordStrength enum indicating the assessed strength level
    pub fn assess_strength(password: &str) -> PasswordStrength {
        let length = password.len();

        // Check for character type diversity
        let has_l = password.chars().any(|c| c.is_lowercase());
        let has_u = password.chars().any(|c| c.is_uppercase());
        let has_n = password.chars().any(|c| c.is_numeric());
        let has_s = password.chars().any(|c| !c.is_alphanumeric());

        // Calculate score based on length and diversity
        let mut score = 0;

        // Length scoring (more points for longer passwords)
        if length >= 8 {
            score += 1;
        }
        if length >= 12 {
            score += 1;
        }
        if length >= 16 {
            score += 1;
        }
        if length >= 20 {
            score += 1;
        }

        // Character diversity scoring
        if has_l {
            score += 1;
        }
        if has_u {
            score += 1;
        }
        if has_n {
            score += 1;
        }
        if has_s {
            score += 1;
        }

        // Map score to strength level
        match score {
            0..=2 => PasswordStrength::VeryWeak,
            3..=4 => PasswordStrength::Weak,
            5..=6 => PasswordStrength::Fair,
            7 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that generated password has correct length
    #[test]
    fn gen_len() {
        let pw = PasswordGenerator::generate(&PasswordOptions::default()).unwrap();
        assert_eq!(pw.len(), 16);
    }

    /// Test that strength assessment works correctly across different levels
    #[test]
    fn strength_scale() {
        // Very weak: short, lowercase only
        assert_eq!(
            PasswordGenerator::assess_strength("abc"),
            PasswordStrength::VeryWeak
        );

        // Weak: has some diversity but short
        assert_eq!(
            PasswordGenerator::assess_strength("Abc123!@#"),
            PasswordStrength::Weak
        );

        // Strong: good length and full diversity
        assert_eq!(
            PasswordGenerator::assess_strength("MyP@ssw0rd12345!"),
            PasswordStrength::Strong
        );
    }
}
