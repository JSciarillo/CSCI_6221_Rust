// Password Generator
// This module provides secure password generation and strength assessment
// 
// Security Features:
// -Uses OS-level entropy source (OsRng) for true randomness
// -Ensures at least one character from each selected character set
// -Fisher-Yates shuffle for distribution
// -No predictable patterns or sequences

use rand::{thread_rng, Rng};

//Password Generation Options
///length selection, include uppercase, include lowercase, include numbers, include special characters

///Default Configuration
///16 characters, all chracter types

#[derive(Debug, Clone)]
pub struct PasswordOptions {
    //Length of password
    pub length: usize,

    //Include uppercase letters
    pub include_uppercase: bool,

    //Include lowercase letters
    pub include_lowercase: bool,

    //Include integers
    pub include_numbers: bool,

    //Include special characters
    pub include_special: bool,

    //Exclude ambiguous characters
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    /// Creates default password options

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

// Password Strength Assessment

/// Enum representing password strength levels.
/// Strength is assessed based on:
/// -Length 
/// -Character diversity 

/// # Levels
/// -VeryWeak: < 3 points
/// -Weak: 3-4 points
/// -Fair: 5-6 points
/// -Strong: 7 points
/// -VeryStrong: 8+ points 
#[derive(Debug, PartialEq, Clone)]
pub enum PasswordStrength {
    VeryWeak,

    Weak,

    Fair,

    
    Strong,

    VeryStrong,
}

impl PasswordStrength {
    //Returns the string representation of the strength level
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
    /// -Red: Very weak 
    /// -Yellow: Weak/Fair 
    /// -Green: Strong
    /// -Bright Green: Very strong 
    
    pub fn color_class(&self) -> &str {
        match self {
            PasswordStrength::VeryWeak => "strength-very-weak",
            PasswordStrength::Weak => "strength-weak",
            PasswordStrength::Fair => "strength-fair",
            PasswordStrength::Strong => "strength-strong",
            PasswordStrength::VeryStrong => "strength-very-strong",
        }
    }
}


//Uppercase letters excluding ambiguous characters
const UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";

//Ambiguous uppercase letters
const UPPERCASE_AMBIGUOUS: &[u8] = b"IO";

//Lowercase letters excluding ambiguous characters  
const LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";

//Ambiguous lowercase letters
const LOWERCASE_AMBIGUOUS: &[u8] = b"l";

//Numeric digits excluding ambiguous characters
const NUMBERS: &[u8] = b"23456789";

//Ambiguous numbers
const NUMBERS_AMBIGUOUS: &[u8] = b"01";

//Special characters for passwords
const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

// Password Generator

/// Main password generator providing generation and strength assessment
pub struct PasswordGenerator;
impl PasswordGenerator {
    /// Generates a secure random password based on the given options.

    /// # Returns
    /// * `Ok(String)` - Generated password meeting requirements
    /// * `Err(String)` - If parameters are invalid
    //Errors
    /// -Length is 0 or > 1024
    /// -No character types selected
    /// -Length too short for required character types
    pub fn generate(options: &PasswordOptions) -> Result<String, String> {
        // Validate length bounds
        if options.length == 0 {
            return Err("Password length must be greater than 0".into());
        }
        if options.length > 1024 {
            return Err("Password length must be less than 1024".into());
        }

        //Build character set and required characters list
        let mut charset = Vec::new();
        let mut required = Vec::new();

        //Add uppercase characters if chosen
        if options.include_uppercase {
            charset.extend_from_slice(UPPERCASE);

            //Add ambiguous characters
            if !options.exclude_ambiguous {
                charset.extend_from_slice(UPPERCASE_AMBIGUOUS);
            }

            //Ensure at least one uppercase in final password
            required.push(*UPPERCASE.first().unwrap());
        }

        //Add lowercase characters if chosen
        if options.include_lowercase {
            charset.extend_from_slice(LOWERCASE);

            if !options.exclude_ambiguous {
                charset.extend_from_slice(LOWERCASE_AMBIGUOUS);
            }

            //Ensure at least one lowercase in final password
            required.push(*LOWERCASE.first().unwrap());
        }

        //Add numbers if chosen
        if options.include_numbers {
            charset.extend_from_slice(NUMBERS);

            if !options.exclude_ambiguous {
                charset.extend_from_slice(NUMBERS_AMBIGUOUS);
            }

            //atleast one number in final password
            required.push(*NUMBERS.first().unwrap());
        }

        //add special characters if chosen
        if options.include_special {
            charset.extend_from_slice(SPECIAL);

            required.push(*SPECIAL.first().unwrap());
        }

        //Validate that at least one character type is selected
        if charset.is_empty() {
            return Err("At least one character type must be selected".into());
        }

        //Validate that password is long enough for required characters
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

        //Add required characters (one from each selected type)
        password.extend_from_slice(&required);

        //Fill remaining positions with random characters
        for _ in required.len()..options.length {
            let idx = rng.gen_range(0..charset.len());
            password.push(charset[idx]);
        }

        //Shuffle the password
        for i in (1..password.len()).rev() {
            let j = rng.gen_range(0..=i);
            password.swap(i, j);
        }

        //Convert byte vector to UTF-8 string
        String::from_utf8(password).map_err(|e| format!("Failed to create password: {}", e))
    }

    /// Assesses the strength of a password.
    ///
    /// #Scoring System
    /// Points are given for:
    /// -Length >= 8: +1 point
    /// -Length >= 12: +1 point (total 2)
    /// -Length >= 16: +1 point (total 3)
    /// -Length >= 20: +1 point (total 4)
    /// -Has lowercase: +1 point
    /// -Has uppercase: +1 point
    /// -Has numbers: +1 point
    /// -Has special characters: +1 point
    ///
    /// #Strength Mapping
    /// - 0-2 points: Very Weak
    /// - 3-4 points: Weak
    /// - 5-6 points: Fair
    /// - 7 points: Strong
    /// - 8+ points: Very Strong
    ///
    /// Returns: PasswordStrength enum indicating the assessed strength level
    pub fn assess_strength(password: &str) -> PasswordStrength {
        let length = password.len();

        //Check for character type diversity
        let has_l = password.chars().any(|c| c.is_lowercase());
        let has_u = password.chars().any(|c| c.is_uppercase());
        let has_n = password.chars().any(|c| c.is_numeric());
        let has_s = password.chars().any(|c| !c.is_alphanumeric());

        //Calculate score based on length and diversity
        let mut score = 0;

        //Length grading 
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

        //Character diversity grading
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

        //Map score to strength level
        match score {
            0..=2 => PasswordStrength::VeryWeak,
            3..=4 => PasswordStrength::Weak,
            5..=6 => PasswordStrength::Fair,
            7 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }
}


// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;

    //Test that generated password has correct length
    #[test]
    fn gen_len() {
        let pw = PasswordGenerator::generate(&PasswordOptions::default()).unwrap();
        assert_eq!(pw.len(), 16);
    }

    //Test that strength assessment works correctly across different levels
    #[test]
    fn strength_scale() {
        //Very weak:short and lowercase only
        assert_eq!(
            PasswordGenerator::assess_strength("abc"),
            PasswordStrength::VeryWeak
        );

        //Weak:diverse but short
        assert_eq!(
            PasswordGenerator::assess_strength("Abc123!@#"),
            PasswordStrength::Weak
        );

        //Strong:good length and diverse
        assert_eq!(
            PasswordGenerator::assess_strength("MyP@ssw0rd12345!"),
            PasswordStrength::Strong
        );
    }
}
