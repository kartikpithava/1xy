//! Utilities Module
//! 
//! Common utility functions and helpers for PDF forensic operations.
//! Provides cryptographic operations, serialization helpers, and forensic utilities
//! for supporting the core PDF processing functionality.

pub mod crypto;
pub mod serialization;
pub mod forensics;

// Re-export commonly used utility functions
pub use self::crypto::{
    HashCalculator, EncryptionHelper, SecurityUtils, CryptoConfig,
    hash_content, verify_integrity, generate_secure_key
};
pub use self::serialization::{
    JsonSerializer, BinarySerializer, CompressionHelper, SerializationConfig,
    serialize_to_json, deserialize_from_json, compress_data, decompress_data
};
pub use self::forensics::{
    TraceRemover, AuthenticityValidator, ForensicAnalyzer, CleaningUtils,
    remove_editing_traces, validate_authenticity, analyze_metadata_traces
};

use crate::{
    errors::{ForensicError, Result},
};

/// Utility operation configuration
#[derive(Debug, Clone)]
pub struct UtilityConfig {
    pub enable_compression: bool,
    pub crypto_strength: u8,
    pub forensic_cleaning_level: u8,
    pub validation_strictness: u8,
}

impl Default for UtilityConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            crypto_strength: 8,  // High strength
            forensic_cleaning_level: 9,  // Maximum cleaning
            validation_strictness: 7,  // High validation
        }
    }
}

/// Common utility result wrapper
pub type UtilityResult<T> = Result<T>;
