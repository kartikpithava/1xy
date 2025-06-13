
pub mod cli;
pub mod config;
pub mod errors;
pub mod types;
pub mod verification;
pub mod encryption;
pub mod forensic;

pub mod pdf {
    pub mod parser;
    pub mod extractor;
    pub mod analyzer;
    pub mod cloner;
    pub mod reconstructor;
    pub mod security;
    pub mod validator;
}

pub mod metadata {
    pub mod scanner;
    pub mod editor;
    pub mod synchronizer;
    pub mod cleaner;
    pub mod authenticator;
}

pub mod data {
    pub mod pdf_objects;
    pub mod metadata_map;
    pub mod clone_data;
}

pub mod utils {
    pub mod crypto;
    pub mod serialization;
    pub mod forensics;
}

// Re-export commonly used types and functions
pub use crate::errors::{ForensicError, Result};
pub use crate::types::{PdfVersion, MetadataField, EncryptionMethod};
pub use crate::cli::CliArgs;
