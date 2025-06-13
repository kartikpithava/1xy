//! PDF Processing Engine
//! 
//! Comprehensive PDF parsing, analysis, and manipulation system with forensic capabilities.
//! Handles complete PDF structure extraction, metadata discovery, and content preservation.

pub mod parser;
pub mod extractor;
pub mod analyzer;
pub mod cloner;
pub mod reconstructor;
pub mod security;
pub mod validator;

// Re-export commonly used types and functions
pub use self::parser::{PdfParser, ParsedPdfData};
pub use self::extractor::{PdfExtractor, ExtractionData};
pub use self::analyzer::{PdfAnalyzer, AnalysisResult};
pub use self::cloner::{PdfCloner, CloneData};
pub use self::reconstructor::{PdfReconstructor, ReconstructionConfig};
pub use self::security::{SecurityHandler, EncryptionInfo};
pub use self::validator::{PdfValidator, ValidationResult};

use crate::{
    errors::{ForensicError, Result},
    types::{PdfVersion, MetadataField, MetadataLocation},
    config::Config,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// PDF processing configuration 
#[derive(Debug, Clone)]
pub struct PdfProcessingConfig {
    pub preserve_structure: bool,
    pub extract_hidden_metadata: bool,
    pub validate_integrity: bool,
    pub forensic_mode: bool,
    pub operator: String,
    pub operation_time: DateTime<Utc>,
}

impl Default for PdfProcessingConfig {
    fn default() -> Self {
        Self {
            preserve_structure: true,
            extract_hidden_metadata: true,
            validate_integrity: true,
            forensic_mode: true,
            operator: "kartikpithava".to_string(), // From user context
            operation_time: DateTime::parse_from_rfc3339("2025-06-13T16:41:32Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }
}

/// Common PDF processing result wrapper
pub type PdfResult<T> = Result<T>;
