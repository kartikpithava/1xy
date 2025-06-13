use std::fmt;
use thiserror::Error;

/// Result type alias for forensic operations
pub type Result<T> = std::result::Result<T, ForensicError>;

/// Comprehensive error types for PDF forensic operations
#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("PDF parsing failed: {message}")]
    ParseError { message: String },
    
    #[error("Metadata operation failed: {operation} - {details}")]
    MetadataError { operation: String, details: String },
    
    #[error("Encryption operation failed: {reason}")]
    EncryptionError { reason: String },
    
    #[error("PDF structure integrity compromised: {issue}")]
    StructureError { issue: String },
    
    #[error("Forensic verification failed: {check}")]
    VerificationError { check: String },
    
    #[error("File system operation failed: {operation}")]
    FileSystemError { operation: String },
    
    #[error("Configuration error: {parameter}")]
    ConfigError { parameter: String },
    
    #[error("Synchronization failed: {location}")]
    SyncError { location: String },
    
    #[error("Authentication failure: {context}")]
    AuthError { context: String },
    
    #[error("Invalid PDF version or format: {details}")]
    FormatError { details: String },
}

impl ForensicError {
    pub fn parse_error(message: &str) -> Self {
        Self::ParseError {
            message: message.to_string(),
        }
    }
    
    pub fn metadata_error(operation: &str, details: &str) -> Self {
        Self::MetadataError {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }
    
    pub fn encryption_error(reason: &str) -> Self {
        Self::EncryptionError {
            reason: reason.to_string(),
        }
    }
    
    pub fn structure_error(issue: &str) -> Self {
        Self::StructureError {
            issue: issue.to_string(),
        }
    }
    
    pub fn verification_error(check: &str) -> Self {
        Self::VerificationError {
            check: check.to_string(),
        }
    }
    
    pub fn sync_error(location: &str) -> Self {
        Self::SyncError {
            location: location.to_string(),
        }
    }
}

// Standard library error conversions
impl From<std::io::Error> for ForensicError {
    fn from(err: std::io::Error) -> Self {
        Self::FileSystemError {
            operation: format!("I/O operation failed: {}", err),
        }
    }
}

impl From<lopdf::Error> for ForensicError {
    fn from(err: lopdf::Error) -> Self {
        Self::ParseError {
            message: format!("LoPDF error: {}", err),
        }
    }
}

impl From<serde_json::Error> for ForensicError {
    fn from(err: serde_json::Error) -> Self {
        Self::ConfigError {
            parameter: format!("JSON serialization error: {}", err),
        }
    }
}
