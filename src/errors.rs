
use std::{fmt, path::PathBuf};
use thiserror::Error;

/// Result type alias for all forensic operations
pub type Result<T> = std::result::Result<T, ForensicError>;

/// Validation error severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Detection risk levels for anti-forensic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionRisk {
    Immediate,  // Detected by basic tools
    Moderate,   // Detected by advanced analysis
    Low,        // Requires specialized tools
    Theoretical, // Only theoretical detection possible
}

/// Comprehensive error types for PDF forensic operations
#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("PDF parsing failed: {message}")]
    ParseError {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Metadata operation failed: {operation} - {details}")]
    MetadataError {
        operation: String,
        details: String,
    },

    #[error("Encryption operation failed: {reason}")]
    EncryptionError {
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("PDF structure integrity compromised: {issue}")]
    StructureError {
        issue: String,
        object_id: Option<String>,
    },

    #[error("Forensic verification failed: {check}")]
    VerificationError {
        check: String,
        details: Option<String>,
    },

    #[error("File system operation failed: {operation}")]
    FileSystemError {
        operation: String,
        path: Option<PathBuf>,
        #[source]
        source: Option<std::io::Error>,
    },

    #[error("Command line argument error: {reason}")]
    CliError {
        reason: String,
        arg: Option<String>,
    },

    #[error("Object processing failed: {details}")]
    ObjectError {
        details: String,
        object_type: String,
        object_id: Option<String>,
    },

    #[error("XMP metadata error: {reason}")]
    XmpError {
        reason: String,
        field: Option<String>,
    },

    #[error("Binary data error: {operation}")]
    BinaryError {
        operation: String,
        size: usize,
        details: String,
    },

    #[error("Cross reference error: {details}")]
    XrefError {
        details: String,
        offset: Option<u64>,
    },

    #[error("Resource limit exceeded: {resource}")]
    ResourceError {
        resource: String,
        limit: usize,
        current: usize,
    },

    #[error("Cleanup operation failed: {operation}")]
    CleanupError {
        operation: String,
        target: String,
    },

    #[error("Forensic detection risk: {pattern}")]
    DetectionError {
        pattern: String,
        risk_level: DetectionRisk,
        mitigation: String,
    },

    #[error("Configuration error: {parameter}")]
    ConfigError {
        parameter: String,
        value: Option<String>,
    },

    #[error("Synchronization failed: {location}")]
    SyncError {
        location: String,
        field: Option<String>,
    },

    #[error("Authentication failure: {context}")]
    AuthError {
        context: String,
        reason: Option<String>,
    },

    #[error("Invalid PDF version or format: {details}")]
    FormatError {
        details: String,
        version: Option<String>,
    },

    #[error("Stream processing error: {reason}")]
    StreamError {
        reason: String,
        stream_id: Option<String>,
    },

    #[error("Memory operation failed: {operation} - {details}")]
    MemoryError {
        operation: String,
        details: String,
    },

    #[error("Object cloning failed: {object_id} - {reason}")]
    CloneError {
        object_id: String,
        reason: String,
    },

    #[error("Content stream error: {details}")]
    ContentError {
        details: String,
        location: Option<String>,
    },

    #[error("Anti-forensic operation failed: {operation} - {details}")]
    AntiForensicError {
        operation: String,
        details: String,
    },

    #[error("Serialization error: {operation} - {details}")]
    SerializationError {
        operation: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Security operation failed: {operation} - {details}")]
    SecurityError {
        operation: String,
        details: String,
    },

    #[error("Validation error: {check} - {details}")]
    ValidationError {
        check: String,
        details: String,
        severity: ValidationSeverity,
    },
}

impl ForensicError {
    /// Create a new parse error
    pub fn parse_error(message: &str) -> Self {
        Self::ParseError {
            message: message.to_string(),
            source: None,
        }
    }

    /// Create a new parse error with source
    pub fn parse_error_with_source(message: &str, source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::ParseError {
            message: message.to_string(),
            source: Some(source),
        }
    }

    /// Create a new metadata error
    pub fn metadata_error(operation: &str, details: &str) -> Self {
        Self::MetadataError {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }

    /// Create a new encryption error
    pub fn encryption_error(reason: &str) -> Self {
        Self::EncryptionError {
            reason: reason.to_string(),
            source: None,
        }
    }

    /// Create a new structure error
    pub fn structure_error(issue: &str) -> Self {
        Self::StructureError {
            issue: issue.to_string(),
            object_id: None,
        }
    }

    /// Create a new verification error
    pub fn verification_error(check: &str, details: Option<&str>) -> Self {
        Self::VerificationError {
            check: check.to_string(),
            details: details.map(ToString::to_string),
        }
    }

    /// Create a new file system error
    pub fn fs_error(operation: &str, path: Option<PathBuf>, source: Option<std::io::Error>) -> Self {
        Self::FileSystemError {
            operation: operation.to_string(),
            path,
            source,
        }
    }

    /// Create a new CLI error
    pub fn cli_error(reason: &str, arg: Option<&str>) -> Self {
        Self::CliError {
            reason: reason.to_string(),
            arg: arg.map(ToString::to_string),
        }
    }

    /// Create a new object error
    pub fn object_error(details: &str, object_type: &str, object_id: Option<&str>) -> Self {
        Self::ObjectError {
            details: details.to_string(),
            object_type: object_type.to_string(),
            object_id: object_id.map(ToString::to_string),
        }
    }

    /// Create a new XMP error
    pub fn xmp_error(reason: &str, field: Option<&str>) -> Self {
        Self::XmpError {
            reason: reason.to_string(),
            field: field.map(ToString::to_string),
        }
    }

    /// Create a new binary error
    pub fn binary_error(operation: &str, size: usize, details: &str) -> Self {
        Self::BinaryError {
            operation: operation.to_string(),
            size,
            details: details.to_string(),
        }
    }

    /// Create a new cross reference error
    pub fn xref_error(details: &str, offset: Option<u64>) -> Self {
        Self::XrefError {
            details: details.to_string(),
            offset,
        }
    }

    /// Create a new resource error
    pub fn resource_error(resource: &str, limit: usize, current: usize) -> Self {
        Self::ResourceError {
            resource: resource.to_string(),
            limit,
            current,
        }
    }

    /// Create a new cleanup error
    pub fn cleanup_error(operation: &str, target: &str) -> Self {
        Self::CleanupError {
            operation: operation.to_string(),
            target: target.to_string(),
        }
    }

    /// Create a new detection error
    pub fn detection_error(pattern: &str, risk_level: DetectionRisk, mitigation: &str) -> Self {
        Self::DetectionError {
            pattern: pattern.to_string(),
            risk_level,
            mitigation: mitigation.to_string(),
        }
    }

    /// Create a new validation error
    pub fn validation_error(check: &str, details: &str, severity: ValidationSeverity) -> Self {
        Self::ValidationError {
            check: check.to_string(),
            details: details.to_string(),
            severity,
        }
    }

    /// Get error severity
    pub fn severity(&self) -> ValidationSeverity {
        match self {
            Self::ParseError { .. } => ValidationSeverity::Critical,
            Self::StructureError { .. } => ValidationSeverity::Critical,
            Self::EncryptionError { .. } => ValidationSeverity::High,
            Self::SecurityError { .. } => ValidationSeverity::High,
            Self::AntiForensicError { .. } => ValidationSeverity::High,
            Self::DetectionError { .. } => ValidationSeverity::High,
            Self::MetadataError { .. } => ValidationSeverity::Medium,
            Self::SyncError { .. } => ValidationSeverity::Medium,
            Self::ValidationError { severity, .. } => severity.clone(),
            _ => ValidationSeverity::Low,
        }
    }
}

// Standard library error conversions
impl From<std::io::Error> for ForensicError {
    fn from(err: std::io::Error) -> Self {
        Self::FileSystemError {
            operation: "I/O operation failed".to_string(),
            path: None,
            source: Some(err),
        }
    }
}

impl From<lopdf::Error> for ForensicError {
    fn from(err: lopdf::Error) -> Self {
        Self::ParseError {
            message: format!("LoPDF error: {}", err),
            source: Some(Box::new(err)),
        }
    }
}

impl From<serde_json::Error> for ForensicError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError {
            operation: "JSON processing".to_string(),
            details: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<std::str::Utf8Error> for ForensicError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::ContentError {
            details: format!("UTF-8 conversion failed: {}", err),
            location: None,
        }
    }
}

impl From<&str> for ForensicError {
    fn from(err: &str) -> Self {
        Self::ParseError {
            message: err.to_string(),
            source: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_creation() {
        let err = ForensicError::parse_error("test error");
        assert!(matches!(err, ForensicError::ParseError { .. }));

        let err = ForensicError::metadata_error("update", "failed");
        assert!(matches!(err, ForensicError::MetadataError { .. }));

        let err = ForensicError::encryption_error("invalid key");
        assert!(matches!(err, ForensicError::EncryptionError { .. }));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let forensic_err: ForensicError = io_err.into();
        assert!(matches!(forensic_err, ForensicError::FileSystemError { .. }));

        let str_err: ForensicError = "test error".into();
        assert!(matches!(str_err, ForensicError::ParseError { .. }));
    }

    #[test]
    fn test_error_severity() {
        let parse_err = ForensicError::parse_error("test");
        assert_eq!(parse_err.severity(), ValidationSeverity::Critical);

        let validation_err = ForensicError::validation_error(
            "test",
            "details",
            ValidationSeverity::Medium
        );
        assert_eq!(validation_err.severity(), ValidationSeverity::Medium);
    }

    #[test]
    fn test_error_display() {
        let err = ForensicError::security_error("encryption", "invalid key");
        assert!(err.to_string().contains("encryption"));
        assert!(err.to_string().contains("invalid key"));
    }

    #[test]
    fn test_cli_error() {
        let err = ForensicError::cli_error("Invalid argument", Some("--input"));
        assert!(matches!(err, ForensicError::CliError { .. }));
    }

    #[test]
    fn test_object_error() {
        let err = ForensicError::object_error("Invalid stream", "Stream", Some("1 0 R"));
        assert!(matches!(err, ForensicError::ObjectError { .. }));
    }

    #[test]
    fn test_detection_error() {
        let err = ForensicError::detection_error(
            "timestamp pattern",
            DetectionRisk::Low,
            "randomize timestamps"
        );
        assert!(matches!(err, ForensicError::DetectionError { .. }));
    }

    #[test]
    fn test_resource_error() {
        let err = ForensicError::resource_error("memory", 1024, 2048);
        assert!(matches!(err, ForensicError::ResourceError { .. }));
    }
    }
