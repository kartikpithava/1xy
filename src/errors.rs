use std::fmt;
use thiserror::Error;

/// Result type alias for forensic operations
pub type Result<T> = std::result::Result<T, ForensicError>;

/// Comprehensive error types for PDF forensic operations
#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("PDF parsing failed: {message}")]
    ParseError {
        message: String
    },

    #[error("Metadata operation failed: {operation} - {details}")]
    MetadataError {
        operation: String,
        details: String
    },

    #[error("Encryption operation failed: {reason}")]
    EncryptionError {
        reason: String
    },

    #[error("PDF structure integrity compromised: {issue}")]
    StructureError {
        issue: String
    },

    #[error("Forensic verification failed: {check}")]
    VerificationError {
        check: String
    },

    #[error("File system operation failed: {operation}")]
    FileSystemError {
        operation: String
    },

    #[error("Configuration error: {parameter}")]
    ConfigError {
        parameter: String
    },

    #[error("Synchronization failed: {location}")]
    SyncError {
        location: String
    },

    #[error("Authentication failure: {context}")]
    AuthError {
        context: String
    },

    #[error("Invalid PDF version or format: {details}")]
    FormatError {
        details: String
    },

    #[error("Content stream processing failed: {reason}")]
    StreamError {
        reason: String
    },

    #[error("Object cloning failed: {object_id} - {reason}")]
    CloneError {
        object_id: String,
        reason: String
    },

    #[error("PDF reconstruction failed: {stage} - {details}")]
    ReconstructionError {
        stage: String,
        details: String
    },

    #[error("Memory operation failed: {operation} - {details}")]
    MemoryError {
        operation: String,
        details: String
    },

    #[error("Timestamp management failed: {operation}")]
    TimestampError {
        operation: String
    },

    #[error("Serialization failed: {operation} - {details}")]
    SerializationError {
        operation: String,
        details: String
    },

    #[error("Validation failed: {component} - {reason}")]
    ValidationError {
        component: String,
        reason: String
    },

    #[error("Anti-forensic operation failed: {technique} - {details}")]
    AntiForensicError {
        technique: String,
        details: String
    },

    #[error("Producer string manipulation failed: {reason}")]
    ProducerError {
        reason: String
    },

    #[error("Security operation failed: {operation} - {details}")]
    SecurityError {
        operation: String,
        details: String
    }
}

impl ForensicError {
    /// Create a new parse error
    pub fn parse_error(message: &str) -> Self {
        Self::ParseError {
            message: message.to_string()
        }
    }

    /// Create a new metadata error
    pub fn metadata_error(operation: &str, details: &str) -> Self {
        Self::MetadataError {
            operation: operation.to_string(),
            details: details.to_string()
        }
    }

    /// Create a new encryption error
    pub fn encryption_error(reason: &str) -> Self {
        Self::EncryptionError {
            reason: reason.to_string()
        }
    }

    /// Create a new structure error
    pub fn structure_error(issue: &str) -> Self {
        Self::StructureError {
            issue: issue.to_string()
        }
    }

    /// Create a new verification error
    pub fn verification_error(check: &str) -> Self {
        Self::VerificationError {
            check: check.to_string()
        }
    }

    /// Create a new file system error
    pub fn file_system_error(operation: &str) -> Self {
        Self::FileSystemError {
            operation: operation.to_string()
        }
    }

    /// Create a new config error
    pub fn config_error(parameter: &str) -> Self {
        Self::ConfigError {
            parameter: parameter.to_string()
        }
    }

    /// Create a new sync error
    pub fn sync_error(location: &str) -> Self {
        Self::SyncError {
            location: location.to_string()
        }
    }

    /// Create a new auth error
    pub fn auth_error(context: &str) -> Self {
        Self::AuthError {
            context: context.to_string()
        }
    }

    /// Create a new format error
    pub fn format_error(details: &str) -> Self {
        Self::FormatError {
            details: details.to_string()
        }
    }

    /// Create a new stream error
    pub fn stream_error(reason: &str) -> Self {
        Self::StreamError {
            reason: reason.to_string()
        }
    }

    /// Create a new clone error
    pub fn clone_error(object_id: &str, reason: &str) -> Self {
        Self::CloneError {
            object_id: object_id.to_string(),
            reason: reason.to_string()
        }
    }

    /// Create a new reconstruction error
    pub fn reconstruction_error(stage: &str, details: &str) -> Self {
        Self::ReconstructionError {
            stage: stage.to_string(),
            details: details.to_string()
        }
    }

    /// Create a new memory error
    pub fn memory_error(operation: &str, details: &str) -> Self {
        Self::MemoryError {
            operation: operation.to_string(),
            details: details.to_string()
        }
    }

    /// Create a new timestamp error
    pub fn timestamp_error(operation: &str) -> Self {
        Self::TimestampError {
            operation: operation.to_string()
        }
    }

    /// Create a new serialization error
    pub fn serialization_error(operation: &str, details: &str) -> Self {
        Self::SerializationError {
            operation: operation.to_string(),
            details: details.to_string()
        }
    }

    /// Create a new validation error
    pub fn validation_error(component: &str, reason: &str) -> Self {
        Self::ValidationError {
            component: component.to_string(),
            reason: reason.to_string()
        }
    }

    /// Create a new anti-forensic error
    pub fn anti_forensic_error(technique: &str, details: &str) -> Self {
        Self::AntiForensicError {
            technique: technique.to_string(),
            details: details.to_string()
        }
    }

    /// Create a new producer error
    pub fn producer_error(reason: &str) -> Self {
        Self::ProducerError {
            reason: reason.to_string()
        }
    }

    /// Create a new security error
    pub fn security_error(operation: &str, details: &str) -> Self {
        Self::SecurityError {
            operation: operation.to_string(),
            details: details.to_string()
        }
    }
}

// Standard library error conversions
impl From<std::io::Error> for ForensicError {
    fn from(err: std::io::Error) -> Self {
        Self::FileSystemError {
            operation: format!("I/O operation failed: {}", err)
        }
    }
}

impl From<lopdf::Error> for ForensicError {
    fn from(err: lopdf::Error) -> Self {
        Self::ParseError {
            message: format!("LoPDF error: {}", err)
        }
    }
}

impl From<serde_json::Error> for ForensicError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError {
            operation: "JSON serialization".to_string(),
            details: err.to_string()
        }
    }
}

impl From<String> for ForensicError {
    fn from(err: String) -> Self {
        Self::ParseError {
            message: err
        }
    }
}

impl From<&str> for ForensicError {
    fn from(err: &str) -> Self {
        Self::ParseError {
            message: err.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        // Test parse error
        let err = ForensicError::parse_error("test error");
        assert!(matches!(err, ForensicError::ParseError { .. }));

        // Test metadata error
        let err = ForensicError::metadata_error("update", "failed");
        assert!(matches!(err, ForensicError::MetadataError { .. }));

        // Test encryption error
        let err = ForensicError::encryption_error("invalid key");
        assert!(matches!(err, ForensicError::EncryptionError { .. }));
    }

    #[test]
    fn test_error_conversion() {
        // Test IO error conversion
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io error");
        let forensic_err: ForensicError = io_err.into();
        assert!(matches!(forensic_err, ForensicError::FileSystemError { .. }));

        // Test string conversion
        let str_err: ForensicError = "test error".into();
        assert!(matches!(str_err, ForensicError::ParseError { .. }));
    }

    #[test]
    fn test_error_display() {
        let err = ForensicError::security_error("encryption", "invalid key");
        assert!(err.to_string().contains("encryption"));
        assert!(err.to_string().contains("invalid key"));
    }
}
