use crate::{
    errors::{ForensicError, Result},
    config::Config,
};
use filetime::{FileTime, set_file_mtime, set_file_atime};
use chrono::{DateTime, Utc};
use std::path::Path;
use std::fs;
use rand::Rng;

/// File timestamp management for forensic invisibility
pub struct TimestampManager {
    preserve_access_time: bool,
    operator: String,
    last_operation: DateTime<Utc>,
}

impl TimestampManager {
    pub fn new() -> Self {
        Self {
            preserve_access_time: true,
            operator: "kartikpithava".to_string(), // Using current user's login
            last_operation: DateTime::parse_from_rfc3339("2025-06-13T18:30:35Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }
    
    /// Synchronize file timestamps with PDF creation date
    pub fn synchronize_timestamps<P: AsRef<Path>>(&self, file_path: P, creation_date: &str) -> Result<()> {
        let path = file_path.as_ref();
        
        let creation_datetime = DateTime::parse_from_rfc3339(creation_date)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid creation date format: {}", e),
            })?;
        
        let timestamp = creation_datetime.timestamp();
        let file_time = FileTime::from_unix_time(timestamp, 0);
        
        set_file_mtime(path, file_time)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to set modification time: {}", e),
            })?;
        
        if !self.preserve_access_time {
            set_file_atime(path, file_time)
                .map_err(|e| ForensicError::FileSystemError {
                    operation: format!("Failed to set access time: {}", e),
                })?;
        }
        
        Ok(())
    }
    
    /// Get current file timestamps for verification
    pub fn get_file_timestamps<P: AsRef<Path>>(&self, file_path: P) -> Result<FileTimestamps> {
        let metadata = fs::metadata(file_path.as_ref())
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read file metadata: {}", e),
            })?;
        
        let modified = metadata.modified()
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read modification time: {}", e),
            })?;
        
        let accessed = metadata.accessed()
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read access time: {}", e),
            })?;
        
        let created = metadata.created().ok();
        
        Ok(FileTimestamps {
            modified,
            accessed,
            created,
        })
    }
    
    /// Verify timestamp alignment with PDF metadata
    pub fn verify_timestamp_alignment<P: AsRef<Path>>(&self, file_path: P, pdf_creation_date: &str) -> Result<bool> {
        let file_timestamps = self.get_file_timestamps(file_path)?;
        
        let creation_datetime = DateTime::parse_from_rfc3339(pdf_creation_date)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid creation date format: {}", e),
            })?;
        
        let expected_timestamp = creation_datetime.timestamp();
        let actual_timestamp = file_timestamps.modified
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid file timestamp: {}", e),
            })?
            .as_secs() as i64;
        
        let difference = (expected_timestamp - actual_timestamp).abs();
        Ok(difference <= Config::TIMESTAMP_PRECISION as i64)
    }
}

/// File timestamp container
#[derive(Debug, Clone)]
pub struct FileTimestamps {
    pub modified: std::time::SystemTime,
    pub accessed: std::time::SystemTime,
    pub created: Option<std::time::SystemTime>,
}

/// Forensic cleaning utilities
pub struct ForensicCleaner {
    operator: String,
    operation_time: DateTime<Utc>,
}

impl ForensicCleaner {
    pub fn new() -> Self {
        Self {
            operator: "kartikpithava".to_string(), // Using current user's login
            operation_time: DateTime::parse_from_rfc3339("2025-06-13T18:30:35Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }
    
    /// Remove forensic traces from file system
    pub fn clean_temporary_files() -> Result<()> {
        let temp_patterns = [
            "temp_*",
            "clone_*",
            "extraction_*.json",
            "debug_*.txt",
            "forensic_*.txt",
        ];
        
        for pattern in &temp_patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries {
                    if let Ok(path) = entry {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Secure memory cleanup (overwrite sensitive data)
    pub fn secure_memory_cleanup(sensitive_data: &mut [u8]) {
        let mut rng = rand::thread_rng();
        
        // First pass: random data
        for byte in sensitive_data.iter_mut() {
            *byte = rng.gen();
        }
        
        // Second pass: zeros
        for byte in sensitive_data.iter_mut() {
            *byte = 0;
        }
    }
    
    /// Generate authentic-looking creation timestamp
    pub fn generate_authentic_timestamp() -> String {
        let now = Utc::now();
        let random_days = rand::thread_rng().gen_range(1..=30);
        let creation_time = now - chrono::Duration::days(random_days);
        creation_time.to_rfc3339()
    }
    
    /// Validate timestamp authenticity
    pub fn validate_timestamp_authenticity(timestamp: &str) -> Result<bool> {
        let datetime = DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| ForensicError::verification_error(&format!("Invalid timestamp: {}", e)))?;
        
        let now = Utc::now();
        let age = now.signed_duration_since(datetime.with_timezone(&Utc));
        
        // Valid if in the past but not too old (within 5 years)
        let days_old = age.num_days();
        Ok(days_old > 0 && days_old < 1826)
    }
    
    /// Clean forensic markers from document
    pub fn clean_forensic_markers(document_data: &mut Vec<u8>) -> Result<()> {
        // Remove any forensic markers like:
        // - Software identifiers
        // - Temporal metadata
        // - System-specific information
        for window in document_data.windows_mut(4) {
            if window == b"xmp:" || window == b"pdf:" {
                window.copy_from_slice(b"    ");
            }
        }
        Ok(())
    }
}

impl Default for TimestampManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ForensicCleaner {
    fn default() -> Self {
        Self::new()
    }
  }
