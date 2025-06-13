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
}

impl TimestampManager {
    pub fn new() -> Self {
        Self {
            preserve_access_time: true,
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
            let access_offset = rand::thread_rng().gen_range(-86400..86400); // ±1 day
            let access_time = FileTime::from_unix_time(timestamp + access_offset, 0);
            
            set_file_atime(path, access_time)
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

/// Anti-forensic cleaning utilities
pub struct ForensicCleaner;

impl ForensicCleaner {
    pub fn new() -> Self {
        Self
    }
    
    /// Remove all forensic traces from filesystem
    pub fn clean_traces() -> Result<()> {
        let temp_patterns = [
            "*.tmp",
            "*.temp",
            "~*",
            "*.bak",
            ".*.swp",
            "*.log",
            "*.cache",
            "._*",          // MacOS metadata
            ".DS_Store",    // MacOS system files
            "Thumbs.db",    // Windows thumbnail cache
            "desktop.ini",  // Windows folder settings
        ];
        
        for pattern in &temp_patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries {
                    if let Ok(path) = entry {
                        Self::secure_delete(&path)?;
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Securely delete a file by overwriting with random data before removal
    fn secure_delete<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            let file_size = fs::metadata(path)
                .map_err(|e| ForensicError::FileSystemError {
                    operation: format!("Failed to get file size: {}", e),
                })?.len();

            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| ForensicError::FileSystemError {
                    operation: format!("Failed to open file for secure deletion: {}", e),
                })?;

            let mut rng = rand::thread_rng();
            let mut buffer = vec![0u8; 8192];

            // Multiple overwrite passes
            for _ in 0..3 {
                // Random data pass
                for chunk in buffer.chunks_mut(8192) {
                    rng.fill(chunk);
                }
                std::io::copy(&mut buffer.as_slice(), &mut file)
                    .map_err(|e| ForensicError::FileSystemError {
                        operation: format!("Failed to overwrite file: {}", e),
                    })?;
                
                // Zero pass
                buffer.fill(0);
                std::io::copy(&mut buffer.as_slice(), &mut file)
                    .map_err(|e| ForensicError::FileSystemError {
                        operation: format!("Failed to overwrite file: {}", e),
                    })?;
            }
        }

        fs::remove_file(path).map_err(|e| ForensicError::FileSystemError {
            operation: format!("Failed to delete file: {}", e),
        })?;

        Ok(())
    }

    /// Clean metadata from document
    pub fn clean_metadata(data: &mut Vec<u8>) -> Result<()> {
        let patterns = [
            b"xap:CreatorTool",
            b"xap:ModifyDate",
            b"xap:CreateDate",
            b"pdf:Producer",
            b"dc:creator",
            b"dc:date",
            b"xmpMM:DocumentID",
            b"xmpMM:InstanceID",
            b"pdfaid:part",
            b"pdfaid:conformance",
            b"pdf:Keywords",
            b"xmp:CreateDate",
            b"xmp:ModifyDate",
            b"xmp:MetadataDate",
        ];

        for pattern in &patterns {
            while let Some(pos) = find_pattern(data, pattern) {
                remove_metadata_field(data, pos);
            }
        }

        Ok(())
    }

    /// Generate plausible past timestamp
    pub fn generate_plausible_timestamp() -> String {
        let now = Utc::now();
        let random_days = rand::thread_rng().gen_range(30..60);
        let plausible_time = now - chrono::Duration::days(random_days);
        plausible_time.to_rfc3339()
    }

    /// Validate timestamp authenticity
    pub fn validate_timestamp_authenticity(timestamp: &str) -> Result<bool> {
        let datetime = DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| ForensicError::verification_error(&format!("Invalid timestamp: {}", e)))?;
        
        let now = Utc::now();
        let age = now.signed_duration_since(datetime.with_timezone(&Utc));
        
        let days_old = age.num_days();
        Ok(days_old > 0 && days_old < 1826) // 5 years = ~1826 days
    }
}

// Helper function to find pattern in byte array
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

// Helper function to remove metadata field and its value
fn remove_metadata_field(data: &mut Vec<u8>, start_pos: usize) {
    let mut end_pos = start_pos;
    let mut depth = 0;
    
    // Find the end of the metadata field
    for i in start_pos..data.len() {
        match data[i] {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    end_pos = i + 1;
                    break;
                }
            }
            _ => continue,
        }
    }
    
    // Remove the metadata field
    if end_pos > start_pos {
        data.drain(start_pos..end_pos);
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
