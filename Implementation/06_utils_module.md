
# Module 06: Utils Module Implementation Guide

## Overview
Complete implementation of the utils module providing utility functions, validation, cryptographic operations, and support services for the PDF anti-forensics library.

## Files to Implement

### 1. PRODUCTION-ENHANCED src/utils/mod.rs (80 lines)
```rust
//! ENTERPRISE-GRADE Utility modules for PDF anti-forensics operations
//! 
//! Provides production-ready cryptographic, validation, support utilities,
//! performance monitoring, caching, cross-platform compatibility, and
//! comprehensive testing framework for enterprise deployment.
//!
//! # PRODUCTION ENHANCEMENTS
//! - Utility function performance monitoring with detailed metrics
//! - Utility function caching with intelligent invalidation
//! - Cross-platform compatibility layers with OS abstraction
//! - Utility function testing framework with property-based testing
//! - Memory-efficient string processing with zero-copy operations
//! - File system operations with atomic writes and rollback
//! - Network utilities with connection pooling and retry logic
//! - Date/time utilities with timezone handling and formatting
//! - Compression utilities with multiple algorithm support
//! - Validation utilities with schema-based validation

pub mod binary_utils;
pub mod cache;
pub mod config;
pub mod crypto_utils;
pub mod entropy;
pub mod file_validation;
pub mod io;
pub mod logger;
pub mod logging;
pub mod memory;
pub mod metadata_utils;
pub mod metrics;
pub mod pattern_utils;
pub mod pattern_validation;
pub mod sanitization_utils;
pub mod structural_validation;
pub mod template_utils;
pub mod validation;
pub mod validator;

// Production-enhanced modules
pub mod performance_monitor;
pub mod cross_platform;
pub mod network_utils;
pub mod compression;
pub mod datetime_utils;
pub mod string_processing;
pub mod atomic_operations;
pub mod schema_validation;
pub mod testing_framework;
pub mod benchmarking;
pub mod profiling;
pub mod resource_monitoring;
pub mod error_recovery;
pub mod circuit_breaker;
pub mod rate_limiter;
pub mod health_checks;

// Re-export commonly used utilities
pub use binary_utils::*;
pub use cache::*;
pub use config::*;
pub use crypto_utils::*;
pub use entropy::*;
pub use file_validation::*;
pub use io::*;
pub use logger::*;
pub use logging::*;
pub use memory::*;
pub use metadata_utils::*;
pub use metrics::*;
pub use pattern_utils::*;
pub use pattern_validation::*;
pub use sanitization_utils::*;
pub use structural_validation::*;
pub use template_utils::*;
pub use validation::*;
pub use validator::*;
```

### 2. src/utils/binary_utils.rs (180 lines)
```rust
//! Binary data utilities for PDF processing
//! Provides functions for binary data manipulation and analysis

use std::io::{Read, Write};
use crate::error::{Result, PdfError, ErrorContext};
use tracing::{debug, info, warn};

/// Binary data utilities
pub struct BinaryUtils;

impl BinaryUtils {
    /// Convert bytes to hexadecimal string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Convert hexadecimal string to bytes
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(PdfError::ValidationError {
                field: "hex_string".to_string(),
                message: "Hex string length must be even".to_string(),
                context: ErrorContext::new("hex_to_bytes", "binary_utils"),
                severity: crate::error::ValidationSeverity::Error,
                validation_type: "format".to_string(),
            });
        }

        let mut bytes = Vec::new();
        for i in (0..hex.len()).step_by(2) {
            let byte_str = &hex[i..i+2];
            let byte = u8::from_str_radix(byte_str, 16)
                .map_err(|e| PdfError::ValidationError {
                    field: "hex_byte".to_string(),
                    message: format!("Invalid hex byte: {}", e),
                    context: ErrorContext::new("hex_to_bytes", "binary_utils"),
                    severity: crate::error::ValidationSeverity::Error,
                    validation_type: "format".to_string(),
                })?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// XOR two byte arrays
    pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    /// Calculate entropy of byte array
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        frequency.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Find pattern in binary data
    pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || data.len() < pattern.len() {
            return Vec::new();
        }

        let mut positions = Vec::new();
        for i in 0..=data.len() - pattern.len() {
            if &data[i..i + pattern.len()] == pattern {
                positions.push(i);
            }
        }
        positions
    }

    /// Replace pattern in binary data
    pub fn replace_pattern(data: &mut [u8], pattern: &[u8], replacement: &[u8]) -> Result<usize> {
        if pattern.len() != replacement.len() {
            return Err(PdfError::ValidationError {
                field: "pattern_size".to_string(),
                message: "Pattern and replacement must have same length".to_string(),
                context: ErrorContext::new("replace_pattern", "binary_utils"),
                severity: crate::error::ValidationSeverity::Error,
                validation_type: "size".to_string(),
            });
        }

        let positions = Self::find_pattern(data, pattern);
        for &pos in &positions {
            data[pos..pos + replacement.len()].copy_from_slice(replacement);
        }
        Ok(positions.len())
    }

    /// Pad data to specified alignment
    pub fn pad_to_alignment(data: &mut Vec<u8>, alignment: usize, pad_byte: u8) {
        let remainder = data.len() % alignment;
        if remainder != 0 {
            let padding_needed = alignment - remainder;
            data.extend(vec![pad_byte; padding_needed]);
        }
    }

    /// Remove padding from data
    pub fn remove_padding(data: &[u8], pad_byte: u8) -> &[u8] {
        data.iter()
            .rposition(|&b| b != pad_byte)
            .map(|pos| &data[..=pos])
            .unwrap_or(&[])
    }

    /// Detect binary file type by magic bytes
    pub fn detect_file_type(data: &[u8]) -> Option<&'static str> {
        if data.len() < 4 {
            return None;
        }

        match &data[0..4] {
            [0x25, 0x50, 0x44, 0x46] => Some("PDF"), // %PDF
            [0x89, 0x50, 0x4E, 0x47] => Some("PNG"),
            [0xFF, 0xD8, 0xFF, _] => Some("JPEG"),
            [0x50, 0x4B, 0x03, 0x04] => Some("ZIP"),
            _ => None,
        }
    }

    /// Secure memory wipe
    pub fn secure_wipe(data: &mut [u8]) {
        // Multiple pass wipe for security
        for &pattern in &[0x00, 0xFF, 0xAA, 0x55] {
            data.fill(pattern);
        }
        // Final random pass
        use rand::RngCore;
        rand::thread_rng().fill_bytes(data);
        data.fill(0);
    }

    /// Validate binary data integrity
    pub fn validate_integrity(data: &[u8], expected_checksum: u32) -> bool {
        let checksum = crc32fast::hash(data);
        checksum == expected_checksum
    }

    /// Compress binary data
    pub fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::{Compression, write::ZlibEncoder};
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)
            .map_err(|e| PdfError::IoError(format!("Compression failed: {}", e)))?;
        
        encoder.finish()
            .map_err(|e| PdfError::IoError(format!("Compression finalization failed: {}", e)))
    }

    /// Decompress binary data
    pub fn decompress_data(compressed: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        
        let mut decoder = ZlibDecoder::new(compressed);
        let mut result = Vec::new();
        decoder.read_to_end(&mut result)
            .map_err(|e| PdfError::IoError(format!("Decompression failed: {}", e)))?;
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x01, 0xAB, 0xFF];
        assert_eq!(BinaryUtils::bytes_to_hex(&bytes), "01abff");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "01abff";
        let result = BinaryUtils::hex_to_bytes(hex).unwrap();
        assert_eq!(result, vec![0x01, 0xAB, 0xFF]);
    }

    #[test]
    fn test_xor_bytes() {
        let a = vec![0xFF, 0x00];
        let b = vec![0x0F, 0xF0];
        let result = BinaryUtils::xor_bytes(&a, &b);
        assert_eq!(result, vec![0xF0, 0xF0]);
    }

    #[test]
    fn test_entropy_calculation() {
        let uniform = vec![0u8; 256];
        let entropy = BinaryUtils::calculate_entropy(&uniform);
        assert!(entropy < 1.0); // Low entropy for uniform data
    }

    #[test]
    fn test_pattern_finding() {
        let data = b"hello world hello";
        let pattern = b"hello";
        let positions = BinaryUtils::find_pattern(data, pattern);
        assert_eq!(positions, vec![0, 12]);
    }
}
```

### 3. src/utils/cache.rs (150 lines)
```rust
//! Caching utilities for performance optimization
//! Provides memory and disk-based caching mechanisms

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use crate::error::{Result, PdfError, ErrorContext};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};

/// Cache entry with expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub value: T,
    pub created_at: Instant,
    pub expires_at: Option<Instant>,
    pub access_count: u64,
    pub last_accessed: Instant,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T, ttl: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            expires_at: ttl.map(|dur| now + dur),
            access_count: 0,
            last_accessed: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Instant::now() > exp)
    }

    pub fn access(&mut self) -> &T {
        self.access_count += 1;
        self.last_accessed = Instant::now();
        &self.value
    }
}

/// Memory cache with LRU eviction
pub struct MemoryCache<K, V> 
where 
    K: Eq + Hash + Clone,
    V: Clone,
{
    entries: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    max_size: usize,
    default_ttl: Option<Duration>,
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired_removals: u64,
}

impl<K, V> MemoryCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new(max_size: usize, default_ttl: Option<Duration>) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            default_ttl,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        if let Some(entry) = entries.get_mut(key) {
            if entry.is_expired() {
                entries.remove(key);
                stats.expired_removals += 1;
                stats.misses += 1;
                return None;
            }
            
            stats.hits += 1;
            Some(entry.access().clone())
        } else {
            stats.misses += 1;
            None
        }
    }

    pub fn put(&self, key: K, value: V) -> Result<()> {
        self.put_with_ttl(key, value, self.default_ttl)
    }

    pub fn put_with_ttl(&self, key: K, value: V, ttl: Option<Duration>) -> Result<()> {
        let mut entries = self.entries.write().unwrap();
        
        // Check if we need to evict entries
        if entries.len() >= self.max_size && !entries.contains_key(&key) {
            self.evict_lru(&mut entries)?;
        }

        let entry = CacheEntry::new(value, ttl);
        entries.insert(key, entry);
        
        Ok(())
    }

    fn evict_lru(&self, entries: &mut HashMap<K, CacheEntry<V>>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // Find the least recently used entry
        let lru_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
            .ok_or_else(|| PdfError::InternalError {
                message: "Failed to find LRU entry".to_string(),
                context: ErrorContext::new("evict_lru", "cache"),
                debug_info: format!("Cache size: {}", entries.len()),
            })?;

        entries.remove(&lru_key);
        
        let mut stats = self.stats.write().unwrap();
        stats.evictions += 1;
        
        Ok(())
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.entries.write().unwrap()
            .remove(key)
            .map(|entry| entry.value)
    }

    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
        *self.stats.write().unwrap() = CacheStats::default();
    }

    pub fn size(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write().unwrap();
        let mut stats = self.stats.write().unwrap();
        
        let initial_size = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let removed_count = initial_size - entries.len();
        
        stats.expired_removals += removed_count as u64;
        removed_count
    }
}

/// Global cache manager
pub struct CacheManager {
    pdf_cache: MemoryCache<String, Vec<u8>>,
    metadata_cache: MemoryCache<String, String>,
    pattern_cache: MemoryCache<String, Vec<usize>>,
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            pdf_cache: MemoryCache::new(100, Some(Duration::from_secs(3600))),
            metadata_cache: MemoryCache::new(500, Some(Duration::from_secs(1800))),
            pattern_cache: MemoryCache::new(200, Some(Duration::from_secs(900))),
        }
    }

    pub fn get_pdf_data(&self, key: &str) -> Option<Vec<u8>> {
        self.pdf_cache.get(key)
    }

    pub fn cache_pdf_data(&self, key: String, data: Vec<u8>) -> Result<()> {
        self.pdf_cache.put(key, data)
    }

    pub fn get_metadata(&self, key: &str) -> Option<String> {
        self.metadata_cache.get(key)
    }

    pub fn cache_metadata(&self, key: String, metadata: String) -> Result<()> {
        self.metadata_cache.put(key, metadata)
    }

    pub fn get_pattern_matches(&self, key: &str) -> Option<Vec<usize>> {
        self.pattern_cache.get(key)
    }

    pub fn cache_pattern_matches(&self, key: String, matches: Vec<usize>) -> Result<()> {
        self.pattern_cache.put(key, matches)
    }

    pub fn cleanup_all(&self) -> (usize, usize, usize) {
        (
            self.pdf_cache.cleanup_expired(),
            self.metadata_cache.cleanup_expired(),
            self.pattern_cache.cleanup_expired(),
        )
    }

    pub fn clear_all(&self) {
        self.pdf_cache.clear();
        self.metadata_cache.clear();
        self.pattern_cache.clear();
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}
```

### 4. src/utils/validation.rs (120 lines)
```rust
//! Validation utilities for PDF processing
//! Provides comprehensive validation functions

use std::path::Path;
use crate::error::{Result, PdfError, ErrorContext, ValidationSeverity};
use tracing::{debug, info, warn, error};

/// PDF validation utilities
pub struct PdfValidator;

impl PdfValidator {
    /// Validate PDF file header
    pub fn validate_pdf_header(data: &[u8]) -> Result<()> {
        if data.len() < 8 {
            return Err(PdfError::ValidationError {
                field: "file_size".to_string(),
                message: "File too small to be valid PDF".to_string(),
                context: ErrorContext::new("validate_pdf_header", "validation"),
                severity: ValidationSeverity::Error,
                validation_type: "format".to_string(),
            });
        }

        if !data.starts_with(b"%PDF-") {
            return Err(PdfError::ValidationError {
                field: "header".to_string(),
                message: "Invalid PDF header signature".to_string(),
                context: ErrorContext::new("validate_pdf_header", "validation"),
                severity: ValidationSeverity::Error,
                validation_type: "format".to_string(),
            });
        }

        // Validate version
        if data.len() >= 8 {
            let version_part = &data[5..8];
            if !version_part.starts_with(b"1.") && !version_part.starts_with(b"2.") {
                return Err(PdfError::ValidationError {
                    field: "version".to_string(),
                    message: "Unsupported PDF version".to_string(),
                    context: ErrorContext::new("validate_pdf_header", "validation"),
                    severity: ValidationSeverity::Warning,
                    validation_type: "version".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate file extension
    pub fn validate_file_extension(path: &Path) -> Result<()> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("pdf") | Some("PDF") => Ok(()),
            Some(ext) => Err(PdfError::ValidationError {
                field: "extension".to_string(),
                message: format!("Invalid file extension: {}", ext),
                context: ErrorContext::new("validate_file_extension", "validation"),
                severity: ValidationSeverity::Warning,
                validation_type: "format".to_string(),
            }),
            None => Err(PdfError::ValidationError {
                field: "extension".to_string(),
                message: "No file extension found".to_string(),
                context: ErrorContext::new("validate_file_extension", "validation"),
                severity: ValidationSeverity::Warning,
                validation_type: "format".to_string(),
            }),
        }
    }

    /// Validate file size limits
    pub fn validate_file_size(size: u64, max_size: u64) -> Result<()> {
        if size == 0 {
            return Err(PdfError::ValidationError {
                field: "file_size".to_string(),
                message: "File is empty".to_string(),
                context: ErrorContext::new("validate_file_size", "validation"),
                severity: ValidationSeverity::Error,
                validation_type: "size".to_string(),
            });
        }

        if size > max_size {
            return Err(PdfError::ValidationError {
                field: "file_size".to_string(),
                message: format!("File size {} exceeds maximum {}", size, max_size),
                context: ErrorContext::new("validate_file_size", "validation"),
                severity: ValidationSeverity::Error,
                validation_type: "size".to_string(),
            });
        }

        Ok(())
    }

    /// Validate PDF structure integrity
    pub fn validate_structure_integrity(data: &[u8]) -> Result<ValidationReport> {
        let mut report = ValidationReport::new();

        // Check for EOF marker
        if !Self::has_eof_marker(data) {
            report.add_issue(ValidationIssue {
                severity: ValidationSeverity::Warning,
                field: "eof_marker".to_string(),
                message: "Missing or invalid EOF marker".to_string(),
                location: data.len(),
            });
        }

        // Check for xref table
        if !Self::has_xref_table(data) {
            report.add_issue(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "xref_table".to_string(),
                message: "Missing cross-reference table".to_string(),
                location: 0,
            });
        }

        // Check for trailer
        if !Self::has_trailer(data) {
            report.add_issue(ValidationIssue {
                severity: ValidationSeverity::Error,
                field: "trailer".to_string(),
                message: "Missing trailer dictionary".to_string(),
                location: 0,
            });
        }

        Ok(report)
    }

    fn has_eof_marker(data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }
        
        let end_slice = &data[data.len().saturating_sub(20)..];
        end_slice.windows(5).any(|window| window == b"%%EOF")
    }

    fn has_xref_table(data: &[u8]) -> bool {
        data.windows(4).any(|window| window == b"xref")
    }

    fn has_trailer(data: &[u8]) -> bool {
        data.windows(7).any(|window| window == b"trailer")
    }
}

/// Validation issue
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub field: String,
    pub message: String,
    pub location: usize,
}

/// Validation report
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
    pub is_valid: bool,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            is_valid: true,
        }
    }

    pub fn add_issue(&mut self, issue: ValidationIssue) {
        if matches!(issue.severity, ValidationSeverity::Error) {
            self.is_valid = false;
        }
        self.issues.push(issue);
    }

    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|issue| matches!(issue.severity, ValidationSeverity::Error))
    }

    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|issue| matches!(issue.severity, ValidationSeverity::Error)).count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|issue| matches!(issue.severity, ValidationSeverity::Warning)).count()
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}
```

## Dependencies Required
Add to Cargo.toml:
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
rand = "0.8"
crc32fast = "1.3"
flate2 = "1.0"
```

## Implementation Steps
1. **Create all utility modules** following the exact structure above
2. **Implement binary operations** with proper error handling
3. **Add caching system** with LRU eviction and TTL support
4. **Implement validation framework** with comprehensive reporting
5. **Add cryptographic utilities** (already implemented in crypto_utils.rs)
6. **Create memory management** with secure operations
7. **Add pattern matching** and text processing utilities
8. **Implement metrics collection** for performance monitoring

## Testing Requirements
- Unit tests for all utility functions
- Performance benchmarks for caching
- Security tests for cryptographic operations
- Validation tests with malformed data
- Memory leak tests for secure operations

## Integration Points
- **Error Module**: Uses unified error types
- **Config Module**: Validation and configuration utilities
- **Hash Module**: Cryptographic and integrity functions
- **Security Module**: Validation and sanitization
- **All Other Modules**: Utility function consumers

Total Implementation: **465+ lines across 3 core files**
Estimated Time: **4-6 hours**
