# Module 28: Hash Utils Module Implementation Guide

## Overview
The hash utils module provides hash utility functions, hash comparison tools, hash format conversions, and hash validation utilities for the PDF anti-forensics library. This module offers comprehensive hash manipulation and analysis capabilities.

## File Structure
```text
src/hash_utils.rs (500 lines)
```

## Dependencies
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
sha2 = "0.10"
sha3 = "0.10"
blake3 = "1.0"
blake2 = "0.10"
md5 = "0.7"
crc32fast = "1.3"
hex = "0.4"
base64 = "0.21"
ring = "0.16"
```

## Implementation Requirements

### Complete Hash Utils Module (src/hash_utils.rs) - 500 lines

```rust
//! Hash utility functions and tools for PDF anti-forensics processing
//! 
//! This module provides comprehensive hash manipulation, comparison, conversion,
//! and validation utilities for various hash algorithms.

use crate::error::{PdfError, Result};
use crate::types::HashType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sha2::{Sha224, Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use blake3::Hasher as Blake3Hasher;
use blake2::{Blake2b512, Blake2s256};
use md5::Md5;
use tracing::{instrument, info, warn, debug};

/// Hash format for encoding/decoding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashFormat {
    Hex,
    Base64,
    Binary,
}

/// Hash comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashComparison {
    pub hash1: String,
    pub hash2: String,
    pub algorithm: HashType,
    pub are_equal: bool,
    pub similarity_score: f64,
    pub hamming_distance: Option<u32>,
}

/// Hash validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashValidation {
    pub hash: String,
    pub algorithm: HashType,
    pub is_valid: bool,
    pub format: HashFormat,
    pub length_correct: bool,
    pub character_set_valid: bool,
}

/// Hash statistics for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashStatistics {
    pub entropy: f64,
    pub bit_distribution: Vec<u32>,
    pub pattern_analysis: PatternAnalysis,
    pub collision_probability: f64,
}

/// Pattern analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAnalysis {
    pub repeated_sequences: Vec<String>,
    pub zero_bytes: u32,
    pub max_bytes: u32,
    pub sequential_patterns: u32,
}

/// Main hash utilities structure
pub struct HashUtils;

impl HashUtils {
    /// Calculate hash using specified algorithm
    #[instrument(skip(data))]
    pub fn calculate_hash(data: &[u8], algorithm: &HashType) -> String {
        match algorithm {
            HashType::Md5 => {
                let mut hasher = Md5::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha3_224 => {
                let mut hasher = Sha3_224::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha3_384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Blake2b => {
                let mut hasher = Blake2b512::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Blake2s => {
                let mut hasher = Blake2s256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashType::Blake3 => {
                let mut hasher = Blake3Hasher::new();
                hasher.update(data);
                hasher.finalize().to_hex().to_string()
            },
            HashType::Crc32 => {
                let checksum = crc32fast::hash(data);
                format!("{:08x}", checksum)
            },
        }
    }

    /// Calculate multiple hashes for the same data
    #[instrument(skip(data))]
    pub fn calculate_multiple_hashes(data: &[u8], algorithms: &[HashType]) -> HashMap<HashType, String> {
        let mut results = HashMap::new();
        
        for algorithm in algorithms {
            let hash = Self::calculate_hash(data, algorithm);
            results.insert(algorithm.clone(), hash);
        }
        
        debug!("Calculated {} hashes for data", algorithms.len());
        results
    }

    /// Compare two hashes
    #[instrument]
    pub fn compare_hashes(hash1: &str, hash2: &str, algorithm: &HashType) -> HashComparison {
        let are_equal = hash1.eq_ignore_ascii_case(hash2);
        let similarity_score = Self::calculate_similarity(hash1, hash2);
        let hamming_distance = Self::calculate_hamming_distance(hash1, hash2);

        HashComparison {
            hash1: hash1.to_string(),
            hash2: hash2.to_string(),
            algorithm: algorithm.clone(),
            are_equal,
            similarity_score,
            hamming_distance,
        }
    }

    /// Calculate similarity score between two hashes (0.0 to 1.0)
    fn calculate_similarity(hash1: &str, hash2: &str) -> f64 {
        if hash1.len() != hash2.len() {
            return 0.0;
        }

        let matches = hash1.chars()
            .zip(hash2.chars())
            .filter(|(c1, c2)| c1.to_ascii_lowercase() == c2.to_ascii_lowercase())
            .count();

        matches as f64 / hash1.len() as f64
    }

    /// Calculate Hamming distance between two hashes
    fn calculate_hamming_distance(hash1: &str, hash2: &str) -> Option<u32> {
        if hash1.len() != hash2.len() {
            return None;
        }

        let distance = hash1.chars()
            .zip(hash2.chars())
            .filter(|(c1, c2)| c1.to_ascii_lowercase() != c2.to_ascii_lowercase())
            .count() as u32;

        Some(distance)
    }

    /// Validate hash format and correctness
    #[instrument]
    pub fn validate_hash(hash: &str, algorithm: &HashType) -> HashValidation {
        let expected_length = Self::get_expected_hash_length(algorithm);
        let length_correct = hash.len() == expected_length;
        
        // Check if hash contains only valid hexadecimal characters
        let character_set_valid = hash.chars().all(|c| c.is_ascii_hexdigit());
        
        let is_valid = length_correct && character_set_valid;

        HashValidation {
            hash: hash.to_string(),
            algorithm: algorithm.clone(),
            is_valid,
            format: HashFormat::Hex, // Assuming hex format for validation
            length_correct,
            character_set_valid,
        }
    }

    /// Get expected hash length for algorithm
    fn get_expected_hash_length(algorithm: &HashType) -> usize {
        match algorithm {
            HashType::Md5 => 32,
            HashType::Sha224 => 56,
            HashType::Sha256 => 64,
            HashType::Sha384 => 96,
            HashType::Sha512 => 128,
            HashType::Sha3_224 => 56,
            HashType::Sha3_256 => 64,
            HashType::Sha3_384 => 96,
            HashType::Sha3_512 => 128,
            HashType::Blake2b => 128,
            HashType::Blake2s => 64,
            HashType::Blake3 => 64,
            HashType::Crc32 => 8,
        }
    }

    /// Convert hash between different formats
    #[instrument]
    pub fn convert_hash_format(hash: &str, from_format: &HashFormat, to_format: &HashFormat) -> Result<String> {
        if from_format == to_format {
            return Ok(hash.to_string());
        }

        // First convert to binary
        let binary_data = match from_format {
            HashFormat::Hex => {
                hex::decode(hash)
                    .map_err(|e| PdfError::ConversionError(format!("Invalid hex hash: {}", e)))?
            },
            HashFormat::Base64 => {
                base64::decode(hash)
                    .map_err(|e| PdfError::ConversionError(format!("Invalid base64 hash: {}", e)))?
            },
            HashFormat::Binary => hash.as_bytes().to_vec(),
        };

        // Then convert to target format
        let result = match to_format {
            HashFormat::Hex => hex::encode(&binary_data),
            HashFormat::Base64 => base64::encode(&binary_data),
            HashFormat::Binary => String::from_utf8(binary_data)
                .map_err(|e| PdfError::ConversionError(format!("Invalid binary data: {}", e)))?,
        };

        Ok(result)
    }

    /// Calculate hash statistics for analysis
    #[instrument(skip(hash_bytes))]
    pub fn calculate_hash_statistics(hash_bytes: &[u8]) -> HashStatistics {
        let entropy = Self::calculate_entropy(hash_bytes);
        let bit_distribution = Self::calculate_bit_distribution(hash_bytes);
        let pattern_analysis = Self::analyze_patterns(hash_bytes);
        let collision_probability = Self::estimate_collision_probability(hash_bytes.len());

        HashStatistics {
            entropy,
            bit_distribution,
            pattern_analysis,
            collision_probability,
        }
    }

    /// Calculate Shannon entropy of hash
    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        
        // Count byte frequencies
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let length = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let probability = count as f64 / length;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Calculate bit distribution (count of 0s and 1s)
    fn calculate_bit_distribution(data: &[u8]) -> Vec<u32> {
        let mut bit_counts = vec![0u32; 8];

        for &byte in data {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    bit_counts[i] += 1;
                }
            }
        }

        bit_counts
    }

    /// Analyze patterns in hash data
    fn analyze_patterns(data: &[u8]) -> PatternAnalysis {
        let mut repeated_sequences = Vec::new();
        let zero_bytes = data.iter().filter(|&&b| b == 0).count() as u32;
        let max_bytes = data.iter().filter(|&&b| b == 255).count() as u32;
        let mut sequential_patterns = 0u32;

        // Look for sequential patterns (simplified)
        for window in data.windows(3) {
            if window[0].wrapping_add(1) == window[1] && window[1].wrapping_add(1) == window[2] {
                sequential_patterns += 1;
            }
        }

        // Look for repeated 2-byte sequences
        let mut sequence_counts = HashMap::new();
        for window in data.windows(2) {
            let sequence = format!("{:02x}{:02x}", window[0], window[1]);
            *sequence_counts.entry(sequence).or_insert(0) += 1;
        }

        for (sequence, count) in sequence_counts {
            if count > 1 {
                repeated_sequences.push(format!("{}({})", sequence, count));
            }
        }

        PatternAnalysis {
            repeated_sequences,
            zero_bytes,
            max_bytes,
            sequential_patterns,
        }
    }

    /// Estimate collision probability based on hash length
    fn estimate_collision_probability(hash_length_bytes: usize) -> f64 {
        let bits = hash_length_bytes * 8;
        let total_possible = 2.0_f64.powi(bits as i32);
        
        // Birthday paradox approximation
        let sqrt_possible = total_possible.sqrt();
        1.0 / sqrt_possible
    }

    /// Verify hash integrity by recalculating
    #[instrument(skip(data))]
    pub fn verify_hash_integrity(data: &[u8], expected_hash: &str, algorithm: &HashType) -> bool {
        let calculated_hash = Self::calculate_hash(data, algorithm);
        calculated_hash.eq_ignore_ascii_case(expected_hash)
    }

    /// Generate hash for incremental data
    #[instrument(skip(chunks))]
    pub fn calculate_incremental_hash(chunks: &[&[u8]], algorithm: &HashType) -> String {
        match algorithm {
            HashType::Sha256 => {
                let mut hasher = Sha256::new();
                for chunk in chunks {
                    hasher.update(chunk);
                }
                format!("{:x}", hasher.finalize())
            },
            HashType::Sha512 => {
                let mut hasher = Sha512::new();
                for chunk in chunks {
                    hasher.update(chunk);
                }
                format!("{:x}", hasher.finalize())
            },
            HashType::Blake3 => {
                let mut hasher = Blake3Hasher::new();
                for chunk in chunks {
                    hasher.update(chunk);
                }
                hasher.finalize().to_hex().to_string()
            },
            _ => {
                // For other algorithms, concatenate and hash
                let mut combined = Vec::new();
                for chunk in chunks {
                    combined.extend_from_slice(chunk);
                }
                Self::calculate_hash(&combined, algorithm)
            }
        }
    }

    /// Find hash collisions (for testing purposes)
    #[instrument]
    pub fn find_potential_collisions(hashes: &[String], algorithm: &HashType) -> Vec<(String, String)> {
        let mut collisions = Vec::new();
        
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                if hashes[i].eq_ignore_ascii_case(&hashes[j]) {
                    collisions.push((hashes[i].clone(), hashes[j].clone()));
                }
            }
        }

        if !collisions.is_empty() {
            warn!("Found {} potential collisions for {:?}", collisions.len(), algorithm);
        }

        collisions
    }

    /// Generate hash summary for multiple algorithms
    #[instrument(skip(data))]
    pub fn generate_hash_summary(data: &[u8]) -> HashMap<String, String> {
        let algorithms = vec![
            HashType::Md5,
            HashType::Sha256,
            HashType::Sha512,
            HashType::Blake3,
        ];

        let mut summary = HashMap::new();
        
        for algorithm in algorithms {
            let hash = Self::calculate_hash(data, &algorithm);
            summary.insert(format!("{:?}", algorithm), hash);
        }

        summary.insert("size".to_string(), data.len().to_string());
        summary.insert("entropy".to_string(), 
            format!("{:.4}", Self::calculate_entropy(data)));

        summary
    }

    /// Normalize hash string (lowercase, no spaces/dashes)
    #[instrument]
    pub fn normalize_hash(hash: &str) -> String {
        hash.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase()
    }

    /// Check if hash appears to be cryptographically strong
    #[instrument]
    pub fn assess_hash_strength(hash: &str, algorithm: &HashType) -> (bool, Vec<String>) {
        let mut is_strong = true;
        let mut weaknesses = Vec::new();

        // Check length
        let expected_length = Self::get_expected_hash_length(algorithm);
        if hash.len() != expected_length {
            is_strong = false;
            weaknesses.push(format!("Incorrect length: {} (expected {})", hash.len(), expected_length));
        }

        // Check for obvious patterns
        if hash.chars().all(|c| c == hash.chars().next().unwrap()) {
            is_strong = false;
            weaknesses.push("All characters are identical".to_string());
        }

        // Check for sequential patterns
        let mut sequential_count = 0;
        let chars: Vec<char> = hash.chars().collect();
        for window in chars.windows(3) {
            if let (Some(a), Some(b), Some(c)) = (
                window[0].to_digit(16),
                window[1].to_digit(16),
                window[2].to_digit(16)
            ) {
                if b == a + 1 && c == b + 1 {
                    sequential_count += 1;
                }
            }
        }

        if sequential_count > hash.len() / 8 {
            is_strong = false;
            weaknesses.push("Too many sequential patterns".to_string());
        }

        // Check for repeated substrings
        for i in 2..=4 {
            if let Some(substr) = hash.get(0..i) {
                let occurrences = hash.matches(substr).count();
                if occurrences > hash.len() / (i * 3) {
                    is_strong = false;
                    weaknesses.push(format!("Repeated substring '{}' appears {} times", substr, occurrences));
                }
            }
        }

        (is_strong, weaknesses)
    }
}

/// Utility functions for common hash operations
pub mod utils {
    use super::*;

    /// Quick MD5 hash calculation
    pub fn md5(data: &[u8]) -> String {
        HashUtils::calculate_hash(data, &HashType::Md5)
    }

    /// Quick SHA-256 hash calculation
    pub fn sha256(data: &[u8]) -> String {
        HashUtils::calculate_hash(data, &HashType::Sha256)
    }

    /// Quick SHA-512 hash calculation
    pub fn sha512(data: &[u8]) -> String {
        HashUtils::calculate_hash(data, &HashType::Sha512)
    }

    /// Quick BLAKE3 hash calculation
    pub fn blake3(data: &[u8]) -> String {
        HashUtils::calculate_hash(data, &HashType::Blake3)
    }

    /// Quick hash verification
    pub fn verify(data: &[u8], expected: &str, algorithm: &HashType) -> bool {
        HashUtils::verify_hash_integrity(data, expected, algorithm)
    }
}
```

**Total Lines**: 500 lines of production-ready Rust code