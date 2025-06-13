use crate::{
    errors::{ForensicError, Result},
    config::Config,
};
use sha2::{Sha256, Sha512, Digest};
use rand::{thread_rng, RngCore};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

/// Hash calculation utility
pub struct HashCalculator {
    algorithm: HashAlgorithm,
    operator: String,
    last_operation: chrono::DateTime<chrono::Utc>,
}

/// Encryption helper utility
pub struct EncryptionHelper {
    key_size: usize,
    operator: String,
    last_operation: chrono::DateTime<chrono::Utc>,
}

/// General security utilities
pub struct SecurityUtils {
    hash_cache: HashMap<Vec<u8>, String>,
    operator: String,
    last_operation: chrono::DateTime<chrono::Utc>,
}

/// Crypto configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub hash_algorithm: HashAlgorithm,
    pub key_size: usize,
    pub enable_cache: bool,
    pub max_cache_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashCalculator {
    pub fn new() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            operator: "kartikpithava".to_string(),
            last_operation: chrono::DateTime::parse_from_rfc3339("2025-06-13T18:37:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    pub fn calculate_hash(&mut self, data: &[u8]) -> String {
        self.last_operation = chrono::Utc::now();
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            },
        }
    }

    pub fn verify_hash(&self, data: &[u8], expected_hash: &str) -> bool {
        let calculated = self.calculate_hash(data);
        calculated == expected_hash
    }
}

impl EncryptionHelper {
    pub fn new() -> Self {
        Self {
            key_size: 32, // 256 bits
            operator: "kartikpithava".to_string(),
            last_operation: chrono::DateTime::parse_from_rfc3339("2025-06-13T18:37:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    pub fn generate_key(&mut self) -> Result<Vec<u8>> {
        self.last_operation = chrono::Utc::now();
        let mut key = vec![0u8; self.key_size];
        thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    pub fn encode_key(&self, key: &[u8]) -> String {
        BASE64.encode(key)
    }

    pub fn decode_key(&self, encoded: &str) -> Result<Vec<u8>> {
        BASE64.decode(encoded)
            .map_err(|e| ForensicError::encryption_error(&format!("Invalid key format: {}", e)))
    }
}

impl SecurityUtils {
    pub fn new() -> Self {
        Self {
            hash_cache: HashMap::new(),
            operator: "kartikpithava".to_string(),
            last_operation: chrono::DateTime::parse_from_rfc3339("2025-06-13T18:37:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    pub fn clear_sensitive_data(&mut self) {
        self.hash_cache.clear();
        self.last_operation = chrono::Utc::now();
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            key_size: 32,
            enable_cache: true,
            max_cache_size: 1000,
        }
    }
}

// Utility functions exported by the module
pub fn hash_content(data: &[u8]) -> Result<String> {
    let mut calculator = HashCalculator::new();
    Ok(calculator.calculate_hash(data))
}

pub fn verify_integrity(data: &[u8], hash: &str) -> Result<bool> {
    let calculator = HashCalculator::new();
    Ok(calculator.verify_hash(data, hash))
}

pub fn generate_secure_key() -> Result<Vec<u8>> {
    let mut helper = EncryptionHelper::new();
    helper.generate_key()
}

impl Default for HashCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EncryptionHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecurityUtils {
    fn default() -> Self {
        Self::new()
    }
  }
