use crate::{
    errors::{ForensicError, Result},
    config::Config,
    types::EncryptionMethod,
};
use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};
use rand::{Rng, thread_rng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cryptographic utilities for PDF forensic operations
pub struct HashCalculator {
    algorithm: HashAlgorithm,
    cache: HashMap<Vec<u8>, String>,
    cache_hits: AtomicUsize,
    last_operation: Option<String>,
}

/// Encryption helper for secure operations
pub struct EncryptionHelper {
    key_size: usize,
    algorithm: EncryptionAlgorithm,
    operation_counter: AtomicUsize,
    last_operation_time: std::sync::Mutex<SystemTime>,
}

/// Security utilities for forensic operations
pub struct SecurityUtils;

/// Cryptographic configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub hash_algorithm: HashAlgorithm,
    pub key_size: usize,
    pub enable_caching: bool,
    pub secure_random: bool,
    pub salt_size: usize,
    pub iteration_count: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

#[derive(Debug, Clone)]
pub enum EncryptionAlgorithm {
    Aes256,
    ChaCha20,
    XChaCha20,
}

impl HashCalculator {
    pub fn new() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            cache: HashMap::new(),
            cache_hits: AtomicUsize::new(0),
            last_operation: None,
        }
    }

    pub fn with_algorithm(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            cache: HashMap::new(),
            cache_hits: AtomicUsize::new(0),
            last_operation: None,
        }
    }

    /// Calculate hash of data
    pub fn calculate_hash(&mut self, data: &[u8]) -> Result<String> {
        if let Some(cached_hash) = self.cache.get(data) {
            self.cache_hits.fetch_add(1, Ordering::SeqCst);
            return Ok(cached_hash.clone());
        }

        let hash = match self.algorithm {
            HashAlgorithm::Sha256 => self.calculate_sha256(data)?,
            HashAlgorithm::Sha512 => self.calculate_sha512(data)?,
            HashAlgorithm::Blake3 => self.calculate_blake3(data)?,
        };

        self.cache.insert(data.to_vec(), hash.clone());
        self.last_operation = Some("calculate_hash".to_string());
        Ok(hash)
    }

    fn calculate_sha256(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn calculate_sha512(&self, data: &[u8]) -> Result<String> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn calculate_blake3(&self, data: &[u8]) -> Result<String> {
        let hash = blake3::hash(data);
        Ok(hash.to_hex().to_string())
    }

    /// Verify data integrity against hash
    pub fn verify_integrity(&mut self, data: &[u8], expected_hash: &str) -> Result<bool> {
        let calculated_hash = self.calculate_hash(data)?;
        self.last_operation = Some("verify_integrity".to_string());
        
        // Use constant-time comparison to prevent timing attacks
        Ok(SecurityUtils::constant_time_compare(
            calculated_hash.as_bytes(),
            expected_hash.as_bytes()
        ))
    }

    /// Calculate hash for PDF object
    pub fn hash_pdf_object(&mut self, object_data: &[u8], object_id: u32) -> Result<String> {
        let mut combined_data = Vec::with_capacity(object_data.len() + 4);
        combined_data.extend_from_slice(object_data);
        combined_data.extend_from_slice(&object_id.to_le_bytes());
        
        self.last_operation = Some("hash_pdf_object".to_string());
        self.calculate_hash(&combined_data)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStats {
        CacheStats {
            entries: self.cache.len(),
            hits: self.cache_hits.load(Ordering::SeqCst),
            algorithm: self.algorithm.clone(),
            last_operation: self.last_operation.clone(),
        }
    }

    /// Clear hash cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_hits.store(0, Ordering::SeqCst);
        self.last_operation = Some("clear_cache".to_string());
    }
}

impl EncryptionHelper {
    pub fn new() -> Self {
        Self {
            key_size: 32, // 256 bits
            algorithm: EncryptionAlgorithm::Aes256,
            operation_counter: AtomicUsize::new(0),
            last_operation_time: std::sync::Mutex::new(SystemTime::now()),
        }
    }

    pub fn with_algorithm(algorithm: EncryptionAlgorithm) -> Self {
        let key_size = match algorithm {
            EncryptionAlgorithm::Aes256 => 32,
            EncryptionAlgorithm::ChaCha20 => 32,
            EncryptionAlgorithm::XChaCha20 => 32,
        };

        Self {
            key_size,
            algorithm,
            operation_counter: AtomicUsize::new(0),
            last_operation_time: std::sync::Mutex::new(SystemTime::now()),
        }
    }

    /// Generate secure encryption key
    pub fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; self.key_size];
        thread_rng().fill(&mut key[..]);
        
        self.increment_operation_counter();
        Ok(key)
    }

    /// Generate initialization vector
    pub fn generate_iv(&self) -> Result<Vec<u8>> {
        let iv_size = match self.algorithm {
            EncryptionAlgorithm::Aes256 => 16,
            EncryptionAlgorithm::ChaCha20 => 12,
            EncryptionAlgorithm::XChaCha20 => 24,
        };

        let mut iv = vec![0u8; iv_size];
        thread_rng().fill(&mut iv[..]);
        
        self.increment_operation_counter();
        Ok(iv)
    }

    /// Encrypt data
    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size {
            return Err(ForensicError::encryption_error("Invalid key size"));
        }

        let result = match self.algorithm {
            EncryptionAlgorithm::Aes256 => self.encrypt_aes256(data, key)?,
            EncryptionAlgorithm::ChaCha20 => self.encrypt_chacha20(data, key)?,
            EncryptionAlgorithm::XChaCha20 => self.encrypt_xchacha20(data, key)?,
        };

        self.increment_operation_counter();
        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size {
            return Err(ForensicError::encryption_error("Invalid key size"));
        }

        let result = match self.algorithm {
            EncryptionAlgorithm::Aes256 => self.decrypt_aes256(encrypted_data, key)?,
            EncryptionAlgorithm::ChaCha20 => self.decrypt_chacha20(encrypted_data, key)?,
            EncryptionAlgorithm::XChaCha20 => self.decrypt_xchacha20(encrypted_data, key)?,
        };

        self.increment_operation_counter();
        Ok(result)
    }

    fn encrypt_aes256(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes::Aes256;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use cbc::Encryptor;

        let cipher = Aes256::new(key.into());
        let iv = self.generate_iv()?;
        
        let mut encryptor = Encryptor::<Aes256>::new(cipher, &iv.into());
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&iv);
        buffer.extend(encryptor.encrypt_padded_vec_mut::<pad::Pkcs7>(data));
        
        Ok(buffer)
    }

    fn decrypt_aes256(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes::Aes256;
        use aes::cipher::{BlockDecrypt, KeyInit};
        use cbc::Decryptor;

        if encrypted_data.len() < 16 {
            return Err(ForensicError::encryption_error("Invalid encrypted data"));
        }

        let (iv, cipher_text) = encrypted_data.split_at(16);
        let cipher = Aes256::new(key.into());
        
        let mut decryptor = Decryptor::<Aes256>::new(cipher, iv.into());
        let result = decryptor.decrypt_padded_vec_mut::<pad::Pkcs7>(cipher_text)
            .map_err(|e| ForensicError::encryption_error(&format!("Decryption failed: {:?}", e)))?;
        
        Ok(result)
    }

    fn encrypt_chacha20(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let nonce = self.generate_iv()?;
        let cipher = ChaCha20::new(key.into(), &nonce.into());
        
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend(buffer);
        
        Ok(result)
    }

    fn decrypt_chacha20(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        if encrypted_data.len() < 12 {
            return Err(ForensicError::encryption_error("Invalid encrypted data"));
        }

        let (nonce, cipher_text) = encrypted_data.split_at(12);
        let cipher = ChaCha20::new(key.into(), nonce.into());
        
        let mut buffer = cipher_text.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        Ok(buffer)
    }

    fn encrypt_xchacha20(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        let nonce = self.generate_iv()?;
        let cipher = XChaCha20::new(key.into(), &nonce.into());
        
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend(buffer);
        
        Ok(result)
    }

    fn decrypt_xchacha20(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        if encrypted_data.len() < 24 {
            return Err(ForensicError::encryption_error("Invalid encrypted data"));
        }

        let (nonce, cipher_text) = encrypted_data.split_at(24);
        let cipher = XChaCha20::new(key.into(), nonce.into());
        
        let mut buffer = cipher_text.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        Ok(buffer)
    }

    /// Derive key from password using PBKDF2
    pub fn derive_key_from_password(&self, password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
        use pbkdf2::{pbkdf2_hmac, Pbkdf2};

        let mut key = vec![0u8; self.key_size];
        pbkdf2_hmac::<Hmac<Sha256>>(
            password.as_bytes(),
            salt,
            iterations,
            &mut key,
        );

        self.increment_operation_counter();
        Ok(key)
    }

    fn increment_operation_counter(&self) {
        self.operation_counter.fetch_add(1, Ordering::SeqCst);
        *self.last_operation_time.lock().unwrap() = SystemTime::now();
    }

    /// Get operation statistics
    pub fn get_stats(&self) -> OperationStats {
        OperationStats {
            operations: self.operation_counter.load(Ordering::SeqCst),
            algorithm: self.algorithm.clone(),
            key_size: self.key_size,
            last_operation_time: *self.last_operation_time.lock().unwrap(),
        }
    }
}

impl SecurityUtils {
    /// Generate cryptographically secure random bytes
    pub fn generate_secure_random(size: usize) -> Result<Vec<u8>> {
        let mut random_bytes = vec![0u8; size];
        thread_rng().fill(&mut random_bytes[..]);
        Ok(random_bytes)
    }

    /// Generate secure salt for key derivation
    pub fn generate_salt() -> Result<Vec<u8>> {
        Self::generate_secure_random(16)
    }

    /// Constant-time comparison to prevent timing attacks
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Secure memory wipe
    pub fn secure_wipe(data: &mut [u8]) {
        // First overwrite with random data
        thread_rng().fill(data);
        
        // Then overwrite with zeros
        for byte in data.iter_mut() {
            *byte = 0;
        }
        
        // Compiler fence to prevent optimization
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// Calculate entropy of data
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Check if data appears to be encrypted/compressed
    pub fn appears_encrypted(data: &[u8]) -> bool {
        let entropy = Self::calculate_entropy(data);
        entropy > 7.5 // High entropy suggests encryption/compression
    }

    /// Generate secure nonce
    pub fn generate_nonce(size: usize) -> Result<Vec<u8>> {
        Self::generate_secure_random(size)
    }

    /// Validate key strength
    pub fn validate_key_strength(key: &[u8]) -> KeyStrength {
        let entropy = Self::calculate_entropy(key);
        let length = key.len();

        match (length, entropy) {
            (l, e) if l >= 32 && e > 7.0 => KeyStrength::Strong,
            (l, e) if l >= 16 && e > 6.0 => KeyStrength::Medium,
            (l, e) if l >= 8 && e > 4.0 => KeyStrength::Weak,
            _ => KeyStrength::VeryWeak,
        }
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: usize,
    pub algorithm: HashAlgorithm,
    pub last_operation: Option<String>,
}

#[derive(Debug)]
pub struct OperationStats {
    pub operations: usize,
    pub algorithm: EncryptionAlgorithm,
    pub key_size: usize,
    pub last_operation_time: SystemTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            key_size: 32,
            enable_caching: true,
            secure_random: true,
            salt_size: 16,
            iteration_count: 10000,
            timestamp: "2025-06-13 20:18:42".to_string(),
        }
    }
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

// Convenience functions
pub fn hash_content(data: &[u8]) -> Result<String> {
    let mut calculator = HashCalculator::new();
    calculator.calculate_hash(data)
}

pub fn verify_integrity(data: &[u8], expected_hash: &str) -> Result<bool> {
    let mut calculator = HashCalculator::new();
    calculator.verify_integrity(data, expected_hash)
}

pub fn generate_secure_key() -> Result<Vec<u8>> {
    let helper = EncryptionHelper::new();
    helper.generate_key()
    }
