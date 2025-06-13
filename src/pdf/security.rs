use crate::{
    errors::{ForensicError, Result},
    types::{EncryptionMethod, PdfVersion},
    config::Config,
    utils::crypto::{EncryptionHelper, SecurityUtils, HashCalculator},
};
use lopdf::{Document, Object, ObjectId, Dictionary};
use std::collections::HashMap;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use chrono::Utc;

/// Security handler for PDF encryption and decryption operations
pub struct SecurityHandler {
    encryption_config: EncryptionConfig,
    security_cache: HashMap<ObjectId, SecurityInfo>,
    current_permissions: u32,
    encryption_helper: Arc<EncryptionHelper>,
    last_operation: Option<String>,
    creation_timestamp: String,
}

#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub method: EncryptionMethod,
    pub key_length: u16,
    pub permissions: u32,
    pub version: u8,
    pub revision: u8,
    pub metadata_encrypted: bool,
    pub user_password_required: bool,
    pub owner_password_required: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    pub is_encrypted: bool,
    pub filter: String,
    pub version: u8,
    pub revision: u8,
    pub key_length: u16,
    pub permissions: u32,
    pub has_user_password: bool,
    pub has_owner_password: bool,
    pub encryption_key: Option<Vec<u8>>,
    pub creation_date: String,
}

#[derive(Debug, Clone)]
struct SecurityInfo {
    pub object_id: ObjectId,
    pub is_encrypted: bool,
    pub encryption_method: EncryptionMethod,
    pub decryption_key: Option<Vec<u8>>,
    pub last_modified: String,
}

impl SecurityHandler {
    pub fn new() -> Self {
        Self {
            encryption_config: EncryptionConfig::default(),
            security_cache: HashMap::new(),
            current_permissions: 0xFFFFFFFC,
            encryption_helper: Arc::new(EncryptionHelper::new()),
            last_operation: None,
            creation_timestamp: "2025-06-13 20:13:18".to_string(), // Using provided timestamp
        }
    }

    pub fn with_config(config: EncryptionConfig) -> Self {
        Self {
            encryption_config: config,
            security_cache: HashMap::new(),
            current_permissions: 0xFFFFFFFC,
            encryption_helper: Arc::new(EncryptionHelper::new()),
            last_operation: None,
            creation_timestamp: "2025-06-13 20:13:18".to_string(), // Using provided timestamp
        }
    }

    /// Analyze document encryption details
    pub fn analyze_document_security(&mut self, document: &Document) -> Result<EncryptionInfo> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(encrypt_ref) = trailer.get(b"Encrypt") {
                if let Ok(encrypt_id) = encrypt_ref.as_reference() {
                    return self.analyze_encryption_dictionary(document, encrypt_id);
                }
            }
        }

        Ok(EncryptionInfo {
            is_encrypted: false,
            filter: "None".to_string(),
            version: 0,
            revision: 0,
            key_length: 0,
            permissions: 0xFFFFFFFC,
            has_user_password: false,
            has_owner_password: false,
            encryption_key: None,
            creation_date: self.creation_timestamp.clone(),
        })
    }

    fn analyze_encryption_dictionary(&mut self, document: &Document, encrypt_id: ObjectId) -> Result<EncryptionInfo> {
        if let Ok(encrypt_obj) = document.get_object(encrypt_id) {
            if let Ok(encrypt_dict) = encrypt_obj.as_dict() {
                let filter = encrypt_dict.get(b"Filter")
                    .and_then(|f| f.as_name_str().ok())
                    .unwrap_or("Standard")
                    .to_string();

                let version = encrypt_dict.get(b"V")
                    .and_then(|v| v.as_i64().ok())
                    .unwrap_or(1) as u8;

                let revision = encrypt_dict.get(b"R")
                    .and_then(|r| r.as_i64().ok())
                    .unwrap_or(2) as u8;

                let key_length = encrypt_dict.get(b"Length")
                    .and_then(|l| l.as_i64().ok())
                    .unwrap_or(40) as u16;

                let permissions = encrypt_dict.get(b"P")
                    .and_then(|p| p.as_i64().ok())
                    .unwrap_or(-4) as u32;

                self.current_permissions = permissions;

                return Ok(EncryptionInfo {
                    is_encrypted: true,
                    filter,
                    version,
                    revision,
                    key_length,
                    permissions,
                    has_user_password: encrypt_dict.has(b"U"),
                    has_owner_password: encrypt_dict.has(b"O"),
                    encryption_key: None,
                    creation_date: self.creation_timestamp.clone(),
                });
            }
        }

        Err(ForensicError::encryption_error("Invalid encryption dictionary"))
    }

    /// Attempt to decrypt document with provided password
    pub fn decrypt_document(&mut self, document: &mut Document, password: Option<&str>) -> Result<bool> {
        let encryption_info = self.analyze_document_security(document)?;

        if !encryption_info.is_encrypted {
            return Ok(true);
        }

        let password = password.ok_or_else(|| {
            ForensicError::encryption_error("Password required for encrypted document")
        })?;

        // Generate encryption key from password
        let encryption_key = self.derive_encryption_key(&encryption_info, password)?;
        
        // Cache the encryption key for later use
        self.security_cache.insert(ObjectId(0, 0), SecurityInfo {
            object_id: ObjectId(0, 0),
            is_encrypted: true,
            encryption_method: self.encryption_config.method.clone(),
            decryption_key: Some(encryption_key.clone()),
            last_modified: self.creation_timestamp.clone(),
        });

        // Decrypt all encrypted objects
        self.decrypt_document_objects(document, &encryption_key)?;

        self.last_operation = Some("decrypt".to_string());
        Ok(true)
    }

    /// Apply encryption to document
    pub fn encrypt_document(
        &mut self,
        document: &mut Document,
        user_password: &str,
        owner_password: Option<&str>
    ) -> Result<()> {
        // Generate encryption dictionary
        let encrypt_dict = self.create_encryption_dictionary(user_password, owner_password)?;
        let encrypt_id = document.add_object(Object::Dictionary(encrypt_dict));

        // Update trailer
        if let Ok(trailer) = document.trailer.as_dict_mut() {
            trailer.set("Encrypt", Object::Reference(encrypt_id));
        }

        // Generate encryption key
        let encryption_key = self.derive_encryption_key_from_password(user_password)?;

        // Encrypt document objects
        self.encrypt_document_objects(document, &encryption_key)?;

        self.last_operation = Some("encrypt".to_string());
        Ok(())
    }

    fn create_encryption_dictionary(
        &self,
        user_password: &str,
        owner_password: Option<&str>
    ) -> Result<Dictionary> {
        let mut encrypt_dict = Dictionary::new();
        
        encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
        
        match self.encryption_config.method {
            EncryptionMethod::RC4_128 => {
                encrypt_dict.set("V", Object::Integer(2));
                encrypt_dict.set("R", Object::Integer(3));
                encrypt_dict.set("Length", Object::Integer(128));
            },
            EncryptionMethod::AES_128 => {
                encrypt_dict.set("V", Object::Integer(4));
                encrypt_dict.set("R", Object::Integer(4));
                encrypt_dict.set("Length", Object::Integer(128));
            },
            EncryptionMethod::AES_256 => {
                encrypt_dict.set("V", Object::Integer(5));
                encrypt_dict.set("R", Object::Integer(5));
                encrypt_dict.set("Length", Object::Integer(256));
            },
            _ => {
                return Err(ForensicError::encryption_error("Unsupported encryption method"));
            }
        }

        encrypt_dict.set("P", Object::Integer(self.encryption_config.permissions as i64));

        // Generate O and U values
        let o_value = self.generate_owner_password_hash(user_password, owner_password)?;
        let u_value = self.generate_user_password_hash(user_password, &o_value)?;

        encrypt_dict.set("O", Object::String(o_value, lopdf::StringFormat::Hexadecimal));
        encrypt_dict.set("U", Object::String(u_value, lopdf::StringFormat::Hexadecimal));

        // Set encryption metadata flag
        if self.encryption_config.metadata_encrypted {
            encrypt_dict.set("EncryptMetadata", Object::Boolean(true));
        }

        Ok(encrypt_dict)
    }

    fn derive_encryption_key(&self, encryption_info: &EncryptionInfo, password: &str) -> Result<Vec<u8>> {
        match encryption_info.version {
            1 | 2 => self.derive_rc4_key(encryption_info, password),
            4 => self.derive_aes_key(encryption_info, password),
            _ => Err(ForensicError::encryption_error("Unsupported encryption version")),
        }
    }

    fn derive_rc4_key(&self, encryption_info: &EncryptionInfo, password: &str) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&encryption_info.permissions.to_le_bytes());
        
        let hash = hasher.finalize();
        let key_length = encryption_info.key_length / 8;
        Ok(hash[..key_length as usize].to_vec())
    }

    fn derive_aes_key(&self, encryption_info: &EncryptionInfo, password: &str) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"salt");
        
        let hash = hasher.finalize();
        let key_length = encryption_info.key_length / 8;
        Ok(hash[..key_length as usize].to_vec())
    }

    fn decrypt_document_objects(&mut self, document: &mut Document, key: &[u8]) -> Result<()> {
        let object_ids: Vec<ObjectId> = document.objects.keys().copied().collect();
        
        for object_id in object_ids {
            if let Some(object) = document.objects.get_mut(&object_id) {
                self.decrypt_object(object, key, object_id)?;
            }
        }
        
        Ok(())
    }

    fn decrypt_object(&self, object: &mut Object, key: &[u8], object_id: ObjectId) -> Result<()> {
        match object {
            Object::String(ref mut data, _) => {
                *data = self.decrypt_string_data(data, key, object_id)?;
            },
            Object::Stream(ref mut stream) => {
                stream.content = self.decrypt_stream_data(&stream.content, key, object_id)?;
                self.decrypt_object(&mut Object::Dictionary(stream.dict.clone()), key, object_id)?;
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter_mut() {
                    self.decrypt_object(value, key, object_id)?;
                }
            },
            Object::Array(array) => {
                for item in array.iter_mut() {
                    self.decrypt_object(item, key, object_id)?;
                }
            },
            _ => {},
        }
        Ok(())
    }

    fn decrypt_string_data(&self, data: &[u8], key: &[u8], object_id: ObjectId) -> Result<Vec<u8>> {
        let object_key = self.generate_object_key(key, object_id);
        
        match self.encryption_config.method {
            EncryptionMethod::RC4_128 => self.decrypt_rc4(data, &object_key),
            EncryptionMethod::AES_128 | EncryptionMethod::AES_256 => self.decrypt_aes(data, &object_key),
            _ => Ok(data.to_vec()),
        }
    }

    fn decrypt_stream_data(&self, data: &[u8], key: &[u8], object_id: ObjectId) -> Result<Vec<u8>> {
        self.decrypt_string_data(data, key, object_id)
    }

    fn generate_object_key(&self, base_key: &[u8], object_id: ObjectId) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(base_key);
        hasher.update(&object_id.0.to_le_bytes());
        hasher.update(&object_id.1.to_le_bytes());
        hasher.finalize()[..16].to_vec()
    }

    fn decrypt_rc4(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.encryption_helper.decrypt(data, key)
    }

    fn decrypt_aes(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        self.encryption_helper.decrypt(data, key)
    }

    fn derive_encryption_key_from_password(&self, password: &str) -> Result<Vec<u8>> {
        let salt = SecurityUtils::generate_salt()?;
        self.encryption_helper.derive_key_from_password(password, &salt, 10000)
    }

    fn generate_owner_password_hash(&self, user_password: &str, owner_password: Option<&str>) -> Result<Vec<u8>> {
        let owner_pass = owner_password.unwrap_or(user_password);
        let mut hasher = Sha256::new();
        hasher.update(owner_pass.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    fn generate_user_password_hash(&self, password: &str, o_value: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(o_value);
        hasher.update(&self.encryption_config.permissions.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }

    fn encrypt_document_objects(&mut self, document: &mut Document, key: &[u8]) -> Result<()> {
        let object_ids: Vec<ObjectId> = document.objects.keys().copied().collect();
        
        for object_id in object_ids {
            if let Some(object) = document.objects.get_mut(&object_id) {
                self.encrypt_object(object, key, object_id)?;
            }
        }
        
        Ok(())
    }

    fn encrypt_object(&self, object: &mut Object, key: &[u8], object_id: ObjectId) -> Result<()> {
        match object {
            Object::String(ref mut data, _) => {
                *data = self.encrypt_string_data(data, key, object_id)?;
            },
            Object::Stream(ref mut stream) => {
                stream.content = self.encrypt_stream_data(&stream.content, key, object_id)?;
                self.encrypt_object(&mut Object::Dictionary(stream.dict.clone()), key, object_id)?;
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter_mut() {
                    self.encrypt_object(value, key, object_id)?;
                }
            },
            Object::Array(array) => {
                for item in array.iter_mut() {
                    self.encrypt_object(item, key, object_id)?;
                }
            },
            _ => {},
        }
        Ok(())
    }

    fn encrypt_string_data(&self, data: &[u8], key: &[u8], object_id: ObjectId) -> Result<Vec<u8>> {
        let object_key = self.generate_object_key(key, object_id);
        
        match self.encryption_config.method {
            EncryptionMethod::RC4_128 => self.encryption_helper.encrypt(data, &object_key),
            EncryptionMethod::AES_128 | EncryptionMethod::AES_256 => self.encryption_helper.encrypt(data, &object_key),
            _ => Ok(data.to_vec()),
        }
    }

    fn encrypt_stream_data(&self, data: &[u8], key: &[u8], object_id: ObjectId) -> Result<Vec<u8>> {
        self.encrypt_string_data(data, key, object_id)
    }

    // Permission checking methods
    pub fn can_modify_document(&self) -> bool {
        (self.current_permissions & 0x08) != 0
    }

    pub fn can_modify_metadata(&self) -> bool {
        (self.current_permissions & 0x20) != 0 || self.can_modify_document()
    }

    pub fn get_permissions(&self) -> u32 {
        self.current_permissions
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            method: EncryptionMethod::AES_256,
            key_length: 256,
            permissions: 0xFFFFFFFC,
            version: 5,
            revision: 5,
            metadata_encrypted: true,
            user_password_required: true,
            owner_password_required: false,
        }
    }
}

impl Default for SecurityHandler {
    fn default() -> Self {
        Self::new()
    }
          }
