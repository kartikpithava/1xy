use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// PDF version specification (always outputs PDF 1.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfVersion {
    V1_4,  // Target output version
    V1_5,  // Input compatibility
    V1_6,  // Input compatibility
    V1_7,  // Input compatibility
    V2_0,  // Input compatibility
}

impl PdfVersion {
    pub fn as_string(&self) -> String {
        match self {
            PdfVersion::V1_4 => "1.4".to_string(),
            PdfVersion::V1_5 => "1.5".to_string(),
            PdfVersion::V1_6 => "1.6".to_string(),
            PdfVersion::V1_7 => "1.7".to_string(),
            PdfVersion::V2_0 => "2.0".to_string(),
        }
    }
    
    pub fn output_version() -> Self {
        PdfVersion::V1_4
    }
}

/// Metadata field enumeration for comprehensive coverage
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataField {
    Title,
    Author,
    Subject,
    Keywords,
    Creator,
    Producer,
    CreationDate,
    ModificationDate,
    Trapped,
    Custom(String),
}

impl MetadataField {
    pub fn as_string(&self) -> String {
        match self {
            MetadataField::Title => "Title".to_string(),
            MetadataField::Author => "Author".to_string(),
            MetadataField::Subject => "Subject".to_string(),
            MetadataField::Keywords => "Keywords".to_string(),
            MetadataField::Creator => "Creator".to_string(),
            MetadataField::Producer => "Producer".to_string(),
            MetadataField::CreationDate => "CreationDate".to_string(),
            MetadataField::ModificationDate => "ModDate".to_string(),
            MetadataField::Trapped => "Trapped".to_string(),
            MetadataField::Custom(name) => name.clone(),
        }
    }
}

/// Encryption method enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMethod {
    None,
    RC4_40,
    RC4_128,
    AES_128,
    AES_256,
}

impl EncryptionMethod {
    pub fn default_method() -> Self {
        EncryptionMethod::AES_128
    }
    
    pub fn requires_password(&self) -> bool {
        !matches!(self, EncryptionMethod::None)
    }
}

/// Metadata storage location tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataLocation {
    DocInfo,           // Document Information Dictionary
    XmpStream,         // XMP Metadata Stream
    ObjectStream(u32), // Embedded in specific object
    Annotation(u32),   // Within annotation objects
    FormField(String), // Within form field objects
    CustomLocation(String), // Other discovered locations
}

/// Comprehensive metadata value container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataValue {
    pub field: MetadataField,
    pub value: Option<String>,
    pub locations: Vec<MetadataLocation>,
    pub is_synchronized: bool,
}

/// Complete metadata map for synchronization
pub type MetadataMap = HashMap<MetadataField, MetadataValue>;

/// Encryption configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub method: EncryptionMethod,
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
    pub permissions: u32,
    pub key_length: u16,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            method: EncryptionMethod::None,
            user_password: None,
            owner_password: None,
            permissions: 0xFFFFFFFC, // All permissions enabled
            key_length: 128,
        }
    }
  }
