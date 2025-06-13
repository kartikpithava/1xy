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

/// Result type for parsed PDF data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPdfData {
    pub version: PdfVersion,
    pub objects: HashMap<u32, Vec<u8>>,
    pub metadata: MetadataMap,
    pub structure: DocumentStructure,
}

/// Document structure information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentStructure {
    pub root: u32,
    pub pages: Vec<u32>,
    pub outline: Option<u32>,
}

/// Data extracted from PDF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    pub text_content: String,
    pub metadata: MetadataMap,
    pub embedded_files: Vec<EmbeddedFile>,
    pub images: Vec<ImageData>,
}

/// Analysis results of PDF processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub validation_status: ValidationStatus,
    pub metadata_analysis: MetadataAnalysis,
    pub security_analysis: SecurityAnalysis,
    pub structure_analysis: StructureAnalysis,
}

/// Data for PDF cloning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneData {
    pub original_id: String,
    pub timestamp: DateTime<Utc>,
    pub modifications: Vec<Modification>,
}

/// Configuration for PDF reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionConfig {
    pub target_version: PdfVersion,
    pub preserve_metadata: bool,
    pub encryption: Option<EncryptionConfig>,
    pub compression_level: CompressionLevel,
}

/// Results from PDF validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub compliance_level: ComplianceLevel,
}

/// Embedded file data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFile {
    pub filename: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// Image data from PDF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub id: String,
    pub width: u32,
    pub height: u32,
    pub format: ImageFormat,
    pub data: Vec<u8>,
}

/// Modification record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Modification {
    pub field: String,
    pub previous: String,
    pub current: String,
    pub timestamp: DateTime<Utc>,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub method: EncryptionMethod,
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
    pub permissions: u32,
    pub key_length: u16,
}

/// Compression level options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionLevel {
    None,
    Fast,
    Default,
    Maximum,
}

/// Image format types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    Jpeg,
    Png,
    Tiff,
    Other(String),
}

/// Validation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    pub severity: Severity,
}

/// Validation warning details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub code: String,
    pub message: String,
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// PDF compliance levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceLevel {
    None,
    Basic,
    Extended,
    Full,
}

/// Validation status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatus {
    pub is_valid: bool,
    pub format_compliance: bool,
    pub structure_integrity: bool,
}

/// Metadata analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataAnalysis {
    pub completeness: f32,
    pub consistency: bool,
    pub duplicates: Vec<MetadataField>,
}

/// Security analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    pub encryption_status: Option<EncryptionMethod>,
    pub permissions: Option<u32>,
    pub vulnerabilities: Vec<String>,
}

/// Structure analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureAnalysis {
    pub object_count: usize,
    pub is_linearized: bool,
    pub has_updates: bool,
}

// Default implementations

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

impl Default for ReconstructionConfig {
    fn default() -> Self {
        Self {
            target_version: PdfVersion::output_version(),
            preserve_metadata: true,
            encryption: None,
            compression_level: CompressionLevel::Default,
        }
    }
}
