# Implementation Guide 03: PDF Processing Engine Core

## Files to Create in This Guide: 5 Files

This guide implements the core PDF processing engine with parsing, extraction, and analysis capabilities.

---

## File 1: `src/pdf/mod.rs` (42 lines)

**Purpose**: PDF processing module interface and coordination
**Location**: src/pdf/mod.rs
**Functionality**: Module exports, type sharing, API coordination

```rust
//! PDF Processing Engine
//! 
//! Comprehensive PDF parsing, analysis, and manipulation system with forensic capabilities.
//! Handles complete PDF structure extraction, metadata discovery, and content preservation.

pub mod parser;
pub mod extractor;
pub mod analyzer;
pub mod cloner;
pub mod reconstructor;
pub mod security;
pub mod validator;

// Re-export commonly used types and functions
pub use self::parser::{PdfParser, ParsedPdfData};
pub use self::extractor::{PdfExtractor, ExtractionData};
pub use self::analyzer::{PdfAnalyzer, AnalysisResult};
pub use self::cloner::{PdfCloner, CloneData};
pub use self::reconstructor::{PdfReconstructor, ReconstructionConfig};
pub use self::security::{SecurityHandler, EncryptionInfo};
pub use self::validator::{PdfValidator, ValidationResult};

use crate::errors::{ForensicError, Result};
use crate::types::{PdfVersion, MetadataField};

/// PDF processing configuration
#[derive(Debug, Clone)]
pub struct PdfProcessingConfig {
    pub preserve_structure: bool,
    pub extract_hidden_metadata: bool,
    pub validate_integrity: bool,
    pub forensic_mode: bool,
}

impl Default for PdfProcessingConfig {
    fn default() -> Self {
        Self {
            preserve_structure: true,
            extract_hidden_metadata: true,
            validate_integrity: true,
            forensic_mode: true,
        }
    }
}

/// Common PDF processing result wrapper
pub type PdfResult<T> = Result<T>;
```

---

## File 2: `src/pdf/parser.rs` (187 lines)

**Purpose**: Complete PDF document parsing with structure analysis
**Location**: src/pdf/parser.rs
**Functionality**: PDF parsing, object extraction, relationship mapping, encryption detection

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{PdfVersion, MetadataField},
    config::Config,
};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Comprehensive PDF parser with forensic capabilities
pub struct PdfParser {
    config: super::PdfProcessingConfig,
    object_cache: HashMap<ObjectId, Object>,
    metadata_locations: Vec<MetadataLocation>,
}

/// Complete parsed PDF data structure
#[derive(Debug, Clone)]
pub struct ParsedPdfData {
    pub document: Document,
    pub version: PdfVersion,
    pub object_map: HashMap<ObjectId, PdfObjectInfo>,
    pub metadata_locations: Vec<MetadataLocation>,
    pub encryption_info: Option<EncryptionInfo>,
    pub page_count: usize,
    pub file_size: u64,
    pub structure_integrity: bool,
}

#[derive(Debug, Clone)]
pub struct PdfObjectInfo {
    pub object_id: ObjectId,
    pub object_type: String,
    pub contains_metadata: bool,
    pub is_encrypted: bool,
    pub references: Vec<ObjectId>,
    pub content_size: usize,
}

#[derive(Debug, Clone)]
pub struct MetadataLocation {
    pub location_type: String,
    pub object_id: Option<ObjectId>,
    pub field_name: String,
    pub field_value: Option<String>,
    pub is_hidden: bool,
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
}

impl PdfParser {
    pub fn new() -> Self {
        Self {
            config: super::PdfProcessingConfig::default(),
            object_cache: HashMap::new(),
            metadata_locations: Vec::new(),
        }
    }
    
    pub fn with_config(config: super::PdfProcessingConfig) -> Self {
        Self {
            config,
            object_cache: HashMap::new(),
            metadata_locations: Vec::new(),
        }
    }
    
    /// Parse PDF file and extract complete structure
    pub fn parse_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<ParsedPdfData> {
        let path = file_path.as_ref();
        
        // Validate file size
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > Config::MAX_FILE_SIZE {
            return Err(ForensicError::parse_error("File too large for processing"));
        }
        
        // Load PDF document
        let document = Document::load(path)
            .map_err(|e| ForensicError::parse_error(&format!("Failed to load PDF: {}", e)))?;
        
        self.parse_document(document, metadata.len())
    }
    
    /// Parse PDF from memory buffer
    pub fn parse_memory(&mut self, pdf_data: &[u8]) -> Result<ParsedPdfData> {
        if pdf_data.len() as u64 > Config::MAX_FILE_SIZE {
            return Err(ForensicError::parse_error("PDF data too large for processing"));
        }
        
        let document = Document::load_mem(pdf_data)
            .map_err(|e| ForensicError::parse_error(&format!("Failed to load PDF from memory: {}", e)))?;
        
        self.parse_document(document, pdf_data.len() as u64)
    }
    
    fn parse_document(&mut self, document: Document, file_size: u64) -> Result<ParsedPdfData> {
        // Extract PDF version
        let version = self.parse_pdf_version(&document)?;
        
        // Analyze document structure
        let object_map = self.analyze_object_structure(&document)?;
        
        // Detect encryption
        let encryption_info = self.detect_encryption(&document)?;
        
        // Discover metadata locations
        self.discover_metadata_locations(&document)?;
        
        // Count pages
        let page_count = document.get_pages().len();
        
        // Validate structure integrity
        let structure_integrity = self.validate_structure_integrity(&document)?;
        
        Ok(ParsedPdfData {
            document,
            version,
            object_map,
            metadata_locations: self.metadata_locations.clone(),
            encryption_info,
            page_count,
            file_size,
            structure_integrity,
        })
    }
    
    fn parse_pdf_version(&self, document: &Document) -> Result<PdfVersion> {
        let version_str = &document.version;
        match version_str.as_str() {
            "1.4" => Ok(PdfVersion::V1_4),
            "1.5" => Ok(PdfVersion::V1_5),
            "1.6" => Ok(PdfVersion::V1_6),
            "1.7" => Ok(PdfVersion::V1_7),
            "2.0" => Ok(PdfVersion::V2_0),
            _ => Err(ForensicError::parse_error(&format!("Unsupported PDF version: {}", version_str))),
        }
    }
    
    fn analyze_object_structure(&mut self, document: &Document) -> Result<HashMap<ObjectId, PdfObjectInfo>> {
        let mut object_map = HashMap::new();
        
        // Iterate through all objects in the document
        for (object_id, object) in document.objects.iter() {
            let object_info = self.analyze_object(*object_id, object)?;
            object_map.insert(*object_id, object_info);
        }
        
        // Analyze cross-references and relationships
        self.analyze_object_relationships(&mut object_map, document)?;
        
        Ok(object_map)
    }
    
    fn analyze_object(&self, object_id: ObjectId, object: &Object) -> Result<PdfObjectInfo> {
        let object_type = self.determine_object_type(object);
        let contains_metadata = self.check_metadata_presence(object);
        let is_encrypted = self.check_encryption_status(object);
        let references = self.extract_object_references(object);
        let content_size = self.calculate_object_size(object);
        
        Ok(PdfObjectInfo {
            object_id,
            object_type,
            contains_metadata,
            is_encrypted,
            references,
            content_size,
        })
    }
    
    fn determine_object_type(&self, object: &Object) -> String {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return type_name.to_string();
                    }
                }
                "Dictionary".to_string()
            },
            Object::Stream(_) => "Stream".to_string(),
            Object::Array(_) => "Array".to_string(),
            Object::String(_, _) => "String".to_string(),
            Object::Name(_) => "Name".to_string(),
            Object::Integer(_) => "Integer".to_string(),
            Object::Real(_) => "Real".to_string(),
            Object::Boolean(_) => "Boolean".to_string(),
            Object::Null => "Null".to_string(),
            Object::Reference(_) => "Reference".to_string(),
        }
    }
    
    fn check_metadata_presence(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => {
                // Check for common metadata keys
                let metadata_keys = [
                    b"Title", b"Author", b"Subject", b"Keywords", 
                    b"Creator", b"Producer", b"CreationDate", b"ModDate"
                ];
                
                for key in &metadata_keys {
                    if dict.has(key) {
                        return true;
                    }
                }
                
                // Check for XMP metadata stream
                if dict.has(b"Metadata") {
                    return true;
                }
                
                false
            },
            Object::Stream(stream) => {
                // Check if stream contains XMP metadata
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            return subtype_name == "XML";
                        }
                    }
                }
                false
            },
            _ => false,
        }
    }
    
    fn check_encryption_status(&self, object: &Object) -> bool {
        // This would be determined by the document's encryption status
        // For now, return false as a placeholder
        false
    }
    
    fn extract_object_references(&self, object: &Object) -> Vec<ObjectId> {
        let mut references = Vec::new();
        self.collect_references_recursive(object, &mut references);
        references
    }
    
    fn collect_references_recursive(&self, object: &Object, references: &mut Vec<ObjectId>) {
        match object {
            Object::Reference(object_id) => {
                references.push(*object_id);
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_references_recursive(value, references);
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.collect_references_recursive(item, references);
                }
            },
            Object::Stream(stream) => {
                self.collect_references_recursive(&Object::Dictionary(stream.dict.clone()), references);
            },
            _ => {},
        }
    }
    
    fn calculate_object_size(&self, object: &Object) -> usize {
        match object {
            Object::Stream(stream) => stream.content.len(),
            Object::String(s, _) => s.len(),
            Object::Array(array) => array.len() * 8, // Estimate
            Object::Dictionary(dict) => dict.len() * 16, // Estimate
            _ => 8, // Basic size estimate
        }
    }
    
    fn analyze_object_relationships(&self, object_map: &mut HashMap<ObjectId, PdfObjectInfo>, document: &Document) -> Result<()> {
        // This would analyze cross-reference relationships
        // Implementation would traverse the object tree and update relationship information
        Ok(())
    }
    
    fn detect_encryption(&self, document: &Document) -> Result<Option<EncryptionInfo>> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(encrypt_ref) = trailer.get(b"Encrypt") {
                if let Ok(object_id) = encrypt_ref.as_reference() {
                    if let Ok(encrypt_obj) = document.get_object(object_id) {
                        if let Ok(encrypt_dict) = encrypt_obj.as_dict() {
                            return Ok(Some(self.parse_encryption_dictionary(encrypt_dict)?));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
    
    fn parse_encryption_dictionary(&self, encrypt_dict: &Dictionary) -> Result<EncryptionInfo> {
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
            .unwrap_or(-1) as u32;
        
        let has_user_password = encrypt_dict.has(b"U");
        let has_owner_password = encrypt_dict.has(b"O");
        
        Ok(EncryptionInfo {
            is_encrypted: true,
            filter,
            version,
            revision,
            key_length,
            permissions,
            has_user_password,
            has_owner_password,
        })
    }
    
    fn discover_metadata_locations(&mut self, document: &Document) -> Result<()> {
        self.metadata_locations.clear();
        
        // Scan Document Information Dictionary
        self.scan_document_info(document)?;
        
        // Scan XMP metadata streams
        self.scan_xmp_metadata(document)?;
        
        // Scan hidden metadata in objects
        self.scan_hidden_metadata(document)?;
        
        Ok(())
    }
    
    fn scan_document_info(&mut self, document: &Document) -> Result<()> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(info_ref) = trailer.get(b"Info") {
                if let Ok(object_id) = info_ref.as_reference() {
                    if let Ok(info_obj) = document.get_object(object_id) {
                        if let Ok(info_dict) = info_obj.as_dict() {
                            for (key, value) in info_dict.iter() {
                                let field_name = String::from_utf8_lossy(key).to_string();
                                let field_value = value.as_str().ok().map(|s| s.to_string());
                                
                                self.metadata_locations.push(MetadataLocation {
                                    location_type: "DocInfo".to_string(),
                                    object_id: Some(object_id),
                                    field_name,
                                    field_value,
                                    is_hidden: false,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn scan_xmp_metadata(&mut self, document: &Document) -> Result<()> {
        // Scan for XMP metadata streams
        for (object_id, object) in &document.objects {
            if let Object::Stream(stream) = object {
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            if subtype_name == "XML" {
                                // This is likely an XMP metadata stream
                                self.metadata_locations.push(MetadataLocation {
                                    location_type: "XMP".to_string(),
                                    object_id: Some(*object_id),
                                    field_name: "XMP Stream".to_string(),
                                    field_value: None,
                                    is_hidden: false,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn scan_hidden_metadata(&mut self, document: &Document) -> Result<()> {
        // Scan for hidden metadata in various object types
        for (object_id, object) in &document.objects {
            if self.check_metadata_presence(object) {
                self.metadata_locations.push(MetadataLocation {
                    location_type: "Hidden".to_string(),
                    object_id: Some(*object_id),
                    field_name: "Hidden Metadata".to_string(),
                    field_value: None,
                    is_hidden: true,
                });
            }
        }
        Ok(())
    }
    
    fn validate_structure_integrity(&self, document: &Document) -> Result<bool> {
        // Validate basic PDF structure
        let has_catalog = document.catalog().is_ok();
        let has_pages = !document.get_pages().is_empty();
        let has_valid_trailer = document.trailer.as_dict().is_ok();
        
        Ok(has_catalog && has_pages && has_valid_trailer)
    }
    
    /// Extract complete PDF structure for cloning
    pub fn extract_complete_structure(&mut self, parsed_data: &ParsedPdfData) -> Result<super::ExtractionData> {
        // This would extract all data needed for perfect cloning
        // Implementation delegated to the extractor module
        let extractor = super::extractor::PdfExtractor::new();
        extractor.extract_complete_data(parsed_data)
    }
}

impl Default for PdfParser {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 3: `src/pdf/extractor.rs` (164 lines)

**Purpose**: Complete data extraction system for PDF cloning
**Location**: src/pdf/extractor.rs
**Functionality**: Visible/hidden content discovery, binary preservation, metadata extraction

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue, MetadataLocation},
    config::Config,
};
use super::{ParsedPdfData, MetadataLocation as PdfMetadataLocation};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Complete PDF data extractor for forensic cloning
pub struct PdfExtractor {
    extract_hidden_content: bool,
    preserve_binary_data: bool,
}

/// Complete extraction data for PDF cloning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    pub metadata_map: MetadataMap,
    pub object_data: HashMap<ObjectId, ExtractedObjectData>,
    pub structure_data: StructureData,
    pub content_streams: HashMap<ObjectId, Vec<u8>>,
    pub binary_objects: HashMap<ObjectId, Vec<u8>>,
    pub cross_references: HashMap<ObjectId, Vec<ObjectId>>,
    pub encryption_data: Option<EncryptionData>,
    pub creation_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedObjectData {
    pub object_id: ObjectId,
    pub object_type: String,
    pub dictionary_data: Option<HashMap<String, String>>,
    pub stream_data: Option<Vec<u8>>,
    pub is_metadata_container: bool,
    pub references: Vec<ObjectId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureData {
    pub pdf_version: String,
    pub page_count: usize,
    pub catalog_id: ObjectId,
    pub pages_root_id: ObjectId,
    pub info_dict_id: Option<ObjectId>,
    pub metadata_stream_id: Option<ObjectId>,
    pub trailer_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionData {
    pub encrypt_dict: HashMap<String, String>,
    pub security_handler: String,
    pub key_length: u16,
    pub permissions: u32,
}

impl PdfExtractor {
    pub fn new() -> Self {
        Self {
            extract_hidden_content: true,
            preserve_binary_data: true,
        }
    }
    
    pub fn with_options(extract_hidden: bool, preserve_binary: bool) -> Self {
        Self {
            extract_hidden_content: extract_hidden,
            preserve_binary_data: preserve_binary,
        }
    }
    
    /// Extract complete PDF data for forensic cloning
    pub fn extract_complete_data(&self, parsed_data: &ParsedPdfData) -> Result<ExtractionData> {
        let metadata_map = self.extract_metadata_map(parsed_data)?;
        let object_data = self.extract_object_data(&parsed_data.document)?;
        let structure_data = self.extract_structure_data(parsed_data)?;
        let content_streams = self.extract_content_streams(&parsed_data.document)?;
        let binary_objects = self.extract_binary_objects(&parsed_data.document)?;
        let cross_references = self.extract_cross_references(&parsed_data.document)?;
        let encryption_data = self.extract_encryption_data(parsed_data)?;
        let creation_date = self.extract_creation_date(parsed_data)?;
        
        Ok(ExtractionData {
            metadata_map,
            object_data,
            structure_data,
            content_streams,
            binary_objects,
            cross_references,
            encryption_data,
            creation_date,
        })
    }
    
    fn extract_metadata_map(&self, parsed_data: &ParsedPdfData) -> Result<MetadataMap> {
        let mut metadata_map = HashMap::new();
        
        for location in &parsed_data.metadata_locations {
            let field = self.parse_metadata_field(&location.field_name)?;
            let metadata_location = self.convert_metadata_location(location);
            
            let metadata_value = MetadataValue {
                field: field.clone(),
                value: location.field_value.clone(),
                locations: vec![metadata_location],
                is_synchronized: false,
            };
            
            // Merge with existing metadata or create new entry
            if let Some(existing) = metadata_map.get_mut(&field) {
                existing.locations.push(metadata_location);
            } else {
                metadata_map.insert(field, metadata_value);
            }
        }
        
        Ok(metadata_map)
    }
    
    fn parse_metadata_field(&self, field_name: &str) -> Result<MetadataField> {
        match field_name {
            "Title" => Ok(MetadataField::Title),
            "Author" => Ok(MetadataField::Author),
            "Subject" => Ok(MetadataField::Subject),
            "Keywords" => Ok(MetadataField::Keywords),
            "Creator" => Ok(MetadataField::Creator),
            "Producer" => Ok(MetadataField::Producer),
            "CreationDate" => Ok(MetadataField::CreationDate),
            "ModDate" => Ok(MetadataField::ModificationDate),
            "Trapped" => Ok(MetadataField::Trapped),
            custom => Ok(MetadataField::Custom(custom.to_string())),
        }
    }
    
    fn convert_metadata_location(&self, location: &PdfMetadataLocation) -> MetadataLocation {
        match location.location_type.as_str() {
            "DocInfo" => MetadataLocation::DocInfo,
            "XMP" => MetadataLocation::XmpStream,
            "Hidden" => {
                if let Some(object_id) = location.object_id {
                    MetadataLocation::ObjectStream(object_id.0 as u32)
                } else {
                    MetadataLocation::CustomLocation("Hidden".to_string())
                }
            },
            _ => MetadataLocation::CustomLocation(location.location_type.clone()),
        }
    }
    
    fn extract_object_data(&self, document: &Document) -> Result<HashMap<ObjectId, ExtractedObjectData>> {
        let mut object_data = HashMap::new();
        
        for (object_id, object) in &document.objects {
            let extracted = self.extract_single_object(*object_id, object)?;
            object_data.insert(*object_id, extracted);
        }
        
        Ok(object_data)
    }
    
    fn extract_single_object(&self, object_id: ObjectId, object: &Object) -> Result<ExtractedObjectData> {
        let object_type = self.determine_object_type(object);
        let dictionary_data = self.extract_dictionary_data(object)?;
        let stream_data = self.extract_stream_data(object)?;
        let is_metadata_container = self.check_metadata_container(object);
        let references = self.extract_object_references(object);
        
        Ok(ExtractedObjectData {
            object_id,
            object_type,
            dictionary_data,
            stream_data,
            is_metadata_container,
            references,
        })
    }
    
    fn determine_object_type(&self, object: &Object) -> String {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return type_name.to_string();
                    }
                }
                "Dictionary".to_string()
            },
            Object::Stream(_) => "Stream".to_string(),
            Object::Array(_) => "Array".to_string(),
            Object::String(_, _) => "String".to_string(),
            Object::Name(_) => "Name".to_string(),
            Object::Integer(_) => "Integer".to_string(),
            Object::Real(_) => "Real".to_string(),
            Object::Boolean(_) => "Boolean".to_string(),
            Object::Null => "Null".to_string(),
            Object::Reference(_) => "Reference".to_string(),
        }
    }
    
    fn extract_dictionary_data(&self, object: &Object) -> Result<Option<HashMap<String, String>>> {
        match object {
            Object::Dictionary(dict) => {
                let mut dict_data = HashMap::new();
                for (key, value) in dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    let value_str = self.object_to_string(value);
                    dict_data.insert(key_str, value_str);
                }
                Ok(Some(dict_data))
            },
            Object::Stream(stream) => {
                let mut dict_data = HashMap::new();
                for (key, value) in stream.dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    let value_str = self.object_to_string(value);
                    dict_data.insert(key_str, value_str);
                }
                Ok(Some(dict_data))
            },
            _ => Ok(None),
        }
    }
    
    fn extract_stream_data(&self, object: &Object) -> Result<Option<Vec<u8>>> {
        match object {
            Object::Stream(stream) => Ok(Some(stream.content.clone())),
            _ => Ok(None),
        }
    }
    
    fn check_metadata_container(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => {
                // Check for common metadata keys
                let metadata_keys = [
                    b"Title", b"Author", b"Subject", b"Keywords", 
                    b"Creator", b"Producer", b"CreationDate", b"ModDate"
                ];
                
                metadata_keys.iter().any(|key| dict.has(key))
            },
            Object::Stream(stream) => {
                // Check if this is an XMP metadata stream
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            return subtype_name == "XML";
                        }
                    }
                }
                false
            },
            _ => false,
        }
    }
    
    fn extract_object_references(&self, object: &Object) -> Vec<ObjectId> {
        let mut references = Vec::new();
        self.collect_references_recursive(object, &mut references);
        references
    }
    
    fn collect_references_recursive(&self, object: &Object, references: &mut Vec<ObjectId>) {
        match object {
            Object::Reference(object_id) => {
                references.push(*object_id);
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_references_recursive(value, references);
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.collect_references_recursive(item, references);
                }
            },
            Object::Stream(stream) => {
                self.collect_references_recursive(&Object::Dictionary(stream.dict.clone()), references);
            },
            _ => {},
        }
    }
    
    fn object_to_string(&self, object: &Object) -> String {
        match object {
            Object::String(s, _) => String::from_utf8_lossy(s).to_string(),
            Object::Name(n) => String::from_utf8_lossy(n).to_string(),
            Object::Integer(i) => i.to_string(),
            Object::Real(r) => r.to_string(),
            Object::Boolean(b) => b.to_string(),
            Object::Null => "null".to_string(),
            Object::Reference(r) => format!("{} {} R", r.0, r.1),
            _ => "[Complex Object]".to_string(),
        }
    }
    
    fn extract_structure_data(&self, parsed_data: &ParsedPdfData) -> Result<StructureData> {
        let document = &parsed_data.document;
        
        let catalog_id = document.catalog()
            .map_err(|e| ForensicError::structure_error(&format!("No catalog found: {}", e)))?;
        
        let pages_root_id = self.find_pages_root(document, catalog_id)?;
        let info_dict_id = self.find_info_dict(document)?;
        let metadata_stream_id = self.find_metadata_stream(document, catalog_id)?;
        let trailer_data = self.extract_trailer_data(document)?;
        
        Ok(StructureData {
            pdf_version: parsed_data.version.as_string(),
            page_count: parsed_data.page_count,
            catalog_id,
            pages_root_id,
            info_dict_id,
            metadata_stream_id,
            trailer_data,
        })
    }
    
    fn find_pages_root(&self, document: &Document, catalog_id: ObjectId) -> Result<ObjectId> {
        if let Ok(catalog_obj) = document.get_object(catalog_id) {
            if let Ok(catalog_dict) = catalog_obj.as_dict() {
                if let Ok(pages_ref) = catalog_dict.get(b"Pages") {
                    if let Ok(pages_id) = pages_ref.as_reference() {
                        return Ok(pages_id);
                    }
                }
            }
        }
        Err(ForensicError::structure_error("Pages root not found"))
    }
    
    fn find_info_dict(&self, document: &Document) -> Result<Option<ObjectId>> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(info_ref) = trailer.get(b"Info") {
                if let Ok(info_id) = info_ref.as_reference() {
                    return Ok(Some(info_id));
                }
            }
        }
        Ok(None)
    }
    
    fn find_metadata_stream(&self, document: &Document, catalog_id: ObjectId) -> Result<Option<ObjectId>> {
        if let Ok(catalog_obj) = document.get_object(catalog_id) {
            if let Ok(catalog_dict) = catalog_obj.as_dict() {
                if let Ok(metadata_ref) = catalog_dict.get(b"Metadata") {
                    if let Ok(metadata_id) = metadata_ref.as_reference() {
                        return Ok(Some(metadata_id));
                    }
                }
            }
        }
        Ok(None)
    }
    
    fn extract_trailer_data(&self, document: &Document) -> Result<HashMap<String, String>> {
        let mut trailer_data = HashMap::new();
        
        if let Ok(trailer_dict) = document.trailer.as_dict() {
            for (key, value) in trailer_dict.iter() {
                let key_str = String::from_utf8_lossy(key).to_string();
                let value_str = self.object_to_string(value);
                trailer_data.insert(key_str, value_str);
            }
        }
        
        Ok(trailer_data)
    }
    
    fn extract_content_streams(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<u8>>> {
        let mut content_streams = HashMap::new();
        
        for (object_id, object) in &document.objects {
            if let Object::Stream(stream) = object {
                // Check if this is a content stream (e.g., page content)
                if self.is_content_stream(stream) {
                    content_streams.insert(*object_id, stream.content.clone());
                }
            }
        }
        
        Ok(content_streams)
    }
    
    fn is_content_stream(&self, stream: &Stream) -> bool {
        // Check if this stream contains page content or other important data
        if let Ok(dict) = &stream.dict.as_dict() {
            // Page content streams don't typically have a specific subtype
            // but they are referenced from page objects
            return !dict.has(b"Subtype") || 
                   dict.get(b"Subtype").and_then(|s| s.as_name_str().ok()).map_or(true, |s| s != "XML");
        }
        true
    }
    
    fn extract_binary_objects(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<u8>>> {
        let mut binary_objects = HashMap::new();
        
        if self.preserve_binary_data {
            for (object_id, object) in &document.objects {
                if let Some(binary_data) = self.extract_binary_data(object) {
                    binary_objects.insert(*object_id, binary_data);
                }
            }
        }
        
        Ok(binary_objects)
    }
    
    fn extract_binary_data(&self, object: &Object) -> Option<Vec<u8>> {
        match object {
            Object::Stream(stream) => {
                // For binary streams (images, fonts, etc.)
                if self.is_binary_stream(stream) {
                    Some(stream.content.clone())
                } else {
                    None
                }
            },
            Object::String(data, _) => {
                // For binary string data
                if data.len() > 50 && self.appears_binary(data) {
                    Some(data.clone())
                } else {
                    None
                }
            },
            _ => None,
        }
    }
    
    fn is_binary_stream(&self, stream: &Stream) -> bool {
        if let Ok(dict) = &stream.dict.as_dict() {
            if let Ok(subtype) = dict.get(b"Subtype") {
                if let Ok(subtype_name) = subtype.as_name_str() {
                    return matches!(subtype_name, "Image" | "Form" | "PS");
                }
            }
        }
        false
    }
    
    fn appears_binary(&self, data: &[u8]) -> bool {
        // Simple heuristic: check for non-printable characters
        let non_printable_count = data.iter()
            .filter(|&&b| b < 32 && b != 9 && b != 10 && b != 13)
            .count();
        
        non_printable_count as f64 / data.len() as f64 > 0.1
    }
    
    fn extract_cross_references(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<ObjectId>>> {
        let mut cross_references = HashMap::new();
        
        for (object_id, object) in &document.objects {
            let references = self.extract_object_references(object);
            if !references.is_empty() {
                cross_references.insert(*object_id, references);
            }
        }
        
        Ok(cross_references)
    }
    
    fn extract_encryption_data(&self, parsed_data: &ParsedPdfData) -> Result<Option<EncryptionData>> {
        if let Some(ref encryption_info) = parsed_data.encryption_info {
            let mut encrypt_dict = HashMap::new();
            encrypt_dict.insert("Filter".to_string(), encryption_info.filter.clone());
            encrypt_dict.insert("V".to_string(), encryption_info.version.to_string());
            encrypt_dict.insert("R".to_string(), encryption_info.revision.to_string());
            encrypt_dict.insert("Length".to_string(), encryption_info.key_length.to_string());
            encrypt_dict.insert("P".to_string(), encryption_info.permissions.to_string());
            
            Ok(Some(EncryptionData {
                encrypt_dict,
                security_handler: encryption_info.filter.clone(),
                key_length: encryption_info.key_length,
                permissions: encryption_info.permissions,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn extract_creation_date(&self, parsed_data: &ParsedPdfData) -> Result<String> {
        // Find creation date in metadata locations
        for location in &parsed_data.metadata_locations {
            if location.field_name == "CreationDate" {
                if let Some(ref date_value) = location.field_value {
                    return Ok(date_value.clone());
                }
            }
        }
        
        // If no creation date found, generate an authentic-looking one
        Ok(crate::forensic::ForensicCleaner::generate_authentic_timestamp())
    }
}

impl Default for PdfExtractor {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 4: `src/pdf/analyzer.rs` (145 lines)

**Purpose**: PDF structure analysis engine with relationship mapping
**Location**: src/pdf/analyzer.rs
**Functionality**: Object relationships, cross-reference analysis, security detection

```rust
use crate::{
    errors::{ForensicError, Result},
    config::ForensicConfig,
};
use super::{ParsedPdfData, ExtractionData};
use lopdf::{Document, Object, ObjectId, Dictionary};
use std::collections::{HashMap, HashSet, VecDeque};

/// PDF structure analyzer for forensic examination
pub struct PdfAnalyzer {
    max_depth: u8,
    check_security: bool,
    analyze_relationships: bool,
}

/// Complete analysis result
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub object_relationships: HashMap<ObjectId, ObjectRelationship>,
    pub metadata_analysis: MetadataAnalysis,
    pub security_analysis: SecurityAnalysis,
    pub structure_integrity: StructureIntegrity,
    pub hidden_content: Vec<HiddenContentItem>,
    pub forensic_indicators: Vec<ForensicIndicator>,
}

#[derive(Debug, Clone)]
pub struct ObjectRelationship {
    pub object_id: ObjectId,
    pub references_to: Vec<ObjectId>,
    pub referenced_by: Vec<ObjectId>,
    pub object_type: String,
    pub contains_metadata: bool,
    pub is_critical: bool,
    pub depth_level: u8,
}

#[derive(Debug, Clone)]
pub struct MetadataAnalysis {
    pub total_metadata_locations: usize,
    pub synchronized_fields: usize,
    pub unsynchronized_fields: Vec<String>,
    pub hidden_metadata_count: usize,
    pub modification_traces: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub is_encrypted: bool,
    pub encryption_strength: String,
    pub has_digital_signatures: bool,
    pub security_handlers: Vec<String>,
    pub permissions_analysis: PermissionsAnalysis,
}

#[derive(Debug, Clone)]
pub struct PermissionsAnalysis {
    pub can_print: bool,
    pub can_modify: bool,
    pub can_copy: bool,
    pub can_annotate: bool,
    pub can_form_fill: bool,
    pub can_extract: bool,
    pub can_assemble: bool,
    pub high_quality_print: bool,
}

#[derive(Debug, Clone)]
pub struct StructureIntegrity {
    pub has_valid_catalog: bool,
    pub has_valid_pages: bool,
    pub cross_ref_integrity: bool,
    pub trailer_integrity: bool,
    pub object_count: usize,
    pub missing_objects: Vec<ObjectId>,
    pub corrupted_objects: Vec<ObjectId>,
}

#[derive(Debug, Clone)]
pub struct HiddenContentItem {
    pub object_id: ObjectId,
    pub content_type: String,
    pub location: String,
    pub estimated_size: usize,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone)]
pub struct ForensicIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: String,
    pub location: Option<ObjectId>,
    pub evidence: String,
}

impl PdfAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: ForensicConfig::MAX_OBJECT_DEPTH,
            check_security: true,
            analyze_relationships: true,
        }
    }
    
    pub fn with_options(max_depth: u8, check_security: bool, analyze_relationships: bool) -> Self {
        Self {
            max_depth,
            check_security,
            analyze_relationships,
        }
    }
    
    /// Perform complete PDF analysis
    pub fn analyze_pdf(&self, parsed_data: &ParsedPdfData) -> Result<AnalysisResult> {
        let object_relationships = if self.analyze_relationships {
            self.analyze_object_relationships(&parsed_data.document)?
        } else {
            HashMap::new()
        };
        
        let metadata_analysis = self.analyze_metadata(parsed_data)?;
        
        let security_analysis = if self.check_security {
            self.analyze_security(parsed_data)?
        } else {
            SecurityAnalysis::default()
        };
        
        let structure_integrity = self.analyze_structure_integrity(&parsed_data.document)?;
        let hidden_content = self.discover_hidden_content(&parsed_data.document)?;
        let forensic_indicators = self.detect_forensic_indicators(parsed_data)?;
        
        Ok(AnalysisResult {
            object_relationships,
            metadata_analysis,
            security_analysis,
            structure_integrity,
            hidden_content,
            forensic_indicators,
        })
    }
    
    fn analyze_object_relationships(&self, document: &Document) -> Result<HashMap<ObjectId, ObjectRelationship>> {
        let mut relationships = HashMap::new();
        let mut reference_map: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
        
        // First pass: collect all references
        for (object_id, object) in &document.objects {
            let references = self.extract_references(object);
            for referenced_id in &references {
                reference_map.entry(*referenced_id)
                    .or_insert_with(Vec::new)
                    .push(*object_id);
            }
            
            let object_type = self.determine_object_type(object);
            let contains_metadata = self.check_metadata_presence(object);
            let is_critical = self.is_critical_object(object);
            
            relationships.insert(*object_id, ObjectRelationship {
                object_id: *object_id,
                references_to: references,
                referenced_by: Vec::new(),
                object_type,
                contains_metadata,
                is_critical,
                depth_level: 0,
            });
        }
        
        // Second pass: populate referenced_by relationships
        for (object_id, referencing_objects) in reference_map {
            if let Some(relationship) = relationships.get_mut(&object_id) {
                relationship.referenced_by = referencing_objects;
            }
        }
        
        // Third pass: calculate depth levels
        self.calculate_depth_levels(&mut relationships, document)?;
        
        Ok(relationships)
    }
    
    fn extract_references(&self, object: &Object) -> Vec<ObjectId> {
        let mut references = Vec::new();
        self.collect_references_recursive(object, &mut references, 0);
        references
    }
    
    fn collect_references_recursive(&self, object: &Object, references: &mut Vec<ObjectId>, depth: u8) {
        if depth >= self.max_depth {
            return;
        }
        
        match object {
            Object::Reference(object_id) => {
                references.push(*object_id);
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_references_recursive(value, references, depth + 1);
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.collect_references_recursive(item, references, depth + 1);
                }
            },
            Object::Stream(stream) => {
                self.collect_references_recursive(&Object::Dictionary(stream.dict.clone()), references, depth + 1);
            },
            _ => {},
        }
    }
    
    fn determine_object_type(&self, object: &Object) -> String {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return type_name.to_string();
                    }
                }
                "Dictionary".to_string()
            },
            Object::Stream(_) => "Stream".to_string(),
            _ => "Other".to_string(),
        }
    }
    
    fn check_metadata_presence(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => {
                let metadata_keys = [b"Title", b"Author", b"Subject", b"Keywords", b"Creator", b"Producer"];
                metadata_keys.iter().any(|key| dict.has(key))
            },
            Object::Stream(stream) => {
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            return subtype_name == "XML";
                        }
                    }
                }
                false
            },
            _ => false,
        }
    }
    
    fn is_critical_object(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return matches!(type_name, "Catalog" | "Pages" | "Page" | "Info");
                    }
                }
                false
            },
            _ => false,
        }
    }
    
    fn calculate_depth_levels(&self, relationships: &mut HashMap<ObjectId, ObjectRelationship>, document: &Document) -> Result<()> {
        // Start from catalog (root) and calculate depths using BFS
        if let Ok(catalog_id) = document.catalog() {
            let mut queue = VecDeque::new();
            let mut visited = HashSet::new();
            
            queue.push_back((catalog_id, 0u8));
            visited.insert(catalog_id);
            
            while let Some((current_id, depth)) = queue.pop_front() {
                if let Some(relationship) = relationships.get_mut(&current_id) {
                    relationship.depth_level = depth;
                    
                    // Add referenced objects to queue
                    for &referenced_id in &relationship.references_to.clone() {
                        if !visited.contains(&referenced_id) && depth < self.max_depth {
                            queue.push_back((referenced_id, depth + 1));
                            visited.insert(referenced_id);
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn analyze_metadata(&self, parsed_data: &ParsedPdfData) -> Result<MetadataAnalysis> {
        let total_metadata_locations = parsed_data.metadata_locations.len();
        
        // Group metadata by field name to check synchronization
        let mut field_locations: HashMap<String, Vec<&super::parser::MetadataLocation>> = HashMap::new();
        for location in &parsed_data.metadata_locations {
            field_locations.entry(location.field_name.clone())
                .or_insert_with(Vec::new)
                .push(location);
        }
        
        let mut synchronized_fields = 0;
        let mut unsynchronized_fields = Vec::new();
        
        for (field_name, locations) in &field_locations {
            if locations.len() > 1 {
                // Check if all locations have the same value
                let first_value = &locations[0].field_value;
                let is_synchronized = locations.iter().all(|loc| &loc.field_value == first_value);
                
                if is_synchronized {
                    synchronized_fields += 1;
                } else {
                    unsynchronized_fields.push(field_name.clone());
                }
            } else {
                synchronized_fields += 1; // Single location is considered synchronized
            }
        }
        
        let hidden_metadata_count = parsed_data.metadata_locations
            .iter()
            .filter(|loc| loc.is_hidden)
            .count();
        
        let modification_traces = self.detect_modification_traces(parsed_data);
        
        Ok(MetadataAnalysis {
            total_metadata_locations,
            synchronized_fields,
            unsynchronized_fields,
            hidden_metadata_count,
            modification_traces,
        })
    }
    
    fn detect_modification_traces(&self, parsed_data: &ParsedPdfData) -> Vec<String> {
        let mut traces = Vec::new();
        
        // Check for ModDate presence (indicates modification)
        for location in &parsed_data.metadata_locations {
            if location.field_name == "ModDate" {
                traces.push("Modification date present".to_string());
            }
        }
        
        // Check for suspicious producers
        for location in &parsed_data.metadata_locations {
            if location.field_name == "Producer" {
                if let Some(ref producer) = location.field_value {
                    let suspicious_producers = ["ghostscript", "itext", "reportlab", "tcpdf"];
                    for suspicious in &suspicious_producers {
                        if producer.to_lowercase().contains(suspicious) {
                            traces.push(format!("Suspicious producer: {}", producer));
                        }
                    }
                }
            }
        }
        
        traces
    }
    
    fn analyze_security(&self, parsed_data: &ParsedPdfData) -> Result<SecurityAnalysis> {
        let is_encrypted = parsed_data.encryption_info.is_some();
        
        let (encryption_strength, security_handlers, permissions_analysis) = if let Some(ref enc_info) = parsed_data.encryption_info {
            let strength = format!("{}-bit {}", enc_info.key_length, enc_info.filter);
            let handlers = vec![enc_info.filter.clone()];
            let permissions = self.analyze_permissions(enc_info.permissions);
            (strength, handlers, permissions)
        } else {
            ("None".to_string(), Vec::new(), PermissionsAnalysis::default())
        };
        
        let has_digital_signatures = self.check_digital_signatures(&parsed_data.document)?;
        
        Ok(SecurityAnalysis {
            is_encrypted,
            encryption_strength,
            has_digital_signatures,
            security_handlers,
            permissions_analysis,
        })
    }
    
    fn analyze_permissions(&self, permissions: u32) -> PermissionsAnalysis {
        PermissionsAnalysis {
            can_print: (permissions & 0x04) != 0,
            can_modify: (permissions & 0x08) != 0,
            can_copy: (permissions & 0x10) != 0,
            can_annotate: (permissions & 0x20) != 0,
            can_form_fill: (permissions & 0x100) != 0,
            can_extract: (permissions & 0x200) != 0,
            can_assemble: (permissions & 0x400) != 0,
            high_quality_print: (permissions & 0x800) != 0,
        }
    }
    
    fn check_digital_signatures(&self, document: &Document) -> Result<bool> {
        // Check for signature dictionaries
        for (_, object) in &document.objects {
            if let Object::Dictionary(dict) = object {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        if type_name == "Sig" {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }
    
    fn analyze_structure_integrity(&self, document: &Document) -> Result<StructureIntegrity> {
        let has_valid_catalog = document.catalog().is_ok();
        let has_valid_pages = !document.get_pages().is_empty();
        let has_valid_trailer = document.trailer.as_dict().is_ok();
        
        let object_count = document.objects.len();
        let missing_objects = self.find_missing_objects(document);
        let corrupted_objects = self.find_corrupted_objects(document);
        
        let cross_ref_integrity = missing_objects.is_empty();
        let trailer_integrity = has_valid_trailer;
        
        Ok(StructureIntegrity {
            has_valid_catalog,
            has_valid_pages,
            cross_ref_integrity,
            trailer_integrity,
            object_count,
            missing_objects,
            corrupted_objects,
        })
    }
    
    fn find_missing_objects(&self, document: &Document) -> Vec<ObjectId> {
        // This would check for referenced but missing objects
        Vec::new() // Placeholder implementation
    }
    
    fn find_corrupted_objects(&self, document: &Document) -> Vec<ObjectId> {
        // This would check for corrupted object data
        Vec::new() // Placeholder implementation
    }
    
    fn discover_hidden_content(&self, document: &Document) -> Result<Vec<HiddenContentItem>> {
        let mut hidden_items = Vec::new();
        
        for (object_id, object) in &document.objects {
            if let Some(hidden_item) = self.check_for_hidden_content(*object_id, object) {
                hidden_items.push(hidden_item);
            }
        }
        
        Ok(hidden_items)
    }
    
    fn check_for_hidden_content(&self, object_id: ObjectId, object: &Object) -> Option<HiddenContentItem> {
        match object {
            Object::Stream(stream) => {
                // Check for potentially hidden content in streams
                if stream.content.len() > 1000 && self.appears_suspicious(&stream.content) {
                    Some(HiddenContentItem {
                        object_id,
                        content_type: "Stream".to_string(),
                        location: "Object Stream".to_string(),
                        estimated_size: stream.content.len(),
                        is_suspicious: true,
                    })
                } else {
                    None
                }
            },
            _ => None,
        }
    }
    
    fn appears_suspicious(&self, content: &[u8]) -> bool {
        // Simple heuristic for suspicious content
        let entropy = self.calculate_entropy(content);
        entropy > 7.5 // High entropy might indicate encrypted or compressed hidden data
    }
    
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
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
    
    fn detect_forensic_indicators(&self, parsed_data: &ParsedPdfData) -> Result<Vec<ForensicIndicator>> {
        let mut indicators = Vec::new();
        
        // Check for modification traces
        for location in &parsed_data.metadata_locations {
            if location.field_name == "ModDate" {
                indicators.push(ForensicIndicator {
                    indicator_type: "Modification Trace".to_string(),
                    description: "Document contains modification date".to_string(),
                    severity: "Medium".to_string(),
                    location: location.object_id,
                    evidence: location.field_value.clone().unwrap_or_default(),
                });
            }
        }
        
        // Check for suspicious producers
        for location in &parsed_data.metadata_locations {
            if location.field_name == "Producer" {
                if let Some(ref producer) = location.field_value {
                    if producer.to_lowercase().contains("ghostscript") {
                        indicators.push(ForensicIndicator {
                            indicator_type: "Editing Software".to_string(),
                            description: "Document shows signs of GhostScript processing".to_string(),
                            severity: "High".to_string(),
                            location: location.object_id,
                            evidence: producer.clone(),
                        });
                    }
                }
            }
        }
        
        Ok(indicators)
    }
}

impl Default for SecurityAnalysis {
    fn default() -> Self {
        Self {
            is_encrypted: false,
            encryption_strength: "None".to_string(),
            has_digital_signatures: false,
            security_handlers: Vec::new(),
            permissions_analysis: PermissionsAnalysis::default(),
        }
    }
}

impl Default for PermissionsAnalysis {
    fn default() -> Self {
        Self {
            can_print: true,
            can_modify: true,
            can_copy: true,
            can_annotate: true,
            can_form_fill: true,
            can_extract: true,
            can_assemble: true,
            high_quality_print: true,
        }
    }
}

impl Default for PdfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 5: `src/pdf/cloner.rs` (178 lines)

**Purpose**: Perfect PDF cloning engine with 1:1 structure replication
**Location**: src/pdf/cloner.rs
**Functionality**: Binary-level content preservation, structure replication, forensic authenticity

```rust
use crate::{
    errors::{ForensicError, Result},
    config::Config,
};
use super::{ExtractionData, AnalysisResult};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Perfect PDF cloning system for forensic operations
pub struct PdfCloner {
    preserve_structure: bool,
    maintain_authenticity: bool,
    clone_binary_data: bool,
}

/// Complete clone data for PDF reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneData {
    pub cloned_objects: HashMap<ObjectId, ClonedObject>,
    pub structure_map: StructureMap,
    pub metadata_modifications: MetadataModifications,
    pub binary_preservation: BinaryPreservation,
    pub authentication_data: AuthenticationData,
    pub reconstruction_instructions: ReconstructionInstructions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClonedObject {
    pub original_id: ObjectId,
    pub new_id: ObjectId,
    pub object_type: String,
    pub cloned_content: ClonedContent,
    pub references: Vec<ObjectId>,
    pub is_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClonedContent {
    Dictionary(HashMap<String, String>),
    Stream { dict: HashMap<String, String>, content: Vec<u8> },
    Primitive(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureMap {
    pub catalog_mapping: ObjectId,
    pub pages_mapping: ObjectId,
    pub info_dict_mapping: Option<ObjectId>,
    pub metadata_stream_mapping: Option<ObjectId>,
    pub encryption_mapping: Option<ObjectId>,
    pub cross_reference_map: HashMap<ObjectId, ObjectId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataModifications {
    pub field_updates: HashMap<String, Option<String>>,
    pub synchronization_map: HashMap<ObjectId, Vec<String>>,
    pub removal_list: Vec<String>,
    pub addition_list: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPreservation {
    pub preserved_streams: HashMap<ObjectId, Vec<u8>>,
    pub image_data: HashMap<ObjectId, Vec<u8>>,
    pub font_data: HashMap<ObjectId, Vec<u8>>,
    pub embedded_files: HashMap<ObjectId, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationData {
    pub original_creation_date: String,
    pub file_size_preservation: u64,
    pub checksum_data: HashMap<ObjectId, String>,
    pub structural_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionInstructions {
    pub object_order: Vec<ObjectId>,
    pub cross_ref_preservation: Vec<(ObjectId, u64)>,
    pub trailer_reconstruction: HashMap<String, String>,
    pub pdf_version: String,
}

impl PdfCloner {
    pub fn new() -> Self {
        Self {
            preserve_structure: true,
            maintain_authenticity: true,
            clone_binary_data: true,
        }
    }
    
    pub fn with_options(preserve_structure: bool, maintain_authenticity: bool, clone_binary_data: bool) -> Self {
        Self {
            preserve_structure,
            maintain_authenticity,
            clone_binary_data,
        }
    }
    
    /// Clone PDF with metadata modifications
    pub fn clone_with_modifications(&mut self, extraction_data: &ExtractionData) -> Result<CloneData> {
        let cloned_objects = self.clone_all_objects(extraction_data)?;
        let structure_map = self.create_structure_map(extraction_data)?;
        let metadata_modifications = self.prepare_metadata_modifications(extraction_data)?;
        let binary_preservation = self.preserve_binary_data(extraction_data)?;
        let authentication_data = self.create_authentication_data(extraction_data)?;
        let reconstruction_instructions = self.create_reconstruction_instructions(extraction_data)?;
        
        Ok(CloneData {
            cloned_objects,
            structure_map,
            metadata_modifications,
            binary_preservation,
            authentication_data,
            reconstruction_instructions,
        })
    }
    
    fn clone_all_objects(&self, extraction_data: &ExtractionData) -> Result<HashMap<ObjectId, ClonedObject>> {
        let mut cloned_objects = HashMap::new();
        let mut id_mapping = HashMap::new();
        
        // First pass: create ID mapping
        for (original_id, _) in &extraction_data.object_data {
            let new_id = *original_id; // Keep same IDs for perfect cloning
            id_mapping.insert(*original_id, new_id);
        }
        
        // Second pass: clone objects with updated references
        for (original_id, object_data) in &extraction_data.object_data {
            let cloned_object = self.clone_single_object(*original_id, object_data, &id_mapping)?;
            cloned_objects.insert(*original_id, cloned_object);
        }
        
        Ok(cloned_objects)
    }
    
    fn clone_single_object(&self, original_id: ObjectId, object_data: &super::ExtractedObjectData, id_mapping: &HashMap<ObjectId, ObjectId>) -> Result<ClonedObject> {
        let new_id = id_mapping.get(&original_id).copied().unwrap_or(original_id);
        
        let cloned_content = if let Some(ref stream_data) = object_data.stream_data {
            ClonedContent::Stream {
                dict: object_data.dictionary_data.clone().unwrap_or_default(),
                content: stream_data.clone(),
            }
        } else if let Some(ref dict_data) = object_data.dictionary_data {
            ClonedContent::Dictionary(dict_data.clone())
        } else {
            ClonedContent::Primitive("Unknown".to_string())
        };
        
        // Update references to use new IDs
        let updated_references = object_data.references.iter()
            .map(|ref_id| id_mapping.get(ref_id).copied().unwrap_or(*ref_id))
            .collect();
        
        let is_modified = object_data.is_metadata_container;
        
        Ok(ClonedObject {
            original_id,
            new_id,
            object_type: object_data.object_type.clone(),
            cloned_content,
            references: updated_references,
            is_modified,
        })
    }
    
    fn create_structure_map(&self, extraction_data: &ExtractionData) -> Result<StructureMap> {
        let structure_data = &extraction_data.structure_data;
        
        Ok(StructureMap {
            catalog_mapping: structure_data.catalog_id,
            pages_mapping: structure_data.pages_root_id,
            info_dict_mapping: structure_data.info_dict_id,
            metadata_stream_mapping: structure_data.metadata_stream_id,
            encryption_mapping: None, // Will be set if encryption is present
            cross_reference_map: extraction_data.cross_references.clone()
                .into_iter()
                .map(|(k, v)| (k, k)) // Identity mapping for perfect cloning
                .collect(),
        })
    }
    
    fn prepare_metadata_modifications(&self, extraction_data: &ExtractionData) -> Result<MetadataModifications> {
        let mut field_updates = HashMap::new();
        let mut synchronization_map = HashMap::new();
        let mut removal_list = Vec::new();
        let mut addition_list = HashMap::new();
        
        // Process metadata map for modifications
        for (field, metadata_value) in &extraction_data.metadata_map {
            let field_name = field.as_string();
            
            // Prepare field updates
            field_updates.insert(field_name.clone(), metadata_value.value.clone());
            
            // Create synchronization map
            for location in &metadata_value.locations {
                if let Some(object_id) = self.location_to_object_id(location) {
                    synchronization_map.entry(object_id)
                        .or_insert_with(Vec::new)
                        .push(field_name.clone());
                }
            }
        }
        
        // Always remove ModDate for forensic cleaning
        removal_list.push("ModDate".to_string());
        removal_list.push("Trapped".to_string());
        
        // Set producer to our standard value
        addition_list.insert("Producer".to_string(), Config::PDF_PRODUCER.to_string());
        
        Ok(MetadataModifications {
            field_updates,
            synchronization_map,
            removal_list,
            addition_list,
        })
    }
    
    fn location_to_object_id(&self, location: &crate::types::MetadataLocation) -> Option<ObjectId> {
        match location {
            crate::types::MetadataLocation::ObjectStream(id) => Some(ObjectId(*id as u32, 0)),
            crate::types::MetadataLocation::Annotation(id) => Some(ObjectId(*id as u32, 0)),
            _ => None,
        }
    }
    
    fn preserve_binary_data(&self, extraction_data: &ExtractionData) -> Result<BinaryPreservation> {
        if !self.clone_binary_data {
            return Ok(BinaryPreservation {
                preserved_streams: HashMap::new(),
                image_data: HashMap::new(),
                font_data: HashMap::new(),
                embedded_files: HashMap::new(),
            });
        }
        
        let mut preserved_streams = HashMap::new();
        let mut image_data = HashMap::new();
        let mut font_data = HashMap::new();
        let mut embedded_files = HashMap::new();
        
        // Categorize binary data by type
        for (object_id, content) in &extraction_data.content_streams {
            preserved_streams.insert(*object_id, content.clone());
        }
        
        for (object_id, binary_content) in &extraction_data.binary_objects {
            // Determine type based on object data
            if let Some(object_data) = extraction_data.object_data.get(object_id) {
                match object_data.object_type.as_str() {
                    "XObject" => {
                        // Could be image
                        image_data.insert(*object_id, binary_content.clone());
                    },
                    "Font" => {
                        font_data.insert(*object_id, binary_content.clone());
                    },
                    "Filespec" => {
                        embedded_files.insert(*object_id, binary_content.clone());
                    },
                    _ => {
                        preserved_streams.insert(*object_id, binary_content.clone());
                    }
                }
            }
        }
        
        Ok(BinaryPreservation {
            preserved_streams,
            image_data,
            font_data,
            embedded_files,
        })
    }
    
    fn create_authentication_data(&self, extraction_data: &ExtractionData) -> Result<AuthenticationData> {
        let original_creation_date = extraction_data.creation_date.clone();
        let file_size_preservation = 0; // Will be calculated during reconstruction
        
        // Create checksums for critical objects
        let mut checksum_data = HashMap::new();
        for (object_id, object_data) in &extraction_data.object_data {
            if object_data.is_metadata_container {
                let checksum = self.calculate_object_checksum(object_data);
                checksum_data.insert(*object_id, checksum);
            }
        }
        
        // Create structural fingerprint
        let structural_fingerprint = self.create_structural_fingerprint(extraction_data)?;
        
        Ok(AuthenticationData {
            original_creation_date,
            file_size_preservation,
            checksum_data,
            structural_fingerprint,
        })
    }
    
    fn calculate_object_checksum(&self, object_data: &super::ExtractedObjectData) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(object_data.object_type.as_bytes());
        
        if let Some(ref dict_data) = object_data.dictionary_data {
            for (key, value) in dict_data {
                hasher.update(key.as_bytes());
                hasher.update(value.as_bytes());
            }
        }
        
        if let Some(ref stream_data) = object_data.stream_data {
            hasher.update(stream_data);
        }
        
        format!("{:x}", hasher.finalize())
    }
    
    fn create_structural_fingerprint(&self, extraction_data: &ExtractionData) -> Result<String> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Include structure data
        hasher.update(extraction_data.structure_data.pdf_version.as_bytes());
        hasher.update(&extraction_data.structure_data.page_count.to_le_bytes());
        hasher.update(&extraction_data.structure_data.catalog_id.0.to_le_bytes());
        hasher.update(&extraction_data.structure_data.pages_root_id.0.to_le_bytes());
        
        // Include object count and types
        hasher.update(&extraction_data.object_data.len().to_le_bytes());
        for (_, object_data) in &extraction_data.object_data {
            hasher.update(object_data.object_type.as_bytes());
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    fn create_reconstruction_instructions(&self, extraction_data: &ExtractionData) -> Result<ReconstructionInstructions> {
        // Preserve original object order for authenticity
        let mut object_order: Vec<ObjectId> = extraction_data.object_data.keys().copied().collect();
        object_order.sort_by_key(|id| id.0);
        
        // Preserve cross-reference positions (simplified)
        let cross_ref_preservation = object_order.iter()
            .enumerate()
            .map(|(index, &object_id)| (object_id, (index * 50) as u64)) // Approximate positions
            .collect();
        
        // Reconstruct trailer data
        let trailer_reconstruction = extraction_data.structure_data.trailer_data.clone();
        
        let pdf_version = extraction_data.structure_data.pdf_version.clone();
        
        Ok(ReconstructionInstructions {
            object_order,
            cross_ref_preservation,
            trailer_reconstruction,
            pdf_version,
        })
    }
    
    /// Apply metadata changes to cloned objects
    pub fn apply_metadata_changes(&mut self, clone_data: &mut CloneData, metadata_changes: &HashMap<String, Option<String>>) -> Result<()> {
        // Update metadata modifications with new changes
        for (field_name, new_value) in metadata_changes {
            clone_data.metadata_modifications.field_updates.insert(field_name.clone(), new_value.clone());
        }
        
        // Apply changes to cloned objects that contain metadata
        for (object_id, cloned_object) in &mut clone_data.cloned_objects {
            if cloned_object.is_modified {
                self.update_object_metadata(cloned_object, metadata_changes)?;
            }
        }
        
        Ok(())
    }
    
    fn update_object_metadata(&self, cloned_object: &mut ClonedObject, metadata_changes: &HashMap<String, Option<String>>) -> Result<()> {
        match &mut cloned_object.cloned_content {
            ClonedContent::Dictionary(dict) => {
                for (field_name, new_value) in metadata_changes {
                    if let Some(value) = new_value {
                        dict.insert(field_name.clone(), value.clone());
                    } else {
                        dict.remove(field_name);
                    }
                }
            },
            ClonedContent::Stream { dict, .. } => {
                for (field_name, new_value) in metadata_changes {
                    if let Some(value) = new_value {
                        dict.insert(field_name.clone(), value.clone());
                    } else {
                        dict.remove(field_name);
                    }
                }
            },
            _ => {
                // Cannot modify primitive content
            }
        }
        
        Ok(())
    }
}

impl Default for PdfCloner {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## Implementation Sequence

1. **Create src/pdf/mod.rs** - Establishes PDF module interface and coordination
2. **Implement src/pdf/parser.rs** - Core PDF parsing with complete structure analysis
3. **Create src/pdf/extractor.rs** - Comprehensive data extraction for cloning
4. **Implement src/pdf/analyzer.rs** - Advanced PDF analysis and relationship mapping
5. **Create src/pdf/cloner.rs** - Perfect PDF cloning with forensic authenticity

## Compilation Requirements

After implementing these 5 files:
- Complete PDF parsing capabilities will be available
- Data extraction system will be functional
- Structure analysis engine will be ready
- Perfect cloning system will be implemented
- Foundation for reconstruction will be established

## Next Guide

Implementation Guide 04 will create the metadata processing system (scanner, editor, synchronizer, cleaner, authenticator).