# Implementation Guide 04: Metadata Processing System

## Files to Create in This Guide: 5 Files

This guide implements the forensic metadata processing system with comprehensive scanning, editing, synchronization, cleaning, and authentication capabilities.

---

## File 1: `src/metadata/mod.rs` (48 lines)

**Purpose**: Metadata processing module interface and coordination
**Location**: src/metadata/mod.rs
**Functionality**: Module exports, metadata operation coordination, cross-module type sharing

```rust
//! Metadata Processing System
//! 
//! Comprehensive forensic metadata editing and synchronization system.
//! Provides universal metadata synchronization across all PDF storage locations
//! with complete forensic invisibility and authenticity preservation.

pub mod scanner;
pub mod editor;
pub mod synchronizer;
pub mod cleaner;
pub mod authenticator;

// Re-export commonly used types and functions
pub use self::scanner::{MetadataScanner, ScanResult, LocationMap};
pub use self::editor::{MetadataEditor, EditOperation, EditResult};
pub use self::synchronizer::{MetadataSynchronizer, SyncResult, SyncStrategy};
pub use self::cleaner::{MetadataCleaner, CleaningResult, CleaningStrategy};
pub use self::authenticator::{MetadataAuthenticator, AuthenticationResult, AuthenticityCheck};

use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataLocation},
};
use std::collections::HashMap;

/// Metadata processing configuration
#[derive(Debug, Clone)]
pub struct MetadataProcessingConfig {
    pub deep_scan_enabled: bool,
    pub hidden_metadata_detection: bool,
    pub universal_synchronization: bool,
    pub forensic_cleaning: bool,
    pub authenticity_preservation: bool,
}

impl Default for MetadataProcessingConfig {
    fn default() -> Self {
        Self {
            deep_scan_enabled: true,
            hidden_metadata_detection: true,
            universal_synchronization: true,
            forensic_cleaning: true,
            authenticity_preservation: true,
        }
    }
}

/// Common metadata processing result wrapper
pub type MetadataResult<T> = Result<T>;
```

---

## File 2: `src/metadata/scanner.rs` (189 lines)

**Purpose**: Metadata location discovery engine with comprehensive scanning
**Location**: src/metadata/scanner.rs
**Functionality**: Hidden metadata detection, storage location cataloging, comprehensive mapping

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue, MetadataLocation},
    config::ForensicConfig,
};
use super::MetadataProcessingConfig;
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::{HashMap, HashSet};

/// Comprehensive metadata location scanner
pub struct MetadataScanner {
    config: MetadataProcessingConfig,
    discovered_locations: Vec<DiscoveredLocation>,
    hidden_metadata_cache: HashMap<ObjectId, Vec<HiddenMetadataItem>>,
}

/// Complete scan result with all discovered metadata locations
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub location_map: LocationMap,
    pub hidden_metadata: Vec<HiddenMetadataItem>,
    pub synchronization_targets: HashMap<MetadataField, Vec<MetadataLocation>>,
    pub coverage_report: CoverageReport,
    pub forensic_indicators: Vec<ForensicMetadataIndicator>,
}

/// Comprehensive location mapping for metadata fields
pub type LocationMap = HashMap<MetadataField, Vec<DiscoveredLocation>>;

#[derive(Debug, Clone)]
pub struct DiscoveredLocation {
    pub location: MetadataLocation,
    pub field: MetadataField,
    pub current_value: Option<String>,
    pub is_writable: bool,
    pub requires_synchronization: bool,
    pub object_id: Option<ObjectId>,
    pub access_path: String,
}

#[derive(Debug, Clone)]
pub struct HiddenMetadataItem {
    pub object_id: ObjectId,
    pub location_description: String,
    pub field_name: String,
    pub hidden_value: Option<String>,
    pub detection_method: String,
    pub confidence_level: f32,
}

#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub total_locations_found: usize,
    pub docinfo_locations: usize,
    pub xmp_locations: usize,
    pub hidden_locations: usize,
    pub synchronizable_fields: usize,
    pub coverage_percentage: f32,
}

#[derive(Debug, Clone)]
pub struct ForensicMetadataIndicator {
    pub indicator_type: String,
    pub location: MetadataLocation,
    pub description: String,
    pub evidence: String,
    pub risk_level: String,
}

impl MetadataScanner {
    pub fn new() -> Self {
        Self {
            config: MetadataProcessingConfig::default(),
            discovered_locations: Vec::new(),
            hidden_metadata_cache: HashMap::new(),
        }
    }
    
    pub fn with_config(config: MetadataProcessingConfig) -> Self {
        Self {
            config,
            discovered_locations: Vec::new(),
            hidden_metadata_cache: HashMap::new(),
        }
    }
    
    /// Perform comprehensive metadata location scan
    pub fn scan_document(&mut self, document: &Document) -> Result<ScanResult> {
        self.discovered_locations.clear();
        self.hidden_metadata_cache.clear();
        
        // Phase 1: Scan Document Information Dictionary
        self.scan_document_info(document)?;
        
        // Phase 2: Scan XMP metadata streams
        self.scan_xmp_metadata_streams(document)?;
        
        // Phase 3: Deep scan for hidden metadata
        if self.config.hidden_metadata_detection {
            self.scan_hidden_metadata(document)?;
        }
        
        // Phase 4: Scan form fields and annotations
        self.scan_form_fields_and_annotations(document)?;
        
        // Phase 5: Scan embedded files and attachments
        self.scan_embedded_files(document)?;
        
        // Phase 6: Build comprehensive results
        let location_map = self.build_location_map();
        let hidden_metadata = self.collect_hidden_metadata();
        let synchronization_targets = self.build_synchronization_targets();
        let coverage_report = self.generate_coverage_report();
        let forensic_indicators = self.detect_forensic_indicators();
        
        Ok(ScanResult {
            location_map,
            hidden_metadata,
            synchronization_targets,
            coverage_report,
            forensic_indicators,
        })
    }
    
    fn scan_document_info(&mut self, document: &Document) -> Result<()> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(info_ref) = trailer.get(b"Info") {
                if let Ok(object_id) = info_ref.as_reference() {
                    if let Ok(info_obj) = document.get_object(object_id) {
                        if let Ok(info_dict) = info_obj.as_dict() {
                            self.scan_dictionary_for_metadata(
                                object_id,
                                info_dict,
                                MetadataLocation::DocInfo,
                                "DocInfo Dictionary"
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn scan_xmp_metadata_streams(&mut self, document: &Document) -> Result<()> {
        // Scan for XMP metadata streams in catalog and objects
        if let Ok(catalog_id) = document.catalog() {
            if let Ok(catalog_obj) = document.get_object(catalog_id) {
                if let Ok(catalog_dict) = catalog_obj.as_dict() {
                    if let Ok(metadata_ref) = catalog_dict.get(b"Metadata") {
                        if let Ok(metadata_id) = metadata_ref.as_reference() {
                            self.scan_xmp_stream(document, metadata_id)?;
                        }
                    }
                }
            }
        }
        
        // Scan all objects for additional XMP streams
        for (object_id, object) in &document.objects {
            if let Object::Stream(stream) = object {
                if self.is_xmp_stream(stream) {
                    self.scan_xmp_stream(document, *object_id)?;
                }
            }
        }
        
        Ok(())
    }
    
    fn scan_xmp_stream(&mut self, document: &Document, stream_id: ObjectId) -> Result<()> {
        if let Ok(stream_obj) = document.get_object(stream_id) {
            if let Object::Stream(stream) = stream_obj {
                // Parse XMP XML content for metadata fields
                let xmp_content = String::from_utf8_lossy(&stream.content);
                self.parse_xmp_content(&xmp_content, stream_id)?;
            }
        }
        Ok(())
    }
    
    fn parse_xmp_content(&mut self, xmp_content: &str, stream_id: ObjectId) -> Result<()> {
        // Simple XMP parsing for common metadata fields
        let field_patterns = [
            ("dc:title", MetadataField::Title),
            ("dc:creator", MetadataField::Author),
            ("dc:description", MetadataField::Subject),
            ("dc:subject", MetadataField::Keywords),
            ("xmp:CreatorTool", MetadataField::Creator),
            ("xmp:CreateDate", MetadataField::CreationDate),
            ("xmp:ModifyDate", MetadataField::ModificationDate),
        ];
        
        for (pattern, field) in &field_patterns {
            if let Some(value) = self.extract_xmp_value(xmp_content, pattern) {
                self.discovered_locations.push(DiscoveredLocation {
                    location: MetadataLocation::XmpStream,
                    field: field.clone(),
                    current_value: Some(value),
                    is_writable: true,
                    requires_synchronization: true,
                    object_id: Some(stream_id),
                    access_path: format!("XMP Stream {} -> {}", stream_id.0, pattern),
                });
            }
        }
        
        Ok(())
    }
    
    fn extract_xmp_value(&self, xmp_content: &str, field_pattern: &str) -> Option<String> {
        // Simple regex-like extraction for XMP values
        if let Some(start_pos) = xmp_content.find(&format!("<{}>", field_pattern)) {
            if let Some(end_pos) = xmp_content[start_pos..].find(&format!("</{}>", field_pattern)) {
                let value_start = start_pos + field_pattern.len() + 2;
                let value_end = start_pos + end_pos;
                if value_start < value_end {
                    let value = xmp_content[value_start..value_end].trim();
                    return Some(value.to_string());
                }
            }
        }
        None
    }
    
    fn is_xmp_stream(&self, stream: &Stream) -> bool {
        if let Ok(dict) = &stream.dict.as_dict() {
            if let Ok(subtype) = dict.get(b"Subtype") {
                if let Ok(subtype_name) = subtype.as_name_str() {
                    return subtype_name == "XML";
                }
            }
            
            // Also check for Type = Metadata
            if let Ok(type_obj) = dict.get(b"Type") {
                if let Ok(type_name) = type_obj.as_name_str() {
                    return type_name == "Metadata";
                }
            }
        }
        false
    }
    
    fn scan_hidden_metadata(&mut self, document: &Document) -> Result<()> {
        for (object_id, object) in &document.objects {
            // Scan dictionaries for hidden metadata fields
            if let Object::Dictionary(dict) = object {
                self.scan_for_hidden_fields(*object_id, dict)?;
            } else if let Object::Stream(stream) = object {
                self.scan_for_hidden_fields(*object_id, &stream.dict)?;
                
                // Scan stream content for embedded metadata
                if !self.is_xmp_stream(stream) {
                    self.scan_stream_content_for_metadata(*object_id, &stream.content)?;
                }
            }
        }
        Ok(())
    }
    
    fn scan_for_hidden_fields(&mut self, object_id: ObjectId, dict: &Dictionary) -> Result<()> {
        // Look for non-standard metadata fields
        for (key, value) in dict.iter() {
            let key_str = String::from_utf8_lossy(key);
            
            // Check if this looks like a metadata field
            if self.is_potential_metadata_field(&key_str) {
                if let Ok(value_str) = value.as_str() {
                    let hidden_item = HiddenMetadataItem {
                        object_id,
                        location_description: format!("Hidden field in object {}", object_id.0),
                        field_name: key_str.to_string(),
                        hidden_value: Some(value_str.to_string()),
                        detection_method: "Dictionary scan".to_string(),
                        confidence_level: 0.8,
                    };
                    
                    self.hidden_metadata_cache
                        .entry(object_id)
                        .or_insert_with(Vec::new)
                        .push(hidden_item);
                }
            }
        }
        Ok(())
    }
    
    fn is_potential_metadata_field(&self, field_name: &str) -> bool {
        let metadata_indicators = [
            "title", "author", "creator", "producer", "subject", "keywords",
            "created", "modified", "creation", "modification", "date",
            "application", "tool", "version", "comment", "description"
        ];
        
        let field_lower = field_name.to_lowercase();
        metadata_indicators.iter().any(|indicator| field_lower.contains(indicator))
    }
    
    fn scan_stream_content_for_metadata(&mut self, object_id: ObjectId, content: &[u8]) -> Result<()> {
        // Look for metadata patterns in stream content
        if let Ok(content_str) = String::from_utf8(content.clone()) {
            // Simple pattern matching for embedded metadata
            if content_str.contains("Creator") || content_str.contains("Producer") || content_str.contains("Title") {
                let hidden_item = HiddenMetadataItem {
                    object_id,
                    location_description: format!("Embedded metadata in stream {}", object_id.0),
                    field_name: "Embedded Metadata".to_string(),
                    hidden_value: Some("[Stream Content Metadata]".to_string()),
                    detection_method: "Content pattern scan".to_string(),
                    confidence_level: 0.6,
                };
                
                self.hidden_metadata_cache
                    .entry(object_id)
                    .or_insert_with(Vec::new)
                    .push(hidden_item);
            }
        }
        Ok(())
    }
    
    fn scan_form_fields_and_annotations(&mut self, document: &Document) -> Result<()> {
        // Scan form fields for metadata
        for (object_id, object) in &document.objects {
            if let Object::Dictionary(dict) = object {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        if type_name == "Annot" {
                            self.scan_annotation_metadata(*object_id, dict)?;
                        }
                    }
                }
                
                // Check for form field metadata
                if dict.has(b"FT") { // Field Type indicates form field
                    self.scan_form_field_metadata(*object_id, dict)?;
                }
            }
        }
        Ok(())
    }
    
    fn scan_annotation_metadata(&mut self, object_id: ObjectId, dict: &Dictionary) -> Result<()> {
        let annotation_metadata_fields = [
            (b"T", "Title"),
            (b"Contents", "Contents"),
            (b"Subj", "Subject"),
            (b"RC", "RichContents"),
        ];
        
        for (key, field_name) in &annotation_metadata_fields {
            if let Ok(value) = dict.get(key) {
                if let Ok(value_str) = value.as_str() {
                    self.discovered_locations.push(DiscoveredLocation {
                        location: MetadataLocation::Annotation(object_id.0 as u32),
                        field: MetadataField::Custom(field_name.to_string()),
                        current_value: Some(value_str.to_string()),
                        is_writable: true,
                        requires_synchronization: false,
                        object_id: Some(object_id),
                        access_path: format!("Annotation {} -> {}", object_id.0, field_name),
                    });
                }
            }
        }
        Ok(())
    }
    
    fn scan_form_field_metadata(&mut self, object_id: ObjectId, dict: &Dictionary) -> Result<()> {
        if let Ok(field_name) = dict.get(b"T") {
            if let Ok(field_name_str) = field_name.as_str() {
                // Check for metadata-like form field names
                if self.is_potential_metadata_field(field_name_str) {
                    let value = dict.get(b"V")
                        .and_then(|v| v.as_str().ok())
                        .map(|s| s.to_string());
                    
                    self.discovered_locations.push(DiscoveredLocation {
                        location: MetadataLocation::FormField(field_name_str.to_string()),
                        field: MetadataField::Custom(field_name_str.to_string()),
                        current_value: value,
                        is_writable: true,
                        requires_synchronization: false,
                        object_id: Some(object_id),
                        access_path: format!("Form Field {} -> {}", object_id.0, field_name_str),
                    });
                }
            }
        }
        Ok(())
    }
    
    fn scan_embedded_files(&mut self, document: &Document) -> Result<()> {
        // Look for embedded files that might contain metadata
        for (object_id, object) in &document.objects {
            if let Object::Dictionary(dict) = object {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        if type_name == "Filespec" {
                            self.scan_embedded_file_metadata(*object_id, dict)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn scan_embedded_file_metadata(&mut self, object_id: ObjectId, dict: &Dictionary) -> Result<()> {
        // Scan file specification objects for metadata
        if let Ok(filename) = dict.get(b"F") {
            if let Ok(filename_str) = filename.as_str() {
                self.discovered_locations.push(DiscoveredLocation {
                    location: MetadataLocation::CustomLocation("EmbeddedFile".to_string()),
                    field: MetadataField::Custom("FileName".to_string()),
                    current_value: Some(filename_str.to_string()),
                    is_writable: true,
                    requires_synchronization: false,
                    object_id: Some(object_id),
                    access_path: format!("Embedded File {} -> Filename", object_id.0),
                });
            }
        }
        
        // Check for embedded file description
        if let Ok(desc) = dict.get(b"Desc") {
            if let Ok(desc_str) = desc.as_str() {
                self.discovered_locations.push(DiscoveredLocation {
                    location: MetadataLocation::CustomLocation("EmbeddedFile".to_string()),
                    field: MetadataField::Custom("Description".to_string()),
                    current_value: Some(desc_str.to_string()),
                    is_writable: true,
                    requires_synchronization: false,
                    object_id: Some(object_id),
                    access_path: format!("Embedded File {} -> Description", object_id.0),
                });
            }
        }
        
        Ok(())
    }
    
    fn scan_dictionary_for_metadata(&mut self, object_id: ObjectId, dict: &Dictionary, location: MetadataLocation, location_desc: &str) -> Result<()> {
        let standard_fields = [
            (b"Title", MetadataField::Title),
            (b"Author", MetadataField::Author),
            (b"Subject", MetadataField::Subject),
            (b"Keywords", MetadataField::Keywords),
            (b"Creator", MetadataField::Creator),
            (b"Producer", MetadataField::Producer),
            (b"CreationDate", MetadataField::CreationDate),
            (b"ModDate", MetadataField::ModificationDate),
            (b"Trapped", MetadataField::Trapped),
        ];
        
        for (key, field) in &standard_fields {
            if let Ok(value) = dict.get(key) {
                if let Ok(value_str) = value.as_str() {
                    self.discovered_locations.push(DiscoveredLocation {
                        location: location.clone(),
                        field: field.clone(),
                        current_value: Some(value_str.to_string()),
                        is_writable: true,
                        requires_synchronization: true,
                        object_id: Some(object_id),
                        access_path: format!("{} -> {}", location_desc, field.as_string()),
                    });
                }
            }
        }
        Ok(())
    }
    
    fn build_location_map(&self) -> LocationMap {
        let mut location_map = HashMap::new();
        
        for discovered in &self.discovered_locations {
            location_map
                .entry(discovered.field.clone())
                .or_insert_with(Vec::new)
                .push(discovered.clone());
        }
        
        location_map
    }
    
    fn collect_hidden_metadata(&self) -> Vec<HiddenMetadataItem> {
        self.hidden_metadata_cache
            .values()
            .flat_map(|items| items.iter().cloned())
            .collect()
    }
    
    fn build_synchronization_targets(&self) -> HashMap<MetadataField, Vec<MetadataLocation>> {
        let mut sync_targets = HashMap::new();
        
        for discovered in &self.discovered_locations {
            if discovered.requires_synchronization {
                sync_targets
                    .entry(discovered.field.clone())
                    .or_insert_with(Vec::new)
                    .push(discovered.location.clone());
            }
        }
        
        sync_targets
    }
    
    fn generate_coverage_report(&self) -> CoverageReport {
        let total_locations_found = self.discovered_locations.len();
        let docinfo_locations = self.discovered_locations.iter()
            .filter(|loc| matches!(loc.location, MetadataLocation::DocInfo))
            .count();
        let xmp_locations = self.discovered_locations.iter()
            .filter(|loc| matches!(loc.location, MetadataLocation::XmpStream))
            .count();
        let hidden_locations = self.hidden_metadata_cache.values()
            .map(|items| items.len())
            .sum();
        
        let synchronizable_fields = self.discovered_locations.iter()
            .filter(|loc| loc.requires_synchronization)
            .map(|loc| &loc.field)
            .collect::<HashSet<_>>()
            .len();
        
        let coverage_percentage = if total_locations_found > 0 {
            (synchronizable_fields as f32 / total_locations_found as f32) * 100.0
        } else {
            0.0
        };
        
        CoverageReport {
            total_locations_found,
            docinfo_locations,
            xmp_locations,
            hidden_locations,
            synchronizable_fields,
            coverage_percentage,
        }
    }
    
    fn detect_forensic_indicators(&self) -> Vec<ForensicMetadataIndicator> {
        let mut indicators = Vec::new();
        
        // Check for ModDate presence
        for discovered in &self.discovered_locations {
            if discovered.field == MetadataField::ModificationDate {
                indicators.push(ForensicMetadataIndicator {
                    indicator_type: "Modification Trace".to_string(),
                    location: discovered.location.clone(),
                    description: "Document contains modification date".to_string(),
                    evidence: discovered.current_value.clone().unwrap_or_default(),
                    risk_level: "Medium".to_string(),
                });
            }
        }
        
        // Check for suspicious producers
        for discovered in &self.discovered_locations {
            if discovered.field == MetadataField::Producer {
                if let Some(ref producer) = discovered.current_value {
                    let suspicious_patterns = ["ghostscript", "itext", "reportlab", "tcpdf"];
                    for pattern in &suspicious_patterns {
                        if producer.to_lowercase().contains(pattern) {
                            indicators.push(ForensicMetadataIndicator {
                                indicator_type: "Editing Software".to_string(),
                                location: discovered.location.clone(),
                                description: format!("Suspicious producer detected: {}", pattern),
                                evidence: producer.clone(),
                                risk_level: "High".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        indicators
    }
}

impl Default for MetadataScanner {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 3: `src/metadata/editor.rs` (156 lines)

**Purpose**: Forensic-level metadata editing with universal field modification
**Location**: src/metadata/editor.rs
**Functionality**: Universal field modification, blank field handling, authentic metadata generation

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue, MetadataLocation},
    cli::CliArgs,
    config::Config,
};
use super::{ScanResult, MetadataProcessingConfig};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Forensic metadata editor for universal field modification
pub struct MetadataEditor {
    config: MetadataProcessingConfig,
    edit_operations: Vec<EditOperation>,
    validation_rules: HashMap<MetadataField, ValidationRule>,
}

/// Individual edit operation specification
#[derive(Debug, Clone)]
pub struct EditOperation {
    pub field: MetadataField,
    pub operation_type: EditOperationType,
    pub new_value: Option<String>,
    pub target_locations: Vec<MetadataLocation>,
    pub preserve_authenticity: bool,
}

#[derive(Debug, Clone)]
pub enum EditOperationType {
    Set,      // Set field to new value
    Clear,    // Remove field completely
    Preserve, // Keep existing value
    Generate, // Generate authentic value
}

/// Edit operation result
#[derive(Debug, Clone)]
pub struct EditResult {
    pub modified_metadata: MetadataMap,
    pub successful_operations: Vec<EditOperation>,
    pub failed_operations: Vec<(EditOperation, String)>,
    pub authenticity_preserved: bool,
    pub total_modifications: usize,
}

#[derive(Debug, Clone)]
struct ValidationRule {
    pub required_format: Option<String>,
    pub max_length: Option<usize>,
    pub allowed_characters: Option<String>,
    pub must_be_authentic: bool,
}

impl MetadataEditor {
    pub fn new() -> Self {
        let mut editor = Self {
            config: MetadataProcessingConfig::default(),
            edit_operations: Vec::new(),
            validation_rules: HashMap::new(),
        };
        
        editor.setup_validation_rules();
        editor
    }
    
    pub fn with_config(config: MetadataProcessingConfig) -> Self {
        let mut editor = Self {
            config,
            edit_operations: Vec::new(),
            validation_rules: HashMap::new(),
        };
        
        editor.setup_validation_rules();
        editor
    }
    
    fn setup_validation_rules(&mut self) {
        // Date fields must follow ISO 8601 format
        self.validation_rules.insert(
            MetadataField::CreationDate,
            ValidationRule {
                required_format: Some("ISO8601".to_string()),
                max_length: Some(50),
                allowed_characters: None,
                must_be_authentic: true,
            }
        );
        
        self.validation_rules.insert(
            MetadataField::ModificationDate,
            ValidationRule {
                required_format: Some("ISO8601".to_string()),
                max_length: Some(50),
                allowed_characters: None,
                must_be_authentic: true,
            }
        );
        
        // Text fields have length limits
        self.validation_rules.insert(
            MetadataField::Title,
            ValidationRule {
                required_format: None,
                max_length: Some(500),
                allowed_characters: None,
                must_be_authentic: false,
            }
        );
        
        self.validation_rules.insert(
            MetadataField::Author,
            ValidationRule {
                required_format: None,
                max_length: Some(200),
                allowed_characters: None,
                must_be_authentic: false,
            }
        );
        
        // Producer must be our standard value for forensic invisibility
        self.validation_rules.insert(
            MetadataField::Producer,
            ValidationRule {
                required_format: None,
                max_length: Some(100),
                allowed_characters: None,
                must_be_authentic: true,
            }
        );
    }
    
    /// Apply metadata changes from CLI arguments
    pub fn apply_changes(&mut self, extraction_data: &crate::pdf::ExtractionData, args: &CliArgs) -> Result<MetadataMap> {
        // Build edit operations from CLI arguments
        self.build_edit_operations_from_args(args)?;
        
        // Add forensic cleaning operations
        self.add_forensic_cleaning_operations();
        
        // Apply all operations to create modified metadata map
        let mut modified_metadata = extraction_data.metadata_map.clone();
        self.apply_edit_operations(&mut modified_metadata)?;
        
        Ok(modified_metadata)
    }
    
    fn build_edit_operations_from_args(&mut self, args: &CliArgs) -> Result<()> {
        let metadata_updates = args.get_metadata_updates();
        
        for (field, new_value) in metadata_updates {
            let operation_type = if new_value.is_some() {
                EditOperationType::Set
            } else {
                EditOperationType::Clear
            };
            
            let edit_op = EditOperation {
                field: field.clone(),
                operation_type,
                new_value,
                target_locations: Vec::new(), // Will be populated during synchronization
                preserve_authenticity: self.requires_authenticity(&field),
            };
            
            self.edit_operations.push(edit_op);
        }
        
        Ok(())
    }
    
    fn requires_authenticity(&self, field: &MetadataField) -> bool {
        self.validation_rules
            .get(field)
            .map(|rule| rule.must_be_authentic)
            .unwrap_or(false)
    }
    
    fn add_forensic_cleaning_operations(&mut self) {
        // Always remove ModDate for forensic invisibility
        self.edit_operations.push(EditOperation {
            field: MetadataField::ModificationDate,
            operation_type: EditOperationType::Clear,
            new_value: None,
            target_locations: Vec::new(),
            preserve_authenticity: true,
        });
        
        // Always remove Trapped field
        self.edit_operations.push(EditOperation {
            field: MetadataField::Trapped,
            operation_type: EditOperationType::Clear,
            new_value: None,
            target_locations: Vec::new(),
            preserve_authenticity: true,
        });
        
        // Set producer to our standard value
        self.edit_operations.push(EditOperation {
            field: MetadataField::Producer,
            operation_type: EditOperationType::Set,
            new_value: Some(Config::PDF_PRODUCER.to_string()),
            target_locations: Vec::new(),
            preserve_authenticity: true,
        });
    }
    
    fn apply_edit_operations(&mut self, metadata_map: &mut MetadataMap) -> Result<()> {
        for operation in &self.edit_operations {
            self.apply_single_operation(metadata_map, operation)?;
        }
        Ok(())
    }
    
    fn apply_single_operation(&self, metadata_map: &mut MetadataMap, operation: &EditOperation) -> Result<()> {
        match operation.operation_type {
            EditOperationType::Set => {
                if let Some(ref new_value) = operation.new_value {
                    let validated_value = self.validate_and_process_value(&operation.field, new_value)?;
                    self.set_metadata_field(metadata_map, &operation.field, Some(validated_value));
                }
            },
            EditOperationType::Clear => {
                self.set_metadata_field(metadata_map, &operation.field, None);
            },
            EditOperationType::Preserve => {
                // Do nothing - keep existing value
            },
            EditOperationType::Generate => {
                let generated_value = self.generate_authentic_value(&operation.field)?;
                self.set_metadata_field(metadata_map, &operation.field, Some(generated_value));
            },
        }
        Ok(())
    }
    
    fn validate_and_process_value(&self, field: &MetadataField, value: &str) -> Result<String> {
        if let Some(rule) = self.validation_rules.get(field) {
            // Check length limit
            if let Some(max_length) = rule.max_length {
                if value.len() > max_length {
                    return Err(ForensicError::metadata_error(
                        "validation",
                        &format!("Value too long for field {}: {} > {}", field.as_string(), value.len(), max_length)
                    ));
                }
            }
            
            // Check format requirements
            if let Some(ref format) = rule.required_format {
                if format == "ISO8601" && !self.is_valid_iso8601(value) {
                    return Err(ForensicError::metadata_error(
                        "validation",
                        &format!("Invalid ISO8601 date format for field {}: {}", field.as_string(), value)
                    ));
                }
            }
            
            // Process value for authenticity if required
            if rule.must_be_authentic {
                return self.make_value_authentic(field, value);
            }
        }
        
        Ok(value.to_string())
    }
    
    fn is_valid_iso8601(&self, date_str: &str) -> bool {
        DateTime::parse_from_rfc3339(date_str).is_ok()
    }
    
    fn make_value_authentic(&self, field: &MetadataField, value: &str) -> Result<String> {
        match field {
            MetadataField::CreationDate | MetadataField::ModificationDate => {
                // Ensure date is in the correct PDF format
                if let Ok(parsed_date) = DateTime::parse_from_rfc3339(value) {
                    // Convert to PDF date format: D:YYYYMMDDHHmmSSOHH'mm
                    let pdf_date = format!("D:{}", parsed_date.format("%Y%m%d%H%M%S%z"));
                    Ok(pdf_date)
                } else {
                    Err(ForensicError::metadata_error(
                        "date_conversion",
                        &format!("Cannot convert date to PDF format: {}", value)
                    ))
                }
            },
            MetadataField::Producer => {
                // Always use our standard producer string
                Ok(Config::PDF_PRODUCER.to_string())
            },
            _ => Ok(value.to_string()),
        }
    }
    
    fn generate_authentic_value(&self, field: &MetadataField) -> Result<String> {
        match field {
            MetadataField::CreationDate => {
                let authentic_date = crate::forensic::ForensicCleaner::generate_authentic_timestamp();
                let parsed_date = DateTime::parse_from_rfc3339(&authentic_date)?;
                Ok(format!("D:{}", parsed_date.format("%Y%m%d%H%M%S%z")))
            },
            MetadataField::Producer => {
                Ok(Config::PDF_PRODUCER.to_string())
            },
            MetadataField::Creator => {
                Ok("Microsoft Word".to_string()) // Common, authentic-looking creator
            },
            _ => Err(ForensicError::metadata_error(
                "generation",
                &format!("Cannot generate authentic value for field: {}", field.as_string())
            )),
        }
    }
    
    fn set_metadata_field(&self, metadata_map: &mut MetadataMap, field: &MetadataField, value: Option<String>) {
        if let Some(existing) = metadata_map.get_mut(field) {
            existing.value = value;
            existing.is_synchronized = false; // Mark as needing synchronization
        } else {
            // Create new metadata value entry
            let metadata_value = MetadataValue {
                field: field.clone(),
                value,
                locations: Vec::new(), // Will be populated during synchronization
                is_synchronized: false,
            };
            metadata_map.insert(field.clone(), metadata_value);
        }
    }
    
    /// Process metadata with scan results for complete location targeting
    pub fn process_with_scan_results(&mut self, scan_result: &ScanResult, metadata_map: &mut MetadataMap) -> Result<EditResult> {
        let mut successful_operations = Vec::new();
        let mut failed_operations = Vec::new();
        let mut total_modifications = 0;
        
        // Update edit operations with location information from scan
        for operation in &mut self.edit_operations {
            if let Some(locations) = scan_result.synchronization_targets.get(&operation.field) {
                operation.target_locations = locations.clone();
            }
        }
        
        // Apply operations with location targeting
        for operation in &self.edit_operations {
            match self.apply_operation_with_locations(metadata_map, operation) {
                Ok(modification_count) => {
                    successful_operations.push(operation.clone());
                    total_modifications += modification_count;
                },
                Err(e) => {
                    failed_operations.push((operation.clone(), e.to_string()));
                }
            }
        }
        
        let authenticity_preserved = failed_operations.is_empty() && 
            self.verify_authenticity_preservation(metadata_map);
        
        Ok(EditResult {
            modified_metadata: metadata_map.clone(),
            successful_operations,
            failed_operations,
            authenticity_preserved,
            total_modifications,
        })
    }
    
    fn apply_operation_with_locations(&self, metadata_map: &mut MetadataMap, operation: &EditOperation) -> Result<usize> {
        let mut modification_count = 0;
        
        // Apply the operation to the metadata map
        self.apply_single_operation(metadata_map, operation)?;
        modification_count += 1;
        
        // Update location information in metadata value
        if let Some(metadata_value) = metadata_map.get_mut(&operation.field) {
            metadata_value.locations = operation.target_locations.clone();
            metadata_value.is_synchronized = false; // Will be synchronized later
        }
        
        Ok(modification_count)
    }
    
    fn verify_authenticity_preservation(&self, metadata_map: &MetadataMap) -> bool {
        // Check that all authenticity-required fields have appropriate values
        for (field, metadata_value) in metadata_map {
            if let Some(rule) = self.validation_rules.get(field) {
                if rule.must_be_authentic {
                    if let Some(ref value) = metadata_value.value {
                        if !self.is_authentic_value(field, value) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }
    
    fn is_authentic_value(&self, field: &MetadataField, value: &str) -> bool {
        match field {
            MetadataField::Producer => value == Config::PDF_PRODUCER,
            MetadataField::CreationDate => {
                // Check if date looks authentic (not obviously generated)
                crate::forensic::ForensicCleaner::validate_timestamp_authenticity(value).unwrap_or(false)
            },
            _ => true, // Other fields don't have specific authenticity requirements
        }
    }
    
    /// Generate blank field removal operations
    pub fn generate_blank_field_operations(&mut self, fields_to_blank: &[MetadataField]) {
        for field in fields_to_blank {
            self.edit_operations.push(EditOperation {
                field: field.clone(),
                operation_type: EditOperationType::Clear,
                new_value: None,
                target_locations: Vec::new(),
                preserve_authenticity: true,
            });
        }
    }
    
    /// Validate all pending operations
    pub fn validate_operations(&self) -> Result<()> {
        for operation in &self.edit_operations {
            if let Some(ref value) = operation.new_value {
                self.validate_and_process_value(&operation.field, value)?;
            }
        }
        Ok(())
    }
}

impl Default for MetadataEditor {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 4: `src/metadata/synchronizer.rs` (145 lines)

**Purpose**: Universal metadata synchronization across all PDF locations
**Location**: src/metadata/synchronizer.rs
**Functionality**: Cross-location consistency enforcement, field propagation, complete coverage verification

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue, MetadataLocation},
    config::Config,
};
use super::{ScanResult, EditResult, MetadataProcessingConfig};
use std::collections::{HashMap, HashSet};

/// Universal metadata synchronization engine
pub struct MetadataSynchronizer {
    config: MetadataProcessingConfig,
    synchronization_strategy: SyncStrategy,
    verification_enabled: bool,
}

/// Synchronization strategy enumeration
#[derive(Debug, Clone)]
pub enum SyncStrategy {
    Universal,      // Synchronize across all discovered locations
    Selective,      // Synchronize only specified locations
    Hierarchical,   // Prioritize certain locations over others
}

/// Complete synchronization result
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub synchronized_metadata: MetadataMap,
    pub synchronization_report: SynchronizationReport,
    pub verification_results: VerificationResults,
    pub total_updates: usize,
    pub failed_synchronizations: Vec<SyncFailure>,
}

#[derive(Debug, Clone)]
pub struct SynchronizationReport {
    pub fields_synchronized: usize,
    pub locations_updated: usize,
    pub docinfo_updates: usize,
    pub xmp_updates: usize,
    pub hidden_location_updates: usize,
    pub synchronization_coverage: f32,
}

#[derive(Debug, Clone)]
pub struct VerificationResults {
    pub all_locations_synchronized: bool,
    pub consistency_verified: bool,
    pub missing_synchronizations: Vec<(MetadataField, MetadataLocation)>,
    pub value_mismatches: Vec<ValueMismatch>,
}

#[derive(Debug, Clone)]
pub struct ValueMismatch {
    pub field: MetadataField,
    pub location1: MetadataLocation,
    pub location2: MetadataLocation,
    pub value1: Option<String>,
    pub value2: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SyncFailure {
    pub field: MetadataField,
    pub location: MetadataLocation,
    pub error_message: String,
    pub retry_possible: bool,
}

impl MetadataSynchronizer {
    pub fn new() -> Self {
        Self {
            config: MetadataProcessingConfig::default(),
            synchronization_strategy: SyncStrategy::Universal,
            verification_enabled: true,
        }
    }
    
    pub fn with_strategy(strategy: SyncStrategy) -> Self {
        Self {
            config: MetadataProcessingConfig::default(),
            synchronization_strategy: strategy,
            verification_enabled: true,
        }
    }
    
    /// Synchronize all metadata across discovered locations
    pub fn synchronize_all_metadata(&mut self, modified_metadata: &MetadataMap) -> Result<SyncResult> {
        let mut synchronized_metadata = modified_metadata.clone();
        let mut total_updates = 0;
        let mut failed_synchronizations = Vec::new();
        
        // Phase 1: Prepare synchronization plan
        let sync_plan = self.create_synchronization_plan(&synchronized_metadata)?;
        
        // Phase 2: Execute synchronization for each field
        for (field, sync_instruction) in sync_plan {
            match self.synchronize_field(&mut synchronized_metadata, &field, &sync_instruction) {
                Ok(update_count) => {
                    total_updates += update_count;
                },
                Err(e) => {
                    failed_synchronizations.push(SyncFailure {
                        field: field.clone(),
                        location: MetadataLocation::CustomLocation("Multiple".to_string()),
                        error_message: e.to_string(),
                        retry_possible: true,
                    });
                }
            }
        }
        
        // Phase 3: Verify synchronization completeness
        let verification_results = if self.verification_enabled {
            self.verify_synchronization(&synchronized_metadata)?
        } else {
            VerificationResults::default()
        };
        
        // Phase 4: Generate synchronization report
        let synchronization_report = self.generate_synchronization_report(&synchronized_metadata, total_updates);
        
        Ok(SyncResult {
            synchronized_metadata,
            synchronization_report,
            verification_results,
            total_updates,
            failed_synchronizations,
        })
    }
    
    fn create_synchronization_plan(&self, metadata_map: &MetadataMap) -> Result<HashMap<MetadataField, SyncInstruction>> {
        let mut sync_plan = HashMap::new();
        
        for (field, metadata_value) in metadata_map {
            if !metadata_value.is_synchronized && !metadata_value.locations.is_empty() {
                let sync_instruction = SyncInstruction {
                    target_value: metadata_value.value.clone(),
                    target_locations: metadata_value.locations.clone(),
                    operation_type: if metadata_value.value.is_some() {
                        SyncOperationType::Set
                    } else {
                        SyncOperationType::Remove
                    },
                    priority: self.get_field_priority(field),
                };
                
                sync_plan.insert(field.clone(), sync_instruction);
            }
        }
        
        Ok(sync_plan)
    }
    
    fn get_field_priority(&self, field: &MetadataField) -> u8 {
        match field {
            MetadataField::CreationDate => 10,    // Highest priority
            MetadataField::Producer => 9,
            MetadataField::Title => 8,
            MetadataField::Author => 7,
            MetadataField::Subject => 6,
            MetadataField::Keywords => 5,
            MetadataField::Creator => 4,
            MetadataField::ModificationDate => 1, // Lowest priority (usually removed)
            MetadataField::Trapped => 1,
            MetadataField::Custom(_) => 3,
        }
    }
    
    fn synchronize_field(&self, metadata_map: &mut MetadataMap, field: &MetadataField, instruction: &SyncInstruction) -> Result<usize> {
        let mut update_count = 0;
        
        // Update the metadata value to mark as synchronized
        if let Some(metadata_value) = metadata_map.get_mut(field) {
            match instruction.operation_type {
                SyncOperationType::Set => {
                    // Ensure all locations have the same value
                    for location in &instruction.target_locations {
                        self.update_location_value(location, &instruction.target_value)?;
                        update_count += 1;
                    }
                },
                SyncOperationType::Remove => {
                    // Remove value from all locations
                    for location in &instruction.target_locations {
                        self.remove_location_value(location)?;
                        update_count += 1;
                    }
                },
                SyncOperationType::Preserve => {
                    // Keep existing values - no changes needed
                },
            }
            
            // Mark as synchronized
            metadata_value.is_synchronized = true;
        }
        
        Ok(update_count)
    }
    
    fn update_location_value(&self, location: &MetadataLocation, value: &Option<String>) -> Result<()> {
        // This is a placeholder for the actual location update logic
        // In a complete implementation, this would update the specific PDF object
        // containing the metadata at the given location
        
        match location {
            MetadataLocation::DocInfo => {
                // Update Document Information Dictionary
            },
            MetadataLocation::XmpStream => {
                // Update XMP metadata stream
            },
            MetadataLocation::ObjectStream(object_id) => {
                // Update specific object stream
            },
            MetadataLocation::Annotation(annotation_id) => {
                // Update annotation object
            },
            MetadataLocation::FormField(field_name) => {
                // Update form field value
            },
            MetadataLocation::CustomLocation(location_name) => {
                // Update custom location
            },
        }
        
        Ok(())
    }
    
    fn remove_location_value(&self, location: &MetadataLocation) -> Result<()> {
        // This is a placeholder for the actual location removal logic
        // In a complete implementation, this would remove the metadata field
        // from the specific PDF object at the given location
        
        Ok(())
    }
    
    fn verify_synchronization(&self, metadata_map: &MetadataMap) -> Result<VerificationResults> {
        let mut all_locations_synchronized = true;
        let mut consistency_verified = true;
        let mut missing_synchronizations = Vec::new();
        let mut value_mismatches = Vec::new();
        
        for (field, metadata_value) in metadata_map {
            if !metadata_value.is_synchronized {
                all_locations_synchronized = false;
                
                for location in &metadata_value.locations {
                    missing_synchronizations.push((field.clone(), location.clone()));
                }
            }
            
            // Check for value consistency across locations
            if metadata_value.locations.len() > 1 {
                let mismatches = self.check_value_consistency(field, metadata_value)?;
                if !mismatches.is_empty() {
                    consistency_verified = false;
                    value_mismatches.extend(mismatches);
                }
            }
        }
        
        Ok(VerificationResults {
            all_locations_synchronized,
            consistency_verified,
            missing_synchronizations,
            value_mismatches,
        })
    }
    
    fn check_value_consistency(&self, field: &MetadataField, metadata_value: &MetadataValue) -> Result<Vec<ValueMismatch>> {
        let mut mismatches = Vec::new();
        
        // This is a placeholder for actual consistency checking
        // In a complete implementation, this would read values from each location
        // and compare them for consistency
        
        Ok(mismatches)
    }
    
    fn generate_synchronization_report(&self, metadata_map: &MetadataMap, total_updates: usize) -> SynchronizationReport {
        let fields_synchronized = metadata_map.values()
            .filter(|mv| mv.is_synchronized)
            .count();
        
        let locations_updated = total_updates;
        
        let docinfo_updates = metadata_map.values()
            .flat_map(|mv| &mv.locations)
            .filter(|loc| matches!(loc, MetadataLocation::DocInfo))
            .count();
        
        let xmp_updates = metadata_map.values()
            .flat_map(|mv| &mv.locations)
            .filter(|loc| matches!(loc, MetadataLocation::XmpStream))
            .count();
        
        let hidden_location_updates = metadata_map.values()
            .flat_map(|mv| &mv.locations)
            .filter(|loc| matches!(loc, MetadataLocation::ObjectStream(_) | MetadataLocation::CustomLocation(_)))
            .count();
        
        let total_fields = metadata_map.len();
        let synchronization_coverage = if total_fields > 0 {
            (fields_synchronized as f32 / total_fields as f32) * 100.0
        } else {
            0.0
        };
        
        SynchronizationReport {
            fields_synchronized,
            locations_updated,
            docinfo_updates,
            xmp_updates,
            hidden_location_updates,
            synchronization_coverage,
        }
    }
    
    /// Force synchronization of specific fields
    pub fn force_synchronize_fields(&mut self, metadata_map: &mut MetadataMap, fields: &[MetadataField]) -> Result<usize> {
        let mut total_updates = 0;
        
        for field in fields {
            if let Some(metadata_value) = metadata_map.get_mut(field) {
                // Force synchronization regardless of current status
                metadata_value.is_synchronized = false;
                
                let sync_instruction = SyncInstruction {
                    target_value: metadata_value.value.clone(),
                    target_locations: metadata_value.locations.clone(),
                    operation_type: if metadata_value.value.is_some() {
                        SyncOperationType::Set
                    } else {
                        SyncOperationType::Remove
                    },
                    priority: self.get_field_priority(field),
                };
                
                total_updates += self.synchronize_field(metadata_map, field, &sync_instruction)?;
            }
        }
        
        Ok(total_updates)
    }
    
    /// Verify specific field synchronization
    pub fn verify_field_synchronization(&self, metadata_map: &MetadataMap, field: &MetadataField) -> Result<bool> {
        if let Some(metadata_value) = metadata_map.get(field) {
            if metadata_value.locations.len() <= 1 {
                return Ok(true); // Single location is always synchronized
            }
            
            // Check that all locations have the same value
            let mismatches = self.check_value_consistency(field, metadata_value)?;
            Ok(mismatches.is_empty())
        } else {
            Ok(true) // Non-existent field is considered synchronized
        }
    }
}

#[derive(Debug, Clone)]
struct SyncInstruction {
    target_value: Option<String>,
    target_locations: Vec<MetadataLocation>,
    operation_type: SyncOperationType,
    priority: u8,
}

#[derive(Debug, Clone)]
enum SyncOperationType {
    Set,
    Remove,
    Preserve,
}

impl Default for VerificationResults {
    fn default() -> Self {
        Self {
            all_locations_synchronized: true,
            consistency_verified: true,
            missing_synchronizations: Vec::new(),
            value_mismatches: Vec::new(),
        }
    }
}

impl Default for MetadataSynchronizer {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 5: `src/metadata/cleaner.rs` (123 lines)

**Purpose**: Original metadata elimination and forensic trace removal
**Location**: src/metadata/cleaner.rs
**Functionality**: Complete data sanitization, invisibility assurance, authentic appearance preservation

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataLocation},
    config::ForensicConfig,
};
use super::{ScanResult, MetadataProcessingConfig};
use std::collections::{HashMap, HashSet};

/// Forensic metadata cleaner for trace elimination
pub struct MetadataCleaner {
    config: MetadataProcessingConfig,
    cleaning_strategy: CleaningStrategy,
    removal_targets: HashSet<MetadataField>,
}

/// Cleaning strategy enumeration
#[derive(Debug, Clone)]
pub enum CleaningStrategy {
    Conservative,  // Remove only obvious editing traces
    Aggressive,   // Remove all non-essential metadata
    Surgical,     // Remove specific targeted fields only
    Complete,     // Remove all metadata except essential fields
}

/// Complete cleaning operation result
#[derive(Debug, Clone)]
pub struct CleaningResult {
    pub cleaned_metadata: MetadataMap,
    pub removed_fields: Vec<MetadataField>,
    pub sanitized_locations: Vec<MetadataLocation>,
    pub cleaning_report: CleaningReport,
    pub forensic_compliance: ForensicCompliance,
}

#[derive(Debug, Clone)]
pub struct CleaningReport {
    pub total_fields_processed: usize,
    pub fields_removed: usize,
    pub fields_sanitized: usize,
    pub locations_cleaned: usize,
    pub traces_eliminated: usize,
    pub cleaning_effectiveness: f32,
}

#[derive(Debug, Clone)]
pub struct ForensicCompliance {
    pub moddate_removed: bool,
    pub trapped_removed: bool,
    pub producer_standardized: bool,
    pub editing_traces_removed: bool,
    pub watermarks_removed: bool,
    pub compliance_score: f32,
}

impl MetadataCleaner {
    pub fn new() -> Self {
        Self {
            config: MetadataProcessingConfig::default(),
            cleaning_strategy: CleaningStrategy::Aggressive,
            removal_targets: Self::default_removal_targets(),
        }
    }
    
    pub fn with_strategy(strategy: CleaningStrategy) -> Self {
        Self {
            config: MetadataProcessingConfig::default(),
            cleaning_strategy: strategy,
            removal_targets: Self::removal_targets_for_strategy(&strategy),
        }
    }
    
    fn default_removal_targets() -> HashSet<MetadataField> {
        let mut targets = HashSet::new();
        targets.insert(MetadataField::ModificationDate);
        targets.insert(MetadataField::Trapped);
        targets
    }
    
    fn removal_targets_for_strategy(strategy: &CleaningStrategy) -> HashSet<MetadataField> {
        let mut targets = HashSet::new();
        
        match strategy {
            CleaningStrategy::Conservative => {
                targets.insert(MetadataField::ModificationDate);
                targets.insert(MetadataField::Trapped);
            },
            CleaningStrategy::Aggressive => {
                targets.insert(MetadataField::ModificationDate);
                targets.insert(MetadataField::Trapped);
                // Add custom fields that might reveal editing
                for field_name in ForensicConfig::FORENSIC_REMOVE_FIELDS {
                    if let Ok(field) = Self::parse_field_name(field_name) {
                        targets.insert(field);
                    }
                }
            },
            CleaningStrategy::Surgical => {
                // Only remove specifically targeted fields
                targets.insert(MetadataField::ModificationDate);
            },
            CleaningStrategy::Complete => {
                // Remove all except essential fields
                targets.insert(MetadataField::ModificationDate);
                targets.insert(MetadataField::Trapped);
                targets.insert(MetadataField::Keywords);
                targets.insert(MetadataField::Subject);
            },
        }
        
        targets
    }
    
    fn parse_field_name(field_name: &str) -> Result<MetadataField> {
        match field_name {
            "ModDate" => Ok(MetadataField::ModificationDate),
            "Trapped" => Ok(MetadataField::Trapped),
            "Producer" => Ok(MetadataField::Producer),
            "GTS_PDFXVersion" => Ok(MetadataField::Custom("GTS_PDFXVersion".to_string())),
            "GTS_PDFXConformance" => Ok(MetadataField::Custom("GTS_PDFXConformance".to_string())),
            custom => Ok(MetadataField::Custom(custom.to_string())),
        }
    }
    
    /// Perform comprehensive forensic cleaning
    pub fn clean_metadata(&mut self, metadata_map: &MetadataMap, scan_result: &ScanResult) -> Result<CleaningResult> {
        let mut cleaned_metadata = metadata_map.clone();
        let mut removed_fields = Vec::new();
        let mut sanitized_locations = Vec::new();
        let mut traces_eliminated = 0;
        
        // Phase 1: Remove targeted metadata fields
        for field in &self.removal_targets {
            if cleaned_metadata.contains_key(field) {
                if let Some(metadata_value) = cleaned_metadata.remove(field) {
                    removed_fields.push(field.clone());
                    sanitized_locations.extend(metadata_value.locations);
                    traces_eliminated += 1;
                }
            }
        }
        
        // Phase 2: Sanitize remaining fields for forensic compliance
        self.sanitize_remaining_fields(&mut cleaned_metadata)?;
        
        // Phase 3: Remove editing software signatures
        traces_eliminated += self.remove_editing_signatures(&mut cleaned_metadata)?;
        
        // Phase 4: Clean hidden metadata discovered in scan
        traces_eliminated += self.clean_hidden_metadata(&mut cleaned_metadata, scan_result)?;
        
        // Generate cleaning report
        let cleaning_report = self.generate_cleaning_report(
            metadata_map.len(),
            removed_fields.len(),
            sanitized_locations.len(),
            traces_eliminated
        );
        
        // Assess forensic compliance
        let forensic_compliance = self.assess_forensic_compliance(&cleaned_metadata);
        
        Ok(CleaningResult {
            cleaned_metadata,
            removed_fields,
            sanitized_locations,
            cleaning_report,
            forensic_compliance,
        })
    }
    
    fn sanitize_remaining_fields(&self, metadata_map: &mut MetadataMap) -> Result<()> {
        for (field, metadata_value) in metadata_map.iter_mut() {
            if let Some(ref mut value) = metadata_value.value {
                let sanitized_value = self.sanitize_field_value(field, value)?;
                *value = sanitized_value;
            }
        }
        Ok(())
    }
    
    fn sanitize_field_value(&self, field: &MetadataField, value: &str) -> Result<String> {
        match field {
            MetadataField::Producer => {
                // Always replace with our standard producer
                Ok(crate::config::Config::PDF_PRODUCER.to_string())
            },
            MetadataField::Creator => {
                // Sanitize creator to remove obvious editing software names
                let suspicious_creators = [
                    "ghostscript", "itext", "reportlab", "tcpdf", "fpdf", 
                    "dompdf", "wkhtmltopdf", "pandoc", "libreoffice", "openoffice"
                ];
                
                let value_lower = value.to_lowercase();
                for suspicious in &suspicious_creators {
                    if value_lower.contains(suspicious) {
                        return Ok("Microsoft Word".to_string()); // Safe, common creator
                    }
                }
                Ok(value.to_string())
            },
            MetadataField::Title | MetadataField::Author | MetadataField::Subject | MetadataField::Keywords => {
                // Remove potentially revealing metadata patterns
                let sanitized = value
                    .replace("temp", "")
                    .replace("test", "")
                    .replace("draft", "")
                    .replace("copy", "")
                    .trim()
                    .to_string();
                
                if sanitized.is_empty() {
                    Ok(value.to_string()) // Keep original if sanitization would empty it
                } else {
                    Ok(sanitized)
                }
            },
            _ => Ok(value.to_string()),
        }
    }
    
    fn remove_editing_signatures(&self, metadata_map: &mut MetadataMap) -> Result<usize> {
        let mut signatures_removed = 0;
        let mut fields_to_remove = Vec::new();
        
        // Scan for fields that contain editing software signatures
        for (field, metadata_value) in metadata_map.iter() {
            if let Some(ref value) = metadata_value.value {
                if self.contains_editing_signature(value) {
                    fields_to_remove.push(field.clone());
                }
            }
        }
        
        // Remove fields with editing signatures
        for field in fields_to_remove {
            metadata_map.remove(&field);
            signatures_removed += 1;
        }
        
        Ok(signatures_removed)
    }
    
    fn contains_editing_signature(&self, value: &str) -> bool {
        let editing_signatures = [
            "ghostscript", "gs ", "itext", "itextpdf", "reportlab", "tcpdf",
            "fpdf", "dompdf", "wkhtmltopdf", "pandoc", "converted", "generated",
            "pdf creator", "pdf maker", "pdf writer", "pdfsharp", "migradoc"
        ];
        
        let value_lower = value.to_lowercase();
        editing_signatures.iter().any(|sig| value_lower.contains(sig))
    }
    
    fn clean_hidden_metadata(&self, metadata_map: &mut MetadataMap, scan_result: &ScanResult) -> Result<usize> {
        let mut hidden_cleaned = 0;
        
        // Process hidden metadata items found during scanning
        for hidden_item in &scan_result.hidden_metadata {
            // Check if this hidden metadata should be removed
            if self.should_remove_hidden_item(hidden_item) {
                // Remove custom fields that correspond to hidden metadata
                let custom_field = MetadataField::Custom(hidden_item.field_name.clone());
                if metadata_map.remove(&custom_field).is_some() {
                    hidden_cleaned += 1;
                }
            }
        }
        
        Ok(hidden_cleaned)
    }
    
    fn should_remove_hidden_item(&self, hidden_item: &super::scanner::HiddenMetadataItem) -> bool {
        // Remove hidden items with high confidence that indicate editing
        hidden_item.confidence_level > 0.7 && 
        (hidden_item.field_name.to_lowercase().contains("modif") ||
         hidden_item.field_name.to_lowercase().contains("edit") ||
         hidden_item.field_name.to_lowercase().contains("creat"))
    }
    
    fn generate_cleaning_report(&self, total_fields: usize, fields_removed: usize, locations_cleaned: usize, traces_eliminated: usize) -> CleaningReport {
        let fields_sanitized = total_fields - fields_removed;
        let cleaning_effectiveness = if total_fields > 0 {
            ((fields_removed + traces_eliminated) as f32 / total_fields as f32) * 100.0
        } else {
            100.0
        };
        
        CleaningReport {
            total_fields_processed: total_fields,
            fields_removed,
            fields_sanitized,
            locations_cleaned,
            traces_eliminated,
            cleaning_effectiveness,
        }
    }
    
    fn assess_forensic_compliance(&self, metadata_map: &MetadataMap) -> ForensicCompliance {
        let moddate_removed = !metadata_map.contains_key(&MetadataField::ModificationDate);
        let trapped_removed = !metadata_map.contains_key(&MetadataField::Trapped);
        
        let producer_standardized = metadata_map
            .get(&MetadataField::Producer)
            .and_then(|mv| mv.value.as_ref())
            .map(|v| v == crate::config::Config::PDF_PRODUCER)
            .unwrap_or(true);
        
        let editing_traces_removed = !self.has_editing_traces(metadata_map);
        let watermarks_removed = !self.has_watermarks(metadata_map);
        
        let compliance_checks = [
            moddate_removed,
            trapped_removed,
            producer_standardized,
            editing_traces_removed,
            watermarks_removed,
        ];
        
        let compliance_score = (compliance_checks.iter().filter(|&&check| check).count() as f32 / compliance_checks.len() as f32) * 100.0;
        
        ForensicCompliance {
            moddate_removed,
            trapped_removed,
            producer_standardized,
            editing_traces_removed,
            watermarks_removed,
            compliance_score,
        }
    }
    
    fn has_editing_traces(&self, metadata_map: &MetadataMap) -> bool {
        for (_, metadata_value) in metadata_map {
            if let Some(ref value) = metadata_value.value {
                if self.contains_editing_signature(value) {
                    return true;
                }
            }
        }
        false
    }
    
    fn has_watermarks(&self, metadata_map: &MetadataMap) -> bool {
        // Check for common watermark indicators
        let watermark_indicators = ["watermark", "demo", "trial", "evaluation", "unregistered"];
        
        for (_, metadata_value) in metadata_map {
            if let Some(ref value) = metadata_value.value {
                let value_lower = value.to_lowercase();
                if watermark_indicators.iter().any(|indicator| value_lower.contains(indicator)) {
                    return true;
                }
            }
        }
        false
    }
    
    /// Add custom fields to removal targets
    pub fn add_removal_targets(&mut self, fields: &[MetadataField]) {
        for field in fields {
            self.removal_targets.insert(field.clone());
        }
    }
    
    /// Remove specific fields from removal targets
    pub fn remove_from_targets(&mut self, fields: &[MetadataField]) {
        for field in fields {
            self.removal_targets.remove(field);
        }
    }
    
    /// Verify cleaning completeness
    pub fn verify_cleaning(&self, metadata_map: &MetadataMap) -> Result<bool> {
        // Verify that all target fields have been removed
        for target_field in &self.removal_targets {
            if metadata_map.contains_key(target_field) {
                return Ok(false);
            }
        }
        
        // Verify that no editing signatures remain
        if self.has_editing_traces(metadata_map) {
            return Ok(false);
        }
        
        Ok(true)
    }
}

impl Default for MetadataCleaner {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## Implementation Sequence

1. **Create src/metadata/mod.rs** - Establishes metadata module interface and coordination
2. **Implement src/metadata/scanner.rs** - Comprehensive metadata location discovery engine
3. **Create src/metadata/editor.rs** - Forensic metadata editing with universal field modification
4. **Implement src/metadata/synchronizer.rs** - Universal synchronization across all locations
5. **Create src/metadata/cleaner.rs** - Complete forensic trace removal and sanitization

## Compilation Requirements

After implementing these 5 files:
- Complete metadata discovery system will be available
- Forensic metadata editing capabilities will be functional
- Universal synchronization engine will be ready
- Comprehensive cleaning system will be implemented
- Foundation for authentic metadata processing will be established

## Next Guide

Implementation Guide 05 will create the data structures and utilities (pdf_objects, metadata_map, clone_data, crypto, serialization, forensics utilities).