use crate::{
    errors::{ForensicError, Result},
    types::{PdfVersion, MetadataField, MetadataLocation},
    config::Config,
};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};
use chrono::{DateTime, Utc};

/// Comprehensive PDF parser with forensic capabilities
pub struct PdfParser {
    config: super::PdfProcessingConfig,
    object_cache: HashMap<ObjectId, Object>,
    metadata_locations: Vec<MetadataLocation>,
    initialization_time: DateTime<Utc>,
    operator: String,
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
    pub parse_timestamp: DateTime<Utc>,
    pub operator: String,
}

#[derive(Debug, Clone)]
pub struct PdfObjectInfo {
    pub object_id: ObjectId,
    pub object_type: String,
    pub contains_metadata: bool,
    pub is_encrypted: bool,
    pub references: Vec<ObjectId>,
    pub content_size: usize,
    pub discovery_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MetadataLocation {
    pub location_type: String,
    pub object_id: Option<ObjectId>,
    pub field_name: String,
    pub field_value: Option<String>,
    pub is_hidden: bool,
    pub discovery_time: DateTime<Utc>,
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
    pub detection_time: DateTime<Utc>,
}

impl PdfParser {
    pub fn new() -> Self {
        Self {
            config: super::PdfProcessingConfig::default(),
            object_cache: HashMap::new(),
            metadata_locations: Vec::new(),
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:42:26Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    pub fn with_config(config: super::PdfProcessingConfig) -> Self {
        Self {
            config,
            object_cache: HashMap::new(),
            metadata_locations: Vec::new(),
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:42:26Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }

    /// Parse PDF file and extract complete structure
    pub fn parse_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<ParsedPdfData> {
        let path = file_path.as_ref();
        
        // Validate file size
        let metadata = std::fs::metadata(path)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read file metadata: {}", e)
            })?;
            
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
            parse_timestamp: self.initialization_time,
            operator: self.operator.clone(),
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
            _ => Err(ForensicError::parse_error(&format!(
                "Unsupported PDF version: {}", version_str
            ))),
        }
    }
    fn analyze_object_structure(&mut self, document: &Document) -> Result<HashMap<ObjectId, PdfObjectInfo>> {
        let mut object_map = HashMap::new();
        
        // Iterate through all objects in the document
        for (object_id, object) in document.objects.iter() {
            let object_info = self.analyze_object(*object_id, object)?;
            object_map.insert(*object_id, object_info);
            
            // Cache object for later reference
            self.object_cache.insert(*object_id, object.clone());
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
            discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:43:12Z")
                .unwrap()
                .with_timezone(&Utc),
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
    
    fn check_encryption_status(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => dict.has(b"Filter") && dict.has(b"V"),
            Object::Stream(stream) => {
                if let Ok(dict) = &stream.dict.as_dict() {
                    dict.has(b"Filter") && dict.has(b"V")
                } else {
                    false
                }
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
    
    fn calculate_object_size(&self, object: &Object) -> usize {
        match object {
            Object::Stream(stream) => stream.content.len(),
            Object::String(s, _) => s.len(),
            Object::Array(array) => array.len() * 8, // Estimate
            Object::Dictionary(dict) => dict.len() * 16, // Estimate
            _ => std::mem::size_of::<Object>(),
        }
    }
    
    fn analyze_object_relationships(&self, object_map: &mut HashMap<ObjectId, PdfObjectInfo>, document: &Document) -> Result<()> {
        let mut reference_counts = HashMap::new();
        
        // Count all references
        for info in object_map.values() {
            for &ref_id in &info.references {
                *reference_counts.entry(ref_id).or_insert(0) += 1;
            }
        }
        
        // Update object info with reference counts
        for info in object_map.values_mut() {
            if reference_counts.get(&info.object_id).unwrap_or(&0) > &2 {
                info.contains_metadata = true; // Objects referenced multiple times often contain metadata
            }
        }
        
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
            
        Ok(EncryptionInfo {
            is_encrypted: true,
            filter,
            version,
            revision,
            key_length,
            permissions,
            has_user_password: encrypt_dict.has(b"U"),
            has_owner_password: encrypt_dict.has(b"O"),
            detection_time: DateTime::parse_from_rfc3339("2025-06-13T16:43:12Z")
                .unwrap()
                .with_timezone(&Utc),
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
                                let field_value = value.as_str()
                                    .map(|s| s.to_string())
                                    .ok();
                                
                                self.metadata_locations.push(MetadataLocation {
                                    location_type: "DocInfo".to_string(),
                                    object_id: Some(object_id),
                                    field_name,
                                    field_value,
                                    is_hidden: false,
                                    discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:44:57Z")
                                        .unwrap()
                                        .with_timezone(&Utc),
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
        for (object_id, object) in &document.objects {
            if let Object::Stream(stream) = object {
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            if subtype_name == "XML" {
                                // Parse XMP stream content for metadata fields
                                if let Ok(xmp_content) = String::from_utf8(stream.content.clone()) {
                                    self.extract_xmp_metadata(*object_id, &xmp_content)?;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn extract_xmp_metadata(&mut self, object_id: ObjectId, xmp_content: &str) -> Result<()> {
        let xmp_fields = [
            ("dc:title", "Title"),
            ("dc:creator", "Author"),
            ("dc:description", "Subject"),
            ("dc:subject", "Keywords"),
            ("xmp:CreatorTool", "Creator"),
            ("pdf:Producer", "Producer"),
            ("xmp:CreateDate", "CreationDate"),
            ("xmp:ModifyDate", "ModDate"),
        ];
        
        for (xmp_tag, field_name) in &xmp_fields {
            if let Some(value) = self.find_xmp_value(xmp_content, xmp_tag) {
                self.metadata_locations.push(MetadataLocation {
                    location_type: "XMP".to_string(),
                    object_id: Some(object_id),
                    field_name: field_name.to_string(),
                    field_value: Some(value),
                    is_hidden: false,
                    discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:44:57Z")
                        .unwrap()
                        .with_timezone(&Utc),
                });
            }
        }
        
        Ok(())
    }
    
    fn find_xmp_value<'a>(&self, xmp_content: &'a str, tag: &str) -> Option<String> {
        // Basic XMP parsing - in production this would use proper XML parsing
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);
        
        if let Some(start) = xmp_content.find(&start_tag) {
            if let Some(end) = xmp_content.find(&end_tag) {
                let value_start = start + start_tag.len();
                if value_start < end {
                    return Some(xmp_content[value_start..end].trim().to_string());
                }
            }
        }
        None
    }
    
    fn scan_hidden_metadata(&mut self, document: &Document) -> Result<()> {
        for (object_id, object) in &document.objects {
            if self.check_metadata_presence(object) {
                // Look for metadata in unusual locations
                match object {
                    Object::Dictionary(dict) => {
                        self.scan_dictionary_for_hidden_metadata(*object_id, dict)?;
                    },
                    Object::Stream(stream) => {
                        self.scan_stream_for_hidden_metadata(*object_id, stream)?;
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    }
    
    fn scan_dictionary_for_hidden_metadata(&mut self, object_id: ObjectId, dict: &Dictionary) -> Result<()> {
        let suspicious_keys = [
            b"Metadata",
            b"PieceInfo",
            b"PrivateData",
            b"UserProperties",
            b"CustomData",
        ];
        
        for &key in &suspicious_keys {
            if let Ok(value) = dict.get(key) {
                let field_name = String::from_utf8_lossy(key).to_string();
                let field_value = match value {
                    Object::String(s, _) => Some(String::from_utf8_lossy(s).to_string()),
                    Object::Dictionary(_) => Some("[Hidden Dictionary Data]".to_string()),
                    Object::Stream(_) => Some("[Hidden Stream Data]".to_string()),
                    _ => None,
                };
                
                self.metadata_locations.push(MetadataLocation {
                    location_type: "Hidden".to_string(),
                    object_id: Some(object_id),
                    field_name,
                    field_value,
                    is_hidden: true,
                    discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:44:57Z")
                        .unwrap()
                        .with_timezone(&Utc),
                });
            }
        }
        Ok(())
    }
    
    fn scan_stream_for_hidden_metadata(&mut self, object_id: ObjectId, stream: &Stream) -> Result<()> {
        // Check for encoded metadata in stream content
        if stream.content.len() > 50 {
            let sample = &stream.content[..50];
            if self.appears_to_be_metadata(sample) {
                self.metadata_locations.push(MetadataLocation {
                    location_type: "EncodedStream".to_string(),
                    object_id: Some(object_id),
                    field_name: "EncodedMetadata".to_string(),
                    field_value: Some("[Encoded Stream Content]".to_string()),
                    is_hidden: true,
                    discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:44:57Z")
                        .unwrap()
                        .with_timezone(&Utc),
                });
            }
        }
        Ok(())
    }
    
    fn appears_to_be_metadata(&self, sample: &[u8]) -> bool {
        // Check if sample contains common metadata markers
        let markers = [b"<?xpacket", b"<x:xmpmeta", b"<rdf:RDF", b"uuid:"];
        markers.iter().any(|marker| sample.windows(marker.len()).any(|window| window == *marker))
    }
    
    fn validate_structure_integrity(&self, document: &Document) -> Result<bool> {
        // Verify basic PDF structure components
        let has_catalog = document.get_object(document.catalog()?)
            .map_err(|e| ForensicError::structure_error(&format!("Invalid catalog: {}", e)))?;
            
        let has_pages = !document.get_pages().is_empty();
        
        let has_valid_xref = document.trailer.as_dict()
            .map(|dict| dict.has(b"Size"))
            .unwrap_or(false);
            
        Ok(has_catalog.is_dictionary() && has_pages && has_valid_xref)
    }
}

impl Default for PdfParser {
    fn default() -> Self {
        Self::new()
    }
}
