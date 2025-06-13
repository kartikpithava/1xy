use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue},
    config::Config,
};
use super::{ParsedPdfData, ExtractionData, AnalysisResult};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};
use chrono::{DateTime, Utc};

/// PDF document cloner with forensic awareness
pub struct PdfCloner {
    preserve_metadata: bool,
    retain_structure: bool,
    sanitize_content: bool,
    initialization_time: DateTime<Utc>,
    operator: String,
}

/// Complete cloning result with audit trail
#[derive(Debug)]
pub struct CloningResult {
    pub document: Document,
    pub clone_map: HashMap<ObjectId, ObjectId>,
    pub metadata_map: MetadataMap,
    pub audit_trail: Vec<CloneAuditEntry>,
    pub sanitization_log: Vec<SanitizationEntry>,
    pub clone_timestamp: DateTime<Utc>,
    pub operator: String,
}

#[derive(Debug)]
pub struct CloneAuditEntry {
    pub original_id: ObjectId,
    pub cloned_id: ObjectId,
    pub object_type: String,
    pub operation: String,
    pub success: bool,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SanitizationEntry {
    pub object_id: ObjectId,
    pub content_type: String,
    pub action_taken: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

impl PdfCloner {
    pub fn new() -> Self {
        Self {
            preserve_metadata: true,
            retain_structure: true,
            sanitize_content: true,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:54:02Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    pub fn with_options(preserve_metadata: bool, retain_structure: bool, sanitize_content: bool) -> Self {
        Self {
            preserve_metadata,
            retain_structure,
            sanitize_content,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:54:02Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    /// Create a forensically sound clone of the PDF document
    pub fn clone_document(
        &self,
        parsed_data: &ParsedPdfData,
        extraction_data: &ExtractionData,
        analysis_result: &AnalysisResult
    ) -> Result<CloningResult> {
        let mut new_document = Document::with_version(parsed_data.version.as_string());
        let mut clone_map = HashMap::new();
        let mut audit_trail = Vec::new();
        let mut sanitization_log = Vec::new();
        
        // Clone critical structures first
        self.clone_critical_objects(
            parsed_data,
            &mut new_document,
            &mut clone_map,
            &mut audit_trail,
        )?;
        
        // Clone remaining objects
        self.clone_remaining_objects(
            parsed_data,
            &mut new_document,
            &mut clone_map,
            &mut audit_trail,
            &mut sanitization_log,
            analysis_result,
        )?;
        
        // Update references
        self.update_object_references(&mut new_document, &clone_map, &mut audit_trail)?;
        
        // Handle metadata
        let metadata_map = if self.preserve_metadata {
            self.clone_metadata(parsed_data, &mut new_document, &clone_map)?
        } else {
            self.create_minimal_metadata()?
        };
        
        Ok(CloningResult {
            document: new_document,
            clone_map,
            metadata_map,
            audit_trail,
            sanitization_log,
            clone_timestamp: self.initialization_time,
            operator: self.operator.clone(),
        })
    }

    fn clone_critical_objects(
        &self,
        parsed_data: &ParsedPdfData,
        new_document: &mut Document,
        clone_map: &mut HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
    ) -> Result<()> {
        // Clone catalog
        let catalog_id = parsed_data.document.catalog()?;
        self.clone_object_with_audit(
            catalog_id,
            &parsed_data.document,
            new_document,
            clone_map,
            audit_trail,
            "Catalog",
        )?;
        
        // Clone page tree
        let pages_id = self.find_pages_root(&parsed_data.document, catalog_id)?;
        self.clone_page_tree(
            pages_id,
            &parsed_data.document,
            new_document,
            clone_map,
            audit_trail,
        )?;
        
        Ok(())
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
    
    fn clone_page_tree(
        &self,
        pages_id: ObjectId,
        original_doc: &Document,
        new_document: &mut Document,
        clone_map: &mut HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
    ) -> Result<()> {
        let mut page_queue = vec![pages_id];
        let mut processed = HashSet::new();
        
        while let Some(current_id) = page_queue.pop() {
            if processed.contains(&current_id) {
                continue;
            }
            
            if let Ok(page_obj) = original_doc.get_object(current_id) {
                if let Ok(page_dict) = page_obj.as_dict() {
                    // Clone the current node
                    self.clone_object_with_audit(
                        current_id,
                        original_doc,
                        new_document,
                        clone_map,
                        audit_trail,
                        "PageTree",
                    )?;
                    
                    // Process children
                    if let Ok(kids) = page_dict.get(b"Kids") {
                        if let Ok(kids_array) = kids.as_array() {
                            for kid in kids_array {
                                if let Ok(kid_id) = kid.as_reference() {
                                    page_queue.push(kid_id);
                                }
                            }
                        }
                    }
                    
                    processed.insert(current_id);
                }
            }
        }
        
        Ok(())
    }
    
    fn clone_remaining_objects(
        &self,
        parsed_data: &ParsedPdfData,
        new_document: &mut Document,
        clone_map: &mut HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
        sanitization_log: &mut Vec<SanitizationEntry>,
        analysis_result: &AnalysisResult,
    ) -> Result<()> {
        for (object_id, object) in &parsed_data.document.objects {
            if !clone_map.contains_key(object_id) {
                let object_type = self.determine_object_type(object);
                
                if self.should_sanitize_object(*object_id, &object_type, analysis_result) {
                    let sanitized_object = self.sanitize_object(
                        *object_id,
                        object,
                        sanitization_log,
                    )?;
                    
                    self.clone_sanitized_object(
                        *object_id,
                        &sanitized_object,
                        new_document,
                        clone_map,
                        audit_trail,
                        &object_type,
                    )?;
                } else {
                    self.clone_object_with_audit(
                        *object_id,
                        &parsed_data.document,
                        new_document,
                        clone_map,
                        audit_trail,
                        &object_type,
                    )?;
                }
            }
        }
        
        Ok(())
    }
    
    fn should_sanitize_object(
        &self,
        object_id: ObjectId,
        object_type: &str,
        analysis_result: &AnalysisResult,
    ) -> bool {
        if !self.sanitize_content {
            return false;
        }
        
        // Check if object is in hidden content list
        let is_hidden = analysis_result.hidden_content.iter()
            .any(|item| item.object_id == object_id);
            
        // Check if object is flagged by forensic indicators
        let is_suspicious = analysis_result.forensic_indicators.iter()
            .any(|indicator| indicator.location == Some(object_id));
            
        // Check for specific object types that need sanitization
        let risky_types = ["JavaScript", "Action", "Launch", "SubmitForm", "ImportData"];
        let is_risky_type = risky_types.contains(&object_type);
        
        is_hidden || is_suspicious || is_risky_type
    }
    
    fn sanitize_object(
        &self,
        object_id: ObjectId,
        object: &Object,
        sanitization_log: &mut Vec<SanitizationEntry>,
    ) -> Result<Object> {
        let current_time = DateTime::parse_from_rfc3339("2025-06-13T16:54:56Z")
            .unwrap()
            .with_timezone(&Utc);
            
        match object {
            Object::Dictionary(dict) => {
                let mut sanitized_dict = Dictionary::new();
                let risky_keys = [b"JavaScript", b"JS", b"Launch", b"SubmitForm", b"ImportData"];
                
                for (key, value) in dict.iter() {
                    if !risky_keys.contains(&key) {
                        sanitized_dict.set(key.clone(), value.clone());
                    } else {
                        sanitization_log.push(SanitizationEntry {
                            object_id,
                            content_type: "Dictionary".to_string(),
                            action_taken: "Removed risky key".to_string(),
                            reason: format!("Potentially unsafe key: {}", String::from_utf8_lossy(key)),
                            timestamp: current_time,
                        });
                    }
                }
                
                Ok(Object::Dictionary(sanitized_dict))
            },
            Object::Stream(stream) => {
                let mut sanitized_stream = stream.clone();
                if self.appears_suspicious(&stream.content) {
                    sanitized_stream.content = Vec::new();
                    sanitization_log.push(SanitizationEntry {
                        object_id,
                        content_type: "Stream".to_string(),
                        action_taken: "Cleared suspicious stream content".to_string(),
                        reason: "High entropy or encryption markers detected".to_string(),
                        timestamp: current_time,
                    });
                }
                Ok(Object::Stream(sanitized_stream))
            },
            _ => Ok(object.clone()),
        }
    }
    
    fn appears_suspicious(&self, content: &[u8]) -> bool {
        // Calculate Shannon entropy
        let entropy = self.calculate_entropy(content);
        
        // Check for suspicious patterns
        let suspicious_patterns = [
            b"eval", b"exec", b"system", b"shell",
            b"JavaScript", b"JS", b"script",
        ];
        
        entropy > 7.5 || content.windows(4).any(|window| {
            suspicious_patterns.iter().any(|pattern| window.starts_with(pattern))
        })
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
    fn clone_sanitized_object(
        &self,
        original_id: ObjectId,
        sanitized_object: &Object,
        new_document: &mut Document,
        clone_map: &mut HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
        object_type: &str,
    ) -> Result<()> {
        let new_id = new_document.add_object(sanitized_object.clone());
        clone_map.insert(original_id, new_id);
        
        audit_trail.push(CloneAuditEntry {
            original_id,
            cloned_id: new_id,
            object_type: object_type.to_string(),
            operation: "Clone with sanitization".to_string(),
            success: true,
            error_message: None,
            timestamp: DateTime::parse_from_rfc3339("2025-06-13T16:56:14Z")
                .unwrap()
                .with_timezone(&Utc),
        });
        
        Ok(())
    }
    
    fn clone_object_with_audit(
        &self,
        object_id: ObjectId,
        original_doc: &Document,
        new_document: &mut Document,
        clone_map: &mut HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
        object_type: &str,
    ) -> Result<()> {
        if let Ok(object) = original_doc.get_object(object_id) {
            let new_id = new_document.add_object(object.clone());
            clone_map.insert(object_id, new_id);
            
            audit_trail.push(CloneAuditEntry {
                original_id: object_id,
                cloned_id: new_id,
                object_type: object_type.to_string(),
                operation: "Direct clone".to_string(),
                success: true,
                error_message: None,
                timestamp: DateTime::parse_from_rfc3339("2025-06-13T16:56:14Z")
                    .unwrap()
                    .with_timezone(&Utc),
            });
            
            Ok(())
        } else {
            audit_trail.push(CloneAuditEntry {
                original_id: object_id,
                cloned_id: ObjectId(0, 0),
                object_type: object_type.to_string(),
                operation: "Direct clone".to_string(),
                success: false,
                error_message: Some("Object not found in original document".to_string()),
                timestamp: DateTime::parse_from_rfc3339("2025-06-13T16:56:14Z")
                    .unwrap()
                    .with_timezone(&Utc),
            });
            
            Err(ForensicError::clone_error(&format!("Failed to clone object {}", object_id)))
        }
    }
    
    fn update_object_references(
        &self,
        new_document: &mut Document,
        clone_map: &HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
    ) -> Result<()> {
        let objects_to_update: Vec<ObjectId> = new_document.objects.keys().cloned().collect();
        
        for object_id in objects_to_update {
            if let Some(object) = new_document.objects.get_mut(&object_id) {
                self.update_references_recursive(object, clone_map, audit_trail)?;
            }
        }
        
        Ok(())
    }
    
    fn update_references_recursive(
        &self,
        object: &mut Object,
        clone_map: &HashMap<ObjectId, ObjectId>,
        audit_trail: &mut Vec<CloneAuditEntry>,
    ) -> Result<()> {
        match object {
            Object::Reference(ref mut id) => {
                if let Some(&new_id) = clone_map.get(id) {
                    *id = new_id;
                } else {
                    audit_trail.push(CloneAuditEntry {
                        original_id: *id,
                        cloned_id: ObjectId(0, 0),
                        object_type: "Reference".to_string(),
                        operation: "Update reference".to_string(),
                        success: false,
                        error_message: Some("Referenced object not found in clone map".to_string()),
                        timestamp: DateTime::parse_from_rfc3339("2025-06-13T16:56:14Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    });
                }
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter_mut() {
                    self.update_references_recursive(value, clone_map, audit_trail)?;
                }
            },
            Object::Array(array) => {
                for item in array.iter_mut() {
                    self.update_references_recursive(item, clone_map, audit_trail)?;
                }
            },
            Object::Stream(stream) => {
                let mut dict = stream.dict.clone();
                for (_, value) in dict.iter_mut() {
                    self.update_references_recursive(value, clone_map, audit_trail)?;
                }
                stream.dict = dict;
            },
            _ => {},
        }
        
        Ok(())
    }
    
    fn clone_metadata(
        &self,
        parsed_data: &ParsedPdfData,
        new_document: &mut Document,
        clone_map: &HashMap<ObjectId, ObjectId>,
    ) -> Result<MetadataMap> {
        let mut metadata_map = HashMap::new();
        
        for location in &parsed_data.metadata_locations {
            let field = self.parse_metadata_field(&location.field_name)?;
            let cloned_location = self.map_metadata_location(location.object_id, clone_map);
            
            let metadata_value = MetadataValue {
                field: field.clone(),
                value: location.field_value.clone(),
                locations: vec![cloned_location],
                is_synchronized: true,
            };
            
            if let Some(existing) = metadata_map.get_mut(&field) {
                existing.locations.push(cloned_location);
            } else {
                metadata_map.insert(field, metadata_value);
            }
        }
        
        Ok(metadata_map)
    }
    
    fn create_minimal_metadata(&self) -> Result<MetadataMap> {
        let mut metadata_map = HashMap::new();
        let current_time = DateTime::parse_from_rfc3339("2025-06-13T16:56:14Z")
            .unwrap()
            .with_timezone(&Utc);
            
        let creation_date = MetadataValue {
            field: MetadataField::CreationDate,
            value: Some(current_time.to_rfc3339()),
            locations: vec![MetadataLocation::DocInfo],
            is_synchronized: true,
        };
        
        metadata_map.insert(MetadataField::CreationDate, creation_date);
        Ok(metadata_map)
    }
    
    fn parse_metadata_field(&self, field_name: &str) -> Result<MetadataField> {
        Ok(match field_name {
            "Title" => MetadataField::Title,
            "Author" => MetadataField::Author,
            "Subject" => MetadataField::Subject,
            "Keywords" => MetadataField::Keywords,
            "Creator" => MetadataField::Creator,
            "Producer" => MetadataField::Producer,
            "CreationDate" => MetadataField::CreationDate,
            "ModDate" => MetadataField::ModificationDate,
            "Trapped" => MetadataField::Trapped,
            custom => MetadataField::Custom(custom.to_string()),
        })
    }
    
    fn map_metadata_location(
        &self,
        original_id: Option<ObjectId>,
        clone_map: &HashMap<ObjectId, ObjectId>,
    ) -> MetadataLocation {
        if let Some(id) = original_id {
            if let Some(&new_id) = clone_map.get(&id) {
                MetadataLocation::ObjectStream(new_id.0 as u32)
            } else {
                MetadataLocation::DocInfo
            }
        } else {
            MetadataLocation::DocInfo
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
}

impl Default for PdfCloner {
    fn default() -> Self {
        Self::new()
    }
}
