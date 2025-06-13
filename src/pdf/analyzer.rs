use crate::{
    errors::{ForensicError, Result},
    config::{Config, ForensicConfig},
    types::{MetadataField, MetadataLocation},
};
use super::{ParsedPdfData, ExtractionData};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::{HashMap, HashSet, VecDeque};
use chrono::{DateTime, Utc};

/// PDF structure analyzer for forensic examination
pub struct PdfAnalyzer {
    max_depth: u8,
    check_security: bool,
    analyze_relationships: bool,
    initialization_time: DateTime<Utc>,
    operator: String,
}

/// Complete analysis result with timestamps
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub object_relationships: HashMap<ObjectId, ObjectRelationship>,
    pub metadata_analysis: MetadataAnalysis,
    pub security_analysis: SecurityAnalysis,
    pub structure_integrity: StructureIntegrity,
    pub hidden_content: Vec<HiddenContentItem>,
    pub forensic_indicators: Vec<ForensicIndicator>,
    pub analysis_timestamp: DateTime<Utc>,
    pub operator: String,
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
    pub analysis_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MetadataAnalysis {
    pub total_metadata_locations: usize,
    pub synchronized_fields: usize,
    pub unsynchronized_fields: Vec<String>,
    pub hidden_metadata_count: usize,
    pub modification_traces: Vec<String>,
    pub analysis_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub is_encrypted: bool,
    pub encryption_strength: String,
    pub has_digital_signatures: bool,
    pub security_handlers: Vec<String>,
    pub permissions_analysis: PermissionsAnalysis,
    pub analysis_time: DateTime<Utc>,
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
    pub verification_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HiddenContentItem {
    pub object_id: ObjectId,
    pub content_type: String,
    pub location: String,
    pub estimated_size: usize,
    pub is_suspicious: bool,
    pub discovery_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ForensicIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: String,
    pub location: Option<ObjectId>,
    pub evidence: String,
    pub detection_time: DateTime<Utc>,
}

impl PdfAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: ForensicConfig::MAX_OBJECT_DEPTH,
            check_security: true,
            analyze_relationships: true,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:49:11Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    pub fn with_options(max_depth: u8, check_security: bool, analyze_relationships: bool) -> Self {
        Self {
            max_depth,
            check_security,
            analyze_relationships,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:49:11Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
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
            analysis_timestamp: self.initialization_time,
            operator: self.operator.clone(),
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
                analysis_time: DateTime::parse_from_rfc3339("2025-06-13T16:50:12Z")
                    .unwrap()
                    .with_timezone(&Utc),
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
        if let Ok(catalog_id) = document.catalog() {
            let mut queue = VecDeque::new();
            let mut visited = HashSet::new();
            
            queue.push_back((catalog_id, 0u8));
            visited.insert(catalog_id);
            
            while let Some((current_id, depth)) = queue.pop_front() {
                if let Some(relationship) = relationships.get_mut(&current_id) {
                    relationship.depth_level = depth;
                    
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
                let first_value = &locations[0].field_value;
                let is_synchronized = locations.iter().all(|loc| &loc.field_value == first_value);
                
                if is_synchronized {
                    synchronized_fields += 1;
                } else {
                    unsynchronized_fields.push(field_name.clone());
                }
            } else {
                synchronized_fields += 1;
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
            analysis_time: DateTime::parse_from_rfc3339("2025-06-13T16:50:55Z")
                .unwrap()
                .with_timezone(&Utc),
        })
    }
    
    fn detect_modification_traces(&self, parsed_data: &ParsedPdfData) -> Vec<String> {
        let mut traces = Vec::new();
        
        // Check for ModDate presence
        for location in &parsed_data.metadata_locations {
            if location.field_name == "ModDate" {
                traces.push("Modification date present".to_string());
                break;
            }
        }
        
        // Check for suspicious producers
        for location in &parsed_data.metadata_locations {
            if location.field_name == "Producer" {
                if let Some(ref producer) = location.field_value {
                    let suspicious_producers = [
                        "ghostscript", "itext", "reportlab", "tcpdf",
                        "pdfforge", "pdf-tools", "pdfedit", "pdfbox"
                    ];
                    for &suspicious in &suspicious_producers {
                        if producer.to_lowercase().contains(suspicious) {
                            traces.push(format!("Suspicious producer detected: {}", producer));
                        }
                    }
                }
            }
        }
        
        // Check for inconsistent creation dates
        let mut creation_dates = HashSet::new();
        for location in &parsed_data.metadata_locations {
            if location.field_name == "CreationDate" {
                if let Some(ref date) = location.field_value {
                    creation_dates.insert(date.clone());
                }
            }
        }
        if creation_dates.len() > 1 {
            traces.push("Inconsistent creation dates detected".to_string());
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
            analysis_time: DateTime::parse_from_rfc3339("2025-06-13T16:50:55Z")
                .unwrap()
                .with_timezone(&Utc),
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
        
        let mut missing_objects = Vec::new();
        let mut corrupted_objects = Vec::new();
        
        // Check cross-reference table integrity
        for (object_id, _) in &document.objects {
            if let Err(_) = document.get_object(*object_id) {
                missing_objects.push(*object_id);
            } else if self.is_object_corrupted(document, *object_id) {
                corrupted_objects.push(*object_id);
            }
        }
        
        let cross_ref_integrity = missing_objects.is_empty();
        let trailer_integrity = document.trailer.as_dict().is_ok();
        let object_count = document.objects.len();
        
        Ok(StructureIntegrity {
            has_valid_catalog,
            has_valid_pages,
            cross_ref_integrity,
            trailer_integrity,
            object_count,
            missing_objects,
            corrupted_objects,
            verification_time: DateTime::parse_from_rfc3339("2025-06-13T16:52:58Z")
                .unwrap()
                .with_timezone(&Utc),
        })
    }
    
    fn is_object_corrupted(&self, document: &Document, object_id: ObjectId) -> bool {
        if let Ok(object) = document.get_object(object_id) {
            match object {
                Object::Dictionary(dict) => {
                    // Check dictionary integrity
                    for (_, value) in dict.iter() {
                        if let Object::Reference(ref_id) = value {
                            if document.get_object(*ref_id).is_err() {
                                return true;
                            }
                        }
                    }
                },
                Object::Stream(stream) => {
                    // Check stream integrity
                    if stream.content.is_empty() && !self.is_empty_stream_valid(&stream) {
                        return true;
                    }
                },
                _ => {}
            }
        }
        false
    }
    
    fn is_empty_stream_valid(&self, stream: &Stream) -> bool {
        if let Ok(dict) = stream.dict.as_dict() {
            // Some streams are legitimately empty (like metadata placeholders)
            if let Ok(type_obj) = dict.get(b"Type") {
                if let Ok(type_name) = type_obj.as_name_str() {
                    return matches!(type_name, "Metadata" | "ObjStm" | "XRef");
                }
            }
        }
        false
    }
    
    fn discover_hidden_content(&self, document: &Document) -> Result<Vec<HiddenContentItem>> {
        let mut hidden_items = Vec::new();
        
        for (object_id, object) in &document.objects {
            if let Some(hidden_item) = self.analyze_object_for_hidden_content(*object_id, object) {
                hidden_items.push(hidden_item);
            }
        }
        
        Ok(hidden_items)
    }
    
    fn analyze_object_for_hidden_content(&self, object_id: ObjectId, object: &Object) -> Option<HiddenContentItem> {
        match object {
            Object::Stream(stream) => {
                if self.appears_suspicious(&stream.content) {
                    Some(HiddenContentItem {
                        object_id,
                        content_type: "Stream".to_string(),
                        location: "Object Stream".to_string(),
                        estimated_size: stream.content.len(),
                        is_suspicious: true,
                        discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:52:58Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    })
                } else {
                    None
                }
            },
            Object::Dictionary(dict) => {
                if self.has_suspicious_keys(dict) {
                    Some(HiddenContentItem {
                        object_id,
                        content_type: "Dictionary".to_string(),
                        location: "Object Dictionary".to_string(),
                        estimated_size: dict.len() * 16,
                        is_suspicious: true,
                        discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:52:58Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    })
                } else {
                    None
                }
            },
            _ => None,
        }
    }
    
    fn appears_suspicious(&self, content: &[u8]) -> bool {
        // Calculate Shannon entropy
        let entropy = self.calculate_entropy(content);
        
        // Check for encrypted or compressed characteristics
        entropy > 7.5 || self.has_encryption_markers(content)
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
    
    fn has_encryption_markers(&self, content: &[u8]) -> bool {
        let markers = [
            b"Encrypt", b"Crypt", b"algorithm", 
            b"RSA", b"RC4", b"AES", b"Filter"
        ];
        
        content.windows(7).any(|window| {
            markers.iter().any(|marker| window.starts_with(marker))
        })
    }
    
    fn has_suspicious_keys(&self, dict: &Dictionary) -> bool {
        let suspicious_keys = [
            b"EmbeddedFiles", b"JavaScript", b"Launch",
            b"SubmitForm", b"ImportData", b"RichMedia"
        ];
        
        suspicious_keys.iter().any(|&key| dict.has(key))
    }
    
    fn detect_forensic_indicators(&self, parsed_data: &ParsedPdfData) -> Result<Vec<ForensicIndicator>> {
        let mut indicators = Vec::new();
        let current_time = DateTime::parse_from_rfc3339("2025-06-13T16:52:58Z")
            .unwrap()
            .with_timezone(&Utc);

        // Check for modification traces
        if let Some(mod_date) = self.find_modification_date(parsed_data) {
            indicators.push(ForensicIndicator {
                indicator_type: "Modification".to_string(),
                description: "Document has been modified".to_string(),
                severity: "Medium".to_string(),
                location: None,
                evidence: format!("Modification date: {}", mod_date),
                detection_time: current_time,
            });
        }

        // Check for suspicious producers
        if let Some((producer, object_id)) = self.find_suspicious_producer(parsed_data) {
            indicators.push(ForensicIndicator {
                indicator_type: "SuspiciousProducer".to_string(),
                description: "Document created with suspicious software".to_string(),
                severity: "High".to_string(),
                location: Some(object_id),
                evidence: format!("Producer: {}", producer),
                detection_time: current_time,
            });
        }

        // Add other forensic indicators
        self.check_additional_indicators(parsed_data, &mut indicators, current_time)?;

        Ok(indicators)
    }

    fn find_modification_date(&self, parsed_data: &ParsedPdfData) -> Option<String> {
        parsed_data.metadata_locations.iter()
            .find(|loc| loc.field_name == "ModDate")
            .and_then(|loc| loc.field_value.clone())
    }

    fn find_suspicious_producer(&self, parsed_data: &ParsedPdfData) -> Option<(String, ObjectId)> {
        for location in &parsed_data.metadata_locations {
            if location.field_name == "Producer" {
                if let Some(ref producer) = location.field_value {
                    let suspicious = ["ghostscript", "itext", "pdftk", "pdfforge"];
                    if suspicious.iter().any(|s| producer.to_lowercase().contains(s)) {
                        return Some((producer.clone(), location.object_id?));
                    }
                }
            }
        }
        None
    }

    fn check_additional_indicators(
        &self,
        parsed_data: &ParsedPdfData,
        indicators: &mut Vec<ForensicIndicator>,
        current_time: DateTime<Utc>
    ) -> Result<()> {
        // Check for JavaScript presence
        self.check_javascript_presence(parsed_data, indicators, current_time)?;
        
        // Check for encryption inconsistencies
        self.check_encryption_indicators(parsed_data, indicators, current_time)?;
        
        // Check for structural anomalies
        self.check_structural_indicators(parsed_data, indicators, current_time)?;
        
        Ok(())
    }

    fn check_javascript_presence(
        &self,
        parsed_data: &ParsedPdfData,
        indicators: &mut Vec<ForensicIndicator>,
        current_time: DateTime<Utc>
    ) -> Result<()> {
        for (object_id, object) in &parsed_data.document.objects {
            if let Object::Dictionary(dict) = object {
                if dict.has(b"JS") || dict.has(b"JavaScript") {
                    indicators.push(ForensicIndicator {
                        indicator_type: "JavaScript".to_string(),
                        description: "Document contains JavaScript code".to_string(),
                        severity: "High".to_string(),
                        location: Some(*object_id),
                        evidence: "JavaScript dictionary keys present".to_string(),
                        detection_time: current_time,
                    });
                }
            }
        }
        Ok(())
    }

    fn check_encryption_indicators(
        &self,
        parsed_data: &ParsedPdfData,
        indicators: &mut Vec<ForensicIndicator>,
        current_time: DateTime<Utc>
    ) -> Result<()> {
        if let Some(ref encryption_info) = parsed_data.encryption_info {
            if encryption_info.key_length < 128 {
                indicators.push(ForensicIndicator {
                    indicator_type: "WeakEncryption".to_string(),
                    description: "Document uses weak encryption".to_string(),
                    severity: "High".to_string(),
                    location: None,
                    evidence: format!("{}-bit encryption detected", encryption_info.key_length),
                    detection_time: current_time,
                });
            }
        }
        Ok(())
    }

    fn check_structural_indicators(
        &self,
        parsed_data: &ParsedPdfData,
        indicators: &mut Vec<ForensicIndicator>,
        current_time: DateTime<Utc>
    ) -> Result<()> {
        // Check for unusual object counts
        if parsed_data.document.objects.len() > 1000 {
            indicators.push(ForensicIndicator {
                indicator_type: "HighObjectCount".to_string(),
                description: "Unusually high number of objects".to_string(),
                severity: "Medium".to_string(),
                location: None,
                evidence: format!("{} objects found", parsed_data.document.objects.len()),
                detection_time: current_time,
            });
        }

        Ok(())
    }
}

impl Default for PdfAnalyzer {
    fn default() -> Self {
        Self::new()
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
            analysis_time: DateTime::parse_from_rfc3339("2025-06-13T16:52:58Z")
                .unwrap()
                .with_timezone(&Utc),
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
