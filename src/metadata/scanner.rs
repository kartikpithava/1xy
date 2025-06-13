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
