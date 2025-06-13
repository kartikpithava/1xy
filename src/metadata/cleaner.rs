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
