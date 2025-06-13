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
}

impl Default for MetadataEditor {
    fn default() -> Self {
        Self::new()
    }
      }
