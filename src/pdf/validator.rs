use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, ValidationRule, ValidationResult},
    config::Config,
};
use super::{ParsedPdfData, ExtractionData, AnalysisResult, CloningResult};
use lopdf::{Document, Object, ObjectId, Dictionary};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

/// PDF document validator for forensic analysis
pub struct PdfValidator {
    strict_mode: bool,
    max_object_size: usize,
    max_stream_size: usize,
    allowed_versions: HashSet<String>,
    initialization_time: DateTime<Utc>,
    operator: String,
}

/// Complete validation result with detailed findings
#[derive(Debug)]
pub struct ValidationReport {
    pub overall_status: bool,
    pub structure_validation: StructureValidation,
    pub content_validation: ContentValidation,
    pub metadata_validation: MetadataValidation,
    pub security_validation: SecurityValidation,
    pub forensic_validation: ForensicValidation,
    pub validation_timestamp: DateTime<Utc>,
    pub operator: String,
}

#[derive(Debug)]
pub struct StructureValidation {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub validation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ContentValidation {
    pub is_valid: bool,
    pub content_issues: Vec<ContentIssue>,
    pub size_violations: Vec<SizeViolation>,
    pub validation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct MetadataValidation {
    pub is_valid: bool,
    pub inconsistencies: Vec<MetadataInconsistency>,
    pub missing_required: Vec<String>,
    pub validation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SecurityValidation {
    pub is_valid: bool,
    pub security_issues: Vec<SecurityIssue>,
    pub permissions_status: PermissionsStatus,
    pub validation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ForensicValidation {
    pub is_valid: bool,
    pub forensic_issues: Vec<ForensicIssue>,
    pub compliance_status: ComplianceStatus,
    pub validation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ValidationError {
    pub error_type: String,
    pub description: String,
    pub location: Option<ObjectId>,
    pub severity: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ValidationWarning {
    pub warning_type: String,
    pub description: String,
    pub location: Option<ObjectId>,
    pub impact: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ContentIssue {
    pub issue_type: String,
    pub description: String,
    pub object_id: ObjectId,
    pub content_type: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SizeViolation {
    pub object_id: ObjectId,
    pub object_type: String,
    pub actual_size: usize,
    pub max_allowed: usize,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct MetadataInconsistency {
    pub field: String,
    pub description: String,
    pub locations: Vec<ObjectId>,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SecurityIssue {
    pub issue_type: String,
    pub description: String,
    pub risk_level: String,
    pub recommendation: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct PermissionsStatus {
    pub is_compliant: bool,
    pub violations: Vec<String>,
    pub check_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ForensicIssue {
    pub issue_type: String,
    pub description: String,
    pub evidence: String,
    pub severity: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ComplianceStatus {
    pub is_compliant: bool,
    pub violations: Vec<String>,
    pub check_time: DateTime<Utc>,
}

impl PdfValidator {
    pub fn new() -> Self {
        let mut allowed_versions = HashSet::new();
        allowed_versions.insert("1.7".to_string());
        allowed_versions.insert("2.0".to_string());
        
        Self {
            strict_mode: true,
            max_object_size: 10 * 1024 * 1024, // 10MB
            max_stream_size: 50 * 1024 * 1024, // 50MB
            allowed_versions,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T17:04:45Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }

    pub fn with_options(
        strict_mode: bool,
        max_object_size: usize,
        max_stream_size: usize,
        allowed_versions: HashSet<String>,
    ) -> Self {
        Self {
            strict_mode,
            max_object_size,
            max_stream_size,
            allowed_versions,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T17:06:31Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    /// Validate PDF document with all available data
    pub fn validate_document(
        &self,
        parsed_data: &ParsedPdfData,
        extraction_data: &ExtractionData,
        analysis_result: &AnalysisResult,
        cloning_result: Option<&CloningResult>,
    ) -> Result<ValidationReport> {
        let structure_validation = self.validate_structure(parsed_data)?;
        let content_validation = self.validate_content(parsed_data, extraction_data)?;
        let metadata_validation = self.validate_metadata(parsed_data, analysis_result)?;
        let security_validation = self.validate_security(parsed_data, analysis_result)?;
        let forensic_validation = self.validate_forensics(parsed_data, analysis_result, cloning_result)?;
        
        let overall_status = structure_validation.is_valid
            && content_validation.is_valid
            && metadata_validation.is_valid
            && security_validation.is_valid
            && forensic_validation.is_valid;
            
        Ok(ValidationReport {
            overall_status,
            structure_validation,
            content_validation,
            metadata_validation,
            security_validation,
            forensic_validation,
            validation_timestamp: self.initialization_time,
            operator: self.operator.clone(),
        })
    }
    
    fn validate_structure(&self, parsed_data: &ParsedPdfData) -> Result<StructureValidation> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Validate PDF version
        if !self.allowed_versions.contains(&parsed_data.version.as_string()) {
            warnings.push(ValidationWarning {
                warning_type: "Version".to_string(),
                description: format!("Unsupported PDF version: {}", parsed_data.version.as_string()),
                location: None,
                impact: "Potential compatibility issues".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        // Validate document structure
        self.validate_catalog(&parsed_data.document, &mut errors, &mut warnings)?;
        self.validate_page_tree(&parsed_data.document, &mut errors, &mut warnings)?;
        self.validate_cross_references(&parsed_data.document, &mut errors, &mut warnings)?;
        
        let is_valid = errors.is_empty() || !self.strict_mode;
        
        Ok(StructureValidation {
            is_valid,
            errors,
            warnings,
            validation_time: self.initialization_time,
        })
    }
    
    fn validate_catalog(
        &self,
        document: &Document,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(catalog_id) = document.catalog() {
            if let Ok(catalog) = document.get_object(catalog_id) {
                if let Ok(catalog_dict) = catalog.as_dict() {
                    // Check required catalog entries
                    let required_keys = [b"Type", b"Pages"];
                    for &key in &required_keys {
                        if !catalog_dict.has(key) {
                            errors.push(ValidationError {
                                error_type: "CatalogStructure".to_string(),
                                description: format!("Missing required catalog entry: {}", String::from_utf8_lossy(key)),
                                location: Some(catalog_id),
                                severity: "Critical".to_string(),
                                detection_time: self.initialization_time,
                            });
                        }
                    }
                    
                    // Validate optional entries if present
                    self.validate_optional_catalog_entries(catalog_dict, catalog_id, warnings)?;
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "CatalogMissing".to_string(),
                description: "Document catalog not found".to_string(),
                location: None,
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn validate_optional_catalog_entries(
        &self,
        catalog_dict: &Dictionary,
        catalog_id: ObjectId,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Check for deprecated entries
        let deprecated_keys = [b"PageMode", b"PageLayout"];
        for &key in &deprecated_keys {
            if catalog_dict.has(key) {
                warnings.push(ValidationWarning {
                    warning_type: "DeprecatedEntry".to_string(),
                    description: format!("Deprecated catalog entry: {}", String::from_utf8_lossy(key)),
                    location: Some(catalog_id),
                    impact: "Future compatibility concerns".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }
        
        // Validate metadata if present
        if let Ok(metadata) = catalog_dict.get(b"Metadata") {
            self.validate_metadata_stream(metadata, catalog_id, warnings)?;
        }
        
        Ok(())
    }
    fn validate_page_tree(
        &self,
        document: &Document,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(catalog_id) = document.catalog() {
            if let Ok(catalog) = document.get_object(catalog_id) {
                if let Ok(catalog_dict) = catalog.as_dict() {
                    if let Ok(pages_ref) = catalog_dict.get(b"Pages") {
                        if let Ok(pages_id) = pages_ref.as_reference() {
                            self.validate_page_node(document, pages_id, errors, warnings, 0)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    fn validate_page_node(
        &self,
        document: &Document,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
        depth: u32,
    ) -> Result<()> {
        const MAX_PAGE_TREE_DEPTH: u32 = 32;
        
        if depth > MAX_PAGE_TREE_DEPTH {
            errors.push(ValidationError {
                error_type: "PageTreeDepth".to_string(),
                description: "Page tree exceeds maximum allowed depth".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
            return Ok(());
        }
        
        if let Ok(node) = document.get_object(node_id) {
            if let Ok(node_dict) = node.as_dict() {
                // Validate node type
                match node_dict.get(b"Type").and_then(|t| t.as_name_str()) {
                    Ok("Pages") => {
                        // Validate intermediate node
                        self.validate_pages_node(document, node_dict, node_id, errors, warnings, depth)?;
                    },
                    Ok("Page") => {
                        // Validate leaf node
                        self.validate_page_node_content(node_dict, node_id, errors, warnings)?;
                    },
                    _ => {
                        errors.push(ValidationError {
                            error_type: "InvalidPageNode".to_string(),
                            description: "Invalid page tree node type".to_string(),
                            location: Some(node_id),
                            severity: "Critical".to_string(),
                            detection_time: self.initialization_time,
                        });
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn validate_pages_node(
        &self,
        document: &Document,
        node_dict: &Dictionary,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
        depth: u32,
    ) -> Result<()> {
        // Validate Kids array
        if let Ok(kids) = node_dict.get(b"Kids") {
            if let Ok(kids_array) = kids.as_array() {
                if kids_array.is_empty() {
                    warnings.push(ValidationWarning {
                        warning_type: "EmptyPageNode".to_string(),
                        description: "Pages node contains no children".to_string(),
                        location: Some(node_id),
                        impact: "Document structure inefficiency".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
                
                // Recursively validate child nodes
                for kid in kids_array {
                    if let Ok(kid_id) = kid.as_reference() {
                        self.validate_page_node(document, kid_id, errors, warnings, depth + 1)?;
                    } else {
                        errors.push(ValidationError {
                            error_type: "InvalidKidReference".to_string(),
                            description: "Invalid child reference in Pages node".to_string(),
                            location: Some(node_id),
                            severity: "Critical".to_string(),
                            detection_time: self.initialization_time,
                        });
                    }
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "MissingKids".to_string(),
                description: "Pages node missing Kids array".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn validate_page_node_content(
        &self,
        node_dict: &Dictionary,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Check required entries
        let required_keys = [b"Type", b"MediaBox"];
        for &key in &required_keys {
            if !node_dict.has(key) {
                errors.push(ValidationError {
                    error_type: "MissingPageEntry".to_string(),
                    description: format!("Page missing required entry: {}", String::from_utf8_lossy(key)),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }
        
        // Validate MediaBox if present
        if let Ok(media_box) = node_dict.get(b"MediaBox") {
            self.validate_rectangle(media_box, node_id, "MediaBox", errors)?;
        }
        
        // Validate Resources if present
        if let Ok(resources) = node_dict.get(b"Resources") {
            self.validate_resources(resources, node_id, errors, warnings)?;
        }
        
        Ok(())
    }

    fn validate_rectangle(
        &self,
        rect_obj: &Object,
        node_id: ObjectId,
        rect_type: &str,
        errors: &mut Vec<ValidationError>,
    ) -> Result<()> {
        if let Ok(rect_array) = rect_obj.as_array() {
            if rect_array.len() != 4 {
                errors.push(ValidationError {
                    error_type: "InvalidRectangle".to_string(),
                    description: format!("{} must have exactly 4 coordinates", rect_type),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
                return Ok(());
            }
            
            // Validate that all elements are numbers
            for (i, coord) in rect_array.iter().enumerate() {
                if !matches!(coord, Object::Integer(_) | Object::Real(_)) {
                    errors.push(ValidationError {
                        error_type: "InvalidCoordinate".to_string(),
                        description: format!("{} coordinate {} is not a number", rect_type, i),
                        location: Some(node_id),
                        severity: "Critical".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
            
            // Validate rectangle bounds
            if let (Ok(llx), Ok(lly), Ok(urx), Ok(ury)) = (
                rect_array[0].as_f64(),
                rect_array[1].as_f64(),
                rect_array[2].as_f64(),
                rect_array[3].as_f64(),
            ) {
                if llx >= urx || lly >= ury {
                    errors.push(ValidationError {
                        error_type: "InvalidBounds".to_string(),
                        description: format!("{} has invalid bounds", rect_type),
                        location: Some(node_id),
                        severity: "Critical".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidRectangle".to_string(),
                description: format!("{} must be an array", rect_type),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn validate_resources(
        &self,
        resources: &Object,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(res_dict) = resources.as_dict() {
            // Validate Font dictionary
            if let Ok(fonts) = res_dict.get(b"Font") {
                self.validate_font_resources(fonts, node_id, errors, warnings)?;
            }
            
            // Validate XObject dictionary
            if let Ok(xobjects) = res_dict.get(b"XObject") {
                self.validate_xobject_resources(xobjects, node_id, errors, warnings)?;
            }
            
            // Validate other resource dictionaries
            let resource_types = [
                (b"ColorSpace", "ColorSpace"),
                (b"Pattern", "Pattern"),
                (b"Shading", "Shading"),
                (b"ExtGState", "ExtGState"),
            ];
            
            for (key, name) in &resource_types {
                if let Ok(dict) = res_dict.get(key) {
                    self.validate_resource_dictionary(dict, node_id, name, errors, warnings)?;
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidResources".to_string(),
                description: "Resources must be a dictionary".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn validate_font_resources(
        &self,
        fonts: &Object,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(font_dict) = fonts.as_dict() {
            for (name, font_ref) in font_dict.iter() {
                if let Ok(font_obj) = font_ref.as_dict() {
                    // Validate required font dictionary entries
                    let required_keys = [b"Type", b"Subtype"];
                    for &key in &required_keys {
                        if !font_obj.has(key) {
                            errors.push(ValidationError {
                                error_type: "InvalidFont".to_string(),
                                description: format!(
                                    "Font {} missing required entry: {}", 
                                    String::from_utf8_lossy(name),
                                    String::from_utf8_lossy(key)
                                ),
                                location: Some(node_id),
                                severity: "Critical".to_string(),
                                detection_time: self.initialization_time,
                            });
                        }
                    }
                    
                    // Validate font subtype
                    if let Ok(subtype) = font_obj.get(b"Subtype").and_then(|s| s.as_name_str()) {
                        match subtype {
                            "Type0" | "Type1" | "MMType1" | "Type3" | "TrueType" => {},
                            _ => {
                                warnings.push(ValidationWarning {
                                    warning_type: "UnknownFontType".to_string(),
                                    description: format!("Unknown font type: {}", subtype),
                                    location: Some(node_id),
                                    impact: "Potential rendering issues".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                    }
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidFontResource".to_string(),
                description: "Font resource must be a dictionary".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }

    fn validate_xobject_resources(
        &self,
        xobjects: &Object,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(xobject_dict) = xobjects.as_dict() {
            for (name, xobject_ref) in xobject_dict.iter() {
                if let Ok(xobject) = xobject_ref.as_dict() {
                    // Validate required XObject entries
                    if !xobject.has(b"Type") || !xobject.has(b"Subtype") {
                        errors.push(ValidationError {
                            error_type: "InvalidXObject".to_string(),
                            description: format!(
                                "XObject {} missing required Type or Subtype entry",
                                String::from_utf8_lossy(name)
                            ),
                            location: Some(node_id),
                            severity: "Critical".to_string(),
                            detection_time: self.initialization_time,
                        });
                        continue;
                    }

                    // Validate XObject subtype
                    if let Ok(subtype) = xobject.get(b"Subtype").and_then(|s| s.as_name_str()) {
                        match subtype {
                            "Image" => self.validate_image_xobject(xobject, node_id, errors, warnings)?,
                            "Form" => self.validate_form_xobject(xobject, node_id, errors, warnings)?,
                            "PS" => {
                                warnings.push(ValidationWarning {
                                    warning_type: "PostScriptXObject".to_string(),
                                    description: "PostScript XObjects may not be supported by all viewers".to_string(),
                                    location: Some(node_id),
                                    impact: "Compatibility concerns".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                            _ => {
                                warnings.push(ValidationWarning {
                                    warning_type: "UnknownXObjectType".to_string(),
                                    description: format!("Unknown XObject type: {}", subtype),
                                    location: Some(node_id),
                                    impact: "Potential rendering issues".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                    }
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidXObjectResource".to_string(),
                description: "XObject resource must be a dictionary".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn validate_image_xobject(
        &self,
        xobject: &Dictionary,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Validate required image entries
        let required_keys = [b"Width", b"Height", b"ColorSpace", b"BitsPerComponent"];
        for &key in &required_keys {
            if !xobject.has(key) {
                errors.push(ValidationError {
                    error_type: "InvalidImageXObject".to_string(),
                    description: format!("Image XObject missing required entry: {}", String::from_utf8_lossy(key)),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        // Validate image dimensions
        if let (Ok(width), Ok(height)) = (
            xobject.get(b"Width").and_then(|w| w.as_i64()),
            xobject.get(b"Height").and_then(|h| h.as_i64()),
        ) {
            if width <= 0 || height <= 0 {
                errors.push(ValidationError {
                    error_type: "InvalidImageDimensions".to_string(),
                    description: "Image dimensions must be positive".to_string(),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
            }
            
            // Check for unreasonably large images
            const MAX_IMAGE_DIMENSION: i64 = 16384;
            if width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
                warnings.push(ValidationWarning {
                    warning_type: "LargeImage".to_string(),
                    description: format!("Image dimensions ({} x {}) exceed reasonable limits", width, height),
                    location: Some(node_id),
                    impact: "Performance and memory concerns".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        // Validate BitsPerComponent
        if let Ok(bits) = xobject.get(b"BitsPerComponent").and_then(|b| b.as_i64()) {
            if ![1, 2, 4, 8, 16].contains(&bits) {
                errors.push(ValidationError {
                    error_type: "InvalidBitsPerComponent".to_string(),
                    description: format!("Invalid BitsPerComponent value: {}", bits),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        Ok(())
    }

    fn validate_form_xobject(
        &self,
        xobject: &Dictionary,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Validate required form XObject entries
        if !xobject.has(b"BBox") {
            errors.push(ValidationError {
                error_type: "InvalidFormXObject".to_string(),
                description: "Form XObject missing required BBox entry".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        } else {
            // Validate BBox
            if let Ok(bbox) = xobject.get(b"BBox") {
                self.validate_rectangle(bbox, node_id, "BBox", errors)?;
            }
        }

        // Validate Form Matrix if present
        if let Ok(matrix) = xobject.get(b"Matrix") {
            self.validate_matrix(matrix, node_id, errors)?;
        }

        // Check for Resources dictionary
        if let Ok(resources) = xobject.get(b"Resources") {
            self.validate_resources(resources, node_id, errors, warnings)?;
        }

        Ok(())
    }

    fn validate_matrix(
        &self,
        matrix: &Object,
        node_id: ObjectId,
        errors: &mut Vec<ValidationError>,
    ) -> Result<()> {
        if let Ok(matrix_array) = matrix.as_array() {
            if matrix_array.len() != 6 {
                errors.push(ValidationError {
                    error_type: "InvalidMatrix".to_string(),
                    description: "Transformation matrix must have exactly 6 elements".to_string(),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
                return Ok(());
            }

            // Validate that all elements are numbers
            for (i, element) in matrix_array.iter().enumerate() {
                if !matches!(element, Object::Integer(_) | Object::Real(_)) {
                    errors.push(ValidationError {
                        error_type: "InvalidMatrixElement".to_string(),
                        description: format!("Matrix element {} is not a number", i),
                        location: Some(node_id),
                        severity: "Critical".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidMatrix".to_string(),
                description: "Transformation matrix must be an array".to_string(),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }

        Ok(())
    }

    fn validate_resource_dictionary(
        &self,
        resource: &Object,
        node_id: ObjectId,
        resource_type: &str,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(dict) = resource.as_dict() {
            for (name, value) in dict.iter() {
                match resource_type {
                    "ColorSpace" => self.validate_colorspace(
                        value,
                        node_id,
                        &String::from_utf8_lossy(name),
                        errors,
                        warnings,
                    )?,
                    "ExtGState" => self.validate_graphics_state(
                        value,
                        node_id,
                        &String::from_utf8_lossy(name),
                        errors,
                        warnings,
                    )?,
                    _ => {
                        // Basic dictionary validation for other resource types
                        if !matches!(value, Object::Dictionary(_) | Object::Reference(_)) {
                            warnings.push(ValidationWarning {
                                warning_type: format!("Invalid{}", resource_type),
                                description: format!(
                                    "{} resource {} has unexpected type",
                                    resource_type,
                                    String::from_utf8_lossy(name)
                                ),
                                location: Some(node_id),
                                impact: "Potential rendering issues".to_string(),
                                detection_time: self.initialization_time,
                            });
                        }
                    }
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: format!("Invalid{}Resource", resource_type),
                description: format!("{} resource must be a dictionary", resource_type),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }

        Ok(())
    }
    fn validate_colorspace(
        &self,
        colorspace: &Object,
        node_id: ObjectId,
        name: &str,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        match colorspace {
            Object::Name(n) => {
                // Validate device color spaces
                let valid_device_spaces = ["DeviceGray", "DeviceRGB", "DeviceCMYK", "Pattern"];
                if !valid_device_spaces.contains(&n.as_str()) {
                    warnings.push(ValidationWarning {
                        warning_type: "UnknownColorSpace".to_string(),
                        description: format!("Unknown device color space: {}", n.as_str()),
                        location: Some(node_id),
                        impact: "Color rendering accuracy".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
            Object::Array(array) => {
                if array.is_empty() {
                    errors.push(ValidationError {
                        error_type: "InvalidColorSpace".to_string(),
                        description: "Color space array cannot be empty".to_string(),
                        location: Some(node_id),
                        severity: "Critical".to_string(),
                        detection_time: self.initialization_time,
                    });
                    return Ok(());
                }

                // Validate color space family
                if let Ok(family) = array[0].as_name_str() {
                    match family {
                        "CalGray" | "CalRGB" | "Lab" => {
                            if array.len() != 2 {
                                errors.push(ValidationError {
                                    error_type: "InvalidColorSpace".to_string(),
                                    description: format!("{} color space must have exactly 2 elements", family),
                                    location: Some(node_id),
                                    severity: "Critical".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                        "ICCBased" => {
                            if array.len() != 2 {
                                errors.push(ValidationError {
                                    error_type: "InvalidColorSpace".to_string(),
                                    description: "ICCBased color space must have exactly 2 elements".to_string(),
                                    location: Some(node_id),
                                    severity: "Critical".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                        "Indexed" => {
                            if array.len() != 4 {
                                errors.push(ValidationError {
                                    error_type: "InvalidColorSpace".to_string(),
                                    description: "Indexed color space must have exactly 4 elements".to_string(),
                                    location: Some(node_id),
                                    severity: "Critical".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                        "Separation" | "DeviceN" => {
                            if array.len() < 4 {
                                errors.push(ValidationError {
                                    error_type: "InvalidColorSpace".to_string(),
                                    description: format!("{} color space must have at least 4 elements", family),
                                    location: Some(node_id),
                                    severity: "Critical".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                        _ => {
                            warnings.push(ValidationWarning {
                                warning_type: "UnknownColorSpace".to_string(),
                                description: format!("Unknown color space family: {}", family),
                                location: Some(node_id),
                                impact: "Color rendering accuracy".to_string(),
                                detection_time: self.initialization_time,
                            });
                        }
                    }
                }
            }
            _ => {
                errors.push(ValidationError {
                    error_type: "InvalidColorSpace".to_string(),
                    description: format!("Color space {} must be a name or array", name),
                    location: Some(node_id),
                    severity: "Critical".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        Ok(())
    }

    fn validate_graphics_state(
        &self,
        gstate: &Object,
        node_id: ObjectId,
        name: &str,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        if let Ok(dict) = gstate.as_dict() {
            // Validate numeric parameters
            let numeric_params = [
                ("LW", "LineWidth", 0.0..=100.0),
                ("ML", "MiterLimit", 1.0..=100.0),
                ("CA", "StrokeAlpha", 0.0..=1.0),
                ("ca", "FillAlpha", 0.0..=1.0),
            ];

            for (key, param_name, range) in numeric_params {
                if let Ok(value) = dict.get(key.as_bytes()).and_then(|v| v.as_f64()) {
                    if !range.contains(&value) {
                        warnings.push(ValidationWarning {
                            warning_type: "InvalidGState".to_string(),
                            description: format!(
                                "Graphics state parameter {} out of range: {}",
                                param_name, value
                            ),
                            location: Some(node_id),
                            impact: "Rendering accuracy".to_string(),
                            detection_time: self.initialization_time,
                        });
                    }
                }
            }

            // Validate blend mode
            if let Ok(blend_mode) = dict.get(b"BM").and_then(|b| b.as_name_str()) {
                let valid_blend_modes = [
                    "Normal", "Compatible", "Multiply", "Screen", "Overlay", "Darken", "Lighten",
                    "ColorDodge", "ColorBurn", "HardLight", "SoftLight", "Difference", "Exclusion",
                ];
                if !valid_blend_modes.contains(&blend_mode) {
                    warnings.push(ValidationWarning {
                        warning_type: "UnknownBlendMode".to_string(),
                        description: format!("Unknown blend mode: {}", blend_mode),
                        location: Some(node_id),
                        impact: "Rendering compatibility".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        } else {
            errors.push(ValidationError {
                error_type: "InvalidGState".to_string(),
                description: format!("Graphics state {} must be a dictionary", name),
                location: Some(node_id),
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }

        Ok(())
    }

    fn validate_cross_references(
        &self,
        document: &Document,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Validate cross-reference entries
        let mut visited_objects = HashSet::new();
        let mut dangling_references = Vec::new();
        
        for (&object_id, object) in &document.objects {
            visited_objects.insert(object_id);
            
            // Check for references within the object
            self.check_references_recursive(
                object,
                document,
                &mut visited_objects,
                &mut dangling_references,
            )?;
        }
        
        // Report dangling references
        for reference in dangling_references {
            errors.push(ValidationError {
                error_type: "DanglingReference".to_string(),
                description: format!("Reference to non-existent object: {}", reference),
                location: None,
                severity: "Critical".to_string(),
                detection_time: self.initialization_time,
            });
        }
        
        Ok(())
    }
    
    fn check_references_recursive(
        &self,
        object: &Object,
        document: &Document,
        visited: &mut HashSet<ObjectId>,
        dangling: &mut Vec<ObjectId>,
    ) -> Result<()> {
        match object {
            Object::Reference(id) => {
                if !document.objects.contains_key(id) {
                    dangling.push(*id);
                }
            }
            Object::Dictionary(dict) => {
                for value in dict.values() {
                    self.check_references_recursive(value, document, visited, dangling)?;
                }
            }
            Object::Array(array) => {
                for item in array {
                    self.check_references_recursive(item, document, visited, dangling)?;
                }
            }
            Object::Stream(stream) => {
                for value in stream.dict.values() {
                    self.check_references_recursive(value, document, visited, dangling)?;
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    fn validate_content(
        &self,
        parsed_data: &ParsedPdfData,
        extraction_data: &ExtractionData,
    ) -> Result<ContentValidation> {
        let mut content_issues = Vec::new();
        let mut size_violations = Vec::new();
        
        // Validate content streams
        for (object_id, content) in &parsed_data.content_streams {
            // Check content stream size
            if content.len() > self.max_stream_size {
                size_violations.push(SizeViolation {
                    object_id: *object_id,
                    object_type: "ContentStream".to_string(),
                    actual_size: content.len(),
                    max_allowed: self.max_stream_size,
                    detection_time: self.initialization_time,
                });
            }
            
            // Validate content stream syntax
            if let Err(e) = self.validate_content_stream(content, *object_id) {
                content_issues.push(ContentIssue {
                    issue_type: "SyntaxError".to_string(),
                    description: e.to_string(),
                    object_id: *object_id,
                    content_type: "ContentStream".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }
        
        // Validate embedded objects
        for (object_id, object_data) in &extraction_data.embedded_objects {
            // Check embedded object size
            if object_data.len() > self.max_object_size {
                size_violations.push(SizeViolation {
                    object_id: *object_id,
                    object_type: "EmbeddedObject".to_string(),
                    actual_size: object_data.len(),
                    max_allowed: self.max_object_size,
                    detection_time: self.initialization_time,
                });
            }
            
            // Validate embedded object format
            if let Err(e) = self.validate_embedded_object(object_data, *object_id) {
                content_issues.push(ContentIssue {
                    issue_type: "InvalidFormat".to_string(),
                    description: e.to_string(),
                    object_id: *object_id,
                    content_type: "EmbeddedObject".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }
        
        let is_valid = content_issues.is_empty() && 
                      (size_violations.is_empty() || !self.strict_mode);
        
        Ok(ContentValidation {
            is_valid,
            content_issues,
            size_violations,
            validation_time: self.initialization_time,
        })
    }

    fn validate_content_stream(
        &self,
        content: &[u8],
        object_id: ObjectId,
    ) -> Result<()> {
        // Basic content stream validation
        let mut depth = 0;
        let mut in_string = false;
        let mut escape_next = false;

        for &byte in content {
            if in_string {
                if escape_next {
                    escape_next = false;
                } else if byte == b'\\' {
                    escape_next = true;
                } else if byte == b')' && !escape_next {
                    in_string = false;
                }
                continue;
            }

            match byte {
                b'(' => {
                    in_string = true;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(ForensicError::ContentStreamError(
                            "Unmatched closing brace in content stream".to_string()
                        ));
                    }
                }
                _ => {}
            }
        }

        if depth != 0 {
            return Err(ForensicError::ContentStreamError(
                "Unclosed brace in content stream".to_string()
            ));
        }

        if in_string {
            return Err(ForensicError::ContentStreamError(
                "Unclosed string in content stream".to_string()
            ));
        }

        Ok(())
    }

    fn validate_embedded_object(
        &self,
        data: &[u8],
        object_id: ObjectId,
    ) -> Result<()> {
        // Check for common file signatures
        if data.len() < 4 {
            return Err(ForensicError::EmbeddedObjectError(
                "Embedded object too small to be valid".to_string()
            ));
        }

        // Validate based on common file signatures
        match &data[0..4] {
            // JPEG signature
            [0xFF, 0xD8, 0xFF, _] => self.validate_jpeg(data),
            // PNG signature
            [0x89, 0x50, 0x4E, 0x47] => self.validate_png(data),
            // Other formats can be added here
            _ => Ok(()) // Unknown format, but not necessarily invalid
        }
    }

    fn validate_jpeg(&self, data: &[u8]) -> Result<()> {
        // Basic JPEG validation
        if data.len() < 2 || data[data.len() - 2..] != [0xFF, 0xD9] {
            return Err(ForensicError::EmbeddedObjectError(
                "Invalid JPEG: Missing end marker".to_string()
            ));
        }
        Ok(())
    }

    fn validate_png(&self, data: &[u8]) -> Result<()> {
        // Basic PNG validation
        const PNG_SIGNATURE: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if data.len() < PNG_SIGNATURE.len() || &data[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
            return Err(ForensicError::EmbeddedObjectError(
                "Invalid PNG: Incorrect signature".to_string()
            ));
        }
        Ok(())
    }

    fn validate_metadata(
        &self,
        parsed_data: &ParsedPdfData,
        analysis_result: &AnalysisResult,
    ) -> Result<MetadataValidation> {
        let mut inconsistencies = Vec::new();
        let mut missing_required = Vec::new();

        // Check required metadata fields
        let required_fields = ["Title", "Author", "Producer", "CreationDate"];
        for &field in &required_fields {
            if !parsed_data.metadata.contains_key(field) {
                missing_required.push(field.to_string());
            }
        }

        // Validate metadata consistency
        self.check_metadata_consistency(
            &parsed_data.metadata,
            analysis_result,
            &mut inconsistencies,
        )?;

        let is_valid = inconsistencies.is_empty() && 
                      (missing_required.is_empty() || !self.strict_mode);

        Ok(MetadataValidation {
            is_valid,
            inconsistencies,
            missing_required,
            validation_time: self.initialization_time,
        })
    }

    fn check_metadata_consistency(
        &self,
        metadata: &MetadataMap,
        analysis_result: &AnalysisResult,
        inconsistencies: &mut Vec<MetadataInconsistency>,
    ) -> Result<()> {
        // Check date consistency
        if let (Some(creation_date), Some(mod_date)) = (
            metadata.get("CreationDate"),
            metadata.get("ModDate"),
        ) {
            if let (Ok(creation), Ok(modification)) = (
                self.parse_pdf_date(creation_date),
                self.parse_pdf_date(mod_date),
            ) {
                if modification < creation {
                    inconsistencies.push(MetadataInconsistency {
                        field: "ModDate".to_string(),
                        description: "Modification date precedes creation date".to_string(),
                        locations: vec![],
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        // Check producer consistency
        if let Some(producer) = metadata.get("Producer") {
            if let Some(version) = metadata.get("PDFVersion") {
                if !self.is_producer_version_consistent(producer, version) {
                    inconsistencies.push(MetadataInconsistency {
                        field: "Producer".to_string(),
                        description: format!(
                            "Producer {} inconsistent with PDF version {}",
                            producer, version
                        ),
                        locations: vec![],
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        // Cross-reference with analysis results
        self.validate_metadata_against_analysis(metadata, analysis_result, inconsistencies)?;

        Ok(())
    }

    fn parse_pdf_date(&self, date_str: &str) -> Result<DateTime<Utc>> {
        // PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
        // where O is either + or - for the offset
        let date_str = date_str.trim_start_matches("D:");
        if date_str.len() < 14 {
            return Err(ForensicError::MetadataError(
                "Invalid date format: too short".to_string()
            ));
        }

        let year = &date_str[0..4];
        let month = &date_str[4..6];
        let day = &date_str[6..8];
        let hour = &date_str[8..10];
        let minute = &date_str[10..12];
        let second = &date_str[12..14];

        let datetime_str = format!("{}-{}-{}T{}:{}:{}Z", year, month, day, hour, minute, second);
        DateTime::parse_from_rfc3339(&datetime_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| ForensicError::MetadataError(format!("Invalid date: {}", e)))
    }

    fn is_producer_version_consistent(&self, producer: &str, version: &str) -> bool {
        // Basic version consistency check
        // This could be expanded based on known producer version patterns
        let version_num = version.parse::<f32>().unwrap_or(0.0);
        
        // Example checks for common producers
        match producer {
            p if p.contains("Adobe") => {
                // Adobe products typically support up to their release version
                if p.contains("Acrobat") && version_num > 2.0 {
                    return false;
                }
            }
            p if p.contains("pdfTeX") => {
                // pdfTeX typically produces PDF 1.5 or lower
                if version_num > 1.5 {
                    return false;
                }
            }
            _ => {
                // Generic check for unknown producers
                if version_num > 2.0 {
                    return false;
                }
            }
        }
        
        true
    }

    fn validate_metadata_against_analysis(
        &self,
        metadata: &MetadataMap,
        analysis_result: &AnalysisResult,
        inconsistencies: &mut Vec<MetadataInconsistency>,
    ) -> Result<()> {
        // Check file size consistency
        if let (Some(stated_size), Some(actual_size)) = (
            metadata.get("FileSize"),
            analysis_result.file_size
        ) {
            if let Ok(stated) = stated_size.parse::<u64>() {
                if stated != actual_size {
                    inconsistencies.push(MetadataInconsistency {
                        field: "FileSize".to_string(),
                        description: format!(
                            "Stated file size ({}) differs from actual size ({})",
                            stated, actual_size
                        ),
                        locations: vec![],
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        // Check encryption consistency
        if let Some(encryption_stated) = metadata.get("Encrypted") {
            let encryption_actual = analysis_result.is_encrypted;
            if encryption_stated.parse::<bool>().unwrap_or(false) != encryption_actual {
                inconsistencies.push(MetadataInconsistency {
                    field: "Encrypted".to_string(),
                    description: "Encryption status mismatch".to_string(),
                    locations: vec![],
                    detection_time: self.initialization_time,
                });
            }
        }

        Ok(())
    }

    fn validate_security(
        &self,
        parsed_data: &ParsedPdfData,
        analysis_result: &AnalysisResult,
    ) -> Result<SecurityValidation> {
        let mut security_issues = Vec::new();
        let mut permissions_status = PermissionsStatus {
            is_compliant: true,
            violations: Vec::new(),
            check_time: self.initialization_time,
        };

        // Validate encryption settings
        if analysis_result.is_encrypted {
            self.validate_encryption_settings(
                &parsed_data.encryption_dict,
                &mut security_issues,
            )?;
        }

        // Validate digital signatures
        if let Some(signatures) = &parsed_data.signatures {
            self.validate_signatures(signatures, &mut security_issues)?;
        }

        // Check permissions
        self.validate_permissions(
            &parsed_data.permissions,
            &mut permissions_status,
        )?;

        // Check for JavaScript presence
        self.check_javascript_security(parsed_data, &mut security_issues)?;

        let is_valid = security_issues.is_empty() && permissions_status.is_compliant;

        Ok(SecurityValidation {
            is_valid,
            security_issues,
            permissions_status,
            validation_time: self.initialization_time,
        })
    }

    fn validate_encryption_settings(
        &self,
        encryption_dict: &Dictionary,
        security_issues: &mut Vec<SecurityIssue>,
    ) -> Result<()> {
        // Check encryption algorithm
        if let Ok(filter) = encryption_dict.get(b"Filter").and_then(|f| f.as_name_str()) {
            if filter != "Standard" {
                security_issues.push(SecurityIssue {
                    issue_type: "NonStandardEncryption".to_string(),
                    description: format!("Non-standard encryption filter: {}", filter),
                    risk_level: "High".to_string(),
                    recommendation: "Use standard encryption filter".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        // Check encryption key length
        if let Ok(key_length) = encryption_dict.get(b"Length").and_then(|l| l.as_i64()) {
            if key_length < 128 {
                security_issues.push(SecurityIssue {
                    issue_type: "WeakEncryption".to_string(),
                    description: format!("Encryption key length too short: {} bits", key_length),
                    risk_level: "Critical".to_string(),
                    recommendation: "Use at least 128-bit encryption".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        // Validate encryption method version
        if let Ok(v) = encryption_dict.get(b"V").and_then(|v| v.as_i64()) {
            if v < 4 {
                security_issues.push(SecurityIssue {
                    issue_type: "ObsoleteEncryption".to_string(),
                    description: format!("Obsolete encryption version: V={}", v),
                    risk_level: "High".to_string(),
                    recommendation: "Update to encryption version 4 or higher".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        Ok(())
    }

    fn validate_signatures(
        &self,
        signatures: &[Dictionary],
        security_issues: &mut Vec<SecurityIssue>,
    ) -> Result<()> {
        for signature in signatures {
            // Check signature type
            if let Ok(sig_type) = signature.get(b"Type").and_then(|t| t.as_name_str()) {
                if sig_type != "Sig" {
                    security_issues.push(SecurityIssue {
                        issue_type: "InvalidSignature".to_string(),
                        description: format!("Invalid signature type: {}", sig_type),
                        risk_level: "High".to_string(),
                        recommendation: "Use standard signature type".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }

            // Validate signature algorithm
            if let Ok(algo) = signature.get(b"SubFilter").and_then(|s| s.as_name_str()) {
                match algo {
                    "adbe.pkcs7.detached" | "adbe.pkcs7.sha1" => {},
                    "adbe.x509.rsa_sha1" => {
                        security_issues.push(SecurityIssue {
                            issue_type: "WeakSignature".to_string(),
                            description: "SHA-1 based signature algorithm is deprecated".to_string(),
                            risk_level: "Medium".to_string(),
                            recommendation: "Use SHA-256 or stronger signature algorithm".to_string(),
                            detection_time: self.initialization_time,
                        });
                    }
                    _ => {
                        security_issues.push(SecurityIssue {
                            issue_type: "UnknownSignature".to_string(),
                            description: format!("Unknown signature algorithm: {}", algo),
                            risk_level: "High".to_string(),
                            recommendation: "Use standard signature algorithm".to_string(),
                            detection_time: self.initialization_time,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_permissions(
        &self,
        permissions: &Dictionary,
        status: &mut PermissionsStatus,
    ) -> Result<()> {
        // Check basic permissions
        let permission_flags = [
            (b"Print", "Printing"),
            (b"Modify", "Content Modification"),
            (b"Copy", "Content Copying"),
            (b"AddNotes", "Annotations"),
            (b"FillForm", "Form Filling"),
            (b"Extract", "Content Extraction"),
            (b"AssembleDoc", "Document Assembly"),
            (b"HighPrintQuality", "High Quality Printing"),
        ];

        for (flag, description) in &permission_flags {
            if let Ok(allowed) = permissions.get(*flag).and_then(|p| p.as_bool()) {
                if !allowed {
                    status.violations.push(PermissionViolation {
                        permission: description.to_string(),
                        description: format!("{} is not allowed", description),
                        impact: "Feature restricted".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        // Check advanced permissions
        if let Ok(Some(advanced)) = permissions.get(b"AdvancedRights") {
            self.validate_advanced_permissions(advanced.as_dict()?, status)?;
        }

        status.is_compliant = status.violations.is_empty();
        Ok(())
    }

    fn validate_advanced_permissions(
        &self,
        advanced: &Dictionary,
        status: &mut PermissionsStatus,
    ) -> Result<()> {
        // Check digital rights management
        if let Ok(Some(drm)) = advanced.get(b"DRM") {
            if let Ok(drm_dict) = drm.as_dict() {
                // Validate DRM expiration
                if let Ok(Some(expiration)) = drm_dict.get(b"Expiration") {
                    if let Ok(exp_date) = expiration.as_string() {
                        if let Ok(exp_time) = self.parse_pdf_date(exp_date) {
                            if exp_time < self.initialization_time {
                                status.violations.push(PermissionViolation {
                                    permission: "DRM".to_string(),
                                    description: "DRM rights have expired".to_string(),
                                    impact: "Document access may be restricted".to_string(),
                                    detection_time: self.initialization_time,
                                });
                            }
                        }
                    }
                }

                // Check usage rights
                if let Ok(Some(usage)) = drm_dict.get(b"Usage") {
                    if let Ok(usage_dict) = usage.as_dict() {
                        self.validate_usage_rights(usage_dict, status)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_usage_rights(
        &self,
        usage: &Dictionary,
        status: &mut PermissionsStatus,
    ) -> Result<()> {
        let usage_rights = [
            (b"Print", "Printing rights"),
            (b"Modify", "Modification rights"),
            (b"Extract", "Content extraction rights"),
            (b"Annotate", "Annotation rights"),
        ];

        for (right, description) in &usage_rights {
            if let Ok(Some(right_dict)) = usage.get(*right) {
                if let Ok(right_dict) = right_dict.as_dict() {
                    // Check if right is enabled
                    if let Ok(Some(enabled)) = right_dict.get(b"Enabled") {
                        if let Ok(false) = enabled.as_bool() {
                            status.violations.push(PermissionViolation {
                                permission: description.to_string(),
                                description: format!("{} are disabled", description),
                                impact: "Feature unavailable".to_string(),
                                detection_time: self.initialization_time,
                            });
                        }
                    }

                    // Check for restrictions
                    if let Ok(Some(restrictions)) = right_dict.get(b"Restrictions") {
                        if let Ok(restrictions) = restrictions.as_dict() {
                            self.check_right_restrictions(
                                restrictions,
                                description,
                                status,
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_right_restrictions(
        &self,
        restrictions: &Dictionary,
        right_desc: &str,
        status: &mut PermissionsStatus,
    ) -> Result<()> {
        // Check for time-based restrictions
        if let Ok(Some(time_restrict)) = restrictions.get(b"TimeLimit") {
            if let Ok(limit) = time_restrict.as_string() {
                status.violations.push(PermissionViolation {
                    permission: right_desc.to_string(),
                    description: format!("{} time-limited: {}", right_desc, limit),
                    impact: "Temporary access only".to_string(),
                    detection_time: self.initialization_time,
                });
            }
        }

        // Check for user-based restrictions
        if let Ok(Some(users)) = restrictions.get(b"Users") {
            if let Ok(user_list) = users.as_array() {
                if !user_list.is_empty() {
                    status.violations.push(PermissionViolation {
                        permission: right_desc.to_string(),
                        description: format!("{} restricted to specific users", right_desc),
                        impact: "Limited user access".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        Ok(())
    }

    fn check_javascript_security(
        &self,
        parsed_data: &ParsedPdfData,
        security_issues: &mut Vec<SecurityIssue>,
    ) -> Result<()> {
        // Check for presence of JavaScript
        if let Some(javascript) = &parsed_data.javascript {
            // Check for potentially dangerous JavaScript functions
            let dangerous_patterns = [
                ("eval", "Dynamic code execution"),
                ("getURL", "External URL access"),
                ("submitForm", "Form submission"),
                ("app.launchURL", "External application launch"),
                ("this.submitForm", "Form submission"),
                ("app.openDoc", "Document opening"),
                ("app.execDialog", "Dialog execution"),
            ];

            for script in javascript {
                let script_content = script.as_string().unwrap_or("");
                
                for (pattern, description) in &dangerous_patterns {
                    if script_content.contains(pattern) {
                        security_issues.push(SecurityIssue {
                            issue_type: "DangerousJavaScript".to_string(),
                            description: format!("Potentially dangerous JavaScript detected: {}", description),
                            risk_level: "High".to_string(),
                            recommendation: format!("Review and validate use of {} function", pattern),
                            detection_time: self.initialization_time,
                        });
                    }
                }

                // Check for obfuscation
                if self.detect_javascript_obfuscation(script_content) {
                    security_issues.push(SecurityIssue {
                        issue_type: "ObfuscatedJavaScript".to_string(),
                        description: "Potentially obfuscated JavaScript detected".to_string(),
                        risk_level: "High".to_string(),
                        recommendation: "Review and deobfuscate JavaScript code".to_string(),
                        detection_time: self.initialization_time,
                    });
                }
            }
        }

        Ok(())
    }

    fn detect_javascript_obfuscation(&self, script: &str) -> bool {
        // Check for common obfuscation patterns
        let obfuscation_indicators = [
            // Long strings of hexadecimal or unicode escapes
            r"\u[0-9a-fA-F]{4}",
            r"\\x[0-9a-fA-F]{2}",
            // Base64-like strings
            r"^[A-Za-z0-9+/]{20,}={0,2}$",
            // Excessive use of escape sequences
            r"\\[0-7]{3}",
            // String splitting and joining
            r"join\(['\"]\['\"]\)",
            // Character code manipulation
            r"fromCharCode\(",
            // Unusual eval variations
            r"\\x65\\x76\\x61\\x6C",
        ];

        let mut suspicious_patterns = 0;
        for pattern in &obfuscation_indicators {
            if Regex::new(pattern).unwrap().is_match(script) {
                suspicious_patterns += 1;
            }
        }

        // Consider it obfuscated if multiple suspicious patterns are found
        suspicious_patterns >= 2
    }

    pub fn generate_report(&self, validation_result: &ValidationResult) -> Report {
        Report {
            timestamp: self.initialization_time,
            summary: self.generate_summary(validation_result),
            details: self.generate_details(validation_result),
            recommendations: self.generate_recommendations(validation_result),
            metadata: self.generate_metadata_report(validation_result),
        }
    }

    fn generate_summary(&self, result: &ValidationResult) -> Summary {
        Summary {
            is_valid: result.is_valid,
            total_issues: result.errors.len() + result.warnings.len(),
            critical_issues: result.errors.iter()
                .filter(|e| e.severity == "Critical")
                .count(),
            validation_time: self.initialization_time,
            pdf_version: result.pdf_version.clone(),
        }
    }

    fn generate_details(&self, result: &ValidationResult) -> Details {
        Details {
            errors: result.errors.clone(),
            warnings: result.warnings.clone(),
            content_issues: result.content_validation.content_issues.clone(),
            security_issues: result.security_validation.security_issues.clone(),
            size_violations: result.content_validation.size_violations.clone(),
        }
    }

    fn generate_recommendations(&self, result: &ValidationResult) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Process errors
        for error in &result.errors {
            recommendations.push(Recommendation {
                priority: "High".to_string(),
                category: "Error".to_string(),
                description: format!("Fix: {}", error.description),
                impact: "Document validity and functionality".to_string(),
                suggested_action: self.suggest_error_fix(&error.error_type),
                timestamp: self.initialization_time,
            });
        }

        // Process security issues
        for issue in &result.security_validation.security_issues {
            recommendations.push(Recommendation {
                priority: match issue.risk_level.as_str() {
                    "Critical" => "Immediate".to_string(),
                    "High" => "High".to_string(),
                    _ => "Medium".to_string(),
                },
                category: "Security".to_string(),
                description: issue.description.clone(),
                impact: "Document security and integrity".to_string(),
                suggested_action: issue.recommendation.clone(),
                timestamp: self.initialization_time,
            });
        }

        // Process content issues
        for issue in &result.content_validation.content_issues {
            recommendations.push(Recommendation {
                priority: "Medium".to_string(),
                category: "Content".to_string(),
                description: issue.description.clone(),
                impact: "Document rendering and functionality".to_string(),
                suggested_action: format!("Review and correct {} in {}", 
                    issue.content_type, 
                    issue.object_id
                ),
                timestamp: self.initialization_time,
            });
        }

        // Sort recommendations by priority
        recommendations.sort_by(|a, b| {
            let priority_order = |p: &str| match p {
                "Immediate" => 0,
                "High" => 1,
                "Medium" => 2,
                _ => 3,
            };
            priority_order(&a.priority).cmp(&priority_order(&b.priority))
        });

        recommendations
    }

    fn suggest_error_fix(&self, error_type: &str) -> String {
        match error_type {
            "InvalidStructure" => 
                "Rebuild document structure using a PDF creation tool".to_string(),
            "DanglingReference" => 
                "Remove or update references to non-existent objects".to_string(),
            "InvalidFont" => 
                "Embed missing fonts or replace with standard fonts".to_string(),
            "InvalidXObject" => 
                "Regenerate XObjects with valid parameters".to_string(),
            "InvalidColorSpace" => 
                "Convert to a standard color space (e.g., DeviceRGB)".to_string(),
            "InvalidMatrix" => 
                "Correct transformation matrix values".to_string(),
            "InvalidRectangle" => 
                "Adjust rectangle coordinates to valid values".to_string(),
            "InvalidMetadata" => 
                "Update metadata fields with correct information".to_string(),
            _ => format!("Review and correct {} issues", error_type),
        }
    }

    fn generate_metadata_report(&self, result: &ValidationResult) -> MetadataReport {
        MetadataReport {
            validation_version: env!("CARGO_PKG_VERSION").to_string(),
            validation_date: self.initialization_time,
            validator_settings: ValidatorSettings {
                strict_mode: self.strict_mode,
                max_stream_size: self.max_stream_size,
                max_object_size: self.max_object_size,
            },
            document_info: DocumentInfo {
                pdf_version: result.pdf_version.clone(),
                file_size: result.file_size,
                object_count: result.object_count,
                is_encrypted: result.is_encrypted,
                has_signatures: !result.security_validation.security_issues.is_empty(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_validator_initialization() {
        let validator = PdfValidator::new(true);
        assert!(validator.strict_mode);
        assert!(validator.max_stream_size > 0);
        assert!(validator.max_object_size > 0);
    }

    #[test]
    fn test_date_parsing() {
        let validator = PdfValidator::new(false);
        let test_date = "D:20250613171652Z";
        let expected = Utc.ymd(2025, 6, 13).and_hms(17, 16, 52);
        assert_eq!(validator.parse_pdf_date(test_date).unwrap(), expected);
    }

    #[test]
    fn test_javascript_detection() {
        let validator = PdfValidator::new(true);
        let suspicious_js = r#"
            eval(\u0063\u006F\u0064\u0065);
            var x = [101,118,97,108].map(function(x){return String.fromCharCode(x);}).join('');
        "#;
        assert!(validator.detect_javascript_obfuscation(suspicious_js));
    }

    // Add more tests as needed...
}
