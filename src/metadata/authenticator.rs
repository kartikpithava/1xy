use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataLocation},
    config::ForensicConfig,
};
use super::{MetadataProcessingConfig, ScanResult};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc, TimeZone};

/// Metadata authentication system for forensic verification
pub struct MetadataAuthenticator {
    config: MetadataProcessingConfig,
    current_timestamp: DateTime<Utc>,
    authenticity_rules: HashMap<MetadataField, AuthenticityRule>,
}

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub is_authentic: bool,
    pub authenticity_score: f32,
    pub field_results: HashMap<MetadataField, FieldAuthenticityResult>,
    pub verification_report: AuthenticationReport,
    pub temporal_analysis: TemporalAnalysis,
}

#[derive(Debug, Clone)]
pub struct FieldAuthenticityResult {
    pub field: MetadataField,
    pub is_authentic: bool,
    pub confidence_score: f32,
    pub verification_details: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticationReport {
    pub total_fields_verified: usize,
    pub authentic_fields: usize,
    pub suspicious_fields: usize,
    pub failed_verifications: Vec<FailedVerification>,
    pub timestamp_consistency: bool,
    pub software_signature_valid: bool,
}

#[derive(Debug, Clone)]
pub struct TemporalAnalysis {
    pub creation_date_valid: bool,
    pub modification_date_valid: bool,
    pub temporal_consistency: bool,
    pub timestamp_format_valid: bool,
    pub temporal_anomalies: Vec<TemporalAnomaly>,
}

#[derive(Debug, Clone)]
pub struct FailedVerification {
    pub field: MetadataField,
    pub location: MetadataLocation,
    pub reason: String,
    pub severity: VerificationSeverity,
}

#[derive(Debug, Clone)]
pub enum VerificationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct TemporalAnomaly {
    pub field: MetadataField,
    pub anomaly_type: String,
    pub details: String,
    pub significance: f32,
}

#[derive(Debug, Clone)]
pub struct AuthenticityCheck {
    pub check_type: String,
    pub field: MetadataField,
    pub result: bool,
    pub confidence: f32,
    pub details: String,
}

struct AuthenticityRule {
    required_format: Option<String>,
    value_constraints: Vec<String>,
    temporal_requirements: bool,
    software_signature_check: bool,
}

impl MetadataAuthenticator {
    pub fn new() -> Self {
        let mut authenticator = Self {
            config: MetadataProcessingConfig::default(),
            current_timestamp: Utc::now(),
            authenticity_rules: HashMap::new(),
        };
        
        authenticator.setup_authenticity_rules();
        authenticator
    }

    fn setup_authenticity_rules(&mut self) {
        // Creation Date rules
        self.authenticity_rules.insert(
            MetadataField::CreationDate,
            AuthenticityRule {
                required_format: Some("D:YYYYMMDDHHmmSSOHH'mm".to_string()),
                value_constraints: vec![
                    "must_be_valid_date".to_string(),
                    "must_be_past".to_string(),
                    "must_be_reasonable".to_string(),
                ],
                temporal_requirements: true,
                software_signature_check: false,
            }
        );

        // Producer rules
        self.authenticity_rules.insert(
            MetadataField::Producer,
            AuthenticityRule {
                required_format: None,
                value_constraints: vec![
                    format!("must_match_{}", ForensicConfig::PDF_PRODUCER),
                ],
                temporal_requirements: false,
                software_signature_check: true,
            }
        );

        // Other standard fields
        for field in [MetadataField::Title, MetadataField::Author, MetadataField::Subject] {
            self.authenticity_rules.insert(
                field,
                AuthenticityRule {
                    required_format: None,
                    value_constraints: vec![
                        "no_suspicious_patterns".to_string(),
                        "reasonable_length".to_string(),
                    ],
                    temporal_requirements: false,
                    software_signature_check: false,
                }
            );
        }
    }

    /// Verify metadata authenticity
    pub fn verify_authenticity(&self, metadata_map: &MetadataMap, scan_result: &ScanResult) -> Result<AuthenticationResult> {
        let mut field_results = HashMap::new();
        let mut failed_verifications = Vec::new();
        let mut total_authentic_score = 0.0;
        let total_fields = metadata_map.len();

        // Verify each field against authenticity rules
        for (field, metadata_value) in metadata_map {
            let result = self.verify_field_authenticity(field, metadata_value, scan_result)?;
            
            if !result.is_authentic {
                failed_verifications.push(FailedVerification {
                    field: field.clone(),
                    location: metadata_value.locations.first().cloned()
                        .unwrap_or(MetadataLocation::CustomLocation("Unknown".to_string())),
                    reason: result.verification_details.join("; "),
                    severity: self.determine_verification_severity(field),
                });
            }

            total_authentic_score += result.confidence_score;
            field_results.insert(field.clone(), result);
        }

        // Perform temporal analysis
        let temporal_analysis = self.analyze_temporal_consistency(metadata_map)?;

        // Generate comprehensive authentication report
        let verification_report = self.generate_authentication_report(
            total_fields,
            &field_results,
            failed_verifications.clone(),
            &temporal_analysis,
        );

        let authenticity_score = if total_fields > 0 {
            total_authentic_score / total_fields as f32
        } else {
            1.0
        };

        Ok(AuthenticationResult {
            is_authentic: failed_verifications.is_empty() && temporal_analysis.temporal_consistency,
            authenticity_score,
            field_results,
            verification_report,
            temporal_analysis,
        })
    }

    fn verify_field_authenticity(&self, field: &MetadataField, value: &MetadataValue, scan_result: &ScanResult) -> Result<FieldAuthenticityResult> {
        let mut verification_details = Vec::new();
        let mut is_authentic = true;
        let mut confidence_score = 1.0;

        if let Some(rule) = self.authenticity_rules.get(field) {
            // Check format requirements
            if let Some(ref required_format) = rule.required_format {
                if let Some(ref value_str) = value.value {
                    if !self.verify_format(value_str, required_format) {
                        is_authentic = false;
                        verification_details.push(format!("Invalid format: expected {}", required_format));
                        confidence_score *= 0.5;
                    }
                }
            }

            // Check value constraints
            for constraint in &rule.value_constraints {
                if let Some(ref value_str) = value.value {
                    if !self.verify_constraint(value_str, constraint) {
                        is_authentic = false;
                        verification_details.push(format!("Failed constraint: {}", constraint));
                        confidence_score *= 0.7;
                    }
                }
            }

            // Check temporal requirements if applicable
            if rule.temporal_requirements {
                if let Some(anomaly) = self.check_temporal_validity(field, value) {
                    is_authentic = false;
                    verification_details.push(anomaly.details);
                    confidence_score *= 0.6;
                }
            }

            // Check software signature if required
            if rule.software_signature_check {
                if !self.verify_software_signature(field, value) {
                    is_authentic = false;
                    verification_details.push("Invalid software signature".to_string());
                    confidence_score *= 0.4;
                }
            }
        }

        Ok(FieldAuthenticityResult {
            field: field.clone(),
            is_authentic,
            confidence_score,
            verification_details,
        })
    }

    fn verify_format(&self, value: &str, format: &str) -> bool {
        match format {
            "D:YYYYMMDDHHmmSSOHH'mm" => {
                // Verify PDF date format
                if !value.starts_with("D:") {
                    return false;
                }
                let date_part = &value[2..];
                DateTime::parse_from_str(date_part, "%Y%m%d%H%M%S%z").is_ok()
            },
            _ => true,
        }
    }

    fn verify_constraint(&self, value: &str, constraint: &str) -> bool {
        match constraint {
            "must_be_valid_date" => {
                DateTime::parse_from_rfc3339(value).is_ok() ||
                DateTime::parse_from_str(value, "D:%Y%m%d%H%M%S%z").is_ok()
            },
            "must_be_past" => {
                if let Ok(date) = DateTime::parse_from_rfc3339(value) {
                    date <= self.current_timestamp
                } else {
                    true // Skip check if can't parse date
                }
            },
            "must_be_reasonable" => {
                if let Ok(date) = DateTime::parse_from_rfc3339(value) {
                    // Check if date is within reasonable range (e.g., not in future, not too old)
                    date <= self.current_timestamp && 
                    date.year() >= 1990 // PDF 1.0 was released in 1993
                } else {
                    true
                }
            },
            constraint if constraint.starts_with("must_match_") => {
                let expected = &constraint["must_match_".len()..];
                value == expected
            },
            "no_suspicious_patterns" => {
                let suspicious = ["test", "draft", "copy", "temp", "delete"];
                !suspicious.iter().any(|&pattern| value.to_lowercase().contains(pattern))
            },
            "reasonable_length" => {
                value.len() >= 1 && value.len() <= 1000
            },
            _ => true,
        }
    }

    fn check_temporal_validity(&self, field: &MetadataField, value: &MetadataValue) -> Option<TemporalAnomaly> {
        if let Some(ref value_str) = value.value {
            match field {
                MetadataField::CreationDate => {
                    if let Ok(date) = DateTime::parse_from_str(&value_str[2..], "%Y%m%d%H%M%S%z") {
                        if date > self.current_timestamp {
                            return Some(TemporalAnomaly {
                                field: field.clone(),
                                anomaly_type: "Future Date".to_string(),
                                details: "Creation date is in the future".to_string(),
                                significance: 1.0,
                            });
                        }
                    }
                },
                MetadataField::ModificationDate => {
                    if let Ok(mod_date) = DateTime::parse_from_str(&value_str[2..], "%Y%m%d%H%M%S%z") {
                        if mod_date > self.current_timestamp {
                            return Some(TemporalAnomaly {
                                field: field.clone(),
                                anomaly_type: "Future Modification".to_string(),
                                details: "Modification date is in the future".to_string(),
                                significance: 0.9,
                            });
                        }
                    }
                },
                _ => {},
            }
        }
        None
    }

    fn verify_software_signature(&self, field: &MetadataField, value: &MetadataValue) -> bool {
        match field {
            MetadataField::Producer => {
                value.value.as_ref().map_or(false, |v| v == ForensicConfig::PDF_PRODUCER)
            },
            _ => true,
        }
    }

    fn analyze_temporal_consistency(&self, metadata_map: &MetadataMap) -> Result<TemporalAnalysis> {
        let mut temporal_anomalies = Vec::new();
        let mut creation_date_valid = true;
        let mut modification_date_valid = true;
        let mut timestamp_format_valid = true;

        // Extract dates
        let creation_date = metadata_map.get(&MetadataField::CreationDate)
            .and_then(|v| v.value.as_ref());
        let modification_date = metadata_map.get(&MetadataField::ModificationDate)
            .and_then(|v| v.value.as_ref());

        // Verify creation date
        if let Some(create_str) = creation_date {
            if !create_str.starts_with("D:") || create_str.len() < 14 {
                timestamp_format_valid = false;
                creation_date_valid = false;
            } else if let Ok(create_date) = DateTime::parse_from_str(&create_str[2..], "%Y%m%d%H%M%S%z") {
                if create_date > self.current_timestamp {
                    creation_date_valid = false;
                    temporal_anomalies.push(TemporalAnomaly {
                        field: MetadataField::CreationDate,
                        anomaly_type: "Future Date".to_string(),
                        details: "Creation date is in the future".to_string(),
                        significance: 1.0,
                    });
                }
            }
        }

        // Verify modification date if present
        if let Some(mod_str) = modification_date {
            if !mod_str.starts_with("D:") || mod_str.len() < 14 {
                timestamp_format_valid = false;
                modification_date_valid = false;
            } else if let Ok(mod_date) = DateTime::parse_from_str(&mod_str[2..], "%Y%m%d%H%M%S%z") {
                if mod_date > self.current_timestamp {
                    modification_date_valid = false;
                    temporal_anomalies.push(TemporalAnomaly {
                        field: MetadataField::ModificationDate,
                        anomaly_type: "Future Date".to_string(),
                        details: "Modification date is in the future".to_string(),
                        significance: 0.9,
                    });
                }

                // Check if modification date is before creation date
                if let Some(create_str) = creation_date {
                    if let Ok(create_date) = DateTime::parse_from_str(&create_str[2..], "%Y%m%d%H%M%S%z") {
                        if mod_date < create_date {
                            temporal_anomalies.push(TemporalAnomaly {
                                field: MetadataField::ModificationDate,
                                anomaly_type: "Temporal Inconsistency".to_string(),
                                details: "Modification date is before creation date".to_string(),
                                significance: 0.8,
                            });
                        }
                    }
                }
            }
        }

        Ok(TemporalAnalysis {
            creation_date_valid,
            modification_date_valid,
            temporal_consistency: temporal_anomalies.is_empty(),
            timestamp_format_valid,
            temporal_anomalies,
        })
    }

    fn determine_verification_severity(&self, field: &MetadataField) -> VerificationSeverity {
        match field {
            MetadataField::CreationDate | MetadataField::ModificationDate => VerificationSeverity::High,
            MetadataField::Producer => VerificationSeverity::Critical,
            MetadataField::Title | MetadataField::Author => VerificationSeverity::Medium,
            _ => VerificationSeverity::Low,
        }
    }

    fn generate_authentication_report(
        &self,
        total_fields: usize,
        field_results: &HashMap<MetadataField, FieldAuthenticityResult>,
        failed_verifications: Vec<FailedVerification>,
        temporal_analysis: &TemporalAnalysis,
    ) -> AuthenticationReport {
        let authentic_fields = field_results.values()
            .filter(|result| result.is_authentic)
            .count();
        
        let suspicious_fields = field_results.values()
            .filter(|result| !result.is_authentic && result.confidence_score < 0.7)
            .count();

        AuthenticationReport {
            total_fields_verified: total_fields,
            authentic_fields,
            suspicious_fields,
            failed_verifications,
            timestamp_consistency: temporal_analysis.temporal_consistency,
            software_signature_valid: self.verify_software_signatures(field_results),
        }
    }

    fn verify_software_signatures(&self, field_results: &HashMap<MetadataField, FieldAuthenticityResult>) -> bool {
        if let Some(producer_result) = field_results.get(&MetadataField::Producer) {
            producer_result.is_authentic
        } else {
            false
        }
    }
}

impl Default for MetadataAuthenticator {
    fn default() -> Self {
        Self::new()
    }
  }
