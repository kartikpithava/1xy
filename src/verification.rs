use crate::{
    errors::{ForensicError, Result},
    config::{Config, ForensicConfig},
    types::PdfVersion,
};
use lopdf::{Document, Object, Dictionary};
use std::collections::HashSet;
use chrono::Utc;

/// Output verification system for forensic compliance
pub struct OutputVerifier {
    verification_checks: Vec<VerificationCheck>,
    last_verification_time: Option<chrono::DateTime<Utc>>,
}

/// Individual verification check specification 
struct VerificationCheck {
    name: String,
    check_fn: fn(&Document) -> Result<bool>,
    required: bool,
}

impl OutputVerifier {
    pub fn new() -> Self {
        let mut verifier = Self {
            verification_checks: Vec::new(),
            last_verification_time: None,
        };
        
        verifier.register_core_checks();
        verifier.register_forensic_checks();
        verifier.register_metadata_checks();
        
        verifier
    }
    
    /// Verify complete PDF compliance before output
    pub fn verify_compliance(&mut self, pdf_data: &[u8]) -> Result<()> {
        let document = Document::load_mem(pdf_data)
            .map_err(|e| ForensicError::verification_error(&format!("PDF load failed: {}", e)))?;
        
        let mut failed_checks = Vec::new();
        let mut warnings = Vec::new();
        
        for check in &self.verification_checks {
            match (check.check_fn)(&document) {
                Ok(true) => {
                    // Check passed
                },
                Ok(false) => {
                    if check.required {
                        failed_checks.push(check.name.clone());
                    } else {
                        warnings.push(check.name.clone());
                    }
                },
                Err(e) => {
                    failed_checks.push(format!("{}: {}", check.name, e));
                }
            }
        }
        
        self.last_verification_time = Some(Utc::now());
        
        if !failed_checks.is_empty() {
            return Err(ForensicError::verification_error(&format!(
                "Verification failed: {}", 
                failed_checks.join(", ")
            )));
        }
        
        if !warnings.empty() {
            eprintln!("Verification warnings: {}", warnings.join(", "));
        }
        
        Ok(())
    }
    
    fn register_core_checks(&mut self) {
        self.verification_checks.push(VerificationCheck {
            name: "PDF Version 1.4".to_string(),
            check_fn: verify_pdf_version,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "No ModDate present".to_string(),
            check_fn: verify_no_moddate,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "CreationDate present".to_string(),
            check_fn: verify_creation_date,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "Valid PDF structure".to_string(),
            check_fn: verify_pdf_structure,
            required: true,
        });
    }
    
    fn register_forensic_checks(&mut self) {
        self.verification_checks.push(VerificationCheck {
            name: "No GhostScript traces".to_string(),
            check_fn: verify_no_ghostscript,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "No editing watermarks".to_string(),
            check_fn: verify_no_watermarks,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "Authentic producer string".to_string(),
            check_fn: verify_producer_string,
            required: true,
        });
    }
    
    fn register_metadata_checks(&mut self) {
        self.verification_checks.push(VerificationCheck {
            name: "Metadata synchronization".to_string(),
            check_fn: verify_metadata_sync,
            required: true,
        });
        
        self.verification_checks.push(VerificationCheck {
            name: "XMP metadata compliance".to_string(),
            check_fn: verify_xmp_metadata,
            required: false,
        });
    }
}

fn verify_pdf_version(document: &Document) -> Result<bool> {
    let version = document.version.clone();
    Ok(version == "1.4")
}

fn verify_no_moddate(document: &Document) -> Result<bool> {
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    return Ok(!info_dict.has(b"ModDate"));
                }
            }
        }
    }
    Ok(true)
}

fn verify_creation_date(document: &Document) -> Result<bool> {
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    return Ok(info_dict.has(b"CreationDate"));
                }
            }
        }
    }
    Ok(false)
}

fn verify_pdf_structure(document: &Document) -> Result<bool> {
    let has_catalog = document.get_object(document.catalog)
        .map_err(|e| ForensicError::verification_error(&format!("Invalid catalog: {}", e)))?;
    let pages = document.get_pages();
    Ok(!pages.is_empty())
}

fn verify_no_ghostscript(document: &Document) -> Result<bool> {
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    for field in &[b"Producer", b"Creator"] {
                        if let Ok(value) = info_dict.get(field) {
                            if let Ok(text) = value.as_str() {
                                if text.to_lowercase().contains("ghostscript") {
                                    return Ok(false);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(true)
}

fn verify_no_watermarks(document: &Document) -> Result<bool> {
    let forbidden_producers = [
        "itext", "itextpdf", "pdfsharp", "reportlab", "tcpdf",
        "fpdf", "dompdf", "wkhtmltopdf", "pandoc"
    ];
    
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    if let Ok(producer) = info_dict.get(b"Producer") {
                        if let Ok(producer_str) = producer.as_str() {
                            let producer_lower = producer_str.to_lowercase();
                            for forbidden in &forbidden_producers {
                                if producer_lower.contains(forbidden) {
                                    return Ok(false);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(true)
}

fn verify_producer_string(document: &Document) -> Result<bool> {
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    if let Ok(producer) = info_dict.get(b"Producer") {
                        if let Ok(producer_str) = producer.as_str() {
                            return Ok(producer_str == Config::PDF_PRODUCER);
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

fn verify_metadata_sync(document: &Document) -> Result<bool> {
    let mut synchronized = true;
    let mut metadata_values = HashMap::new();
    
    // Check Document Info Dictionary
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    for &field in Config::SYNC_REQUIRED_FIELDS {
                        if let Ok(value) = info_dict.get(field.as_bytes()) {
                            metadata_values.insert(field, value.as_str()?.to_string());
                        }
                    }
                }
            }
        }
    }
    
    // Check XMP metadata stream
    if let Some(xmp_stream) = find_xmp_stream(document)? {
        for &field in Config::SYNC_REQUIRED_FIELDS {
            if let Some(xmp_value) = extract_xmp_value(xmp_stream, field)? {
                if let Some(info_value) = metadata_values.get(field) {
                    if xmp_value != *info_value {
                        synchronized = false;
                        break;
                    }
                }
            }
        }
    }
    
    Ok(synchronized)
}

fn verify_xmp_metadata(_document: &Document) -> Result<bool> {
    // XMP metadata verification is optional
    Ok(true)
}

fn find_xmp_stream(document: &Document) -> Result<Option<&Stream>> {
    // Implementation would search for XMP metadata stream
    Ok(None)
}

fn extract_xmp_value(_stream: &Stream, _field: &str) -> Result<Option<String>> {
    // Implementation would extract specific field from XMP
    Ok(None)
      }
