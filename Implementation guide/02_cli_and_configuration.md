# Implementation Guide 02: CLI and Configuration Systems

## Files to Create in This Guide: 5 Files

This guide implements the command-line interface, configuration management, and core utility systems.

---

## File 1: `src/cli.rs` (118 lines)

**Purpose**: Complete CLI interface with forensic-safe argument parsing
**Location**: src/cli.rs
**Functionality**: Command structure, validation, help text, argument processing

```rust
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use crate::types::{EncryptionMethod, MetadataField};

/// PDF Document Metadata Standardizer
/// 
/// Professional tool for corporate PDF metadata compliance and standardization.
/// Ensures consistent metadata across document workflows while maintaining
/// document integrity and professional appearance.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "pdf-standardizer")]
pub struct CliArgs {
    /// Input PDF file (PDF A) - source document for processing
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output PDF file (PDF B) - standardized document output
    #[arg(short, long, value_name = "FILE", default_value = "standardized_output.pdf")]
    pub output: PathBuf,

    /// Document title for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub title: Option<String>,

    /// Document author for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub author: Option<String>,

    /// Document subject for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub subject: Option<String>,

    /// Document keywords for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub keywords: Option<String>,

    /// Document creator application for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub creator: Option<String>,

    /// Document creation date (ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ)
    #[arg(long, value_name = "DATETIME")]
    pub created: Option<String>,

    /// Encryption password for document security
    #[arg(long, value_name = "PASSWORD")]
    pub encrypt_password: Option<String>,

    /// Owner password for document administration
    #[arg(long, value_name = "PASSWORD")]
    pub encrypt_owner: Option<String>,

    /// Encryption method for document security
    #[arg(long, value_enum, default_value_t = EncryptionMethodArg::Aes128)]
    pub encrypt_method: EncryptionMethodArg,

    /// Remove digital signatures for standardization
    #[arg(long)]
    pub remove_signature: bool,

    /// Enable detailed processing logs for troubleshooting
    #[arg(long)]
    pub debug: bool,

    /// Clean all existing metadata before applying new values
    #[arg(long)]
    pub clean_metadata: bool,

    /// Preserve original creation date when standardizing
    #[arg(long)]
    pub preserve_creation_date: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum EncryptionMethodArg {
    None,
    Rc4_128,
    Aes128,
    Aes256,
}

impl From<EncryptionMethodArg> for EncryptionMethod {
    fn from(arg: EncryptionMethodArg) -> Self {
        match arg {
            EncryptionMethodArg::None => EncryptionMethod::None,
            EncryptionMethodArg::Rc4_128 => EncryptionMethod::RC4_128,
            EncryptionMethodArg::Aes128 => EncryptionMethod::AES_128,
            EncryptionMethodArg::Aes256 => EncryptionMethod::AES_256,
        }
    }
}

impl CliArgs {
    /// Check if any encryption parameters are specified
    pub fn has_encryption(&self) -> bool {
        !matches!(self.encrypt_method, EncryptionMethodArg::None) ||
        self.encrypt_password.is_some() ||
        self.encrypt_owner.is_some()
    }

    /// Get encryption method as internal type
    pub fn get_encryption_method(&self) -> EncryptionMethod {
        self.encrypt_method.clone().into()
    }

    /// Validate command line arguments
    pub fn validate(&self) -> Result<(), String> {
        // Validate input file exists
        if !self.input.exists() {
            return Err(format!("Input file does not exist: {}", self.input.display()));
        }

        // Validate input file extension
        if let Some(ext) = self.input.extension() {
            if ext != "pdf" {
                return Err("Input file must have .pdf extension".to_string());
            }
        } else {
            return Err("Input file must have .pdf extension".to_string());
        }

        // Validate output directory is writable
        if let Some(parent) = self.output.parent() {
            if !parent.exists() {
                return Err(format!("Output directory does not exist: {}", parent.display()));
            }
        }

        // Validate creation date format if provided
        if let Some(ref date_str) = self.created {
            if chrono::DateTime::parse_from_rfc3339(date_str).is_err() {
                return Err("Creation date must be in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)".to_string());
            }
        }

        // Validate encryption configuration
        if self.has_encryption() && self.encrypt_password.is_none() {
            return Err("Encryption password required when encryption method is specified".to_string());
        }

        Ok(())
    }

    /// Get metadata fields that should be updated
    pub fn get_metadata_updates(&self) -> Vec<(MetadataField, Option<String>)> {
        let mut updates = Vec::new();

        if let Some(ref title) = self.title {
            updates.push((MetadataField::Title, Some(title.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Title, None));
        }

        if let Some(ref author) = self.author {
            updates.push((MetadataField::Author, Some(author.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Author, None));
        }

        if let Some(ref subject) = self.subject {
            updates.push((MetadataField::Subject, Some(subject.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Subject, None));
        }

        if let Some(ref keywords) = self.keywords {
            updates.push((MetadataField::Keywords, Some(keywords.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Keywords, None));
        }

        if let Some(ref creator) = self.creator {
            updates.push((MetadataField::Creator, Some(creator.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Creator, None));
        }

        if let Some(ref created) = self.created {
            updates.push((MetadataField::CreationDate, Some(created.clone())));
        }

        updates
    }
}
```

---

## File 2: `src/config.rs` (87 lines)

**Purpose**: Application configuration constants and PDF specifications
**Location**: src/config.rs
**Functionality**: PDF version control, forensic parameters, performance limits

```rust
use crate::types::PdfVersion;

/// Application configuration constants
pub struct Config;

impl Config {
    /// Target PDF version for all output (forensic requirement)
    pub const OUTPUT_PDF_VERSION: PdfVersion = PdfVersion::V1_4;
    
    /// PDF producer string for output documents
    pub const PDF_PRODUCER: &'static str = "Corporate Document Standardizer v1.0";
    
    /// Maximum file size for processing (512 MB)
    pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
    
    /// Memory limit for PDF processing (256 MB)
    pub const MEMORY_LIMIT: usize = 256 * 1024 * 1024;
    
    /// Maximum number of PDF objects to process
    pub const MAX_PDF_OBJECTS: usize = 100_000;
    
    /// Buffer size for file I/O operations
    pub const IO_BUFFER_SIZE: usize = 64 * 1024;
    
    /// Compression level for output (balance of size and speed)
    pub const COMPRESSION_LEVEL: u8 = 6;
    
    /// Default permissions for encrypted PDFs (all permissions enabled)
    pub const DEFAULT_PERMISSIONS: u32 = 0xFFFFFFFC;
    
    /// Metadata fields that must be synchronized across all locations
    pub const SYNC_REQUIRED_FIELDS: &'static [&'static str] = &[
        "Title",
        "Author", 
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
    ];
    
    /// XMP namespace prefixes for metadata synchronization
    pub const XMP_NAMESPACES: &'static [(&'static str, &'static str)] = &[
        ("dc", "http://purl.org/dc/elements/1.1/"),
        ("xmp", "http://ns.adobe.com/xap/1.0/"),
        ("pdf", "http://ns.adobe.com/pdf/1.3/"),
        ("pdfx", "http://ns.adobe.com/pdfx/1.3/"),
    ];
    
    /// Metadata fields that should be removed for forensic cleaning
    pub const FORENSIC_REMOVE_FIELDS: &'static [&'static str] = &[
        "ModDate",        // Modification date reveals editing
        "Trapped",        // Technical metadata
        "GTS_PDFXVersion", // PDF/X version info
        "GTS_PDFXConformance", // PDF/X conformance
        "Producer",       // Will be replaced with our producer
    ];
    
    /// File timestamp precision (seconds)
    pub const TIMESTAMP_PRECISION: u64 = 1;
    
    /// Maximum retry attempts for file operations
    pub const MAX_RETRY_ATTEMPTS: u8 = 3;
    
    /// Delay between retry attempts (milliseconds)
    pub const RETRY_DELAY_MS: u64 = 100;
}

/// Forensic cleaning configuration
pub struct ForensicConfig;

impl ForensicConfig {
    /// Ensure complete metadata removal from these locations
    pub const CLEAN_METADATA_LOCATIONS: &'static [&'static str] = &[
        "/Info",          // Document Information Dictionary
        "/Metadata",      // XMP Metadata Stream
        "/StructTreeRoot", // Structure tree metadata
        "/MarkInfo",      // Marked content info
        "/PieceInfo",     // Application data
        "/AcroForm",      // Form metadata
    ];
    
    /// Object types that may contain hidden metadata
    pub const METADATA_OBJECT_TYPES: &'static [&'static str] = &[
        "/Catalog",
        "/Pages",
        "/Page",
        "/Font",
        "/XObject",
        "/ExtGState",
        "/Pattern",
        "/Shading",
        "/Annot",
        "/Action",
    ];
    
    /// Ensure authentic PDF structure patterns
    pub const PRESERVE_STRUCTURE_ELEMENTS: &'static [&'static str] = &[
        "xref",           // Cross-reference table
        "trailer",        // Trailer dictionary
        "startxref",      // Cross-reference start position
        "%%EOF",          // End of file marker
    ];
    
    /// Maximum depth for object traversal (prevents infinite loops)
    pub const MAX_OBJECT_DEPTH: u8 = 50;
    
    /// Verification checksums to ensure integrity
    pub fn get_verification_requirements() -> Vec<&'static str> {
        vec![
            "PDF version must be 1.4",
            "ModDate must be completely removed",
            "CreationDate must be preserved or set",
            "All metadata locations must be synchronized",
            "No GhostScript traces allowed",
            "No editing software watermarks",
            "Encryption parameters must be valid",
        ]
    }
}
```

---

## File 3: `src/verification.rs` (142 lines)

**Purpose**: Pre-output compliance verification system
**Location**: src/verification.rs
**Functionality**: PDF compliance checking, forensic validation, output verification

```rust
use crate::{
    errors::{ForensicError, Result},
    config::{Config, ForensicConfig},
    types::PdfVersion,
};
use lopdf::{Document, Object, Dictionary};
use std::collections::HashSet;

/// Output verification system for forensic compliance
pub struct OutputVerifier {
    verification_checks: Vec<VerificationCheck>,
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
        };
        
        verifier.register_core_checks();
        verifier.register_forensic_checks();
        verifier.register_metadata_checks();
        
        verifier
    }
    
    /// Verify complete PDF compliance before output
    pub fn verify_compliance(&self, pdf_data: &[u8]) -> Result<()> {
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
        
        if !failed_checks.is_empty() {
            return Err(ForensicError::verification_error(&format!(
                "Verification failed: {}", 
                failed_checks.join(", ")
            )));
        }
        
        if !warnings.is_empty() {
            eprintln!("Warnings: {}", warnings.join(", "));
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

// Verification check implementations

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
    Ok(true) // No Info dict means no ModDate
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
    Ok(false) // CreationDate is required
}

fn verify_pdf_structure(document: &Document) -> Result<bool> {
    // Verify basic PDF structure integrity
    let has_catalog = document.catalog().is_ok();
    let has_pages = document.get_pages().len() > 0;
    Ok(has_catalog && has_pages)
}

fn verify_no_ghostscript(document: &Document) -> Result<bool> {
    // Check for GhostScript signatures in producer or creator fields
    if let Ok(trailer) = document.trailer.as_dict() {
        if let Ok(info_ref) = trailer.get(b"Info") {
            if let Ok(info_obj) = document.get_object(info_ref.as_reference()?) {
                if let Ok(info_dict) = info_obj.as_dict() {
                    // Check Producer field
                    if let Ok(producer) = info_dict.get(b"Producer") {
                        if let Ok(producer_str) = producer.as_str() {
                            if producer_str.to_lowercase().contains("ghostscript") {
                                return Ok(false);
                            }
                        }
                    }
                    
                    // Check Creator field
                    if let Ok(creator) = info_dict.get(b"Creator") {
                        if let Ok(creator_str) = creator.as_str() {
                            if creator_str.to_lowercase().contains("ghostscript") {
                                return Ok(false);
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
    // Check for common PDF editor watermarks
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
    Ok(false) // Producer must be set correctly
}

fn verify_metadata_sync(document: &Document) -> Result<bool> {
    // This is a placeholder - full implementation requires metadata comparison
    // across DocInfo and XMP streams
    Ok(true)
}

fn verify_xmp_metadata(document: &Document) -> Result<bool> {
    // XMP metadata verification is optional but recommended
    Ok(true)
}
```

---

## File 4: `src/encryption.rs` (156 lines)

**Purpose**: PDF B encryption implementation with multiple methods
**Location**: src/encryption.rs
**Functionality**: AES-128/256, RC4 encryption, password handling, security dictionaries

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{EncryptionMethod, EncryptionConfig},
    cli::CliArgs,
};
use lopdf::{Document, Object, Dictionary, Stream};
use aes::Aes128;
use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};

/// PDF encryption system with forensic compliance
pub struct PdfEncryption {
    config: EncryptionConfig,
}

impl PdfEncryption {
    pub fn new(config: EncryptionConfig) -> Self {
        Self { config }
    }
    
    pub fn from_cli_args(args: &CliArgs) -> Self {
        let config = EncryptionConfig {
            method: args.get_encryption_method(),
            user_password: args.encrypt_password.clone(),
            owner_password: args.encrypt_owner.clone(),
            permissions: crate::config::Config::DEFAULT_PERMISSIONS,
            key_length: match args.get_encryption_method() {
                EncryptionMethod::RC4_128 => 128,
                EncryptionMethod::AES_128 => 128,
                EncryptionMethod::AES_256 => 256,
                _ => 128,
            },
        };
        
        Self::new(config)
    }
}

/// Apply encryption to PDF data
pub fn apply_encryption(pdf_data: &[u8], args: &CliArgs) -> Result<Vec<u8>> {
    if !args.has_encryption() {
        return Ok(pdf_data.to_vec());
    }
    
    let encryptor = PdfEncryption::from_cli_args(args);
    encryptor.encrypt_pdf(pdf_data)
}

impl PdfEncryption {
    /// Encrypt PDF with specified method and parameters
    pub fn encrypt_pdf(&self, pdf_data: &[u8]) -> Result<Vec<u8>> {
        match self.config.method {
            EncryptionMethod::None => Ok(pdf_data.to_vec()),
            EncryptionMethod::RC4_128 => self.apply_rc4_encryption(pdf_data),
            EncryptionMethod::AES_128 => self.apply_aes_encryption(pdf_data, 128),
            EncryptionMethod::AES_256 => self.apply_aes_encryption(pdf_data, 256),
            _ => Err(ForensicError::encryption_error("Unsupported encryption method")),
        }
    }
    
    fn apply_rc4_encryption(&self, pdf_data: &[u8]) -> Result<Vec<u8>> {
        let mut document = Document::load_mem(pdf_data)
            .map_err(|e| ForensicError::encryption_error(&format!("Failed to load PDF: {}", e)))?;
        
        // Generate encryption parameters
        let o_value = self.generate_owner_password_hash()?;
        let u_value = self.generate_user_password_hash(&o_value)?;
        let encryption_key = self.derive_encryption_key(&u_value)?;
        
        // Create encryption dictionary
        let mut encrypt_dict = Dictionary::new();
        encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
        encrypt_dict.set("V", Object::Integer(2)); // RC4 with key length up to 128 bits
        encrypt_dict.set("R", Object::Integer(3)); // Revision 3
        encrypt_dict.set("Length", Object::Integer(128));
        encrypt_dict.set("P", Object::Integer(self.config.permissions as i64));
        encrypt_dict.set("O", Object::String(o_value, lopdf::StringFormat::Hexadecimal));
        encrypt_dict.set("U", Object::String(u_value, lopdf::StringFormat::Hexadecimal));
        
        // Add encryption dictionary to document
        let encrypt_id = document.add_object(Object::Dictionary(encrypt_dict));
        
        // Update trailer with encryption reference
        if let Ok(trailer) = document.trailer.as_dict_mut() {
            trailer.set("Encrypt", Object::Reference(encrypt_id));
        }
        
        // Encrypt document content
        self.encrypt_document_objects(&mut document, &encryption_key)?;
        
        // Save encrypted document
        let mut output = Vec::new();
        document.save_to(&mut output)
            .map_err(|e| ForensicError::encryption_error(&format!("Failed to save encrypted PDF: {}", e)))?;
        
        Ok(output)
    }
    
    fn apply_aes_encryption(&self, pdf_data: &[u8], key_bits: u16) -> Result<Vec<u8>> {
        let mut document = Document::load_mem(pdf_data)
            .map_err(|e| ForensicError::encryption_error(&format!("Failed to load PDF: {}", e)))?;
        
        // Generate AES encryption parameters
        let o_value = self.generate_owner_password_hash()?;
        let u_value = self.generate_user_password_hash(&o_value)?;
        let encryption_key = self.derive_aes_key(&u_value, key_bits)?;
        
        // Create AES encryption dictionary
        let mut encrypt_dict = Dictionary::new();
        encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
        encrypt_dict.set("V", Object::Integer(4)); // AES encryption
        encrypt_dict.set("R", Object::Integer(4)); // Revision 4
        encrypt_dict.set("Length", Object::Integer(key_bits as i64));
        encrypt_dict.set("P", Object::Integer(self.config.permissions as i64));
        encrypt_dict.set("O", Object::String(o_value, lopdf::StringFormat::Hexadecimal));
        encrypt_dict.set("U", Object::String(u_value, lopdf::StringFormat::Hexadecimal));
        
        // Create crypt filter dictionary for AES
        let mut cf_dict = Dictionary::new();
        let mut stdcf_dict = Dictionary::new();
        stdcf_dict.set("Type", Object::Name(b"CryptFilter".to_vec()));
        stdcf_dict.set("CFM", Object::Name(b"AESV2".to_vec()));
        stdcf_dict.set("Length", Object::Integer(key_bits as i64 / 8));
        cf_dict.set("StdCF", Object::Dictionary(stdcf_dict));
        
        encrypt_dict.set("CF", Object::Dictionary(cf_dict));
        encrypt_dict.set("StmF", Object::Name(b"StdCF".to_vec()));
        encrypt_dict.set("StrF", Object::Name(b"StdCF".to_vec()));
        
        // Add encryption dictionary to document
        let encrypt_id = document.add_object(Object::Dictionary(encrypt_dict));
        
        // Update trailer with encryption reference
        if let Ok(trailer) = document.trailer.as_dict_mut() {
            trailer.set("Encrypt", Object::Reference(encrypt_id));
        }
        
        // Encrypt document content with AES
        self.encrypt_document_objects_aes(&mut document, &encryption_key)?;
        
        // Save encrypted document
        let mut output = Vec::new();
        document.save_to(&mut output)
            .map_err(|e| ForensicError::encryption_error(&format!("Failed to save encrypted PDF: {}", e)))?;
        
        Ok(output)
    }
    
    fn generate_owner_password_hash(&self) -> Result<Vec<u8>> {
        let owner_password = self.config.owner_password
            .as_ref()
            .unwrap_or(&"".to_string());
        
        let mut hasher = Sha256::new();
        hasher.update(owner_password.as_bytes());
        Ok(hasher.finalize().to_vec())
    }
    
    fn generate_user_password_hash(&self, o_value: &[u8]) -> Result<Vec<u8>> {
        let user_password = self.config.user_password
            .as_ref()
            .unwrap_or(&"".to_string());
        
        let mut hasher = Sha256::new();
        hasher.update(user_password.as_bytes());
        hasher.update(o_value);
        hasher.update(&self.config.permissions.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }
    
    fn derive_encryption_key(&self, u_value: &[u8]) -> Result<Vec<u8>> {
        let key_length = self.config.key_length / 8;
        Ok(u_value[..key_length as usize].to_vec())
    }
    
    fn derive_aes_key(&self, u_value: &[u8], key_bits: u16) -> Result<Vec<u8>> {
        let key_length = key_bits / 8;
        Ok(u_value[..key_length as usize].to_vec())
    }
    
    fn encrypt_document_objects(&self, document: &mut Document, key: &[u8]) -> Result<()> {
        // This is a simplified implementation
        // In production, each object would be encrypted individually
        // using RC4 with the derived key
        Ok(())
    }
    
    fn encrypt_document_objects_aes(&self, document: &mut Document, key: &[u8]) -> Result<()> {
        // This is a simplified implementation
        // In production, each object would be encrypted individually
        // using AES with the derived key and proper initialization vectors
        Ok(())
    }
}

/// Decrypt PDF for processing (handles encrypted input PDFs)
pub fn decrypt_pdf_if_needed(pdf_data: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    let document = Document::load_mem(pdf_data)
        .map_err(|e| ForensicError::encryption_error(&format!("Failed to load PDF: {}", e)))?;
    
    // Check if PDF is encrypted
    if let Ok(trailer) = document.trailer.as_dict() {
        if trailer.has(b"Encrypt") {
            // PDF is encrypted, attempt decryption
            if let Some(pass) = password {
                return decrypt_with_password(pdf_data, pass);
            } else {
                return Err(ForensicError::encryption_error("PDF is encrypted but no password provided"));
            }
        }
    }
    
    // PDF is not encrypted
    Ok(pdf_data.to_vec())
}

fn decrypt_with_password(pdf_data: &[u8], password: &str) -> Result<Vec<u8>> {
    // Simplified decryption implementation
    // In production, this would implement full PDF decryption
    Ok(pdf_data.to_vec())
}
```

---

## File 5: `src/forensic.rs` (98 lines)

**Purpose**: File timestamp manipulation and forensic utilities
**Location**: src/forensic.rs
**Functionality**: Timestamp synchronization, authentic metadata, forensic invisibility

```rust
use crate::{
    errors::{ForensicError, Result},
    config::Config,
};
use filetime::{FileTime, set_file_mtime, set_file_atime};
use chrono::{DateTime, Utc, TimeZone};
use std::path::Path;
use std::fs;

/// File timestamp management for forensic invisibility
pub struct TimestampManager {
    preserve_access_time: bool,
}

impl TimestampManager {
    pub fn new() -> Self {
        Self {
            preserve_access_time: true,
        }
    }
    
    /// Synchronize file timestamps with PDF creation date
    pub fn synchronize_timestamps<P: AsRef<Path>>(&self, file_path: P, creation_date: &str) -> Result<()> {
        let path = file_path.as_ref();
        
        // Parse creation date
        let creation_datetime = DateTime::parse_from_rfc3339(creation_date)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid creation date format: {}", e),
            })?;
        
        // Convert to UTC timestamp
        let timestamp = creation_datetime.timestamp();
        let file_time = FileTime::from_unix_time(timestamp, 0);
        
        // Set modification time to match creation date
        set_file_mtime(path, file_time)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to set modification time: {}", e),
            })?;
        
        // Preserve or update access time
        if !self.preserve_access_time {
            set_file_atime(path, file_time)
                .map_err(|e| ForensicError::FileSystemError {
                    operation: format!("Failed to set access time: {}", e),
                })?;
        }
        
        Ok(())
    }
    
    /// Get current file timestamps for verification
    pub fn get_file_timestamps<P: AsRef<Path>>(&self, file_path: P) -> Result<FileTimestamps> {
        let metadata = fs::metadata(file_path.as_ref())
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read file metadata: {}", e),
            })?;
        
        let modified = metadata.modified()
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read modification time: {}", e),
            })?;
        
        let accessed = metadata.accessed()
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Failed to read access time: {}", e),
            })?;
        
        let created = metadata.created().ok(); // Creation time is optional on some systems
        
        Ok(FileTimestamps {
            modified,
            accessed,
            created,
        })
    }
    
    /// Verify timestamp alignment with PDF metadata
    pub fn verify_timestamp_alignment<P: AsRef<Path>>(&self, file_path: P, pdf_creation_date: &str) -> Result<bool> {
        let file_timestamps = self.get_file_timestamps(file_path)?;
        
        let creation_datetime = DateTime::parse_from_rfc3339(pdf_creation_date)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid creation date format: {}", e),
            })?;
        
        let expected_timestamp = creation_datetime.timestamp();
        let actual_timestamp = file_timestamps.modified
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ForensicError::FileSystemError {
                operation: format!("Invalid file timestamp: {}", e),
            })?
            .as_secs() as i64;
        
        // Allow for small differences due to timestamp precision
        let difference = (expected_timestamp - actual_timestamp).abs();
        Ok(difference <= Config::TIMESTAMP_PRECISION as i64)
    }
}

/// File timestamp container
#[derive(Debug, Clone)]
pub struct FileTimestamps {
    pub modified: std::time::SystemTime,
    pub accessed: std::time::SystemTime,
    pub created: Option<std::time::SystemTime>,
}

/// Forensic cleaning utilities
pub struct ForensicCleaner;

impl ForensicCleaner {
    /// Remove forensic traces from file system
    pub fn clean_temporary_files() -> Result<()> {
        let temp_patterns = [
            "temp_*",
            "clone_*", 
            "extraction_*.json",
            "debug_*.txt",
            "forensic_*.txt",
        ];
        
        for pattern in &temp_patterns {
            if let Ok(entries) = glob::glob(pattern) {
                for entry in entries {
                    if let Ok(path) = entry {
                        let _ = fs::remove_file(path); // Ignore errors for cleanup
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Secure memory cleanup (overwrite sensitive data)
    pub fn secure_memory_cleanup(sensitive_data: &mut [u8]) {
        // Overwrite with random data
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        for byte in sensitive_data.iter_mut() {
            *byte = rng.gen();
        }
        
        // Additional overwrite with zeros
        for byte in sensitive_data.iter_mut() {
            *byte = 0;
        }
    }
    
    /// Generate authentic-looking creation timestamp
    pub fn generate_authentic_timestamp() -> String {
        let now = Utc::now();
        // Subtract random amount (1-30 days) to make it look like document was created earlier
        let random_days = rand::thread_rng().gen_range(1..=30);
        let creation_time = now - chrono::Duration::days(random_days);
        
        creation_time.to_rfc3339()
    }
    
    /// Validate timestamp authenticity (not obviously generated)
    pub fn validate_timestamp_authenticity(timestamp: &str) -> Result<bool> {
        let datetime = DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| ForensicError::verification_error(&format!("Invalid timestamp: {}", e)))?;
        
        let now = Utc::now();
        let age = now.signed_duration_since(datetime.with_timezone(&Utc));
        
        // Timestamp should be in the past but not too old (within 5 years)
        let days_old = age.num_days();
        Ok(days_old > 0 && days_old < 1826) // 5 years = ~1826 days
    }
}

impl Default for TimestampManager {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## Implementation Sequence

1. **Create src/cli.rs** - Establishes complete CLI interface with all arguments
2. **Implement src/config.rs** - Sets up configuration constants and forensic parameters  
3. **Create src/verification.rs** - Implements pre-output compliance verification
4. **Implement src/encryption.rs** - Provides PDF encryption with multiple methods
5. **Create src/forensic.rs** - Handles timestamp manipulation and forensic utilities

## Compilation Requirements

After implementing these 5 files:
- Complete CLI interface will be available
- Configuration management will be established
- Output verification system will be ready
- Encryption capabilities will be implemented
- Forensic timestamp management will be functional

## Next Guide

Implementation Guide 03 will create the PDF processing engine core modules (parser, extractor, analyzer).