use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, PdfVersion},
};
use std::path::PathBuf;

/// Application version and metadata
pub const VERSION: &str = "1.0.0";
pub const BUILD_DATE: &str = "2025-06-13";
pub const AUTHOR: &str = "Corporate Documentation Team";

/// Parser settings for PDF processing
#[derive(Debug, Clone)]
pub struct ParserSettings {
    pub max_object_size: usize,
    pub max_stream_size: usize,
    pub max_string_length: usize,
    pub max_array_length: usize,
    pub max_dict_length: usize,
}

/// Configuration for data serialization
#[derive(Debug, Clone)]
pub struct SerializationConfig {
    pub compression_enabled: bool,
    pub use_base64: bool,
    pub chunk_size: usize,
    pub buffer_size: usize,
}

/// Settings for PDF reconstruction
#[derive(Debug, Clone)]
pub struct ReconstructionSettings {
    pub preserve_structure: bool,
    pub optimize_output: bool,
    pub validate_output: bool,
    pub maintain_authenticity: bool,
}

/// System-wide operational settings
#[derive(Debug, Clone)]
pub struct SystemSettings {
    pub max_threads: usize,
    pub temp_dir: PathBuf,
    pub cleanup_on_exit: bool,
    pub debug_logging: bool,
}

/// Security and protection settings
#[derive(Debug, Clone)]
pub struct SecuritySettings {
    pub secure_memory: bool,
    pub wipe_temp_files: bool,
    pub encrypt_temp_data: bool,
    pub verify_signatures: bool,
}

/// Anti-forensic operation settings
#[derive(Debug, Clone)]
pub struct AntiForensicSettings {
    pub obfuscation_enabled: bool,
    pub inject_decoys: bool,
    pub spoof_timestamps: bool,
    pub mask_patterns: bool,
}

/// Metadata validation rules
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub field: &'static str,
    pub format: &'static str,
    pub required: bool,
}

/// Application configuration constants
#[derive(Debug, Clone)]
pub struct Config;

impl Config {
    /// Target PDF version for output
    pub const OUTPUT_PDF_VERSION: PdfVersion = PdfVersion::V1_4;

    /// Official producer string
    pub const PDF_PRODUCER: &'static str = "Corporate Document Standardizer v1.0";

    /// File size and memory limits
    pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;  // 512 MB
    pub const MEMORY_LIMIT: usize = 256 * 1024 * 1024; // 256 MB
    pub const MAX_PDF_OBJECTS: usize = 100_000;
    pub const IO_BUFFER_SIZE: usize = 64 * 1024;       // 64 KB

    /// Processing settings
    pub const COMPRESSION_LEVEL: u8 = 6;
    pub const DEFAULT_PERMISSIONS: u32 = 0xFFFFFFFC;
    pub const MAX_RETRY_ATTEMPTS: u8 = 3;
    pub const RETRY_DELAY_MS: u64 = 100;

    /// File prefixes
    pub const TEMP_FILE_PREFIX: &'static str = "pdf_forensic_";
    pub const LOG_FILE_PREFIX: &'static str = "pdf_log_";

    /// Required metadata fields
    pub const SYNC_REQUIRED_FIELDS: &'static [&'static str] = &[
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
    ];

    /// XMP metadata namespaces
    pub const XMP_NAMESPACES: &'static [(&'static str, &'static str)] = &[
        ("dc", "http://purl.org/dc/elements/1.1/"),
        ("xmp", "http://ns.adobe.com/xap/1.0/"),
        ("pdf", "http://ns.adobe.com/pdf/1.3/"),
        ("pdfx", "http://ns.adobe.com/pdfx/1.3/"),
    ];

    /// Parser configuration
    pub const PARSER_SETTINGS: ParserSettings = ParserSettings {
        max_object_size: 50 * 1024 * 1024,   // 50 MB
        max_stream_size: 100 * 1024 * 1024,  // 100 MB
        max_string_length: 1024 * 1024,      // 1 MB
        max_array_length: 1_000_000,
        max_dict_length: 1_000_000,
    };

    /// Serialization configuration
    pub const SERIALIZATION_CONFIG: SerializationConfig = SerializationConfig {
        compression_enabled: true,
        use_base64: true,
        chunk_size: 1024 * 1024,  // 1 MB chunks
        buffer_size: 8192,        // 8 KB buffer
    };

    /// Reconstruction settings
    pub const RECONSTRUCTION_SETTINGS: ReconstructionSettings = ReconstructionSettings {
        preserve_structure: true,
        optimize_output: true,
        validate_output: true,
        maintain_authenticity: true,
    };

    /// System settings
    pub const SYSTEM_SETTINGS: SystemSettings = SystemSettings {
        max_threads: 4,
        temp_dir: PathBuf::new(), // Set at runtime
        cleanup_on_exit: true,
        debug_logging: false,
    };

    /// Compression patterns for authenticity
    pub const COMPRESSION_PATTERNS: &'static [(&'static str, &'static [u8])] = &[
        ("FlateDecode", &[0x78, 0x9C]),     // zlib header
        ("DCTDecode", &[0xFF, 0xD8, 0xFF]), // JPEG SOI
        ("LZWDecode", &[0x00]),             // LZW
    ];

    /// Authentic producer strings
    pub const AUTHENTIC_PRODUCERS: &'static [&'static str] = &[
        "Microsoft® Word",
        "Microsoft® Excel",
        "Adobe PDF Library",
        "Adobe InDesign",
        "Acrobat Distiller",
    ];
}

/// Forensic configuration for secure operation
#[derive(Debug, Clone)]
pub struct ForensicConfig;

impl ForensicConfig {
    /// Metadata locations for cleanup
    pub const CLEAN_METADATA_LOCATIONS: &'static [&'static str] = &[
        "/Info",          // Document Information Dictionary
        "/Metadata",      // XMP Metadata Stream
        "/StructTreeRoot", // Structure tree metadata
        "/MarkInfo",      // Marked content info
        "/PieceInfo",     // Application data
        "/AcroForm",      // Form metadata
    ];

    /// Fields to remove during cleaning
    pub const FORENSIC_REMOVE_FIELDS: &'static [&'static str] = &[
        "ModDate",
        "Trapped",
        "GTS_PDFXVersion",
        "GTS_PDFXConformance",
        "Producer",
    ];

    /// Object types that may contain metadata
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

    /// Critical PDF structure elements
    pub const PRESERVE_STRUCTURE_ELEMENTS: &'static [&'static str] = &[
        "xref",
        "trailer",
        "startxref",
        "%%EOF",
    ];

    /// Anti-forensic settings
    pub const ANTI_FORENSIC_SETTINGS: AntiForensicSettings = AntiForensicSettings {
        obfuscation_enabled: true,
        inject_decoys: true,
        spoof_timestamps: true,
        mask_patterns: true,
    };

    /// Security settings
    pub const SECURITY_SETTINGS: SecuritySettings = SecuritySettings {
        secure_memory: true,
        wipe_temp_files: true,
        encrypt_temp_data: true,
        verify_signatures: true,
    };

    /// Timestamp patterns
    pub const TIMESTAMP_PATTERNS: &'static [&'static str] = &[
        "D:%Y%m%d%H%M%S",
        "D:%Y%m%d%H%M%S%z",
        "D:%Y%m%d%H%M%SZ00'00'",
    ];

    /// File size patterns (min, max) in bytes
    pub const SIZE_PATTERNS: &'static [(usize, usize)] = &[
        (10_000, 100_000),      // Text documents
        (100_000, 1_000_000),   // With images
        (1_000_000, 5_000_000), // Complex documents
    ];

    /// Metadata validation rules
    pub const METADATA_VALIDATION: &'static [ValidationRule] = &[
        ValidationRule {
            field: "CreationDate",
            format: "D:\\d{14}[+-]\\d{2}'\\d{2}'",
            required: true,
        },
        ValidationRule {
            field: "Producer",
            format: "^(Adobe|Microsoft|LibreOffice).*",
            required: true,
        },
    ];

    /// Get verification requirements
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_constants() {
        assert_eq!(Config::OUTPUT_PDF_VERSION, PdfVersion::V1_4);
        assert!(Config::MAX_FILE_SIZE > 0);
        assert!(Config::MEMORY_LIMIT > 0);
        assert!(Config::MAX_PDF_OBJECTS > 0);
        assert!(Config::IO_BUFFER_SIZE > 0);
        assert!(Config::COMPRESSION_LEVEL <= 9);
    }

    #[test]
    fn test_parser_settings() {
        assert!(Config::PARSER_SETTINGS.max_object_size > 0);
        assert!(Config::PARSER_SETTINGS.max_stream_size > 0);
        assert!(Config::PARSER_SETTINGS.max_string_length > 0);
        assert!(Config::PARSER_SETTINGS.max_array_length > 0);
    }

    #[test]
    fn test_serialization_config() {
        assert!(Config::SERIALIZATION_CONFIG.chunk_size > 0);
        assert!(Config::SERIALIZATION_CONFIG.buffer_size > 0);
    }

    #[test]
    fn test_reconstruction_settings() {
        assert!(Config::RECONSTRUCTION_SETTINGS.preserve_structure);
        assert!(Config::RECONSTRUCTION_SETTINGS.validate_output);
    }

    #[test]
    fn test_system_settings() {
        assert!(Config::SYSTEM_SETTINGS.max_threads > 0);
        assert!(Config::SYSTEM_SETTINGS.cleanup_on_exit);
    }

    #[test]
    fn test_security_settings() {
        assert!(ForensicConfig::SECURITY_SETTINGS.secure_memory);
        assert!(ForensicConfig::SECURITY_SETTINGS.wipe_temp_files);
    }

    #[test]
    fn test_anti_forensic_settings() {
        assert!(ForensicConfig::ANTI_FORENSIC_SETTINGS.obfuscation_enabled);
        assert!(ForensicConfig::ANTI_FORENSIC_SETTINGS.mask_patterns);
    }

    #[test]
    fn test_metadata_validation() {
        let creation_date_rule = ForensicConfig::METADATA_VALIDATION
            .iter()
            .find(|rule| rule.field == "CreationDate")
            .unwrap();
        assert!(creation_date_rule.required);
    }

    #[test]
    fn test_compression_patterns() {
        let flate = Config::COMPRESSION_PATTERNS
            .iter()
            .find(|(name, _)| *name == "FlateDecode")
            .unwrap();
        assert_eq!(flate.1, &[0x78, 0x9C]);
    }
        }
