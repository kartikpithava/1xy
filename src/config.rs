//! Configuration constants for PDF forensic operations
//! Central source of truth for all configuration values

use crate::types::PdfVersion;

/// Application configuration constants for PDF processing
pub struct Config;

impl Config {
    /// Target PDF version for output (required for forensic standardization)
    pub const OUTPUT_PDF_VERSION: PdfVersion = PdfVersion::V1_4;

    /// Official producer string for all output documents
    /// Must be consistent across all document processing
    pub const PDF_PRODUCER: &'static str = "Corporate Document Standardizer v1.0";

    /// Maximum file size limit (512 MB)
    /// Prevents memory exhaustion attacks
    pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

    /// Memory limit for PDF processing (256 MB)
    /// Ensures consistent memory usage across platforms
    pub const MEMORY_LIMIT: usize = 256 * 1024 * 1024;

    /// Maximum number of PDF objects to process
    /// Prevents infinite object chain attacks
    pub const MAX_PDF_OBJECTS: usize = 100_000;

    /// Buffer size for efficient file I/O operations
    pub const IO_BUFFER_SIZE: usize = 64 * 1024;

    /// Compression level (0-9) for output files
    /// Balance between size and processing speed
    pub const COMPRESSION_LEVEL: u8 = 6;

    /// Default permissions for encrypted PDFs
    /// All permissions enabled by default
    pub const DEFAULT_PERMISSIONS: u32 = 0xFFFFFFFC;

    /// Required metadata fields for synchronization
    /// Must be consistent across all metadata locations
    pub const SYNC_REQUIRED_FIELDS: &'static [&'static str] = &[
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
    ];

    /// XMP metadata namespace definitions
    /// Required for proper metadata synchronization
    pub const XMP_NAMESPACES: &'static [(&'static str, &'static str)] = &[
        ("dc", "http://purl.org/dc/elements/1.1/"),
        ("xmp", "http://ns.adobe.com/xap/1.0/"),
        ("pdf", "http://ns.adobe.com/pdf/1.3/"),
        ("pdfx", "http://ns.adobe.com/pdfx/1.3/"),
    ];

    /// Fields to remove during forensic cleaning
    pub const FORENSIC_REMOVE_FIELDS: &'static [&'static str] = &[
        "ModDate",        // Modification date reveals editing
        "Trapped",        // Technical metadata
        "GTS_PDFXVersion", // PDF/X version info
        "GTS_PDFXConformance", // PDF/X conformance
        "Producer",       // Will be replaced with our producer
    ];

    /// Forensic timestamp precision in seconds
    pub const TIMESTAMP_PRECISION: u64 = 1;

    /// Maximum retry attempts for file operations
    pub const MAX_RETRY_ATTEMPTS: u8 = 3;

    /// Delay between retry attempts (milliseconds)
    pub const RETRY_DELAY_MS: u64 = 100;

    /// Anti-forensic trace cleanup patterns
    pub const CLEANUP_PATTERNS: &'static [&'static str] = &[
        "temp_", "~", ".bak", "copy_", "draft_"
    ];

    /// Stream compression types for binary data
    pub const ALLOWED_COMPRESSION_TYPES: &'static [&'static str] = &[
        "FlateDecode",
        "DCTDecode",
        "ASCIIHexDecode",
        "ASCII85Decode",
    ];
}

/// Forensic configuration for secure operation
pub struct ForensicConfig;

impl ForensicConfig {
    /// Metadata locations requiring complete cleanup
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

    /// Critical PDF structure elements to preserve
    pub const PRESERVE_STRUCTURE_ELEMENTS: &'static [&'static str] = &[
        "xref",           // Cross-reference table
        "trailer",        // Trailer dictionary
        "startxref",      // Cross-reference start position
        "%%EOF",          // End of file marker
    ];

    /// Recursive traversal limit for object trees
    pub const MAX_OBJECT_DEPTH: u8 = 50;

    /// Forbidden producer strings (reveals editing)
    pub const FORBIDDEN_PRODUCERS: &'static [&'static str] = &[
        "ghostscript",
        "itext",
        "pdfsharp",
        "reportlab",
        "tcpdf",
        "adobe distiller",
    ];

    /// Security verification requirements
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

    /// Get secure timestamp format pattern
    pub fn get_timestamp_format() -> &'static str {
        "D:%Y%m%d%H%M%S%z"
    }

    /// Get validation requirements for encryption
    pub fn get_encryption_requirements() -> Vec<&'static str> {
        vec![
            "AES-128 or higher encryption",
            "Secure password handling",
            "Standard security handler",
            "Valid permissions dictionary",
        ]
    }

    /// Minimum object count for authentic documents
    pub const MIN_AUTHENTIC_OBJECTS: usize = 5;

    /// Maximum object count for performance
    pub const MAX_AUTHENTIC_OBJECTS: usize = 1_000_000;
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
    fn test_sync_required_fields() {
        assert!(!Config::SYNC_REQUIRED_FIELDS.is_empty());
        assert!(Config::SYNC_REQUIRED_FIELDS.contains(&"Title"));
        assert!(Config::SYNC_REQUIRED_FIELDS.contains(&"Author"));
        assert!(Config::SYNC_REQUIRED_FIELDS.contains(&"CreationDate"));
    }

    #[test]
    fn test_forensic_requirements() {
        let reqs = ForensicConfig::get_verification_requirements();
        assert!(!reqs.is_empty());
        assert!(reqs.iter().any(|&r| r.contains("PDF version")));
        assert!(reqs.iter().any(|&r| r.contains("ModDate")));
    }

    #[test]
    fn test_metadata_locations() {
        assert!(!ForensicConfig::CLEAN_METADATA_LOCATIONS.is_empty());
        assert!(ForensicConfig::CLEAN_METADATA_LOCATIONS.contains(&"/Info"));
        assert!(ForensicConfig::CLEAN_METADATA_LOCATIONS.contains(&"/Metadata"));
    }
            }
