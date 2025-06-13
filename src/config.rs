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
