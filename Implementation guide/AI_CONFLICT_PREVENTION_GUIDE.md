# AI Conflict Prevention Guide for PDF Forensic Editor

## Critical Implementation Requirements

### ZERO TOLERANCE RULES

#### 1. NO PLACEHOLDERS EVER
```rust
// ❌ FORBIDDEN - Will cause compilation failure
fn process_pdf() -> Result<()> {
    todo!("Implement PDF processing")
}

// ❌ FORBIDDEN - Will cause compilation failure
fn analyze_metadata() -> Result<()> {
    unimplemented!("Add metadata analysis")
}

// ❌ FORBIDDEN - Will cause compilation failure
fn sync_metadata() -> Result<()> {
    // TODO: Add synchronization logic
    Ok(())
}

// ✅ REQUIRED - Complete implementation only
fn process_pdf() -> Result<()> {
    let parser = PdfParser::new();
    let document = parser.parse_file(&self.input_path)?;
    let processed = self.processor.process(document)?;
    Ok(())
}
```

#### 2. TYPE CONSISTENCY ENFORCEMENT
```rust
// ✅ ALWAYS use canonical imports
use crate::types::{MetadataField, MetadataLocation, PdfVersion};
use crate::errors::{ForensicError, Result};

// ❌ NEVER create duplicate types
// Don't define MetadataField in multiple files

// ✅ ALWAYS use consistent ObjectId handling
let object_id = ObjectId(id_number, generation);
let (id_num, gen) = (object_id.0, object_id.1);

// ❌ NEVER mix ObjectId representations
// Don't use tuples where ObjectId is expected
```

#### 3. COMPILATION ERROR PREVENTION
```rust
// ✅ ALWAYS use proper lopdf StringFormat
Object::String(data, lopdf::StringFormat::Literal)

// ✅ ALWAYS handle Result types properly
document.get_object(object_id)
    .map_err(|e| ForensicError::parse_error(&format!("Failed: {}", e)))?

// ✅ ALWAYS use proper Dictionary access
if let Ok(value) = dict.get(b"key") {
    // Process value
}
```

## Central Type Repository

### Core Types (src/types.rs) - CANONICAL SOURCE
```rust
// MetadataField - Use ONLY this definition
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataField {
    Title,
    Author,
    Subject,
    Keywords,
    Creator,
    Producer,
    CreationDate,
    ModificationDate,
    Trapped,
    Custom(String),
}

// MetadataLocation - Use ONLY this definition
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataLocation {
    DocInfo,
    XmpStream,
    ObjectStream(u32),
    Annotation(u32),
    FormField(String),
    CustomLocation(String),
}

// PdfVersion - Use ONLY this definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfVersion {
    V1_4,  // Target output version
    V1_5,  // Input compatibility
    V1_6,  // Input compatibility
    V1_7,  // Input compatibility
    V2_0,  // Input compatibility
}

// EncryptionMethod - Use ONLY this definition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMethod {
    None,
    RC4_40,
    RC4_128,
    AES_128,
    AES_256,
}
```

### Error Types (src/errors.rs) - CANONICAL SOURCE
```rust
// ForensicError - Use ONLY this definition
#[derive(Error, Debug)]
pub enum ForensicError {
    #[error("PDF parsing failed: {message}")]
    ParseError { message: String },
    
    #[error("Metadata operation failed: {operation} - {details}")]
    MetadataError { operation: String, details: String },
    
    #[error("Encryption operation failed: {reason}")]
    EncryptionError { reason: String },
    
    #[error("PDF structure integrity compromised: {issue}")]
    StructureError { issue: String },
    
    #[error("Forensic verification failed: {check}")]
    VerificationError { check: String },
    
    #[error("File system operation failed: {operation}")]
    FileSystemError { operation: String },
    
    #[error("Configuration error: {parameter}")]
    ConfigError { parameter: String },
    
    #[error("Synchronization failed: {location}")]
    SyncError { location: String },
    
    #[error("Authentication failure: {context}")]
    AuthError { context: String },
    
    #[error("Invalid PDF version or format: {details}")]
    FormatError { details: String },
}

// Result type alias - Use ONLY this definition
pub type Result<T> = std::result::Result<T, ForensicError>;
```

## Session Memory Conflict Prevention

### 1. Import Consistency Protocol
Every file MUST start with these exact imports:
```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation, PdfVersion, EncryptionMethod},
    config::Config,
};
```

### 2. Function Signature Consistency
```rust
// Parser functions - ALWAYS use these signatures
impl PdfParser {
    pub fn new() -> Self
    pub fn parse_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<ParsedPdfData>
    pub fn extract_complete_structure(&mut self, parsed_data: &ParsedPdfData) -> Result<ExtractionData>
}

// Metadata functions - ALWAYS use these signatures
impl MetadataEditor {
    pub fn new() -> Self
    pub fn apply_changes(&mut self, extraction_data: &ExtractionData, args: &CliArgs) -> Result<MetadataMap>
}

// Error creation - ALWAYS use these patterns
ForensicError::parse_error("message")
ForensicError::metadata_error("operation", "details")
ForensicError::encryption_error("reason")
```

### 3. Module Structure Consistency
```rust
// ALWAYS use this pattern in mod.rs files
pub mod submodule1;
pub mod submodule2;

pub use self::submodule1::{Type1, Type2, function1};
pub use self::submodule2::{Type3, Type4, function2};

// ALWAYS include these in lib.rs
pub mod cli;
pub mod config;
pub mod errors;
pub mod types;
pub mod verification;
pub mod encryption;
pub mod forensic;

pub mod pdf {
    pub mod parser;
    pub mod extractor;
    pub mod analyzer;
    pub mod cloner;
    pub mod reconstructor;
    pub mod security;
    pub mod validator;
}

pub mod metadata {
    pub mod scanner;
    pub mod editor;
    pub mod synchronizer;
    pub mod cleaner;
    pub mod authenticator;
}

pub mod data {
    pub mod pdf_objects;
    pub mod metadata_map;
    pub mod clone_data;
}

pub mod utils {
    pub mod crypto;
    pub mod serialization;
    pub mod forensics;
}
```

## Memory-Safe Implementation Patterns

### 1. Struct Initialization Pattern
```rust
// ALWAYS use this pattern for new structs
impl ComponentName {
    pub fn new() -> Self {
        Self {
            field1: DefaultValue::default(),
            field2: Vec::new(),
            field3: HashMap::new(),
        }
    }
    
    pub fn with_config(config: ComponentConfig) -> Self {
        Self {
            field1: config.field1,
            field2: Vec::new(),
            field3: HashMap::new(),
        }
    }
}

impl Default for ComponentName {
    fn default() -> Self {
        Self::new()
    }
}
```

### 2. Error Handling Pattern
```rust
// ALWAYS use this exact pattern
fn process_operation(&self) -> Result<OutputType> {
    let step1 = self.do_step1()
        .map_err(|e| ForensicError::operation_error(&format!("Step1 failed: {}", e)))?;
    
    let step2 = self.do_step2(step1)
        .map_err(|e| ForensicError::operation_error(&format!("Step2 failed: {}", e)))?;
    
    Ok(step2)
}
```

### 3. Configuration Pattern
```rust
// ALWAYS use this exact pattern for configs
#[derive(Debug, Clone)]
pub struct ComponentConfig {
    pub option1: bool,
    pub option2: String,
    pub option3: usize,
}

impl Default for ComponentConfig {
    fn default() -> Self {
        Self {
            option1: true,
            option2: "default_value".to_string(),
            option3: 1024,
        }
    }
}
```

## Dependency Consistency Rules

### 1. Cargo.toml Dependencies - NEVER CHANGE
```toml
[dependencies]
lopdf = "0.32"
clap = { version = "4.0", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
sha2 = "0.10"
anyhow = "1.0"
thiserror = "1.0"
filetime = "0.2"
flate2 = "1.0"
base64 = "0.21"
uuid = { version = "1.0", features = ["v4"] }
rand = "0.8"
regex = "1.0"
```

### 2. Feature Flags - NEVER CHANGE
```toml
[dev-dependencies]
tempfile = "3.0"
assert_cmd = "2.0"
predicates = "3.0"
```

## Cross-Session Verification Checklist

Before implementing any module, verify:

1. **Type Imports**: All types imported from canonical sources
2. **Error Handling**: Uses Result<T> = std::result::Result<T, ForensicError>
3. **Function Signatures**: Match exactly with specification
4. **No Placeholders**: Zero TODO, FIXME, unimplemented!, or panic! calls
5. **Complete Implementation**: Every function has working code
6. **Consistent Patterns**: Follows established patterns exactly

## Integration Points - CRITICAL

### 1. CLI Integration
```rust
// main.rs MUST call these in exact order
fn run_forensic_editor(args: CliArgs) -> Result<()> {
    let mut parser = PdfParser::new();
    let pdf_data = parser.parse_file(&args.input)?;
    let extraction_data = parser.extract_complete_structure(&pdf_data)?;
    let mut metadata_editor = MetadataEditor::new();
    let modified_metadata = metadata_editor.apply_changes(&extraction_data, &args)?;
    let mut synchronizer = MetadataSynchronizer::new();
    let synchronized_data = synchronizer.synchronize_all_metadata(&modified_metadata)?;
    let mut cloner = PdfCloner::new();
    let cloned_structure = cloner.clone_with_modifications(&synchronized_data)?;
    let mut reconstructor = PdfReconstructor::new();
    let final_pdf = reconstructor.rebuild_pdf(&cloned_structure)?;
    
    // Apply encryption if specified
    let encrypted_pdf = if args.has_encryption() {
        crate::encryption::apply_encryption(&final_pdf, &args)?
    } else {
        final_pdf
    };
    
    // Pre-output verification
    let verifier = OutputVerifier::new();
    verifier.verify_compliance(&encrypted_pdf)?;
    
    std::fs::write(&args.output, &encrypted_pdf)?;
    
    let timestamp_manager = TimestampManager::new();
    timestamp_manager.synchronize_timestamps(&args.output, &synchronized_data.creation_date)?;
    
    Ok(())
}
```

### 2. Data Flow Consistency
```
Input PDF → Parser → Extractor → Analyzer → Editor → Synchronizer → Cloner → Reconstructor → Verifier → Output PDF
```

Each component MUST accept the output of the previous component as input.

## Memory Management Rules

### 1. String Handling
```rust
// ✅ Efficient string operations
let key_str = String::from_utf8_lossy(key);

// ✅ Reference when possible
fn process_metadata(&self, metadata: &MetadataMap) -> Result<()>

// ✅ Clone only when ownership needed
fn store_metadata(&mut self, metadata: MetadataMap) -> Result<()>
```

### 2. Object ID Handling
```rust
// ✅ ALWAYS use ObjectId type
let object_id = ObjectId(id_number, generation);

// ✅ Extract components consistently
let (id_num, gen) = (object_id.0, object_id.1);

// ✅ Convert for serialization
let serializable_id = format!("{}_{}", object_id.0, object_id.1);
```

## Compilation Error Prevention

### Common lopdf Issues - SOLUTIONS
```rust
// PROBLEM: Missing StringFormat
Object::String(data) // ❌ Fails

// SOLUTION:
Object::String(data, lopdf::StringFormat::Literal) // ✅

// PROBLEM: Dictionary access without error handling
let value = dict["key"]; // ❌ Fails

// SOLUTION:
if let Ok(value) = dict.get(b"key") { // ✅
    // Handle value
}
```

### Type Mismatch Prevention
```rust
// PROBLEM: Using String where MetadataField expected
metadata_map.insert("Title", value); // ❌

// SOLUTION:
metadata_map.insert(MetadataField::Title, value); // ✅

// PROBLEM: ObjectId confusion
let id = (object_id.0, object_id.1); // ❌

// SOLUTION:
let object_id = ObjectId(id_number, generation); // ✅
```

## SUCCESS CRITERIA

Implementation is successful when:
1. `cargo check` passes without errors
2. `cargo build --release` completes successfully
3. `cargo test` runs without compilation errors
4. All 40 files compile together
5. No placeholder code exists
6. Type consistency maintained across all modules
7. Integration points work correctly

## FAILURE INDICATORS

Stop and fix immediately if:
1. Any TODO, FIXME, or unimplemented!() appears
2. Compilation errors occur
3. Type mismatches detected
4. Function signatures don't match specification
5. Import statements are inconsistent
6. Error handling patterns are different

This guide ensures that any AI session can implement the PDF Forensic Editor without conflicts, compilation errors, or architectural inconsistencies.