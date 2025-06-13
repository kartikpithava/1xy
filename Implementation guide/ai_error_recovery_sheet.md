# AI Error Recovery Sheet for PDF Forensic Editor

## Purpose
This document provides systematic guidelines for AI to resolve compilation errors while maintaining code consistency and avoiding unintended alterations to the codebase. The AI must use the same format and patterns across all files.

---

## Core Principles

### 1. Never Remove or Alter Existing Functionality
- **DO NOT** delete any existing methods, structs, or functionality
- **DO NOT** change the signature of existing public methods
- **DO NOT** modify the core logic of working implementations
- **ONLY** add missing imports, implementations, or fix syntax errors

### 2. Maintain Consistent Code Format
- Use the exact same naming conventions throughout the project
- Follow the established error handling patterns using `Result<T, Box<dyn std::error::Error>>`
- Maintain consistent import statement ordering and grouping
- Keep the same indentation and spacing patterns

### 3. Preserve Integration Points
- **DO NOT** modify the integration wiring in `src/main.rs`
- **DO NOT** alter module declarations in `src/lib.rs`
- **DO NOT** change the CLI argument structure in `src/cli.rs`
- Ensure all enhancement files integrate exactly as specified

---

## Common Error Categories and Solutions

### Category 1: Missing Trait Implementations

**Error Pattern**: `trait X is not implemented for Y`

**Solution Template**:
```rust
// Add the missing trait implementation following existing patterns
impl TraitName for StructName {
    fn required_method(&self) -> ReturnType {
        // Implementation that follows project patterns
        // Use existing error handling style
        // Return appropriate default or calculated value
    }
}
```

**Example Fix**:
```rust
// If ObjectProcessor trait is missing implementation
impl ObjectProcessor for FontObjectProcessor {
    fn process(&self, object: &mut dyn std::any::Any) -> Result<(), Box<dyn std::error::Error>> {
        // Follow the established error handling pattern
        if let Some(font_obj) = object.downcast_mut::<FontObject>() {
            font_obj.apply_processing();
            Ok(())
        } else {
            Err("Invalid object type for FontObjectProcessor".into())
        }
    }
}
```

### Category 2: Missing Method Implementations

**Error Pattern**: `method X is not defined for struct Y`

**Solution Template**:
```rust
impl StructName {
    pub fn missing_method(&self, params: ParamType) -> Result<ReturnType, Box<dyn std::error::Error>> {
        // Implementation following project patterns
        // Use consistent error handling
        // Maintain same return type patterns
        Ok(default_value)
    }
}
```

**Example Fix**:
```rust
// Add missing methods to Document struct
impl Document {
    pub fn get_content_streams_mut(&mut self) -> &mut Vec<Stream> {
        &mut self.content_streams
    }
    
    pub fn get_object_ids(&self) -> Vec<u32> {
        self.objects.iter().map(|obj| obj.id).collect()
    }
    
    pub fn inject_metadata_pattern(&mut self, pattern: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.metadata_patterns.push(pattern);
        Ok(())
    }
}
```

### Category 3: Missing Struct Definitions

**Error Pattern**: `cannot find type X in this scope`

**Solution Template**:
```rust
// Add missing struct definition with consistent field patterns
pub struct MissingStruct {
    pub field1: Type1,
    pub field2: Type2,
    // Follow naming conventions used in similar structs
}

impl MissingStruct {
    pub fn new() -> Self {
        Self {
            field1: Default::default(),
            field2: Type2::new(),
        }
    }
}
```

**Example Fix**:
```rust
// Add missing Stream struct
pub struct Stream {
    pub data: Vec<u8>,
    pub dictionary: HashMap<String, String>,
    pub filter_type: Option<String>,
}

impl Stream {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            dictionary: HashMap::new(),
            filter_type: None,
        }
    }
    
    pub fn get_filter_type(&self) -> Option<String> {
        self.filter_type.clone()
    }
    
    pub fn calculate_compression_ratio(&self) -> f64 {
        // Provide meaningful implementation
        if self.data.is_empty() { 0.0 } else { 1.0 }
    }
}
```

### Category 4: Import Statement Errors

**Error Pattern**: `use of undeclared crate or module`

**Solution Template**:
```rust
// Add missing imports following project structure
use crate::module_name::StructName;
use std::collections::HashMap;
use external_crate::RequiredType;

// Group imports consistently:
// 1. Standard library imports
// 2. External crate imports  
// 3. Internal crate imports
```

**Example Fix**:
```rust
// Fix missing imports in enhancement files
use std::collections::HashMap;
use std::path::Path;
use chrono::{DateTime, Utc};
use crate::pdf::{Document, PdfData, PdfObject};
use crate::errors::Result;
```

### Category 5: Missing Dependencies

**Error Pattern**: `could not find X in the dependencies`

**Solution**: Add missing dependencies to `Cargo.toml` following established patterns:
```toml
[dependencies]
# Core dependencies (maintain existing versions)
lopdf = "0.32"
chrono = { version = "0.4", features = ["serde"] }
filetime = "0.2"

# Add missing dependencies with appropriate versions
missing_crate = "1.0"

[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

---

## Specific Fix Patterns for Enhancement Files

### Pattern 1: PDF Document Method Extensions

When enhancement files reference methods not yet implemented in the base PDF structures:

```rust
// Add to src/pdf/mod.rs or appropriate location
impl Document {
    // Metadata manipulation methods
    pub fn get_content_streams(&self) -> &Vec<Stream> { &self.streams }
    pub fn get_content_streams_mut(&mut self) -> &mut Vec<Stream> { &mut self.streams }
    pub fn get_object_ids(&self) -> Vec<u32> { self.objects.keys().cloned().collect() }
    pub fn get_xref_entry_count(&self) -> usize { self.xref_table.entries.len() }
    pub fn get_free_object_ids(&self) -> Vec<usize> { self.xref_table.free_entries.clone() }
    pub fn get_generation_numbers(&self) -> HashMap<usize, u16> { self.xref_table.generation_numbers.clone() }
    
    // Producer and creator methods
    pub fn get_producer(&self) -> Option<String> { self.info_dict.get("Producer").cloned() }
    pub fn get_creator(&self) -> Option<String> { self.info_dict.get("Creator").cloned() }
    pub fn set_producer(&mut self, producer: &str) { self.info_dict.insert("Producer".to_string(), producer.to_string()); }
    pub fn get_pdf_version(&self) -> Option<String> { Some(self.version.clone()) }
    
    // Date handling methods
    pub fn get_creation_date(&self) -> Option<DateTime<Utc>> { self.parse_date_field("CreationDate") }
    pub fn get_modification_date(&self) -> Option<DateTime<Utc>> { self.parse_date_field("ModDate") }
    pub fn get_metadata_date(&self) -> Option<DateTime<Utc>> { self.parse_date_field("MetadataDate") }
    pub fn set_modification_date(&mut self, date: DateTime<Utc>) { self.set_date_field("ModDate", date); }
    
    // Forensic analysis methods
    pub fn count_decoy_objects(&self) -> usize { self.decoy_objects.len() }
    pub fn get_object_count(&self) -> usize { self.objects.len() }
    pub fn count_padded_streams(&self) -> usize { self.streams.iter().filter(|s| s.is_padded).count() }
    pub fn get_stream_count(&self) -> usize { self.streams.len() }
    pub fn detect_suspicious_patterns(&self) -> usize { self.suspicious_pattern_count }
    pub fn has_complete_encryption_dictionary(&self) -> bool { self.encryption_dict.contains_key("V") }
    pub fn get_encryption_dictionary(&self) -> &HashMap<String, String> { &self.encryption_dict }
}
```

### Pattern 2: PdfData Structure Extensions

```rust
// Add to appropriate PDF data structure
impl PdfData {
    pub fn extract_font_objects(&self) -> Vec<FontObject> { self.font_objects.clone() }
    pub fn update_font_objects(&mut self, fonts: Vec<FontObject>) { self.font_objects = fonts; }
    pub fn extract_annotations(&self) -> Vec<Annotation> { self.annotations.clone() }
    pub fn update_annotations(&mut self, annotations: Vec<Annotation>) { self.annotations = annotations; }
    pub fn get_font_count(&self) -> usize { self.font_objects.len() }
    pub fn get_annotation_count(&self) -> usize { self.annotations.len() }
    pub fn extract_all_timestamps(&self) -> Vec<Timestamp> { self.timestamps.clone() }
    pub fn update_timestamps(&mut self, timestamps: Vec<Timestamp>) { self.timestamps = timestamps; }
    pub fn count_padded_streams(&self) -> usize { self.document.count_padded_streams() }
    
    // Authenticity validation methods
    pub fn has_authentic_stream_patterns(&self) -> bool { self.stream_authenticity_score > 0.8 }
    pub fn has_authentic_font_signatures(&self) -> bool { self.font_authenticity_score > 0.8 }
    pub fn has_authentic_annotation_patterns(&self) -> bool { self.annotation_authenticity_score > 0.8 }
}
```

### Pattern 3: Helper Structure Definitions

```rust
// Add missing helper structures with consistent patterns
pub struct FontObject {
    pub font_type: String,
    pub creator_signature: Option<String>,
    pub creation_tool: Option<String>,
    pub metadata_patterns: Vec<Vec<u8>>,
}

impl FontObject {
    pub fn new() -> Self {
        Self {
            font_type: "Type1".to_string(),
            creator_signature: None,
            creation_tool: None,
            metadata_patterns: Vec::new(),
        }
    }
    
    pub fn set_creator_signature(&mut self, signature: &str) {
        self.creator_signature = Some(signature.to_string());
    }
    
    pub fn set_creation_tool(&mut self, tool: &str) {
        self.creation_tool = Some(tool.to_string());
    }
    
    pub fn inject_metadata_pattern(&mut self, pattern: &[u8]) {
        self.metadata_patterns.push(pattern.to_vec());
    }
    
    pub fn normalize_encoding_for_authenticity(&mut self) {
        // Implement encoding normalization
    }
}

pub struct Annotation {
    pub annotation_type: String,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub creator: Option<String>,
    pub flags: u32,
    pub authentic_patterns: Vec<Vec<u8>>,
}

impl Annotation {
    pub fn new() -> Self {
        Self {
            annotation_type: "Text".to_string(),
            creation_date: None,
            modification_date: None,
            creator: None,
            flags: 0,
            authentic_patterns: Vec::new(),
        }
    }
    
    pub fn set_creation_date(&mut self, date: &str) { self.creation_date = Some(date.to_string()); }
    pub fn set_modification_date(&mut self, date: &str) { self.modification_date = Some(date.to_string()); }
    pub fn set_creator(&mut self, creator: &str) { self.creator = Some(creator.to_string()); }
    pub fn set_flags(&mut self, flags: u32) { self.flags = flags; }
    pub fn inject_authentic_pattern(&mut self, pattern: &[u8]) { self.authentic_patterns.push(pattern.to_vec()); }
}
```

---

## Error Recovery Workflow

### Step 1: Identify Error Category
1. Read the compilation error message carefully
2. Identify which category it falls into (trait, method, struct, import, dependency)
3. Locate the specific file and line causing the error

### Step 2: Apply Appropriate Fix Pattern
1. Use the corresponding solution template from above
2. Maintain consistency with existing code patterns
3. Follow the established naming conventions
4. Use the same error handling approach

### Step 3: Verify Integration Consistency
1. Ensure the fix doesn't break existing functionality
2. Check that method signatures match usage in other files
3. Verify that the implementation follows project patterns
4. Confirm that imports are properly organized

### Step 4: Test Compilation
1. Attempt to compile after each fix
2. Address any cascading errors that arise
3. Ensure all enhancement files compile successfully
4. Verify that the main binary can be built

---

## Critical Don'ts

### ❌ Never Do These:
- Remove existing method implementations
- Change public API method signatures
- Alter the core processing pipeline logic
- Modify the CLI argument structure
- Delete any existing struct fields
- Change the error handling patterns
- Modify the integration wiring code
- Alter the module structure in lib.rs
- Remove any dependency imports

### ✅ Always Do These:
- Add missing implementations using established patterns
- Follow the existing code style and naming conventions
- Use the same error handling approach throughout
- Maintain consistent return types and method signatures
- Add proper documentation following existing patterns
- Group imports in the established order
- Use meaningful variable names that match project conventions
- Implement traits using the same pattern as existing implementations

---

## Recovery Examples

### Example 1: Missing Trait Implementation Error

**Error**: `the trait bound 'BytePatternMasker: MaskingStrategy' is not satisfied`

**Fix**:
```rust
impl MaskingStrategy for BytePatternMasker {
    fn mask_pattern(&self, data: &mut Vec<u8>, pattern: &[u8]) -> bool {
        if let Some(pos) = data.windows(pattern.len()).position(|window| window == pattern) {
            for i in 0..pattern.len() {
                data[pos + i] = b'X'; // Replace with innocuous pattern
            }
            true
        } else {
            false
        }
    }
}
```

### Example 2: Missing Method Error

**Error**: `no method named 'extract_signatures' found for struct 'CompressionAnalyzer'`

**Fix**:
```rust
impl CompressionAnalyzer {
    pub fn extract_signatures(&self, document: &Document) -> Result<HashMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
        let mut signatures = HashMap::new();
        
        for stream in document.get_content_streams() {
            if let Some(filter_type) = stream.get_filter_type() {
                if let Some(signature) = self.compression_signatures.get(&filter_type) {
                    signatures.insert(filter_type, signature.clone());
                }
            }
        }
        
        Ok(signatures)
    }
}
```

### Example 3: Missing Struct Field Error

**Error**: `no field 'stream_authenticity_score' on type 'PdfData'`

**Fix**:
```rust
// Add to PdfData struct definition
pub struct PdfData {
    pub document: Document,
    pub file_path: Option<PathBuf>,
    pub font_objects: Vec<FontObject>,
    pub annotations: Vec<Annotation>,
    pub timestamps: Vec<Timestamp>,
    pub raw_data: Vec<u8>,
    // Add missing authenticity score fields
    pub stream_authenticity_score: f32,
    pub font_authenticity_score: f32,
    pub annotation_authenticity_score: f32,
    pub suspicious_pattern_count: usize,
}

impl PdfData {
    pub fn new(document: Document) -> Self {
        Self {
            document,
            file_path: None,
            font_objects: Vec::new(),
            annotations: Vec::new(),
            timestamps: Vec::new(),
            raw_data: Vec::new(),
            stream_authenticity_score: 0.0,
            font_authenticity_score: 0.0,
            annotation_authenticity_score: 0.0,
            suspicious_pattern_count: 0,
        }
    }
}
```

---

## Final Verification Checklist

Before completing error recovery:

- [ ] All compilation errors are resolved
- [ ] No existing functionality has been removed or altered
- [ ] All method signatures remain consistent
- [ ] Error handling follows established patterns
- [ ] Import statements are properly organized
- [ ] Code formatting matches project standards
- [ ] All enhancement files integrate correctly
- [ ] Main binary builds successfully
- [ ] No warnings are introduced by the fixes
- [ ] All public APIs remain unchanged

This recovery sheet ensures that AI maintains the integrity and consistency of the codebase while resolving compilation errors systematically and safely.