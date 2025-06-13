# Implementation Guide 01: Core Foundation Setup

## Files to Create in This Guide: 5 Files

This guide creates the foundational layer of the PDF forensic editor with complete, production-ready implementations.

---

## File 1: `Cargo.toml` (52 lines)

**Purpose**: Project configuration with optimized dependencies for forensic operations
**Location**: Root directory
**Dependencies**: Core Rust PDF processing libraries with specific versions for stability

```toml
[package]
name = "pdf-forensic-editor"
version = "1.0.0"
edition = "2021"
authors = ["Corporate Development Team"]
description = "PDF Document Metadata Standardizer for Corporate Compliance"
license = "MIT"
repository = "https://github.com/corporate/pdf-standardizer"
readme = "README.md"
keywords = ["pdf", "metadata", "compliance", "standardization"]
categories = ["command-line-utilities", "data-structures"]

[dependencies]
# PDF Processing Core
lopdf = "0.32"
pdf = "0.8"

# CLI and Configuration
clap = { version = "4.0", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Cryptography and Security
aes = "0.8"
sha2 = "0.10"
rand = "0.8"

# File System Operations
filetime = "0.2"
chrono = { version = "0.4", features = ["serde"] }

# Error Handling
anyhow = "1.0"
thiserror = "1.0"

# Utilities
base64 = "0.21"
uuid = { version = "1.0", features = ["v4"] }

[dev-dependencies]
tempfile = "3.0"
assert_cmd = "2.0"
predicates = "3.0"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true

[profile.dev]
opt-level = 0
debug = true
overflow-checks = true
```

---

## File 2: `src/lib.rs` (45 lines)

**Purpose**: Public API interface with comprehensive module exports
**Location**: src/lib.rs
**Exports**: All core functionality for external library usage

```rust
//! PDF Forensic Editor Library
//! 
//! A comprehensive PDF metadata editing and cloning system with forensic invisibility.
//! Provides complete metadata synchronization across all PDF storage locations.

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

// Re-export commonly used types and functions
pub use crate::errors::{ForensicError, Result};
pub use crate::types::{PdfVersion, MetadataField, EncryptionMethod};
pub use crate::cli::CliArgs;
```

---

## File 3: `src/main.rs` (78 lines)

**Purpose**: CLI entry point with robust argument parsing and execution flow
**Location**: src/main.rs
**Functionality**: Command routing, error handling, main execution coordination

```rust
use clap::Parser;
use std::process;
use pdf_forensic_editor::{
    cli::CliArgs,
    errors::{ForensicError, Result},
    pdf::{parser::PdfParser, cloner::PdfCloner, reconstructor::PdfReconstructor},
    metadata::{editor::MetadataEditor, synchronizer::MetadataSynchronizer},
    verification::OutputVerifier,
    forensic::TimestampManager,
};

fn main() {
    let args = CliArgs::parse();
    
    if let Err(e) = run_forensic_editor(args) {
        eprintln!("Error: {}", e);
        
        // Chain error causes for debugging
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("Caused by: {}", err);
            source = err.source();
        }
        
        process::exit(1);
    }
}

fn run_forensic_editor(args: CliArgs) -> Result<()> {
    // Phase 1: Parse input PDF (PDF A)
    let mut parser = PdfParser::new();
    let pdf_data = parser.parse_file(&args.input)?;
    
    // Phase 2: Extract complete PDF structure and metadata
    let extraction_data = parser.extract_complete_structure(&pdf_data)?;
    
    // Phase 3: Apply metadata modifications
    let mut metadata_editor = MetadataEditor::new();
    let modified_metadata = metadata_editor.apply_changes(&extraction_data, &args)?;
    
    // Phase 4: Synchronize metadata across all locations
    let mut synchronizer = MetadataSynchronizer::new();
    let synchronized_data = synchronizer.synchronize_all_metadata(&modified_metadata)?;
    
    // Phase 5: Clone and reconstruct PDF (PDF B)
    let mut cloner = PdfCloner::new();
    let cloned_structure = cloner.clone_with_modifications(&synchronized_data)?;
    
    // Phase 6: Reconstruct final PDF
    let mut reconstructor = PdfReconstructor::new();
    let final_pdf = reconstructor.rebuild_pdf(&cloned_structure)?;
    
    // Phase 7: Apply encryption if specified
    let encrypted_pdf = if args.has_encryption() {
        crate::encryption::apply_encryption(&final_pdf, &args)?
    } else {
        final_pdf
    };
    
    // Phase 8: Pre-output verification
    let verifier = OutputVerifier::new();
    verifier.verify_compliance(&encrypted_pdf)?;
    
    // Phase 9: Write output file
    std::fs::write(&args.output, &encrypted_pdf)?;
    
    // Phase 10: Synchronize file timestamps
    let timestamp_manager = TimestampManager::new();
    timestamp_manager.synchronize_timestamps(&args.output, &synchronized_data.creation_date)?;
    
    println!("PDF processing completed successfully");
    println!("Input: {}", args.input);
    println!("Output: {}", args.output);
    
    Ok(())
}
```

---

## File 4: `src/errors.rs` (92 lines)

**Purpose**: Centralized error handling with forensic operation specificity
**Location**: src/errors.rs
**Functionality**: Comprehensive error types, conversions, user-friendly messages

```rust
use std::fmt;
use thiserror::Error;

/// Result type alias for forensic operations
pub type Result<T> = std::result::Result<T, ForensicError>;

/// Comprehensive error types for PDF forensic operations
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

impl ForensicError {
    pub fn parse_error(message: &str) -> Self {
        Self::ParseError {
            message: message.to_string(),
        }
    }
    
    pub fn metadata_error(operation: &str, details: &str) -> Self {
        Self::MetadataError {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }
    
    pub fn encryption_error(reason: &str) -> Self {
        Self::EncryptionError {
            reason: reason.to_string(),
        }
    }
    
    pub fn structure_error(issue: &str) -> Self {
        Self::StructureError {
            issue: issue.to_string(),
        }
    }
    
    pub fn verification_error(check: &str) -> Self {
        Self::VerificationError {
            check: check.to_string(),
        }
    }
    
    pub fn sync_error(location: &str) -> Self {
        Self::SyncError {
            location: location.to_string(),
        }
    }
}

// Standard library error conversions
impl From<std::io::Error> for ForensicError {
    fn from(err: std::io::Error) -> Self {
        Self::FileSystemError {
            operation: format!("I/O operation failed: {}", err),
        }
    }
}

impl From<lopdf::Error> for ForensicError {
    fn from(err: lopdf::Error) -> Self {
        Self::ParseError {
            message: format!("LoPDF error: {}", err),
        }
    }
}

impl From<serde_json::Error> for ForensicError {
    fn from(err: serde_json::Error) -> Self {
        Self::ConfigError {
            parameter: format!("JSON serialization error: {}", err),
        }
    }
}
```

---

## File 5: `src/types.rs` (115 lines)

**Purpose**: Core type definitions and enumerations for the entire system
**Location**: src/types.rs
**Functionality**: Shared data structures, type safety abstractions, common enums

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// PDF version specification (always outputs PDF 1.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfVersion {
    V1_4,  // Target output version
    V1_5,  // Input compatibility
    V1_6,  // Input compatibility
    V1_7,  // Input compatibility
    V2_0,  // Input compatibility
}

impl PdfVersion {
    pub fn as_string(&self) -> String {
        match self {
            PdfVersion::V1_4 => "1.4".to_string(),
            PdfVersion::V1_5 => "1.5".to_string(),
            PdfVersion::V1_6 => "1.6".to_string(),
            PdfVersion::V1_7 => "1.7".to_string(),
            PdfVersion::V2_0 => "2.0".to_string(),
        }
    }
    
    pub fn output_version() -> Self {
        PdfVersion::V1_4
    }
}

/// Metadata field enumeration for comprehensive coverage
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

impl MetadataField {
    pub fn as_string(&self) -> String {
        match self {
            MetadataField::Title => "Title".to_string(),
            MetadataField::Author => "Author".to_string(),
            MetadataField::Subject => "Subject".to_string(),
            MetadataField::Keywords => "Keywords".to_string(),
            MetadataField::Creator => "Creator".to_string(),
            MetadataField::Producer => "Producer".to_string(),
            MetadataField::CreationDate => "CreationDate".to_string(),
            MetadataField::ModificationDate => "ModDate".to_string(),
            MetadataField::Trapped => "Trapped".to_string(),
            MetadataField::Custom(name) => name.clone(),
        }
    }
}

/// Encryption method enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMethod {
    None,
    RC4_40,
    RC4_128,
    AES_128,
    AES_256,
}

impl EncryptionMethod {
    pub fn default_method() -> Self {
        EncryptionMethod::AES_128
    }
    
    pub fn requires_password(&self) -> bool {
        !matches!(self, EncryptionMethod::None)
    }
}

/// Metadata storage location tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataLocation {
    DocInfo,           // Document Information Dictionary
    XmpStream,         // XMP Metadata Stream
    ObjectStream(u32), // Embedded in specific object
    Annotation(u32),   // Within annotation objects
    FormField(String), // Within form field objects
    CustomLocation(String), // Other discovered locations
}

/// Comprehensive metadata value container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataValue {
    pub field: MetadataField,
    pub value: Option<String>,
    pub locations: Vec<MetadataLocation>,
    pub is_synchronized: bool,
}

/// Complete metadata map for synchronization
pub type MetadataMap = HashMap<MetadataField, MetadataValue>;

/// Encryption configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub method: EncryptionMethod,
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
    pub permissions: u32,
    pub key_length: u16,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            method: EncryptionMethod::None,
            user_password: None,
            owner_password: None,
            permissions: 0xFFFFFFFC, // All permissions enabled
            key_length: 128,
        }
    }
}
```

---

## Implementation Sequence

1. **Create Cargo.toml first** - Establishes project structure and dependencies
2. **Implement src/lib.rs** - Sets up module structure and exports
3. **Create src/main.rs** - Provides CLI entry point and execution flow
4. **Implement src/errors.rs** - Establishes error handling foundation
5. **Create src/types.rs** - Defines core types used throughout the system

## Compilation Requirements

After implementing these 5 files:
- All type definitions will be available system-wide
- Error handling infrastructure will be complete
- CLI framework will be established
- Project dependencies will be properly configured
- Module structure will be ready for subsequent implementation guides

## Next Guide

Implementation Guide 02 will create the CLI interface and configuration systems, building upon this foundation.