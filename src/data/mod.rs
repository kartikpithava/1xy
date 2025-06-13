//! Data Structures Module
//! 
//! Complete data modeling and serialization system for PDF forensic operations.
//! Provides comprehensive object representations, metadata mapping, and clone data structures
//! with efficient serialization and deserialization capabilities.

pub mod pdf_objects;
pub mod metadata_map;
pub mod clone_data;

// Re-export commonly used types and functions
pub use self::pdf_objects::{
    PdfObjectData, ObjectContainer, ObjectRelationships, BinaryContent,
    StreamContent, DictionaryContent, ObjectType, ObjectMetadata
};
pub use self::metadata_map::{
    MetadataLocationTracker, LocationMapping, FieldSynchronizationMap,
    CoverageTracker, SynchronizationStatus
};
pub use self::clone_data::{
    SerializableCloneData, ReconstructionData, VerificationData,
    CompressionConfig, SerializationFormat
};

use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation},
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Data processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProcessingConfig {
    pub enable_compression: bool,
    pub preserve_object_order: bool,
    pub validate_integrity: bool,
    pub optimize_serialization: bool,
}

impl Default for DataProcessingConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            preserve_object_order: true,
            validate_integrity: true,
            optimize_serialization: true,
        }
    }
}
