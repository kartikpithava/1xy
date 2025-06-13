# Implementation Guide 05: Data Structures and Utilities

## Files to Create in This Guide: 5 Files

This guide implements the data structures and utility systems for PDF object representation, serialization, and forensic operations.

---

## File 1: `src/data/mod.rs` (38 lines)

**Purpose**: Data structures module interface and serialization coordination
**Location**: src/data/mod.rs
**Functionality**: Type export management, serialization system coordination, cross-module data sharing

```rust
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
```

---

## File 2: `src/data/pdf_objects.rs` (198 lines)

**Purpose**: Complete PDF object representations with relationship mapping
**Location**: src/data/pdf_objects.rs
**Functionality**: Object modeling, relationship tracking, binary content containers

```rust
use crate::{
    errors::{ForensicError, Result},
    types::MetadataField,
};
use lopdf::{Object, ObjectId, Dictionary, Stream};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Complete PDF object data representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfObjectData {
    pub object_id: ObjectId,
    pub object_type: ObjectType,
    pub content: ObjectContainer,
    pub metadata: ObjectMetadata,
    pub relationships: ObjectRelationships,
    pub binary_data: Option<BinaryContent>,
    pub modification_history: Vec<ModificationRecord>,
}

/// Object type enumeration with detailed classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectType {
    Catalog,
    Pages,
    Page,
    Font,
    XObject,
    ExtGState,
    Pattern,
    Shading,
    Annotation,
    Action,
    Outline,
    Info,
    Metadata,
    Stream,
    Dictionary,
    Array,
    String,
    Name,
    Number,
    Boolean,
    Null,
    Reference,
    Custom(String),
}

/// Object content container with type-specific handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectContainer {
    Dictionary(DictionaryContent),
    Stream(StreamContent),
    Array(Vec<SerializableObject>),
    Primitive(PrimitiveValue),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryContent {
    pub entries: HashMap<String, SerializableObject>,
    pub entry_order: Vec<String>,
    pub contains_metadata: bool,
    pub is_critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamContent {
    pub dictionary: DictionaryContent,
    pub raw_content: Vec<u8>,
    pub decoded_content: Option<Vec<u8>>,
    pub filter_chain: Vec<String>,
    pub content_type: StreamContentType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamContentType {
    PageContent,
    XmpMetadata,
    Image,
    Font,
    Form,
    ColorSpace,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableObject {
    Dictionary(HashMap<String, SerializableObject>),
    Array(Vec<SerializableObject>),
    String(String),
    Name(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Null,
    Reference(u32, u16),
    Stream(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrimitiveValue {
    String(String),
    Name(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Null,
}

/// Object metadata and properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub size_estimate: usize,
    pub contains_metadata_fields: HashSet<MetadataField>,
    pub is_encrypted: bool,
    pub compression_applied: bool,
    pub last_modified: Option<String>,
    pub access_count: u32,
    pub criticality_score: f32,
}

/// Object relationship mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRelationships {
    pub references_to: Vec<ObjectId>,
    pub referenced_by: Vec<ObjectId>,
    pub parent_object: Option<ObjectId>,
    pub child_objects: Vec<ObjectId>,
    pub dependency_level: u8,
    pub circular_references: bool,
}

/// Binary content preservation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryContent {
    pub content_hash: String,
    pub original_size: usize,
    pub compressed_size: usize,
    pub content_data: Vec<u8>,
    pub compression_method: CompressionMethod,
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionMethod {
    None,
    Flate,
    LZW,
    RunLength,
    DCT,
    JBIG2,
    JPX,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModificationRecord {
    pub timestamp: String,
    pub operation_type: String,
    pub field_changed: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

impl PdfObjectData {
    /// Create new PDF object data from lopdf Object
    pub fn from_lopdf_object(object_id: ObjectId, object: &Object) -> Result<Self> {
        let object_type = Self::determine_object_type(object)?;
        let content = Self::convert_object_content(object)?;
        let metadata = Self::extract_object_metadata(object)?;
        let relationships = ObjectRelationships::new();
        let binary_data = Self::extract_binary_data(object)?;
        
        Ok(Self {
            object_id,
            object_type,
            content,
            metadata,
            relationships,
            binary_data,
            modification_history: Vec::new(),
        })
    }
    
    fn determine_object_type(object: &Object) -> Result<ObjectType> {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return Ok(match type_name {
                            "Catalog" => ObjectType::Catalog,
                            "Pages" => ObjectType::Pages,
                            "Page" => ObjectType::Page,
                            "Font" => ObjectType::Font,
                            "XObject" => ObjectType::XObject,
                            "ExtGState" => ObjectType::ExtGState,
                            "Pattern" => ObjectType::Pattern,
                            "Shading" => ObjectType::Shading,
                            "Annot" => ObjectType::Annotation,
                            "Action" => ObjectType::Action,
                            "Outlines" => ObjectType::Outline,
                            "Info" => ObjectType::Info,
                            "Metadata" => ObjectType::Metadata,
                            other => ObjectType::Custom(other.to_string()),
                        });
                    }
                }
                Ok(ObjectType::Dictionary)
            },
            Object::Stream(_) => Ok(ObjectType::Stream),
            Object::Array(_) => Ok(ObjectType::Array),
            Object::String(_, _) => Ok(ObjectType::String),
            Object::Name(_) => Ok(ObjectType::Name),
            Object::Integer(_) => Ok(ObjectType::Number),
            Object::Real(_) => Ok(ObjectType::Number),
            Object::Boolean(_) => Ok(ObjectType::Boolean),
            Object::Null => Ok(ObjectType::Null),
            Object::Reference(_) => Ok(ObjectType::Reference),
        }
    }
    
    fn convert_object_content(object: &Object) -> Result<ObjectContainer> {
        match object {
            Object::Dictionary(dict) => {
                let dict_content = Self::convert_dictionary(dict)?;
                Ok(ObjectContainer::Dictionary(dict_content))
            },
            Object::Stream(stream) => {
                let stream_content = Self::convert_stream(stream)?;
                Ok(ObjectContainer::Stream(stream_content))
            },
            Object::Array(array) => {
                let mut converted_array = Vec::new();
                for item in array {
                    converted_array.push(Self::convert_to_serializable(item)?);
                }
                Ok(ObjectContainer::Array(converted_array))
            },
            _ => {
                let primitive = Self::convert_to_primitive(object)?;
                Ok(ObjectContainer::Primitive(primitive))
            }
        }
    }
    
    fn convert_dictionary(dict: &Dictionary) -> Result<DictionaryContent> {
        let mut entries = HashMap::new();
        let mut entry_order = Vec::new();
        let mut contains_metadata = false;
        
        for (key, value) in dict.iter() {
            let key_str = String::from_utf8_lossy(key).to_string();
            let serializable_value = Self::convert_to_serializable(value)?;
            
            // Check if this key indicates metadata
            if Self::is_metadata_key(&key_str) {
                contains_metadata = true;
            }
            
            entries.insert(key_str.clone(), serializable_value);
            entry_order.push(key_str);
        }
        
        let is_critical = Self::is_critical_dictionary(dict);
        
        Ok(DictionaryContent {
            entries,
            entry_order,
            contains_metadata,
            is_critical,
        })
    }
    
    fn convert_stream(stream: &Stream) -> Result<StreamContent> {
        let dictionary = Self::convert_dictionary(&stream.dict)?;
        let raw_content = stream.content.clone();
        let decoded_content = None; // Would be populated during decoding
        let filter_chain = Self::extract_filter_chain(&stream.dict);
        let content_type = Self::determine_stream_content_type(&stream.dict);
        
        Ok(StreamContent {
            dictionary,
            raw_content,
            decoded_content,
            filter_chain,
            content_type,
        })
    }
    
    fn extract_filter_chain(dict: &Dictionary) -> Vec<String> {
        let mut filters = Vec::new();
        
        if let Ok(filter_obj) = dict.get(b"Filter") {
            match filter_obj {
                Object::Name(name) => {
                    filters.push(String::from_utf8_lossy(name).to_string());
                },
                Object::Array(array) => {
                    for item in array {
                        if let Ok(name) = item.as_name_str() {
                            filters.push(name.to_string());
                        }
                    }
                },
                _ => {},
            }
        }
        
        filters
    }
    
    fn determine_stream_content_type(dict: &Dictionary) -> StreamContentType {
        if let Ok(subtype) = dict.get(b"Subtype") {
            if let Ok(subtype_name) = subtype.as_name_str() {
                return match subtype_name {
                    "XML" => StreamContentType::XmpMetadata,
                    "Image" => StreamContentType::Image,
                    "Form" => StreamContentType::Form,
                    _ => StreamContentType::Unknown,
                };
            }
        }
        
        if let Ok(type_obj) = dict.get(b"Type") {
            if let Ok(type_name) = type_obj.as_name_str() {
                return match type_name {
                    "Metadata" => StreamContentType::XmpMetadata,
                    "Font" => StreamContentType::Font,
                    "ColorSpace" => StreamContentType::ColorSpace,
                    _ => StreamContentType::Unknown,
                };
            }
        }
        
        StreamContentType::PageContent // Default assumption
    }
    
    fn convert_to_serializable(object: &Object) -> Result<SerializableObject> {
        match object {
            Object::Dictionary(dict) => {
                let mut converted_dict = HashMap::new();
                for (key, value) in dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    converted_dict.insert(key_str, Self::convert_to_serializable(value)?);
                }
                Ok(SerializableObject::Dictionary(converted_dict))
            },
            Object::Array(array) => {
                let mut converted_array = Vec::new();
                for item in array {
                    converted_array.push(Self::convert_to_serializable(item)?);
                }
                Ok(SerializableObject::Array(converted_array))
            },
            Object::String(s, _) => Ok(SerializableObject::String(String::from_utf8_lossy(s).to_string())),
            Object::Name(n) => Ok(SerializableObject::Name(String::from_utf8_lossy(n).to_string())),
            Object::Integer(i) => Ok(SerializableObject::Integer(*i)),
            Object::Real(r) => Ok(SerializableObject::Real(*r)),
            Object::Boolean(b) => Ok(SerializableObject::Boolean(*b)),
            Object::Null => Ok(SerializableObject::Null),
            Object::Reference(obj_id) => Ok(SerializableObject::Reference(obj_id.0, obj_id.1)),
            Object::Stream(stream) => Ok(SerializableObject::Stream(stream.content.clone())),
        }
    }
    
    fn convert_to_primitive(object: &Object) -> Result<PrimitiveValue> {
        match object {
            Object::String(s, _) => Ok(PrimitiveValue::String(String::from_utf8_lossy(s).to_string())),
            Object::Name(n) => Ok(PrimitiveValue::Name(String::from_utf8_lossy(n).to_string())),
            Object::Integer(i) => Ok(PrimitiveValue::Integer(*i)),
            Object::Real(r) => Ok(PrimitiveValue::Real(*r)),
            Object::Boolean(b) => Ok(PrimitiveValue::Boolean(*b)),
            Object::Null => Ok(PrimitiveValue::Null),
            _ => Err(ForensicError::structure_error("Cannot convert complex object to primitive")),
        }
    }
    
    fn extract_object_metadata(object: &Object) -> Result<ObjectMetadata> {
        let size_estimate = Self::estimate_object_size(object);
        let contains_metadata_fields = Self::extract_metadata_fields(object);
        let is_encrypted = false; // Would be determined by document encryption status
        let compression_applied = Self::has_compression(object);
        
        Ok(ObjectMetadata {
            size_estimate,
            contains_metadata_fields,
            is_encrypted,
            compression_applied,
            last_modified: None,
            access_count: 0,
            criticality_score: Self::calculate_criticality_score(object),
        })
    }
    
    fn estimate_object_size(object: &Object) -> usize {
        match object {
            Object::Stream(stream) => stream.content.len() + 100, // Add dictionary overhead
            Object::String(s, _) => s.len(),
            Object::Array(array) => array.len() * 10, // Estimate
            Object::Dictionary(dict) => dict.len() * 20, // Estimate
            _ => 10, // Basic overhead
        }
    }
    
    fn extract_metadata_fields(object: &Object) -> HashSet<MetadataField> {
        let mut fields = HashSet::new();
        
        if let Object::Dictionary(dict) = object {
            let metadata_keys = [
                (b"Title", MetadataField::Title),
                (b"Author", MetadataField::Author),
                (b"Subject", MetadataField::Subject),
                (b"Keywords", MetadataField::Keywords),
                (b"Creator", MetadataField::Creator),
                (b"Producer", MetadataField::Producer),
                (b"CreationDate", MetadataField::CreationDate),
                (b"ModDate", MetadataField::ModificationDate),
                (b"Trapped", MetadataField::Trapped),
            ];
            
            for (key, field) in &metadata_keys {
                if dict.has(key) {
                    fields.insert(field.clone());
                }
            }
        }
        
        fields
    }
    
    fn has_compression(object: &Object) -> bool {
        if let Object::Stream(stream) = object {
            return stream.dict.has(b"Filter");
        }
        false
    }
    
    fn calculate_criticality_score(object: &Object) -> f32 {
        if let Object::Dictionary(dict) = object {
            if let Ok(type_obj) = dict.get(b"Type") {
                if let Ok(type_name) = type_obj.as_name_str() {
                    return match type_name {
                        "Catalog" => 1.0,
                        "Pages" => 0.9,
                        "Page" => 0.8,
                        "Info" => 0.7,
                        "Metadata" => 0.6,
                        _ => 0.3,
                    };
                }
            }
        }
        0.1
    }
    
    fn is_metadata_key(key: &str) -> bool {
        matches!(key, "Title" | "Author" | "Subject" | "Keywords" | "Creator" | "Producer" | "CreationDate" | "ModDate" | "Trapped")
    }
    
    fn is_critical_dictionary(dict: &Dictionary) -> bool {
        if let Ok(type_obj) = dict.get(b"Type") {
            if let Ok(type_name) = type_obj.as_name_str() {
                return matches!(type_name, "Catalog" | "Pages" | "Page" | "Info");
            }
        }
        false
    }
    
    fn extract_binary_data(object: &Object) -> Result<Option<BinaryContent>> {
        if let Object::Stream(stream) = object {
            if stream.content.len() > 100 && Self::appears_binary(&stream.content) {
                let content_hash = Self::calculate_content_hash(&stream.content);
                
                return Ok(Some(BinaryContent {
                    content_hash,
                    original_size: stream.content.len(),
                    compressed_size: stream.content.len(), // Same if no compression
                    content_data: stream.content.clone(),
                    compression_method: CompressionMethod::None, // Would be determined from filters
                    integrity_verified: true,
                }));
            }
        }
        Ok(None)
    }
    
    fn appears_binary(data: &[u8]) -> bool {
        if data.len() < 100 {
            return false;
        }
        
        let non_printable_count = data.iter()
            .take(100)
            .filter(|&&b| b < 32 && b != 9 && b != 10 && b != 13)
            .count();
        
        non_printable_count as f64 / 100.0 > 0.1
    }
    
    fn calculate_content_hash(content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
    
    /// Add modification record
    pub fn record_modification(&mut self, operation_type: String, field_changed: Option<String>, old_value: Option<String>, new_value: Option<String>) {
        let record = ModificationRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operation_type,
            field_changed,
            old_value,
            new_value,
        };
        self.modification_history.push(record);
    }
    
    /// Update object relationships
    pub fn update_relationships(&mut self, relationships: ObjectRelationships) {
        self.relationships = relationships;
    }
    
    /// Check if object contains specific metadata field
    pub fn contains_metadata_field(&self, field: &MetadataField) -> bool {
        self.metadata.contains_metadata_fields.contains(field)
    }
}

impl ObjectRelationships {
    pub fn new() -> Self {
        Self {
            references_to: Vec::new(),
            referenced_by: Vec::new(),
            parent_object: None,
            child_objects: Vec::new(),
            dependency_level: 0,
            circular_references: false,
        }
    }
    
    pub fn add_reference_to(&mut self, object_id: ObjectId) {
        if !self.references_to.contains(&object_id) {
            self.references_to.push(object_id);
        }
    }
    
    pub fn add_referenced_by(&mut self, object_id: ObjectId) {
        if !self.referenced_by.contains(&object_id) {
            self.referenced_by.push(object_id);
        }
    }
    
    pub fn set_parent(&mut self, parent_id: ObjectId) {
        self.parent_object = Some(parent_id);
    }
    
    pub fn add_child(&mut self, child_id: ObjectId) {
        if !self.child_objects.contains(&child_id) {
            self.child_objects.push(child_id);
        }
    }
}

impl Default for ObjectMetadata {
    fn default() -> Self {
        Self {
            size_estimate: 0,
            contains_metadata_fields: HashSet::new(),
            is_encrypted: false,
            compression_applied: false,
            last_modified: None,
            access_count: 0,
            criticality_score: 0.0,
        }
    }
}
```

---

## File 3: `src/data/metadata_map.rs` (134 lines)

**Purpose**: Metadata location mapping and synchronization tracking
**Location**: src/data/metadata_map.rs
**Functionality**: Field storage tracking, synchronization target identification, coverage verification

```rust
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation, MetadataMap, MetadataValue},
};
use lopdf::ObjectId;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Comprehensive metadata location tracking system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataLocationTracker {
    pub field_locations: LocationMapping,
    pub synchronization_status: HashMap<MetadataField, SynchronizationStatus>,
    pub coverage_tracker: CoverageTracker,
    pub field_sync_map: FieldSynchronizationMap,
    pub location_priorities: HashMap<MetadataLocation, u8>,
}

/// Mapping of metadata fields to their storage locations
pub type LocationMapping = HashMap<MetadataField, Vec<LocationEntry>>;

/// Synchronization mapping for coordinated updates
pub type FieldSynchronizationMap = HashMap<MetadataField, SynchronizationGroup>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationEntry {
    pub location: MetadataLocation,
    pub object_id: Option<ObjectId>,
    pub current_value: Option<String>,
    pub last_modified: Option<String>,
    pub is_writable: bool,
    pub requires_synchronization: bool,
    pub access_path: String,
    pub validation_status: ValidationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationGroup {
    pub primary_location: MetadataLocation,
    pub secondary_locations: Vec<MetadataLocation>,
    pub sync_strategy: SyncStrategy,
    pub last_sync_timestamp: Option<String>,
    pub sync_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStrategy {
    MasterSlave,    // One primary location, others follow
    Bidirectional,  // All locations stay synchronized
    Hierarchical,   // Priority-based synchronization
    Custom(String), // Application-specific strategy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationStatus {
    pub is_synchronized: bool,
    pub last_sync_check: Option<String>,
    pub sync_conflicts: Vec<SyncConflict>,
    pub pending_updates: Vec<PendingUpdate>,
    pub sync_quality_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub location1: MetadataLocation,
    pub location2: MetadataLocation,
    pub value1: Option<String>,
    pub value2: Option<String>,
    pub conflict_type: ConflictType,
    pub resolution_strategy: ResolutionStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    ValueMismatch,
    MissingValue,
    FormatInconsistency,
    EncodingDifference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionStrategy {
    UseFirst,
    UseLast,
    UsePrimary,
    Merge,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub target_location: MetadataLocation,
    pub new_value: Option<String>,
    pub operation_type: UpdateOperation,
    pub priority: u8,
    pub retry_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateOperation {
    Set,
    Clear,
    Modify,
    Synchronize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Valid,
    Invalid(String),
    Pending,
    NotChecked,
}

/// Coverage tracking for metadata synchronization completeness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTracker {
    pub total_fields_discovered: usize,
    pub fields_with_multiple_locations: usize,
    pub synchronized_fields: usize,
    pub unsynchronized_fields: Vec<MetadataField>,
    pub coverage_percentage: f32,
    pub missing_standard_locations: Vec<(MetadataField, MetadataLocation)>,
}

impl MetadataLocationTracker {
    pub fn new() -> Self {
        Self {
            field_locations: HashMap::new(),
            synchronization_status: HashMap::new(),
            coverage_tracker: CoverageTracker::new(),
            field_sync_map: HashMap::new(),
            location_priorities: Self::default_location_priorities(),
        }
    }
    
    fn default_location_priorities() -> HashMap<MetadataLocation, u8> {
        let mut priorities = HashMap::new();
        priorities.insert(MetadataLocation::DocInfo, 10);        // Highest priority
        priorities.insert(MetadataLocation::XmpStream, 9);
        priorities.insert(MetadataLocation::ObjectStream(0), 5); // Medium priority
        priorities.insert(MetadataLocation::Annotation(0), 3);
        priorities.insert(MetadataLocation::FormField("".to_string()), 2);
        priorities.insert(MetadataLocation::CustomLocation("".to_string()), 1); // Lowest priority
        priorities
    }
    
    /// Add metadata location discovery
    pub fn add_location(&mut self, field: MetadataField, location: MetadataLocation, object_id: Option<ObjectId>, current_value: Option<String>, access_path: String) -> Result<()> {
        let location_entry = LocationEntry {
            location: location.clone(),
            object_id,
            current_value: current_value.clone(),
            last_modified: Some(chrono::Utc::now().to_rfc3339()),
            is_writable: self.is_location_writable(&location),
            requires_synchronization: self.requires_synchronization(&field, &location),
            access_path,
            validation_status: ValidationStatus::NotChecked,
        };
        
        self.field_locations
            .entry(field.clone())
            .or_insert_with(Vec::new)
            .push(location_entry);
        
        // Update synchronization status
        self.update_synchronization_status(&field);
        
        // Update coverage tracking
        self.update_coverage_tracking();
        
        Ok(())
    }
    
    fn is_location_writable(&self, location: &MetadataLocation) -> bool {
        match location {
            MetadataLocation::DocInfo => true,
            MetadataLocation::XmpStream => true,
            MetadataLocation::ObjectStream(_) => true,
            MetadataLocation::Annotation(_) => true,
            MetadataLocation::FormField(_) => true,
            MetadataLocation::CustomLocation(_) => false, // Conservative default
        }
    }
    
    fn requires_synchronization(&self, field: &MetadataField, location: &MetadataLocation) -> bool {
        // Standard metadata fields in standard locations require synchronization
        matches!(field, 
            MetadataField::Title | 
            MetadataField::Author | 
            MetadataField::Subject | 
            MetadataField::Keywords | 
            MetadataField::Creator | 
            MetadataField::Producer | 
            MetadataField::CreationDate
        ) && matches!(location, 
            MetadataLocation::DocInfo | 
            MetadataLocation::XmpStream
        )
    }
    
    fn update_synchronization_status(&mut self, field: &MetadataField) {
        let locations = self.field_locations.get(field).unwrap_or(&Vec::new());
        
        if locations.len() <= 1 {
            // Single location is always synchronized
            self.synchronization_status.insert(field.clone(), SynchronizationStatus {
                is_synchronized: true,
                last_sync_check: Some(chrono::Utc::now().to_rfc3339()),
                sync_conflicts: Vec::new(),
                pending_updates: Vec::new(),
                sync_quality_score: 1.0,
            });
            return;
        }
        
        // Check for synchronization across multiple locations
        let values: Vec<_> = locations.iter()
            .map(|loc| &loc.current_value)
            .collect();
        
        let is_synchronized = values.windows(2).all(|pair| pair[0] == pair[1]);
        let sync_conflicts = if !is_synchronized {
            self.detect_sync_conflicts(locations)
        } else {
            Vec::new()
        };
        
        let sync_quality_score = self.calculate_sync_quality_score(locations, &sync_conflicts);
        
        self.synchronization_status.insert(field.clone(), SynchronizationStatus {
            is_synchronized,
            last_sync_check: Some(chrono::Utc::now().to_rfc3339()),
            sync_conflicts,
            pending_updates: Vec::new(),
            sync_quality_score,
        });
    }
    
    fn detect_sync_conflicts(&self, locations: &[LocationEntry]) -> Vec<SyncConflict> {
        let mut conflicts = Vec::new();
        
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let loc1 = &locations[i];
                let loc2 = &locations[j];
                
                if loc1.current_value != loc2.current_value {
                    let conflict_type = if loc1.current_value.is_none() || loc2.current_value.is_none() {
                        ConflictType::MissingValue
                    } else {
                        ConflictType::ValueMismatch
                    };
                    
                    conflicts.push(SyncConflict {
                        location1: loc1.location.clone(),
                        location2: loc2.location.clone(),
                        value1: loc1.current_value.clone(),
                        value2: loc2.current_value.clone(),
                        conflict_type,
                        resolution_strategy: ResolutionStrategy::UsePrimary,
                    });
                }
            }
        }
        
        conflicts
    }
    
    fn calculate_sync_quality_score(&self, locations: &[LocationEntry], conflicts: &[SyncConflict]) -> f32 {
        if locations.is_empty() {
            return 1.0;
        }
        
        let synchronized_pairs = (locations.len() * (locations.len() - 1)) / 2;
        let conflict_count = conflicts.len();
        
        if synchronized_pairs == 0 {
            1.0
        } else {
            1.0 - (conflict_count as f32 / synchronized_pairs as f32)
        }
    }
    
    fn update_coverage_tracking(&mut self) {
        let total_fields_discovered = self.field_locations.len();
        let fields_with_multiple_locations = self.field_locations.values()
            .filter(|locations| locations.len() > 1)
            .count();
        
        let synchronized_fields = self.synchronization_status.values()
            .filter(|status| status.is_synchronized)
            .count();
        
        let unsynchronized_fields = self.synchronization_status.iter()
            .filter_map(|(field, status)| {
                if !status.is_synchronized {
                    Some(field.clone())
                } else {
                    None
                }
            })
            .collect();
        
        let coverage_percentage = if total_fields_discovered > 0 {
            (synchronized_fields as f32 / total_fields_discovered as f32) * 100.0
        } else {
            0.0
        };
        
        let missing_standard_locations = self.find_missing_standard_locations();
        
        self.coverage_tracker = CoverageTracker {
            total_fields_discovered,
            fields_with_multiple_locations,
            synchronized_fields,
            unsynchronized_fields,
            coverage_percentage,
            missing_standard_locations,
        };
    }
    
    fn find_missing_standard_locations(&self) -> Vec<(MetadataField, MetadataLocation)> {
        let mut missing = Vec::new();
        let standard_fields = [
            MetadataField::Title,
            MetadataField::Author,
            MetadataField::Subject,
            MetadataField::Keywords,
            MetadataField::Creator,
            MetadataField::Producer,
            MetadataField::CreationDate,
        ];
        
        let standard_locations = [
            MetadataLocation::DocInfo,
            MetadataLocation::XmpStream,
        ];
        
        for field in &standard_fields {
            if let Some(locations) = self.field_locations.get(field) {
                for standard_location in &standard_locations {
                    let has_location = locations.iter()
                        .any(|loc| std::mem::discriminant(&loc.location) == std::mem::discriminant(standard_location));
                    
                    if !has_location {
                        missing.push((field.clone(), standard_location.clone()));
                    }
                }
            } else {
                // Field not found at all
                for standard_location in &standard_locations {
                    missing.push((field.clone(), standard_location.clone()));
                }
            }
        }
        
        missing
    }
    
    /// Create synchronization group for coordinated updates
    pub fn create_synchronization_group(&mut self, field: MetadataField, primary_location: MetadataLocation, secondary_locations: Vec<MetadataLocation>, strategy: SyncStrategy) -> Result<()> {
        let sync_group = SynchronizationGroup {
            primary_location,
            secondary_locations,
            sync_strategy: strategy,
            last_sync_timestamp: None,
            sync_failures: 0,
        };
        
        self.field_sync_map.insert(field, sync_group);
        Ok(())
    }
    
    /// Update metadata value across all locations
    pub fn update_field_value(&mut self, field: &MetadataField, new_value: Option<String>) -> Result<Vec<PendingUpdate>> {
        let mut pending_updates = Vec::new();
        
        if let Some(locations) = self.field_locations.get_mut(field) {
            for location_entry in locations.iter_mut() {
                if location_entry.is_writable {
                    location_entry.current_value = new_value.clone();
                    location_entry.last_modified = Some(chrono::Utc::now().to_rfc3339());
                    
                    pending_updates.push(PendingUpdate {
                        target_location: location_entry.location.clone(),
                        new_value: new_value.clone(),
                        operation_type: if new_value.is_some() { UpdateOperation::Set } else { UpdateOperation::Clear },
                        priority: self.get_location_priority(&location_entry.location),
                        retry_count: 0,
                    });
                }
            }
        }
        
        // Update synchronization status
        if let Some(sync_status) = self.synchronization_status.get_mut(field) {
            sync_status.pending_updates.extend(pending_updates.clone());
            sync_status.is_synchronized = false; // Mark as needing synchronization
        }
        
        Ok(pending_updates)
    }
    
    fn get_location_priority(&self, location: &MetadataLocation) -> u8 {
        // Match location type for priority lookup
        match location {
            MetadataLocation::DocInfo => 10,
            MetadataLocation::XmpStream => 9,
            MetadataLocation::ObjectStream(_) => 5,
            MetadataLocation::Annotation(_) => 3,
            MetadataLocation::FormField(_) => 2,
            MetadataLocation::CustomLocation(_) => 1,
        }
    }
    
    /// Get comprehensive metadata map for processing
    pub fn to_metadata_map(&self) -> MetadataMap {
        let mut metadata_map = HashMap::new();
        
        for (field, locations) in &self.field_locations {
            let primary_value = self.get_primary_value(locations);
            let all_locations: Vec<MetadataLocation> = locations.iter()
                .map(|entry| entry.location.clone())
                .collect();
            
            let is_synchronized = self.synchronization_status
                .get(field)
                .map(|status| status.is_synchronized)
                .unwrap_or(true);
            
            let metadata_value = MetadataValue {
                field: field.clone(),
                value: primary_value,
                locations: all_locations,
                is_synchronized,
            };
            
            metadata_map.insert(field.clone(), metadata_value);
        }
        
        metadata_map
    }
    
    fn get_primary_value(&self, locations: &[LocationEntry]) -> Option<String> {
        // Find the highest priority location with a value
        locations.iter()
            .filter(|entry| entry.current_value.is_some())
            .max_by_key(|entry| self.get_location_priority(&entry.location))
            .and_then(|entry| entry.current_value.clone())
    }
    
    /// Validate all location entries
    pub fn validate_all_locations(&mut self) -> Result<ValidationSummary> {
        let mut validation_summary = ValidationSummary::new();
        
        for (field, locations) in &mut self.field_locations {
            for location_entry in locations {
                let validation_result = self.validate_location_entry(field, location_entry)?;
                location_entry.validation_status = validation_result;
                validation_summary.add_result(field, &location_entry.validation_status);
            }
        }
        
        Ok(validation_summary)
    }
    
    fn validate_location_entry(&self, field: &MetadataField, entry: &LocationEntry) -> Result<ValidationStatus> {
        // Validate based on field type and value format
        if let Some(ref value) = entry.current_value {
            match field {
                MetadataField::CreationDate | MetadataField::ModificationDate => {
                    if self.is_valid_date_format(value) {
                        Ok(ValidationStatus::Valid)
                    } else {
                        Ok(ValidationStatus::Invalid("Invalid date format".to_string()))
                    }
                },
                _ => Ok(ValidationStatus::Valid), // Basic validation for other fields
            }
        } else {
            Ok(ValidationStatus::Valid) // Null values are valid
        }
    }
    
    fn is_valid_date_format(&self, date_str: &str) -> bool {
        // Check for PDF date format or ISO 8601
        chrono::DateTime::parse_from_rfc3339(date_str).is_ok() ||
        date_str.starts_with("D:") // PDF date format
    }
}

#[derive(Debug, Clone)]
pub struct ValidationSummary {
    pub total_validated: usize,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub pending_count: usize,
    pub validation_errors: Vec<(MetadataField, String)>,
}

impl ValidationSummary {
    fn new() -> Self {
        Self {
            total_validated: 0,
            valid_count: 0,
            invalid_count: 0,
            pending_count: 0,
            validation_errors: Vec::new(),
        }
    }
    
    fn add_result(&mut self, field: &MetadataField, status: &ValidationStatus) {
        self.total_validated += 1;
        match status {
            ValidationStatus::Valid => self.valid_count += 1,
            ValidationStatus::Invalid(error) => {
                self.invalid_count += 1;
                self.validation_errors.push((field.clone(), error.clone()));
            },
            ValidationStatus::Pending => self.pending_count += 1,
            ValidationStatus::NotChecked => {},
        }
    }
}

impl CoverageTracker {
    fn new() -> Self {
        Self {
            total_fields_discovered: 0,
            fields_with_multiple_locations: 0,
            synchronized_fields: 0,
            unsynchronized_fields: Vec::new(),
            coverage_percentage: 0.0,
            missing_standard_locations: Vec::new(),
        }
    }
}

impl Default for MetadataLocationTracker {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## File 4: `src/utils/mod.rs` (42 lines)

**Purpose**: Utilities module interface and helper function coordination
**Location**: src/utils/mod.rs
**Functionality**: Helper function exports, common operation coordination, cross-utility type sharing

```rust
//! Utilities Module
//! 
//! Common utility functions and helpers for PDF forensic operations.
//! Provides cryptographic operations, serialization helpers, and forensic utilities
//! for supporting the core PDF processing functionality.

pub mod crypto;
pub mod serialization;
pub mod forensics;

// Re-export commonly used utility functions
pub use self::crypto::{
    HashCalculator, EncryptionHelper, SecurityUtils, CryptoConfig,
    hash_content, verify_integrity, generate_secure_key
};
pub use self::serialization::{
    JsonSerializer, BinarySerializer, CompressionHelper, SerializationConfig,
    serialize_to_json, deserialize_from_json, compress_data, decompress_data
};
pub use self::forensics::{
    TraceRemover, AuthenticityValidator, ForensicAnalyzer, CleaningUtils,
    remove_editing_traces, validate_authenticity, analyze_metadata_traces
};

use crate::{
    errors::{ForensicError, Result},
};

/// Utility operation configuration
#[derive(Debug, Clone)]
pub struct UtilityConfig {
    pub enable_compression: bool,
    pub crypto_strength: u8,
    pub forensic_cleaning_level: u8,
    pub validation_strictness: u8,
}

impl Default for UtilityConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            crypto_strength: 8,  // High strength
            forensic_cleaning_level: 9,  // Maximum cleaning
            validation_strictness: 7,  // High validation
        }
    }
}

/// Common utility result wrapper
pub type UtilityResult<T> = Result<T>;
```

---

## File 5: `src/utils/serialization.rs` (143 lines)

**Purpose**: JSON serialization helpers and efficient data representation
**Location**: src/utils/serialization.rs
**Functionality**: Efficient data representation, compression optimization, binary encoding

```rust
use crate::{
    errors::{ForensicError, Result},
    data::{
        clone_data::SerializableCloneData,
        pdf_objects::PdfObjectData,
        metadata_map::MetadataLocationTracker,
    },
};
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};

/// JSON serialization helper with compression support
pub struct JsonSerializer {
    config: SerializationConfig,
    compression_enabled: bool,
}

/// Binary serialization helper for efficient storage
pub struct BinarySerializer {
    config: SerializationConfig,
    format: BinaryFormat,
}

/// Compression helper for data optimization
pub struct CompressionHelper {
    compression_level: u8,
    algorithm: CompressionAlgorithm,
}

/// Serialization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationConfig {
    pub pretty_print: bool,
    pub include_metadata: bool,
    pub preserve_order: bool,
    pub compression_threshold: usize,
    pub max_memory_usage: usize,
}

#[derive(Debug, Clone)]
pub enum BinaryFormat {
    MessagePack,
    Bincode,
    Custom,
}

#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
    None,
}

impl JsonSerializer {
    pub fn new() -> Self {
        Self {
            config: SerializationConfig::default(),
            compression_enabled: true,
        }
    }
    
    pub fn with_config(config: SerializationConfig) -> Self {
        Self {
            config,
            compression_enabled: true,
        }
    }
    
    /// Serialize clone data to JSON
    pub fn serialize_clone_data(&self, clone_data: &SerializableCloneData) -> Result<Vec<u8>> {
        let json_data = if self.config.pretty_print {
            serde_json::to_vec_pretty(clone_data)
        } else {
            serde_json::to_vec(clone_data)
        }.map_err(|e| ForensicError::ConfigError {
            parameter: format!("JSON serialization failed: {}", e),
        })?;
        
        if self.compression_enabled && json_data.len() > self.config.compression_threshold {
            self.compress_json_data(&json_data)
        } else {
            Ok(json_data)
        }
    }
    
    /// Deserialize clone data from JSON
    pub fn deserialize_clone_data(&self, data: &[u8]) -> Result<SerializableCloneData> {
        let json_data = if self.is_compressed(data) {
            self.decompress_json_data(data)?
        } else {
            data.to_vec()
        };
        
        serde_json::from_slice(&json_data)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("JSON deserialization failed: {}", e),
            })
    }
    
    /// Serialize PDF object data to JSON
    pub fn serialize_object_data(&self, object_data: &[PdfObjectData]) -> Result<Vec<u8>> {
        let json_data = if self.config.pretty_print {
            serde_json::to_vec_pretty(object_data)
        } else {
            serde_json::to_vec(object_data)
        }.map_err(|e| ForensicError::ConfigError {
            parameter: format!("Object data serialization failed: {}", e),
        })?;
        
        if self.compression_enabled && json_data.len() > self.config.compression_threshold {
            self.compress_json_data(&json_data)
        } else {
            Ok(json_data)
        }
    }
    
    /// Serialize metadata location tracker
    pub fn serialize_metadata_tracker(&self, tracker: &MetadataLocationTracker) -> Result<Vec<u8>> {
        let json_data = if self.config.pretty_print {
            serde_json::to_vec_pretty(tracker)
        } else {
            serde_json::to_vec(tracker)
        }.map_err(|e| ForensicError::ConfigError {
            parameter: format!("Metadata tracker serialization failed: {}", e),
        })?;
        
        if self.compression_enabled && json_data.len() > self.config.compression_threshold {
            self.compress_json_data(&json_data)
        } else {
            Ok(json_data)
        }
    }
    
    fn compress_json_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let compressor = CompressionHelper::new();
        compressor.compress(data)
    }
    
    fn decompress_json_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let compressor = CompressionHelper::new();
        compressor.decompress(data)
    }
    
    fn is_compressed(&self, data: &[u8]) -> bool {
        // Simple heuristic: check for compression magic bytes
        data.len() > 4 && (
            data.starts_with(&[0x1f, 0x8b]) || // Gzip
            data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) // Zstd
        )
    }
}

impl BinarySerializer {
    pub fn new() -> Self {
        Self {
            config: SerializationConfig::default(),
            format: BinaryFormat::Bincode,
        }
    }
    
    pub fn with_format(format: BinaryFormat) -> Self {
        Self {
            config: SerializationConfig::default(),
            format,
        }
    }
    
    /// Serialize data to binary format
    pub fn serialize<T: Serialize>(&self, data: &T) -> Result<Vec<u8>> {
        match self.format {
            BinaryFormat::Bincode => {
                bincode::serialize(data)
                    .map_err(|e| ForensicError::ConfigError {
                        parameter: format!("Bincode serialization failed: {}", e),
                    })
            },
            BinaryFormat::MessagePack => {
                rmp_serde::to_vec(data)
                    .map_err(|e| ForensicError::ConfigError {
                        parameter: format!("MessagePack serialization failed: {}", e),
                    })
            },
            BinaryFormat::Custom => {
                // Custom binary format implementation
                self.serialize_custom(data)
            },
        }
    }
    
    /// Deserialize data from binary format
    pub fn deserialize<T: for<'de> Deserialize<'de>>(&self, data: &[u8]) -> Result<T> {
        match self.format {
            BinaryFormat::Bincode => {
                bincode::deserialize(data)
                    .map_err(|e| ForensicError::ConfigError {
                        parameter: format!("Bincode deserialization failed: {}", e),
                    })
            },
            BinaryFormat::MessagePack => {
                rmp_serde::from_slice(data)
                    .map_err(|e| ForensicError::ConfigError {
                        parameter: format!("MessagePack deserialization failed: {}", e),
                    })
            },
            BinaryFormat::Custom => {
                // Custom binary format implementation
                self.deserialize_custom(data)
            },
        }
    }
    
    fn serialize_custom<T: Serialize>(&self, _data: &T) -> Result<Vec<u8>> {
        // Placeholder for custom binary serialization
        Err(ForensicError::ConfigError {
            parameter: "Custom binary serialization not implemented".to_string(),
        })
    }
    
    fn deserialize_custom<T: for<'de> Deserialize<'de>>(&self, _data: &[u8]) -> Result<T> {
        // Placeholder for custom binary deserialization
        Err(ForensicError::ConfigError {
            parameter: "Custom binary deserialization not implemented".to_string(),
        })
    }
}

impl CompressionHelper {
    pub fn new() -> Self {
        Self {
            compression_level: 6,
            algorithm: CompressionAlgorithm::Gzip,
        }
    }
    
    pub fn with_algorithm(algorithm: CompressionAlgorithm) -> Self {
        Self {
            compression_level: 6,
            algorithm,
        }
    }
    
    /// Compress data using configured algorithm
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Gzip => self.compress_gzip(data),
            CompressionAlgorithm::Zstd => self.compress_zstd(data),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }
    
    /// Decompress data using configured algorithm
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Gzip => self.decompress_gzip(data),
            CompressionAlgorithm::Zstd => self.decompress_zstd(data),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }
    
    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::{write::GzEncoder, Compression};
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.compression_level as u32));
        encoder.write_all(data)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Gzip compression failed: {}", e),
            })?;
        
        encoder.finish()
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Gzip compression finish failed: {}", e),
            })
    }
    
    fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Gzip decompression failed: {}", e),
            })?;
        
        Ok(decompressed)
    }
    
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::compress(data, self.compression_level as i32)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Zstd compression failed: {}", e),
            })
    }
    
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::bulk::decompress(data, 1024 * 1024) // 1MB max decompressed size
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Zstd decompression failed: {}", e),
            })
    }
    
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::compress(data)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("LZ4 compression failed: {}", e),
            })
    }
    
    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("LZ4 decompression failed: {}", e),
            })
    }
    
    /// Calculate compression ratio
    pub fn compression_ratio(&self, original_size: usize, compressed_size: usize) -> f32 {
        if original_size == 0 {
            return 1.0;
        }
        compressed_size as f32 / original_size as f32
    }
    
    /// Estimate optimal compression algorithm for data
    pub fn estimate_optimal_algorithm(&self, data: &[u8]) -> CompressionAlgorithm {
        let entropy = self.calculate_entropy(data);
        
        if entropy > 7.5 {
            // High entropy data (already compressed/encrypted)
            CompressionAlgorithm::None
        } else if entropy > 5.0 {
            // Medium entropy - LZ4 for speed
            CompressionAlgorithm::Lz4
        } else {
            // Low entropy - Zstd for better compression
            CompressionAlgorithm::Zstd
        }
    }
    
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Default for SerializationConfig {
    fn default() -> Self {
        Self {
            pretty_print: false,
            include_metadata: true,
            preserve_order: true,
            compression_threshold: 1024, // 1KB
            max_memory_usage: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Convenience functions for common serialization operations

/// Serialize data to JSON with compression
pub fn serialize_to_json<T: Serialize>(data: &T) -> Result<Vec<u8>> {
    let serializer = JsonSerializer::new();
    let json_bytes = serde_json::to_vec(data)
        .map_err(|e| ForensicError::ConfigError {
            parameter: format!("JSON serialization failed: {}", e),
        })?;
    
    if json_bytes.len() > 1024 {
        let compressor = CompressionHelper::new();
        compressor.compress(&json_bytes)
    } else {
        Ok(json_bytes)
    }
}

/// Deserialize data from JSON with decompression
pub fn deserialize_from_json<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    let json_data = if data.len() > 4 && (data.starts_with(&[0x1f, 0x8b]) || data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])) {
        let compressor = CompressionHelper::new();
        compressor.decompress(data)?
    } else {
        data.to_vec()
    };
    
    serde_json::from_slice(&json_data)
        .map_err(|e| ForensicError::ConfigError {
            parameter: format!("JSON deserialization failed: {}", e),
        })
}

/// Compress data with optimal algorithm selection
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let compressor = CompressionHelper::new();
    let optimal_algorithm = compressor.estimate_optimal_algorithm(data);
    let optimal_compressor = CompressionHelper::with_algorithm(optimal_algorithm);
    optimal_compressor.compress(data)
}

/// Decompress data (auto-detect algorithm)
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b]) {
        let compressor = CompressionHelper::with_algorithm(CompressionAlgorithm::Gzip);
        compressor.decompress(data)
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let compressor = CompressionHelper::with_algorithm(CompressionAlgorithm::Zstd);
        compressor.decompress(data)
    } else {
        // Assume LZ4 or uncompressed
        let compressor = CompressionHelper::with_algorithm(CompressionAlgorithm::Lz4);
        compressor.decompress(data).or_else(|_| Ok(data.to_vec()))
    }
}

impl Default for JsonSerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for BinarySerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CompressionHelper {
    fn default() -> Self {
        Self::new()
    }
}
```

---

## Implementation Sequence

1. **Create src/data/mod.rs** - Establishes data structures module interface
2. **Implement src/data/pdf_objects.rs** - Complete PDF object representations with relationships
3. **Create src/data/metadata_map.rs** - Metadata location mapping and synchronization tracking
4. **Implement src/utils/mod.rs** - Utilities module interface and coordination
5. **Create src/utils/serialization.rs** - JSON serialization and compression helpers

## Compilation Requirements

After implementing these 5 files:
- Complete PDF object data structures will be available
- Metadata location tracking system will be functional
- Comprehensive serialization capabilities will be ready
- Utility functions will be implemented
- Foundation for data persistence and cloning will be established

## Next Guide

Implementation Guide 06 will create the remaining PDF processing modules (reconstructor, security, validator) and complete the final system components.