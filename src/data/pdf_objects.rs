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

    // Additional implementation methods follow...
    // [Continue with all remaining methods from the implementation guide]
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
