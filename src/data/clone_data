use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation},
};
use lopdf::ObjectId;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Serializable clone data for complete PDF reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableCloneData {
    pub metadata: ClonedMetadata,
    pub objects: HashMap<String, ClonedObjectData>,
    pub structure: DocumentStructure,
    pub binary_content: BinaryContentMap,
    pub reconstruction_info: ReconstructionData,
    pub verification: VerificationData,
    pub format_config: SerializationFormat,
}

/// Complete reconstruction data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionData {
    pub object_order: Vec<String>,
    pub cross_reference_table: Vec<CrossRefEntry>,
    pub trailer_info: TrailerData,
    pub pdf_version: String,
    pub file_size_estimate: u64,
    pub checksum_verification: HashMap<String, String>,
}

/// Verification data for integrity checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationData {
    pub content_hashes: HashMap<String, String>,
    pub structure_fingerprint: String,
    pub metadata_checksum: String,
    pub timestamp_verification: String,
    pub authenticity_markers: Vec<AuthenticityMarker>,
}

/// Compression configuration for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm,
    pub compression_level: u8,
    pub enable_streaming: bool,
    pub chunk_size: usize,
}

/// Serialization format specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationFormat {
    pub version: String,
    pub encoding: String,
    pub compression: CompressionConfig,
    pub metadata_included: bool,
    pub binary_encoding: BinaryEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClonedMetadata {
    pub fields: HashMap<String, Option<String>>,
    pub locations: HashMap<String, Vec<String>>,
    pub synchronization_status: HashMap<String, bool>,
    pub original_values: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClonedObjectData {
    pub object_id: String,
    pub object_type: String,
    pub content: ObjectContent,
    pub relationships: ObjectRelationships,
    pub metadata_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectContent {
    Dictionary(HashMap<String, SerializableValue>),
    Stream { dict: HashMap<String, SerializableValue>, content_ref: String },
    Array(Vec<SerializableValue>),
    Primitive(SerializableValue),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableValue {
    String(String),
    Name(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Null,
    Reference(String),
    Array(Vec<SerializableValue>),
    Dictionary(HashMap<String, SerializableValue>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRelationships {
    pub references_to: Vec<String>,
    pub referenced_by: Vec<String>,
    pub parent: Option<String>,
    pub children: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentStructure {
    pub catalog_id: String,
    pub pages_root_id: String,
    pub info_dict_id: Option<String>,
    pub metadata_stream_id: Option<String>,
    pub page_count: usize,
    pub object_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryContentMap {
    pub streams: HashMap<String, BinaryContent>,
    pub images: HashMap<String, BinaryContent>,
    pub fonts: HashMap<String, BinaryContent>,
    pub embedded_files: HashMap<String, BinaryContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryContent {
    pub content_id: String,
    pub data: Vec<u8>,
    pub original_size: usize,
    pub compression_method: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRefEntry {
    pub object_id: String,
    pub offset: u64,
    pub generation: u16,
    pub in_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrailerData {
    pub size: u64,
    pub root_ref: String,
    pub info_ref: Option<String>,
    pub id_array: Option<Vec<String>>,
    pub prev_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticityMarker {
    pub marker_type: String,
    pub location: String,
    pub value: String,
    pub verification_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    None,
    Gzip,
    Zstd,
    Lz4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryEncoding {
    Base64,
    Hexadecimal,
    Raw,
}

impl SerializableCloneData {
    /// Create new clone data from extraction
    pub fn from_extraction_data(extraction_data: &crate::pdf::ExtractionData) -> Result<Self> {
        let metadata = Self::convert_metadata(&extraction_data.metadata_map)?;
        let objects = Self::convert_objects(&extraction_data.object_data)?;
        let structure = Self::convert_structure(&extraction_data.structure_data)?;
        let binary_content = Self::convert_binary_content(extraction_data)?;
        let reconstruction_info = Self::create_reconstruction_info(extraction_data)?;
        let verification = Self::create_verification_data(extraction_data)?;
        let format_config = SerializationFormat::default();

        Ok(Self {
            metadata,
            objects,
            structure,
            binary_content,
            reconstruction_info,
            verification,
            format_config,
        })
    }

    fn convert_metadata(metadata_map: &crate::types::MetadataMap) -> Result<ClonedMetadata> {
        let mut fields = HashMap::new();
        let mut locations = HashMap::new();
        let mut synchronization_status = HashMap::new();
        let mut original_values = HashMap::new();

        for (field, metadata_value) in metadata_map {
            let field_name = field.as_string();
            fields.insert(field_name.clone(), metadata_value.value.clone());

            let location_strings: Vec<String> = metadata_value.locations.iter()
                .map(|loc| Self::location_to_string(loc))
                .collect();
            locations.insert(field_name.clone(), location_strings);

            synchronization_status.insert(field_name.clone(), metadata_value.is_synchronized);
            original_values.insert(field_name, metadata_value.value.clone());
        }

        Ok(ClonedMetadata {
            fields,
            locations,
            synchronization_status,
            original_values,
        })
    }

    fn location_to_string(location: &MetadataLocation) -> String {
        match location {
            MetadataLocation::DocInfo => "DocInfo".to_string(),
            MetadataLocation::XmpStream => "XmpStream".to_string(),
            MetadataLocation::ObjectStream(id) => format!("ObjectStream:{}", id),
            MetadataLocation::Annotation(id) => format!("Annotation:{}", id),
            MetadataLocation::FormField(name) => format!("FormField:{}", name),
            MetadataLocation::CustomLocation(name) => format!("Custom:{}", name),
        }
    }

    fn convert_objects(object_data: &HashMap<ObjectId, crate::pdf::ExtractedObjectData>) -> Result<HashMap<String, ClonedObjectData>> {
        let mut objects = HashMap::new();

        for (object_id, extracted_object) in object_data {
            let object_id_str = format!("{}_{}", object_id.0, object_id.1);
            let content = Self::convert_object_content(extracted_object)?;
            let relationships = Self::convert_relationships(&extracted_object.references);

            let metadata_flags = if extracted_object.is_metadata_container {
                vec!["metadata_container".to_string()]
            } else {
                vec![]
            };

            let cloned_object = ClonedObjectData {
                object_id: object_id_str.clone(),
                object_type: extracted_object.object_type.clone(),
                content,
                relationships,
                metadata_flags,
            };

            objects.insert(object_id_str, cloned_object);
        }

        Ok(objects)
    }

    fn convert_object_content(extracted_object: &crate::pdf::ExtractedObjectData) -> Result<ObjectContent> {
        if let Some(ref stream_data) = extracted_object.stream_data {
            let dict = extracted_object.dictionary_data.clone().unwrap_or_default();
            let dict_converted = Self::convert_string_map_to_serializable(dict)?;
            Ok(ObjectContent::Stream {
                dict: dict_converted,
                content_ref: format!("stream_{}", extracted_object.object_id.0),
            })
        } else if let Some(ref dict_data) = extracted_object.dictionary_data {
            let dict_converted = Self::convert_string_map_to_serializable(dict_data.clone())?;
            Ok(ObjectContent::Dictionary(dict_converted))
        } else {
            Ok(ObjectContent::Primitive(SerializableValue::String("Unknown".to_string())))
        }
    }

    fn convert_string_map_to_serializable(map: HashMap<String, String>) -> Result<HashMap<String, SerializableValue>> {
        let mut result = HashMap::new();
        for (key, value) in map {
            let serializable_value = Self::string_to_serializable_value(&value);
            result.insert(key, serializable_value);
        }
        Ok(result)
    }

    fn string_to_serializable_value(value: &str) -> SerializableValue {
        if value == "null" {
            SerializableValue::Null
        } else if value == "true" {
            SerializableValue::Boolean(true)
        } else if value == "false" {
            SerializableValue::Boolean(false)
        } else if let Ok(int_val) = value.parse::<i64>() {
            SerializableValue::Integer(int_val)
        } else if let Ok(real_val) = value.parse::<f64>() {
            SerializableValue::Real(real_val)
        } else if value.contains(" R") {
            SerializableValue::Reference(value.to_string())
        } else if value.starts_with('/') {
            SerializableValue::Name(value.to_string())
        } else {
            SerializableValue::String(value.to_string())
        }
    }

    fn convert_relationships(references: &[ObjectId]) -> ObjectRelationships {
        let references_to: Vec<String> = references.iter()
            .map(|id| format!("{}_{}", id.0, id.1))
            .collect();

        ObjectRelationships {
            references_to,
            referenced_by: Vec::new(),
            parent: None,
            children: Vec::new(),
        }
    }

    fn convert_structure(structure_data: &crate::pdf::StructureData) -> Result<DocumentStructure> {
        Ok(DocumentStructure {
            catalog_id: format!("{}_{}", structure_data.catalog_id.0, structure_data.catalog_id.1),
            pages_root_id: format!("{}_{}", structure_data.pages_root_id.0, structure_data.pages_root_id.1),
            info_dict_id: structure_data.info_dict_id.map(|id| format!("{}_{}", id.0, id.1)),
            metadata_stream_id: structure_data.metadata_stream_id.map(|id| format!("{}_{}", id.0, id.1)),
            page_count: structure_data.page_count,
            object_count: 0, // Can be set to actual objects.len() if desired
        })
    }

    fn convert_binary_content(extraction_data: &crate::pdf::ExtractionData) -> Result<BinaryContentMap> {
        let mut streams = HashMap::new();
        let mut images = HashMap::new();
        let mut fonts = HashMap::new();
        let mut embedded_files = HashMap::new();

        for (object_id, content) in &extraction_data.content_streams {
            let content_id = format!("stream_{}_{}", object_id.0, object_id.1);
            let binary_content = BinaryContent {
                content_id: content_id.clone(),
                data: content.clone(),
                original_size: content.len(),
                compression_method: "none".to_string(),
                content_hash: Self::calculate_hash(content),
            };
            streams.insert(content_id, binary_content);
        }

        for (object_id, content) in &extraction_data.binary_objects {
            let content_id = format!("binary_{}_{}", object_id.0, object_id.1);
            let binary_content = BinaryContent {
                content_id: content_id.clone(),
                data: content.clone(),
                original_size: content.len(),
                compression_method: "none".to_string(),
                content_hash: Self::calculate_hash(content),
            };

            // Categorize by type (simplified)
            if content.len() > 1000 && Self::appears_image(content) {
                images.insert(content_id, binary_content);
            } else {
                embedded_files.insert(content_id, binary_content);
            }
        }

        Ok(BinaryContentMap {
            streams,
            images,
            fonts,
            embedded_files,
        })
    }

    fn calculate_hash(data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn appears_image(data: &[u8]) -> bool {
        data.len() > 10 && (
            data.starts_with(b"\xFF\xD8") || // JPEG
            data.starts_with(b"\x89PNG") ||  // PNG
            data.starts_with(b"GIF87") ||    // GIF87
            data.starts_with(b"GIF89")       // GIF89
        )
    }

    fn create_reconstruction_info(extraction_data: &crate::pdf::ExtractionData) -> Result<ReconstructionData> {
        let object_order: Vec<String> = extraction_data.object_data.keys()
            .map(|id| format!("{}_{}", id.0, id.1))
            .collect();

        let cross_reference_table: Vec<CrossRefEntry> = extraction_data.object_data.keys()
            .enumerate()
            .map(|(i, id)| CrossRefEntry {
                object_id: format!("{}_{}", id.0, id.1),
                offset: (i * 100) as u64, // Simplified offset calculation
                generation: id.1,
                in_use: true,
            })
            .collect();

        let trailer_info = TrailerData {
            size: extraction_data.object_data.len() as u64 + 1,
            root_ref: format!("{}_{}", extraction_data.structure_data.catalog_id.0, extraction_data.structure_data.catalog_id.1),
            info_ref: extraction_data.structure_data.info_dict_id.map(|id| format!("{}_{}", id.0, id.1)),
            id_array: None,
            prev_offset: None,
        };

        let mut checksum_verification = HashMap::new();
        for (object_id, object_data) in &extraction_data.object_data {
            let object_id_str = format!("{}_{}", object_id.0, object_id.1);
            if let Some(ref stream_data) = object_data.stream_data {
                checksum_verification.insert(object_id_str, Self::calculate_hash(stream_data));
            }
        }

        Ok(ReconstructionData {
            object_order,
            cross_reference_table,
            trailer_info,
            pdf_version: extraction_data.structure_data.pdf_version.clone(),
            file_size_estimate: 0, // Will be calculated during reconstruction
            checksum_verification,
        })
    }

    fn create_verification_data(extraction_data: &crate::pdf::ExtractionData) -> Result<VerificationData> {
        let mut content_hashes = HashMap::new();

        for (object_id, object_data) in &extraction_data.object_data {
            let object_id_str = format!("{}_{}", object_id.0, object_id.1);
            if let Some(ref stream_data) = object_data.stream_data {
                content_hashes.insert(object_id_str, Self::calculate_hash(stream_data));
            }
        }

        let structure_fingerprint = Self::calculate_hash(
            format!("{:?}", extraction_data.structure_data).as_bytes()
        );

        let metadata_checksum = Self::calculate_hash(
            format!("{:?}", extraction_data.metadata_map).as_bytes()
        );

        let authenticity_markers = vec![
            AuthenticityMarker {
                marker_type: "timestamp".to_string(),
                location: "creation_date".to_string(),
                value: extraction_data.creation_date.clone(),
                verification_method: "datetime_parse".to_string(),
            }
        ];

        Ok(VerificationData {
            content_hashes,
            structure_fingerprint,
            metadata_checksum,
            timestamp_verification: chrono::Utc::now().to_rfc3339(),
            authenticity_markers,
        })
    }
}

impl Default for SerializationFormat {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            encoding: "utf-8".to_string(),
            compression: CompressionConfig::default(),
            metadata_included: true,
            binary_encoding: BinaryEncoding::Base64,
        }
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Gzip,
            compression_level: 6,
            enable_streaming: false,
            chunk_size: 1024 * 1024, // 1MB
        }
    }
}
