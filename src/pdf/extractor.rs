use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataValue, MetadataLocation},
    config::Config,
};
use super::{ParsedPdfData, MetadataLocation as PdfMetadataLocation};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Complete PDF data extractor for forensic cloning
pub struct PdfExtractor {
    extract_hidden_content: bool,
    preserve_binary_data: bool,
    initialization_time: DateTime<Utc>,
    operator: String,
}

/// Complete extraction data for PDF cloning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    pub metadata_map: MetadataMap,
    pub object_data: HashMap<ObjectId, ExtractedObjectData>,
    pub structure_data: StructureData,
    pub content_streams: HashMap<ObjectId, Vec<u8>>,
    pub binary_objects: HashMap<ObjectId, Vec<u8>>,
    pub cross_references: HashMap<ObjectId, Vec<ObjectId>>,
    pub encryption_data: Option<EncryptionData>,
    pub creation_date: String,
    pub extraction_time: DateTime<Utc>,
    pub operator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedObjectData {
    pub object_id: ObjectId,
    pub object_type: String,
    pub dictionary_data: Option<HashMap<String, String>>,
    pub stream_data: Option<Vec<u8>>,
    pub is_metadata_container: bool,
    pub references: Vec<ObjectId>,
    pub discovery_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureData {
    pub pdf_version: String,
    pub page_count: usize,
    pub catalog_id: ObjectId,
    pub pages_root_id: ObjectId,
    pub info_dict_id: Option<ObjectId>,
    pub metadata_stream_id: Option<ObjectId>,
    pub trailer_data: HashMap<String, String>,
    pub analysis_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionData {
    pub encrypt_dict: HashMap<String, String>,
    pub security_handler: String,
    pub key_length: u16,
    pub permissions: u32,
    pub detection_time: DateTime<Utc>,
}

impl PdfExtractor {
    pub fn new() -> Self {
        Self {
            extract_hidden_content: true,
            preserve_binary_data: true,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:45:59Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    pub fn with_options(extract_hidden: bool, preserve_binary: bool) -> Self {
        Self {
            extract_hidden_content: extract_hidden,
            preserve_binary_data: preserve_binary,
            initialization_time: DateTime::parse_from_rfc3339("2025-06-13T16:45:59Z")
                .unwrap()
                .with_timezone(&Utc),
            operator: "kartikpithava".to_string(),
        }
    }
    
    /// Extract complete PDF data for forensic cloning
    pub fn extract_complete_data(&self, parsed_data: &ParsedPdfData) -> Result<ExtractionData> {
        let metadata_map = self.extract_metadata_map(parsed_data)?;
        let object_data = self.extract_object_data(&parsed_data.document)?;
        let structure_data = self.extract_structure_data(parsed_data)?;
        let content_streams = self.extract_content_streams(&parsed_data.document)?;
        let binary_objects = self.extract_binary_objects(&parsed_data.document)?;
        let cross_references = self.extract_cross_references(&parsed_data.document)?;
        let encryption_data = self.extract_encryption_data(parsed_data)?;
        let creation_date = self.extract_creation_date(parsed_data)?;
        
        Ok(ExtractionData {
            metadata_map,
            object_data,
            structure_data,
            content_streams,
            binary_objects,
            cross_references,
            encryption_data,
            creation_date,
            extraction_time: self.initialization_time,
            operator: self.operator.clone(),
        })
    }
    
    fn extract_metadata_map(&self, parsed_data: &ParsedPdfData) -> Result<MetadataMap> {
        let mut metadata_map = HashMap::new();
        
        for location in &parsed_data.metadata_locations {
            let field = self.parse_metadata_field(&location.field_name)?;
            let metadata_location = self.convert_metadata_location(location);
            
            let metadata_value = MetadataValue {
                field: field.clone(),
                value: location.field_value.clone(),
                locations: vec![metadata_location],
                is_synchronized: false,
            };
            
            if let Some(existing) = metadata_map.get_mut(&field) {
                existing.locations.push(metadata_location);
            } else {
                metadata_map.insert(field, metadata_value);
            }
        }
        
        Ok(metadata_map)
    }
    
    fn parse_metadata_field(&self, field_name: &str) -> Result<MetadataField> {
        match field_name {
            "Title" => Ok(MetadataField::Title),
            "Author" => Ok(MetadataField::Author),
            "Subject" => Ok(MetadataField::Subject),
            "Keywords" => Ok(MetadataField::Keywords),
            "Creator" => Ok(MetadataField::Creator),
            "Producer" => Ok(MetadataField::Producer),
            "CreationDate" => Ok(MetadataField::CreationDate),
            "ModDate" => Ok(MetadataField::ModificationDate),
            "Trapped" => Ok(MetadataField::Trapped),
            custom => Ok(MetadataField::Custom(custom.to_string())),
        }
    }

    fn convert_metadata_location(&self, location: &PdfMetadataLocation) -> MetadataLocation {
        match location.location_type.as_str() {
            "DocInfo" => MetadataLocation::DocInfo,
            "XMP" => MetadataLocation::XmpStream,
            "Hidden" => {
                if let Some(object_id) = location.object_id {
                    MetadataLocation::ObjectStream(object_id.0 as u32)
                } else {
                    MetadataLocation::CustomLocation("Hidden".to_string())
                }
            },
            _ => MetadataLocation::CustomLocation(location.location_type.clone()),
        }
    }
    
    fn extract_object_data(&self, document: &Document) -> Result<HashMap<ObjectId, ExtractedObjectData>> {
        let mut object_data = HashMap::new();
        
        for (object_id, object) in &document.objects {
            let extracted = self.extract_single_object(*object_id, object)?;
            object_data.insert(*object_id, extracted);
        }
        
        Ok(object_data)
    }
    
    fn extract_single_object(&self, object_id: ObjectId, object: &Object) -> Result<ExtractedObjectData> {
        let object_type = self.determine_object_type(object);
        let dictionary_data = self.extract_dictionary_data(object)?;
        let stream_data = self.extract_stream_data(object)?;
        let is_metadata_container = self.check_metadata_container(object);
        let references = self.extract_object_references(object);
        
        Ok(ExtractedObjectData {
            object_id,
            object_type,
            dictionary_data,
            stream_data,
            is_metadata_container,
            references,
            discovery_time: DateTime::parse_from_rfc3339("2025-06-13T16:46:46Z")
                .unwrap()
                .with_timezone(&Utc),
        })
    }
    
    fn determine_object_type(&self, object: &Object) -> String {
        match object {
            Object::Dictionary(dict) => {
                if let Ok(type_obj) = dict.get(b"Type") {
                    if let Ok(type_name) = type_obj.as_name_str() {
                        return type_name.to_string();
                    }
                }
                "Dictionary".to_string()
            },
            Object::Stream(_) => "Stream".to_string(),
            Object::Array(_) => "Array".to_string(),
            Object::String(_, _) => "String".to_string(),
            Object::Name(_) => "Name".to_string(),
            Object::Integer(_) => "Integer".to_string(),
            Object::Real(_) => "Real".to_string(),
            Object::Boolean(_) => "Boolean".to_string(),
            Object::Null => "Null".to_string(),
            Object::Reference(_) => "Reference".to_string(),
        }
    }
    
    fn extract_dictionary_data(&self, object: &Object) -> Result<Option<HashMap<String, String>>> {
        match object {
            Object::Dictionary(dict) => {
                let mut dict_data = HashMap::new();
                for (key, value) in dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    let value_str = self.object_to_string(value);
                    dict_data.insert(key_str, value_str);
                }
                Ok(Some(dict_data))
            },
            Object::Stream(stream) => {
                let mut dict_data = HashMap::new();
                for (key, value) in stream.dict.iter() {
                    let key_str = String::from_utf8_lossy(key).to_string();
                    let value_str = self.object_to_string(value);
                    dict_data.insert(key_str, value_str);
                }
                Ok(Some(dict_data))
            },
            _ => Ok(None),
        }
    }
    
    fn extract_stream_data(&self, object: &Object) -> Result<Option<Vec<u8>>> {
        match object {
            Object::Stream(stream) => {
                if self.preserve_binary_data {
                    Ok(Some(stream.content.clone()))
                } else {
                    Ok(None)
                }
            },
            _ => Ok(None),
        }
    }
    
    fn check_metadata_container(&self, object: &Object) -> bool {
        match object {
            Object::Dictionary(dict) => {
                let metadata_keys = [
                    b"Title", b"Author", b"Subject", b"Keywords",
                    b"Creator", b"Producer", b"CreationDate", b"ModDate"
                ];
                metadata_keys.iter().any(|key| dict.has(key))
            },
            Object::Stream(stream) => {
                if let Ok(dict) = &stream.dict.as_dict() {
                    if let Ok(subtype) = dict.get(b"Subtype") {
                        if let Ok(subtype_name) = subtype.as_name_str() {
                            return subtype_name == "XML";
                        }
                    }
                }
                false
            },
            _ => false,
        }
    }
    
    fn extract_object_references(&self, object: &Object) -> Vec<ObjectId> {
        let mut references = Vec::new();
        self.collect_references_recursive(object, &mut references);
        references
    }
    
    fn collect_references_recursive(&self, object: &Object, references: &mut Vec<ObjectId>) {
        match object {
            Object::Reference(object_id) => {
                references.push(*object_id);
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_references_recursive(value, references);
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.collect_references_recursive(item, references);
                }
            },
            Object::Stream(stream) => {
                self.collect_references_recursive(&Object::Dictionary(stream.dict.clone()), references);
            },
            _ => {},
        }
    }
    
    fn object_to_string(&self, object: &Object) -> String {
        match object {
            Object::String(s, _) => String::from_utf8_lossy(s).to_string(),
            Object::Name(n) => String::from_utf8_lossy(n).to_string(),
            Object::Integer(i) => i.to_string(),
            Object::Real(r) => r.to_string(),
            Object::Boolean(b) => b.to_string(),
            Object::Null => "null".to_string(),
            Object::Reference(r) => format!("{} {} R", r.0, r.1),
            Object::Array(_) => "[Array]".to_string(),
            Object::Dictionary(_) => "[Dictionary]".to_string(),
            Object::Stream(_) => "[Stream]".to_string(),
        }
    }

    fn extract_structure_data(&self, parsed_data: &ParsedPdfData) -> Result<StructureData> {
        let document = &parsed_data.document;
        
        let catalog_id = document.catalog()
            .map_err(|e| ForensicError::structure_error(&format!("No catalog found: {}", e)))?;
        
        let pages_root_id = self.find_pages_root(document, catalog_id)?;
        let info_dict_id = self.find_info_dict(document)?;
        let metadata_stream_id = self.find_metadata_stream(document, catalog_id)?;
        let trailer_data = self.extract_trailer_data(document)?;
        
        Ok(StructureData {
            pdf_version: parsed_data.version.as_string(),
            page_count: parsed_data.page_count,
            catalog_id,
            pages_root_id,
            info_dict_id,
            metadata_stream_id,
            trailer_data,
            analysis_time: DateTime::parse_from_rfc3339("2025-06-13T16:47:56Z")
                .unwrap()
                .with_timezone(&Utc),
        })
    }
    
    fn find_pages_root(&self, document: &Document, catalog_id: ObjectId) -> Result<ObjectId> {
        if let Ok(catalog_obj) = document.get_object(catalog_id) {
            if let Ok(catalog_dict) = catalog_obj.as_dict() {
                if let Ok(pages_ref) = catalog_dict.get(b"Pages") {
                    if let Ok(pages_id) = pages_ref.as_reference() {
                        return Ok(pages_id);
                    }
                }
            }
        }
        Err(ForensicError::structure_error("Pages root not found"))
    }
    
    fn find_info_dict(&self, document: &Document) -> Result<Option<ObjectId>> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(info_ref) = trailer.get(b"Info") {
                if let Ok(info_id) = info_ref.as_reference() {
                    return Ok(Some(info_id));
                }
            }
        }
        Ok(None)
    }
    
    fn find_metadata_stream(&self, document: &Document, catalog_id: ObjectId) -> Result<Option<ObjectId>> {
        if let Ok(catalog_obj) = document.get_object(catalog_id) {
            if let Ok(catalog_dict) = catalog_obj.as_dict() {
                if let Ok(metadata_ref) = catalog_dict.get(b"Metadata") {
                    if let Ok(metadata_id) = metadata_ref.as_reference() {
                        return Ok(Some(metadata_id));
                    }
                }
            }
        }
        Ok(None)
    }
    
    fn extract_trailer_data(&self, document: &Document) -> Result<HashMap<String, String>> {
        let mut trailer_data = HashMap::new();
        
        if let Ok(trailer_dict) = document.trailer.as_dict() {
            for (key, value) in trailer_dict.iter() {
                let key_str = String::from_utf8_lossy(key).to_string();
                let value_str = self.object_to_string(value);
                trailer_data.insert(key_str, value_str);
            }
        }
        
        Ok(trailer_data)
    }
    
    fn extract_content_streams(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<u8>>> {
        let mut content_streams = HashMap::new();
        
        // Extract page content streams
        for page_id in document.page_iter() {
            if let Ok(page_obj) = document.get_object(page_id) {
                if let Ok(page_dict) = page_obj.as_dict() {
                    if let Ok(contents) = page_dict.get(b"Contents") {
                        self.extract_content_from_object(contents, document, &mut content_streams)?;
                    }
                }
            }
        }
        
        Ok(content_streams)
    }
    
    fn extract_content_from_object(
        &self,
        object: &Object,
        document: &Document,
        content_streams: &mut HashMap<ObjectId, Vec<u8>>
    ) -> Result<()> {
        match object {
            Object::Reference(object_id) => {
                if let Ok(referenced_obj) = document.get_object(*object_id) {
                    self.extract_content_from_object(referenced_obj, document, content_streams)?;
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.extract_content_from_object(item, document, content_streams)?;
                }
            },
            Object::Stream(stream) => {
                content_streams.insert(document.get_object_id(object).unwrap_or(ObjectId(0, 0)), 
                                    stream.content.clone());
            },
            _ => {},
        }
        Ok(())
    }
    
    fn extract_binary_objects(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<u8>>> {
        let mut binary_objects = HashMap::new();
        
        if self.preserve_binary_data {
            for (object_id, object) in &document.objects {
                if let Some(binary_data) = self.extract_binary_data(object) {
                    binary_objects.insert(*object_id, binary_data);
                }
            }
        }
        
        Ok(binary_objects)
    }
    
    fn extract_binary_data(&self, object: &Object) -> Option<Vec<u8>> {
        match object {
            Object::Stream(stream) => {
                if self.is_binary_stream(stream) {
                    Some(stream.content.clone())
                } else {
                    None
                }
            },
            Object::String(data, _) => {
                if data.len() > 50 && self.appears_binary(data) {
                    Some(data.clone())
                } else {
                    None
                }
            },
            _ => None,
        }
    }
    
    fn is_binary_stream(&self, stream: &Stream) -> bool {
        if let Ok(dict) = &stream.dict.as_dict() {
            if let Ok(subtype) = dict.get(b"Subtype") {
                if let Ok(subtype_name) = subtype.as_name_str() {
                    return matches!(subtype_name, "Image" | "Form" | "PS" | "FontFile" | "FontFile2" | "FontFile3");
                }
            }
        }
        false
    }
    
    fn appears_binary(&self, data: &[u8]) -> bool {
        let non_printable_count = data.iter()
            .filter(|&&b| b < 32 && !matches!(b, 9 | 10 | 13))
            .count();
        
        (non_printable_count as f64 / data.len() as f64) > 0.1
    }
    
    fn extract_cross_references(&self, document: &Document) -> Result<HashMap<ObjectId, Vec<ObjectId>>> {
        let mut cross_references = HashMap::new();
        
        for (object_id, object) in &document.objects {
            let references = self.extract_object_references(object);
            if !references.is_empty() {
                cross_references.insert(*object_id, references);
            }
        }
        
        Ok(cross_references)
    }
    
    fn extract_encryption_data(&self, parsed_data: &ParsedPdfData) -> Result<Option<EncryptionData>> {
        if let Some(ref encryption_info) = parsed_data.encryption_info {
            let mut encrypt_dict = HashMap::new();
            encrypt_dict.insert("Filter".to_string(), encryption_info.filter.clone());
            encrypt_dict.insert("V".to_string(), encryption_info.version.to_string());
            encrypt_dict.insert("R".to_string(), encryption_info.revision.to_string());
            encrypt_dict.insert("Length".to_string(), encryption_info.key_length.to_string());
            
            Ok(Some(EncryptionData {
                encrypt_dict,
                security_handler: encryption_info.filter.clone(),
                key_length: encryption_info.key_length,
                permissions: encryption_info.permissions,
                detection_time: DateTime::parse_from_rfc3339("2025-06-13T16:47:56Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }))
        } else {
            Ok(None)
        }
    }
    
    fn extract_creation_date(&self, parsed_data: &ParsedPdfData) -> Result<String> {
        for location in &parsed_data.metadata_locations {
            if location.field_name == "CreationDate" {
                if let Some(ref date_value) = location.field_value {
                    return Ok(date_value.clone());
                }
            }
        }
        
        Ok(crate::forensic::ForensicCleaner::generate_authentic_timestamp())
    }
}

impl Default for PdfExtractor {
    fn default() -> Self {
        Self::new()
    }
              }
