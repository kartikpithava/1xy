use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation, PdfVersion},
    config::Config,
};
use lopdf::{Document, Object, ObjectId, Dictionary, Stream};
use std::collections::{HashMap, BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

/// PDF reconstruction engine for forensic operations
pub struct PdfReconstructor {
    config: ReconstructionConfig,
    object_mapping: HashMap<ObjectId, ObjectId>,
    reconstruction_order: Vec<ObjectId>,
    processing_state: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct ReconstructionConfig {
    pub target_pdf_version: PdfVersion,
    pub preserve_structure: bool,
    pub optimize_output: bool,
    pub maintain_authenticity: bool,
    pub compression_enabled: bool,
}

#[derive(Debug)]
struct ProcessingContext {
    processed: HashSet<ObjectId>,
    processing_stack: Vec<ObjectId>,
    dependencies: HashMap<ObjectId, Vec<ObjectId>>,
}

impl PdfReconstructor {
    pub fn new() -> Self {
        Self {
            config: ReconstructionConfig::default(),
            object_mapping: HashMap::new(),
            reconstruction_order: Vec::new(),
            processing_state: AtomicBool::new(false),
        }
    }
    
    pub fn with_config(config: ReconstructionConfig) -> Self {
        Self {
            config,
            object_mapping: HashMap::new(),
            reconstruction_order: Vec::new(),
            processing_state: AtomicBool::new(false),
        }
    }

    /// Rebuild PDF from clone data with modifications
    pub fn rebuild_pdf(&mut self, clone_data: &CloneData) -> Result<Vec<u8>> {
        if self.processing_state.load(Ordering::SeqCst) {
            return Err(ForensicError::structure_error("Reconstruction already in progress"));
        }
        self.processing_state.store(true, Ordering::SeqCst);

        // Phase 1: Initialize new document structure
        let mut new_document = Document::with_version(self.config.target_pdf_version.as_string());
        
        // Phase 2: Build object mapping for ID preservation
        self.build_object_mapping(clone_data)?;
        
        // Phase 3: Reconstruct objects in proper order
        self.reconstruct_objects(&mut new_document, clone_data)?;
        
        // Phase 4: Rebuild document structure
        self.rebuild_document_structure(&mut new_document, clone_data)?;
        
        // Phase 5: Apply metadata modifications
        self.apply_metadata_modifications(&mut new_document, clone_data)?;
        
        // Phase 6: Optimize and validate output
        if self.config.optimize_output {
            self.optimize_document(&mut new_document)?;
        }
        
        // Phase 7: Generate final PDF bytes
        let mut output_buffer = Vec::new();
        new_document.save_to(&mut output_buffer)
            .map_err(|e| ForensicError::structure_error(&format!("Failed to save reconstructed PDF: {}", e)))?;
        
        self.processing_state.store(false, Ordering::SeqCst);
        Ok(output_buffer)
    }

    fn build_object_mapping(&mut self, clone_data: &CloneData) -> Result<()> {
        self.object_mapping.clear();
        
        for (original_id, cloned_object) in &clone_data.cloned_objects {
            self.object_mapping.insert(*original_id, cloned_object.new_id);
        }
        
        self.reconstruction_order = self.calculate_reconstruction_order(clone_data)?;
        Ok(())
    }

    fn calculate_reconstruction_order(&self, clone_data: &CloneData) -> Result<Vec<ObjectId>> {
        let mut context = ProcessingContext {
            processed: HashSet::new(),
            processing_stack: Vec::new(),
            dependencies: HashMap::new(),
        };

        let mut order = Vec::new();
        
        // Process critical objects first
        let critical_objects = [
            clone_data.structure_map.catalog_mapping,
            clone_data.structure_map.pages_mapping,
        ];

        for &critical_id in &critical_objects {
            if !context.processed.contains(&critical_id) {
                self.process_object_dependencies(
                    critical_id,
                    clone_data,
                    &mut order,
                    &mut context,
                )?;
            }
        }

        // Process remaining objects
        for original_id in clone_data.cloned_objects.keys() {
            if !context.processed.contains(original_id) {
                self.process_object_dependencies(
                    *original_id,
                    clone_data,
                    &mut order,
                    &mut context,
                )?;
            }
        }

        Ok(order)
    }

    fn process_object_dependencies(
        &self,
        object_id: ObjectId,
        clone_data: &CloneData,
        order: &mut Vec<ObjectId>,
        context: &mut ProcessingContext,
    ) -> Result<()> {
        if context.processed.contains(&object_id) {
            return Ok(());
        }

        if context.processing_stack.contains(&object_id) {
            return Ok(());  // Break circular dependencies
        }

        context.processing_stack.push(object_id);

        if let Some(cloned_object) = clone_data.cloned_objects.get(&object_id) {
            for &referenced_id in &cloned_object.references {
                if clone_data.cloned_objects.contains_key(&referenced_id) {
                    self.process_object_dependencies(
                        referenced_id,
                        clone_data,
                        order,
                        context,
                    )?;
                }
            }
        }

        context.processing_stack.pop();

        if !context.processed.contains(&object_id) {
            order.push(object_id);
            context.processed.insert(object_id);
        }

        Ok(())
    }

    fn reconstruct_objects(&mut self, document: &mut Document, clone_data: &CloneData) -> Result<()> {
        for &object_id in &self.reconstruction_order {
            if let Some(cloned_object) = clone_data.cloned_objects.get(&object_id) {
                let reconstructed_object = self.reconstruct_single_object(cloned_object, clone_data)?;
                let new_id = self.object_mapping.get(&object_id).copied().unwrap_or(object_id);
                document.objects.insert(new_id, reconstructed_object);
            }
        }
        Ok(())
    }

    fn reconstruct_single_object(&self, cloned_object: &ClonedObject, clone_data: &CloneData) -> Result<Object> {
        match &cloned_object.cloned_content {
            ClonedContent::Dictionary(dict_data) => {
                let mut dictionary = Dictionary::new();
                for (key, value) in dict_data {
                    let object_value = self.convert_string_to_object(value)?;
                    dictionary.set(key.as_bytes(), object_value);
                }
                Ok(Object::Dictionary(dictionary))
            },
            ClonedContent::Stream { dict, content } => {
                let mut dictionary = Dictionary::new();
                for (key, value) in dict {
                    let object_value = self.convert_string_to_object(value)?;
                    dictionary.set(key.as_bytes(), object_value);
                }
                
                let stream_content = if let Some(preserved_content) = clone_data.binary_preservation.preserved_streams.get(&cloned_object.original_id) {
                    preserved_content.clone()
                } else {
                    content.clone()
                };
                
                let stream = Stream::new(dictionary, stream_content);
                Ok(Object::Stream(stream))
            },
            ClonedContent::Primitive(primitive) => {
                self.convert_primitive_to_object(primitive)
            },
        }
    }

    fn convert_string_to_object(&self, value_str: &str) -> Result<Object> {
        if value_str == "null" {
            Ok(Object::Null)
        } else if value_str == "true" {
            Ok(Object::Boolean(true))
        } else if value_str == "false" {
            Ok(Object::Boolean(false))
        } else if let Ok(int_val) = value_str.parse::<i64>() {
            Ok(Object::Integer(int_val))
        } else if let Ok(real_val) = value_str.parse::<f64>() {
            Ok(Object::Real(real_val))
        } else if value_str.contains(" R") {
            let parts: Vec<&str> = value_str.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "R" {
                if let (Ok(id), Ok(gen)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                    let original_ref = ObjectId(id, gen);
                    let new_ref = self.object_mapping.get(&original_ref).copied().unwrap_or(original_ref);
                    return Ok(Object::Reference(new_ref));
                }
            }
            Ok(Object::String(value_str.as_bytes().to_vec(), lopdf::StringFormat::Literal))
        } else if value_str.starts_with('/') {
            Ok(Object::Name(value_str[1..].as_bytes().to_vec()))
        } else {
            Ok(Object::String(value_str.as_bytes().to_vec(), lopdf::StringFormat::Literal))
        }
    }

    fn convert_primitive_to_object(&self, primitive: &str) -> Result<Object> {
        self.convert_string_to_object(primitive)
    }

    fn rebuild_document_structure(&mut self, document: &mut Document, clone_data: &CloneData) -> Result<()> {
        let catalog_id = self.object_mapping.get(&clone_data.structure_map.catalog_mapping)
            .copied()
            .unwrap_or(clone_data.structure_map.catalog_mapping);
        
        let mut trailer = Dictionary::new();
        trailer.set("Size", Object::Integer((document.objects.len() + 1) as i64));
        trailer.set("Root", Object::Reference(catalog_id));
        
        if let Some(info_id) = clone_data.structure_map.info_dict_mapping {
            let mapped_info_id = self.object_mapping.get(&info_id).copied().unwrap_or(info_id);
            trailer.set("Info", Object::Reference(mapped_info_id));
        }
        
        document.trailer = Object::Dictionary(trailer);
        Ok(())
    }

    fn apply_metadata_modifications(&self, document: &mut Document, clone_data: &CloneData) -> Result<()> {
        for (field_name, new_value) in &clone_data.metadata_modifications.field_updates {
            self.update_metadata_field(document, field_name, new_value.as_deref())?;
        }

        for field_name in &clone_data.metadata_modifications.removal_list {
            self.remove_metadata_field(document, field_name)?;
        }

        for (field_name, field_value) in &clone_data.metadata_modifications.addition_list {
            self.update_metadata_field(document, field_name, Some(field_value))?;
        }

        Ok(())
    }

    fn update_metadata_field(&self, document: &mut Document, field_name: &str, new_value: Option<&str>) -> Result<()> {
        if let Ok(trailer) = document.trailer.as_dict() {
            if let Ok(info_ref) = trailer.get(b"Info") {
                if let Ok(info_id) = info_ref.as_reference() {
                    if let Some(info_obj) = document.objects.get_mut(&info_id) {
                        if let Object::Dictionary(ref mut info_dict) = info_obj {
                            match new_value {
                                Some(value) => {
                                    info_dict.set(field_name.as_bytes(), 
                                        Object::String(value.as_bytes().to_vec(), lopdf::StringFormat::Literal));
                                },
                                None => {
                                    info_dict.remove(field_name.as_bytes());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        self.update_xmp_metadata(document, field_name, new_value)?;
        Ok(())
    }

    fn remove_metadata_field(&self, document: &mut Document, field_name: &str) -> Result<()> {
        self.update_metadata_field(document, field_name, None)
    }

    fn update_xmp_metadata(&self, document: &mut Document, field_name: &str, new_value: Option<&str>) -> Result<()> {
        for (_, object) in document.objects.iter_mut() {
            if let Object::Stream(ref mut stream) = object {
                if self.is_xmp_stream(&stream.dict) {
                    let xmp_content = String::from_utf8_lossy(&stream.content);
                    let updated_xmp = self.update_xmp_content(&xmp_content, field_name, new_value)?;
                    stream.content = updated_xmp.into_bytes();
                }
            }
        }
        Ok(())
    }

    fn is_xmp_stream(&self, dict: &Dictionary) -> bool {
        if let Ok(subtype) = dict.get(b"Subtype") {
            if let Ok(subtype_name) = subtype.as_name_str() {
                return subtype_name == "XML";
            }
        }
        
        if let Ok(type_obj) = dict.get(b"Type") {
            if let Ok(type_name) = type_obj.as_name_str() {
                return type_name == "Metadata";
            }
        }
        
        false
    }

    fn update_xmp_content(&self, xmp_content: &str, field_name: &str, new_value: Option<&str>) -> Result<String> {
        let mut updated_content = xmp_content.to_string();
        
        let xmp_field = match field_name {
            "Title" => "dc:title",
            "Author" => "dc:creator",
            "Subject" => "dc:description",
            "Keywords" => "dc:subject",
            "Creator" => "xmp:CreatorTool",
            "Producer" => "pdf:Producer",
            "CreationDate" => "xmp:CreateDate",
            "ModDate" => "xmp:ModifyDate",
            _ => return Ok(updated_content),
        };

        match new_value {
            Some(value) => {
                let field_pattern = format!("<{}>[^<]*</{}>", xmp_field, xmp_field);
                let replacement = format!("<{}>{}</{}>", xmp_field, value, xmp_field);
                
                if updated_content.contains(xmp_field) {
                    updated_content = regex::Regex::new(&field_pattern)
                        .map_err(|e| ForensicError::metadata_error("xmp_update", &e.to_string()))?
                        .replace(&updated_content, replacement.as_str())
                        .to_string();
                } else {
                    let insert_point = updated_content.find("</rdf:Description>")
                        .unwrap_or(updated_content.len().saturating_sub(20));
                    updated_content.insert_str(insert_point, &format!("  {}\n", replacement));
                }
            },
            None => {
                let field_pattern = format!(r"<{}>[^<]*</{}>", xmp_field, xmp_field);
                updated_content = regex::Regex::new(&field_pattern)
                    .map_err(|e| ForensicError::metadata_error("xmp_remove", &e.to_string()))?
                    .replace_all(&updated_content, "")
                    .to_string();
            }
        }
        
        Ok(updated_content)
    }

    fn optimize_document(&mut self, document: &mut Document) -> Result<()> {
        if !self.config.optimize_output {
            return Ok(());
        }

        // Optimize cross-reference table
        self.optimize_cross_references(document)?;
        
        // Apply compression where beneficial
        if self.config.compression_enabled {
            self.apply_stream_compression(document)?;
        }
        
        // Remove unused objects (if safe to do so)
        if !self.config.maintain_authenticity {
            self.remove_unused_objects(document)?;
        }

        Ok(())
    }

    fn optimize_cross_references(&self, document: &mut Document) -> Result<()> {
        let mut new_objects = BTreeMap::new();
        let mut id_counter = 1u32;
        
        for (_, object) in &document.objects {
            let new_id = ObjectId(id_counter, 0);
            new_objects.insert(new_id, object.clone());
            id_counter += 1;
        }
        
        for (_, object) in new_objects.iter_mut() {
            self.update_object_references(object, &document.objects, &new_objects)?;
        }
        
        document.objects = new_objects;
        Ok(())
    }

    fn update_object_references(
        &self,
        object: &mut Object,
        old_objects: &BTreeMap<ObjectId, Object>,
        new_objects: &BTreeMap<ObjectId, Object>
    ) -> Result<()> {
        match object {
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter_mut() {
                    self.update_object_references(value, old_objects, new_objects)?;
                }
            },
            Object::Array(array) => {
                for item in array.iter_mut() {
                    self.update_object_references(item, old_objects, new_objects)?;
                }
            },
            Object::Stream(stream) => {
                self.update_object_references(&mut Object::Dictionary(stream.dict.clone()), old_objects, new_objects)?;
            },
            Object::Reference(ref mut obj_id) => {
                if let Some((new_id, _)) = new_objects.iter()
                    .find(|(_, obj)| std::ptr::eq(obj.as_ref(), old_objects.get(obj_id).unwrap())) {
                    *obj_id = *new_id;
                }
            },
            _ => {},
        }
        Ok(())
    }

    fn apply_stream_compression(&self, document: &mut Document) -> Result<()> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;

        for (_, object) in document.objects.iter_mut() {
            if let Object::Stream(ref mut stream) = object {
                if !stream.dict.has(b"Filter") && stream.content.len() > 100 {
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&stream.content)
                        .map_err(|e| ForensicError::structure_error(&format!("Compression failed: {}", e)))?;

                    let compressed_content = encoder.finish()
                        .map_err(|e| ForensicError::structure_error(&format!("Compression finish failed: {}", e)))?;

                    if compressed_content.len() < stream.content.len() {
                        stream.content = compressed_content;
                        stream.dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
                        stream.dict.set("Length", Object::Integer(stream.content.len() as i64));
                    }
                }
            }
        }
        Ok(())
    }

    fn remove_unused_objects(&self, document: &mut Document) -> Result<()> {
        let mut referenced_objects = HashSet::new();
        
        // Collect all referenced objects
        for (_, object) in &document.objects {
            self.collect_object_references(object, &mut referenced_objects);
        }
        
        // Keep only referenced objects
        document.objects.retain(|id, _| referenced_objects.contains(id));
        
        Ok(())
    }

    fn collect_object_references(&self, object: &Object, references: &mut HashSet<ObjectId>) {
        match object {
            Object::Reference(obj_id) => {
                references.insert(*obj_id);
            },
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_object_references(value, references);
                }
            },
            Object::Array(array) => {
                for item in array {
                    self.collect_object_references(item, references);
                }
            },
            Object::Stream(stream) => {
                self.collect_object_references(&Object::Dictionary(stream.dict.clone()), references);
            },
            _ => {},
        }
    }
}

impl Default for ReconstructionConfig {
    fn default() -> Self {
        Self {
            target_pdf_version: PdfVersion::V1_4,
            preserve_structure: true,
            optimize_output: true,
            maintain_authenticity: true,
            compression_enabled: false,
        }
    }
}

impl Default for PdfReconstructor {
    fn default() -> Self {
        Self::new()
    }
}
