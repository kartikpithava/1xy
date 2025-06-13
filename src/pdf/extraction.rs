use std::collections::HashMap;
use std::io::{self, Read};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::error::ForensicError;
use crate::pdf::types::{Object, ObjectId, Dictionary, Stream};

pub type Result<T> = std::result::Result<T, ForensicError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionData {
    pub embedded_objects: HashMap<ObjectId, Vec<u8>>,
    pub javascript: Vec<Object>,
    pub fonts: HashMap<String, FontData>,
    pub images: HashMap<ObjectId, ImageData>,
    pub text_content: HashMap<ObjectId, String>,
    pub form_fields: Vec<FormField>,
    pub extraction_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontData {
    pub font_type: String,
    pub font_name: String,
    pub is_embedded: bool,
    pub subset_name: Option<String>,
    pub encoding: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub image_type: String,
    pub width: u32,
    pub height: u32,
    pub bits_per_component: u8,
    pub color_space: String,
    pub size_bytes: u64,
    pub compression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub field_type: String,
    pub field_name: String,
    pub field_value: Option<String>,
    pub required: bool,
    pub read_only: bool,
    pub object_id: ObjectId,
}

pub struct PdfExtractor {
    initialization_time: DateTime<Utc>,
    extraction_cache: HashMap<ObjectId, Vec<u8>>,
}

impl PdfExtractor {
    pub fn new() -> Self {
        Self {
            initialization_time: Utc::now(),
            extraction_cache: HashMap::new(),
        }
    }

    pub fn extract_data(&mut self, document: &[u8]) -> Result<ExtractionData> {
        let mut extraction_data = ExtractionData {
            embedded_objects: HashMap::new(),
            javascript: Vec::new(),
            fonts: HashMap::new(),
            images: HashMap::new(),
            text_content: HashMap::new(),
            form_fields: Vec::new(),
            extraction_time: self.initialization_time,
        };

        let parser = self.create_parser(document)?;
        let objects = self.parse_objects(&parser)?;

        for (object_id, object) in objects {
            self.process_object(
                object_id,
                &object,
                &mut extraction_data,
            )?;
        }

        Ok(extraction_data)
    }

    fn create_parser(&self, document: &[u8]) -> Result<Vec<u8>> {
        // Basic validation of PDF header
        if document.len() < 8 {
            return Err(ForensicError::ExtractionError(
                "Document too short to be valid PDF".to_string()
            ));
        }

        let header = &document[0..8];
        if !header.starts_with(b"%PDF-1.") {
            return Err(ForensicError::ExtractionError(
                "Invalid PDF header".to_string()
            ));
        }

        Ok(document.to_vec())
    }

    fn parse_objects(&self, data: &[u8]) -> Result<HashMap<ObjectId, Object>> {
        let mut objects = HashMap::new();
        let mut offset = 0;

        while offset < data.len() {
            if let Some((object_id, object, new_offset)) = self.parse_next_object(data, offset)? {
                objects.insert(object_id, object);
                offset = new_offset;
            } else {
                break;
            }
        }

        Ok(objects)
    }

    fn parse_next_object(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<Option<(ObjectId, Object, usize)>> {
        let mut reader = io::Cursor::new(&data[offset..]);
        let mut buffer = Vec::new();

        // Find object start marker
        while reader.position() < (data.len() - offset) as u64 {
            reader.read_to_end(&mut buffer)?;
            
            if let Some(start_pos) = self.find_object_start(&buffer) {
                if let Some((object_id, object, consumed)) = 
                    self.parse_object_content(&buffer[start_pos..])? {
                    return Ok(Some((
                        object_id,
                        object,
                        offset + start_pos + consumed
                    )));
                }
            }
        }

        Ok(None)
    }

impl PdfExtractor {
    fn find_object_start(&self, buffer: &[u8]) -> Option<usize> {
        let pattern = b"obj";
        
        for (i, window) in buffer.windows(pattern.len()).enumerate() {
            if window == pattern && self.is_valid_object_header(buffer, i) {
                return Some(self.find_object_number_start(buffer, i));
            }
        }
        
        None
    }

    fn is_valid_object_header(&self, buffer: &[u8], obj_pos: usize) -> bool {
        if obj_pos < 2 {
            return false;
        }

        // Check for whitespace before "obj"
        matches!(buffer[obj_pos - 1], b' ' | b'\t' | b'\n' | b'\r') &&
        // Ensure there's a valid object number before
        buffer[..obj_pos].iter().rev().skip(1)
            .take_while(|&&b| b.is_ascii_digit())
            .count() > 0
    }

    fn find_object_number_start(&self, buffer: &[u8], obj_pos: usize) -> usize {
        let mut pos = obj_pos;
        while pos > 0 {
            if !buffer[pos - 1].is_ascii_digit() && buffer[pos - 1] != b' ' {
                break;
            }
            pos -= 1;
        }
        pos
    }

    fn parse_object_content(
        &self,
        data: &[u8],
    ) -> Result<Option<(ObjectId, Object, usize)>> {
        let mut reader = io::Cursor::new(data);
        let mut number_str = String::new();
        
        // Read object number
        while let Ok(byte) = reader.read_u8() {
            if byte.is_ascii_digit() {
                number_str.push(byte as char);
            } else if byte == b' ' {
                break;
            }
        }

        let object_number = number_str.parse::<u32>()
            .map_err(|_| ForensicError::ExtractionError(
                "Invalid object number".to_string()
            ))?;

        // Read generation number
        let mut gen_str = String::new();
        while let Ok(byte) = reader.read_u8() {
            if byte.is_ascii_digit() {
                gen_str.push(byte as char);
            } else if byte == b' ' {
                break;
            }
        }

        let generation = gen_str.parse::<u16>()
            .map_err(|_| ForensicError::ExtractionError(
                "Invalid generation number".to_string()
            ))?;

        // Skip "obj" marker
        let mut obj_marker = [0u8; 3];
        reader.read_exact(&mut obj_marker)?;
        if &obj_marker != b"obj" {
            return Err(ForensicError::ExtractionError(
                "Missing obj marker".to_string()
            ));
        }

        // Parse object content
        let (object, consumed) = self.parse_object_data(
            &data[reader.position() as usize..]
        )?;

        Ok(Some((
            ObjectId::new(object_number, generation),
            object,
            reader.position() as usize + consumed
        )))
    }

    fn parse_object_data(&self, data: &[u8]) -> Result<(Object, usize)> {
        let mut reader = io::Cursor::new(data);
        let mut content = Vec::new();
        let mut depth = 0;
        let mut in_string = false;
        let mut escape_next = false;

        while let Ok(byte) = reader.read_u8() {
            content.push(byte);

            if in_string {
                if escape_next {
                    escape_next = false;
                } else if byte == b'\\' {
                    escape_next = true;
                } else if byte == b')' {
                    in_string = false;
                }
                continue;
            }

            match byte {
                b'(' => in_string = true,
                b'<' => {
                    if reader.position() < data.len() as u64 &&
                       data[reader.position() as usize] == b'<' {
                        depth += 1;
                        content.push(reader.read_u8()?);
                    }
                }
                b'>' => {
                    if reader.position() < data.len() as u64 &&
                       data[reader.position() as usize] == b'>' {
                        depth -= 1;
                        content.push(reader.read_u8()?);
                    }
                }
                _ => {}
            }

            // Check for "endobj" marker when not in nested structure
            if depth == 0 && !in_string {
                if let Some(end_pos) = self.find_endobj(&content) {
                    return self.create_object(&content[..end_pos])
                        .map(|obj| (obj, end_pos + 6));
                }
            }
        }

        Err(ForensicError::ExtractionError(
            "Unexpected end of object data".to_string()
        ))
    }
impl PdfExtractor {
    fn find_endobj(&self, content: &[u8]) -> Option<usize> {
        let pattern = b"endobj";
        for (i, window) in content.windows(pattern.len()).enumerate() {
            if window == pattern {
                return Some(i);
            }
        }
        None
    }

    fn create_object(&self, data: &[u8]) -> Result<Object> {
        let mut reader = io::Cursor::new(data);
        self.skip_whitespace(&mut reader);

        match reader.read_u8()? {
            b'<' => {
                if data.get(reader.position() as usize) == Some(&b'<') {
                    reader.set_position(reader.position() + 1);
                    self.parse_dictionary(&mut reader)
                } else {
                    self.parse_hex_string(&mut reader)
                }
            }
            b'(' => self.parse_literal_string(&mut reader),
            b'[' => self.parse_array(&mut reader),
            b'/' => self.parse_name(&mut reader),
            b'+' | b'-' | b'.' | b'0'..=b'9' => self.parse_number(&mut reader),
            b't' => self.parse_true(&mut reader),
            b'f' => self.parse_false(&mut reader),
            b'n' => self.parse_null(&mut reader),
            _ => Err(ForensicError::ExtractionError(
                "Unknown object type".to_string()
            )),
        }
    }

    fn process_object(
        &mut self,
        object_id: ObjectId,
        object: &Object,
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        match object {
            Object::Dictionary(dict) => {
                self.process_dictionary(object_id, dict, extraction_data)?;
            }
            Object::Stream(stream) => {
                self.process_stream(object_id, stream, extraction_data)?;
            }
            Object::Array(array) => {
                for item in array {
                    if let Object::Dictionary(dict) = item {
                        self.process_dictionary(object_id, dict, extraction_data)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn process_dictionary(
        &mut self,
        object_id: ObjectId,
        dict: &Dictionary,
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        // Check for JavaScript
        if let Some(js_type) = dict.get(b"S").and_then(|s| s.as_name()) {
            if js_type == b"JavaScript" {
                if let Some(js) = dict.get(b"JS") {
                    extraction_data.javascript.push(js.clone());
                }
            }
        }

        // Check for Font
        if let Some(font_type) = dict.get(b"Type").and_then(|t| t.as_name()) {
            if font_type == b"Font" {
                self.extract_font_data(object_id, dict, extraction_data)?;
            }
        }

        // Check for Form Fields
        if let Some(field_type) = dict.get(b"FT").and_then(|t| t.as_name()) {
            self.extract_form_field(object_id, dict, field_type, extraction_data)?;
        }

        Ok(())
    }

    fn process_stream(
        &mut self,
        object_id: ObjectId,
        stream: &Stream,
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        let stream_dict = &stream.dict;

        // Check for image stream
        if let Some(subtype) = stream_dict.get(b"Subtype").and_then(|s| s.as_name()) {
            if subtype == b"Image" {
                self.extract_image_data(object_id, stream, extraction_data)?;
            }
        }

        // Check for embedded file stream
        if let Some(stream_type) = stream_dict.get(b"Type").and_then(|t| t.as_name()) {
            if stream_type == b"EmbeddedFile" {
                extraction_data.embedded_objects.insert(
                    object_id,
                    stream.data.clone()
                );
            }
        }

        Ok(())
    }

    fn extract_font_data(
        &self,
        object_id: ObjectId,
        dict: &Dictionary,
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        let font_name = dict.get(b"BaseFont")
            .and_then(|n| n.as_name_str())
            .unwrap_or("Unknown")
            .to_string();

        let font_type = dict.get(b"Subtype")
            .and_then(|t| t.as_name_str())
            .unwrap_or("Unknown")
            .to_string();

        let encoding = dict.get(b"Encoding")
            .and_then(|e| e.as_name_str())
            .map(String::from);

        let subset_name = if font_name.starts_with('/') {
            Some(font_name[1..7].to_string())
        } else {
            None
        };

        let is_embedded = dict.get(b"FontDescriptor").is_some();
        let size_bytes = dict.get(b"Length1")
            .and_then(|l| l.as_i64())
            .unwrap_or(0) as u64;

        extraction_data.fonts.insert(
            font_name.clone(),
            FontData {
                font_type,
                font_name,
                is_embedded,
                subset_name,
                encoding,
                size_bytes,
            }
        );

        Ok(())
    }

impl PdfExtractor {
    fn extract_form_field(
        &self,
        object_id: ObjectId,
        dict: &Dictionary,
        field_type: &[u8],
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        let field_name = dict.get(b"T")
            .and_then(|t| t.as_string())
            .map(String::from_utf8_lossy)
            .map(|s| s.into_owned())
            .unwrap_or_else(|| "Unnamed".to_string());

        let field_value = dict.get(b"V")
            .and_then(|v| v.as_string())
            .map(String::from_utf8_lossy)
            .map(|s| s.into_owned());

        let field_flags = dict.get(b"Ff")
            .and_then(|f| f.as_i64())
            .unwrap_or(0);

        let required = (field_flags & 0x2) != 0;
        let read_only = (field_flags & 0x1) != 0;

        let field_type = match field_type {
            b"Tx" => "Text",
            b"Btn" => "Button",
            b"Ch" => "Choice",
            b"Sig" => "Signature",
            _ => "Unknown",
        };

        extraction_data.form_fields.push(FormField {
            field_type: field_type.to_string(),
            field_name,
            field_value,
            required,
            read_only,
            object_id,
        });

        Ok(())
    }

    fn extract_image_data(
        &self,
        object_id: ObjectId,
        stream: &Stream,
        extraction_data: &mut ExtractionData,
    ) -> Result<()> {
        let dict = &stream.dict;

        let width = dict.get(b"Width")
            .and_then(|w| w.as_i64())
            .ok_or_else(|| ForensicError::ExtractionError(
                "Missing image width".to_string()
            ))? as u32;

        let height = dict.get(b"Height")
            .and_then(|h| h.as_i64())
            .ok_or_else(|| ForensicError::ExtractionError(
                "Missing image height".to_string()
            ))? as u32;

        let bits_per_component = dict.get(b"BitsPerComponent")
            .and_then(|b| b.as_i64())
            .unwrap_or(8) as u8;

        let color_space = dict.get(b"ColorSpace")
            .and_then(|c| c.as_name_str())
            .unwrap_or("DeviceRGB")
            .to_string();

        let compression = dict.get(b"Filter")
            .and_then(|f| f.as_name_str())
            .map(String::from);

        extraction_data.images.insert(
            object_id,
            ImageData {
                image_type: self.determine_image_type(&stream.data)?,
                width,
                height,
                bits_per_component,
                color_space,
                size_bytes: stream.data.len() as u64,
                compression,
            }
        );

        Ok(())
    }

    fn determine_image_type(&self, data: &[u8]) -> Result<String> {
        if data.len() < 4 {
            return Ok("Unknown".to_string());
        }

        let signature = &data[0..4];
        match signature {
            [0x89, 0x50, 0x4E, 0x47] => Ok("PNG".to_string()),
            [0xFF, 0xD8, 0xFF, _] => Ok("JPEG".to_string()),
            [0x47, 0x49, 0x46, 0x38] => Ok("GIF".to_string()),
            _ => Ok("Unknown".to_string()),
        }
    }

    fn skip_whitespace(&self, reader: &mut io::Cursor<&[u8]>) {
        while let Ok(byte) = reader.read_u8() {
            if !byte.is_ascii_whitespace() {
                reader.set_position(reader.position() - 1);
                break;
            }
        }
    }

    fn parse_hex_string(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut hex_string = Vec::new();
        let mut complete = false;

        while let Ok(byte) = reader.read_u8() {
            match byte {
                b'>' => {
                    complete = true;
                    break;
                }
                b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                    hex_string.push(byte);
                }
                _ if byte.is_ascii_whitespace() => continue,
                _ => return Err(ForensicError::ExtractionError(
                    "Invalid character in hex string".to_string()
                )),
            }
        }

        if !complete {
            return Err(ForensicError::ExtractionError(
                "Unterminated hex string".to_string()
            ));
        }

        Ok(Object::String(
            hex::decode(&hex_string)
                .map_err(|e| ForensicError::ExtractionError(e.to_string()))?
        ))
    }
impl PdfExtractor {
    fn parse_literal_string(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut string = Vec::new();
        let mut depth = 1;
        let mut escape = false;

        while let Ok(byte) = reader.read_u8() {
            if escape {
                match byte {
                    b'n' => string.push(b'\n'),
                    b'r' => string.push(b'\r'),
                    b't' => string.push(b'\t'),
                    b'b' => string.push(b'\x08'),
                    b'f' => string.push(b'\x0C'),
                    b'(' => string.push(b'('),
                    b')' => string.push(b')'),
                    b'\\' => string.push(b'\\'),
                    b'0'..=b'7' => {
                        let mut octal = Vec::new();
                        octal.push(byte);
                        for _ in 0..2 {
                            if let Ok(next) = reader.read_u8() {
                                if next.is_ascii_octdigit() {
                                    octal.push(next);
                                } else {
                                    reader.set_position(reader.position() - 1);
                                    break;
                                }
                            }
                        }
                        let octal_str = String::from_utf8_lossy(&octal);
                        if let Ok(value) = u8::from_str_radix(&octal_str, 8) {
                            string.push(value);
                        }
                    }
                    _ => string.push(byte),
                }
                escape = false;
            } else {
                match byte {
                    b'\\' => escape = true,
                    b'(' => {
                        depth += 1;
                        string.push(byte);
                    }
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        string.push(byte);
                    }
                    _ => string.push(byte),
                }
            }
        }

        if depth != 0 {
            return Err(ForensicError::ExtractionError(
                "Unmatched parentheses in string".to_string()
            ));
        }

        Ok(Object::String(string))
    }

    fn parse_array(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut array = Vec::new();
        
        loop {
            self.skip_whitespace(reader);
            
            match reader.read_u8()? {
                b']' => break,
                _ => {
                    reader.set_position(reader.position() - 1);
                    array.push(self.create_object(&reader.get_ref()[reader.position() as usize..])?);
                }
            }
        }

        Ok(Object::Array(array))
    }

    fn parse_name(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut name = Vec::new();
        
        while let Ok(byte) = reader.read_u8() {
            match byte {
                b'#' => {
                    // Handle hex encoding in name
                    let hex1 = reader.read_u8()?;
                    let hex2 = reader.read_u8()?;
                    if let Ok(decoded) = hex::decode(&[hex1, hex2]) {
                        name.push(decoded[0]);
                    }
                }
                b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' => {
                    reader.set_position(reader.position() - 1);
                    break;
                }
                _ => name.push(byte),
            }
        }

        Ok(Object::Name(name))
    }

    fn parse_number(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut number_str = String::new();
        let mut is_float = false;
        
        while let Ok(byte) = reader.read_u8() {
            match byte {
                b'0'..=b'9' | b'+' | b'-' => number_str.push(byte as char),
                b'.' => {
                    is_float = true;
                    number_str.push('.');
                }
                _ => {
                    reader.set_position(reader.position() - 1);
                    break;
                }
            }
        }

        if is_float {
            Ok(Object::Real(number_str.parse().map_err(|_| 
                ForensicError::ExtractionError("Invalid real number".to_string())
            )?))
        } else {
            Ok(Object::Integer(number_str.parse().map_err(|_| 
                ForensicError::ExtractionError("Invalid integer".to_string())
            )?))
        }
    }

    fn parse_true(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut buf = [0; 3];
        reader.read_exact(&mut buf)?;
        if &buf != b"rue" {
            return Err(ForensicError::ExtractionError("Invalid 'true' value".to_string()));
        }
        Ok(Object::Boolean(true))
    }

    fn parse_false(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut buf = [0; 4];
        reader.read_exact(&mut buf)?;
        if &buf != b"alse" {
            return Err(ForensicError::ExtractionError("Invalid 'false' value".to_string()));
        }
        Ok(Object::Boolean(false))
    }

    fn parse_null(&self, reader: &mut io::Cursor<&[u8]>) -> Result<Object> {
        let mut buf = [0; 3];
        reader.read_exact(&mut buf)?;
        if &buf != b"ull" {
            return Err(ForensicError::ExtractionError("Invalid 'null' value".to_string()));
        }
        Ok(Object::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty_pdf() {
        let mut extractor = PdfExtractor::new();
        let result = extractor.extract_data(b"%PDF-1.7\n%%EOF");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_pdf_header() {
        let mut extractor = PdfExtractor::new();
        let result = extractor.extract_data(b"Not a PDF file");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_literal_string() {
        let mut extractor = PdfExtractor::new();
        let data = b"(Test\\n)";
        let mut reader = io::Cursor::new(&data[..]);
        let result = extractor.parse_literal_string(&mut reader);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_hex_string() {
        let mut extractor = PdfExtractor::new();
        let data = b"<4142>";
        let mut reader = io::Cursor::new(&data[..]);
        let result = extractor.parse_hex_string(&mut reader);
        assert!(result.is_ok());
    }
}
