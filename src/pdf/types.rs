use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Object {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    String(Vec<u8>),
    Name(Vec<u8>),
    Array(Vec<Object>),
    Dictionary(Dictionary),
    Stream(Stream),
    Reference(ObjectId),
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectId {
    pub number: u32,
    pub generation: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    pub dict: Dictionary,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dictionary {
    entries: HashMap<Vec<u8>, Object>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub error_type: String,
    pub description: String,
    pub severity: String,
    pub location: Option<ObjectId>,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub warning_type: String,
    pub description: String,
    pub impact_level: String,
    pub object_id: Option<ObjectId>,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentIssue {
    pub issue_type: String,
    pub description: String,
    pub content_type: String,
    pub object_id: ObjectId,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub issue_type: String,
    pub description: String,
    pub risk_level: String,
    pub recommendation: String,
    pub detection_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeViolation {
    pub violation_type: String,
    pub size: u64,
    pub max_allowed: u64,
    pub object_id: ObjectId,
    pub detection_time: DateTime<Utc>,
}

impl ObjectId {
    pub fn new(number: u32, generation: u16) -> Self {
        Self { number, generation }
    }

    pub fn to_string(&self) -> String {
        format!("{} {} R", self.number, self.generation)
    }
}

impl Object {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Object::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Object::Integer(i) => Some(*i),
            Object::Real(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Object::Integer(i) => Some(*i as f64),
            Object::Real(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            Object::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Object::Name(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_name_str(&self) -> Option<&str> {
        self.as_name().and_then(|n| std::str::from_utf8(n).ok())
    }

    pub fn as_array(&self) -> Option<&Vec<Object>> {
        match self {
            Object::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_dictionary(&self) -> Option<&Dictionary> {
        match self {
            Object::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_stream(&self) -> Option<&Stream> {
        match self {
            Object::Stream(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_reference(&self) -> Option<ObjectId> {
        match self {
            Object::Reference(r) => Some(*r),
            _ => None,
        }
    }
}

impl Dictionary {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Object) -> Option<Object> {
        self.entries.insert(key, value)
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<Object> {
        self.entries.remove(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Object)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_id() {
        let id = ObjectId::new(1, 0);
        assert_eq!(id.to_string(), "1 0 R");
    }

    #[test]
    fn test_dictionary_operations() {
        let mut dict = Dictionary::new();
        assert!(dict.is_empty());
        
        dict.insert(b"Test".to_vec(), Object::Integer(42));
        assert_eq!(dict.len(), 1);
        
        if let Some(Object::Integer(value)) = dict.get(b"Test") {
            assert_eq!(*value, 42);
        } else {
            panic!("Expected integer value");
        }
        
        dict.remove(b"Test");
        assert!(dict.is_empty());
    }

    #[test]
    fn test_object_conversions() {
        let int_obj = Object::Integer(42);
        assert_eq!(int_obj.as_i64(), Some(42));
        assert_eq!(int_obj.as_f64(), Some(42.0));
        assert_eq!(int_obj.as_bool(), None);

        let bool_obj = Object::Boolean(true);
        assert_eq!(bool_obj.as_bool(), Some(true));
        assert_eq!(bool_obj.as_i64(), None);

        let name_obj = Object::Name(b"Test".to_vec());
        assert_eq!(name_obj.as_name_str(), Some("Test"));
    }
}
