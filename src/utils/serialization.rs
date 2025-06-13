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
                self.deserialize_custom(data)
            },
        }
    }

    fn serialize_custom<T: Serialize>(&self, _data: &T) -> Result<Vec<u8>> {
        Err(ForensicError::ConfigError {
            parameter: "Custom binary serialization not implemented".to_string(),
        })
    }

    fn deserialize_custom<T: for<'de> Deserialize<'de>>(&self, _data: &[u8]) -> Result<T> {
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
        zstd::bulk::decompress(data, self.config.max_memory_usage)
            .map_err(|e| ForensicError::ConfigError {
                parameter: format!("Zstd decompression failed: {}", e),
            })
    }

    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        lz4_flex::compress_prepend_size(data)
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

    /// Estimate optimal compression algorithm
    pub fn estimate_optimal_algorithm(&self, data: &[u8]) -> CompressionAlgorithm {
        let entropy = self.calculate_entropy(data);
        
        if entropy > 7.5 {
            CompressionAlgorithm::None  // High entropy - likely already compressed
        } else if entropy > 5.0 {
            CompressionAlgorithm::Lz4   // Medium entropy - prefer speed
        } else {
            CompressionAlgorithm::Zstd  // Low entropy - prefer compression ratio
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
            compression_threshold: 1024,    // 1KB
            max_memory_usage: 100_000_000, // 100MB
        }
    }
}

/// Convenience functions for common serialization operations
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

pub fn deserialize_from_json<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    let json_data = if data.len() > 4 && (
        data.starts_with(&[0x1f, 0x8b]) || // Gzip
        data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) // Zstd
    ) {
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

pub fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let compressor = CompressionHelper::new();
    let optimal_algorithm = compressor.estimate_optimal_algorithm(data);
    let optimal_compressor = CompressionHelper::with_algorithm(optimal_algorithm);
    optimal_compressor.compress(data)
}

pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b]) {
        let compressor = CompressionHelper::with_algorithm(CompressionAlgorithm::Gzip);
        compressor.decompress(data)
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let compressor = CompressionHelper::with_algorithm(CompressionAlgorithm::Zstd);
        compressor.decompress(data)
    } else {
        // Try LZ4 or return as uncompressed
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
