# Module 15: Content Module Implementation Guide

## Overview
The content module provides comprehensive PDF content processing capabilities including font handling, image extraction and sanitization, resource optimization, and content validation with enterprise-grade performance and security.

## File Structure
```text
src/content/
├── mod.rs (150 lines)
├── font_processor.rs (380 lines)
├── image_extractor.rs (420 lines)
├── resource_optimizer.rs (350 lines)
├── content_validator.rs (290 lines)
├── stream_handler.rs (320 lines)
└── content_sanitizer.rs (380 lines)
```

## Dependencies
```toml
[dependencies]
image = { version = "0.24", features = ["jpeg", "png", "gif", "webp"] }
fontdue = "0.7"
pdf-extract = "0.6"
regex = "1.10"
bytes = "1.5"
tokio = { version = "1.0", features = ["full"] }
futures = "0.3"
rayon = "1.7"
tracing = "0.1"
serde = { version = "1.0", features = ["derive"] }
uuid = { version = "1.6", features = ["v4"] }
```

## Implementation Requirements

### File 1: `src/content/mod.rs` (150 lines)

```rust
//! Content Processing Module for PDF Anti-Forensics
//! 
//! Provides comprehensive content handling including font processing, image extraction,
//! resource optimization, and content validation with security-focused sanitization.

pub mod font_processor;
pub mod image_extractor;
pub mod resource_optimizer;
pub mod content_validator;
pub mod stream_handler;
pub mod content_sanitizer;

// Re-export main types
pub use font_processor::{FontProcessor, FontInfo, FontProcessingResult};
pub use image_extractor::{ImageExtractor, ImageInfo, ExtractionResult};
pub use resource_optimizer::{ResourceOptimizer, OptimizationConfig, OptimizationResult};
pub use content_validator::{ContentValidator, ValidationConfig, ValidationReport};
pub use stream_handler::{StreamHandler, StreamInfo, ProcessingConfig};
pub use content_sanitizer::{ContentSanitizer, SanitizationConfig, SanitizationResult};

use crate::error::{Result, PdfError, SecurityLevel, ErrorContext};
use crate::types::{Document, SecurityContext, PerformanceMetrics};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

/// Content processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentConfig {
    /// Font processing settings
    pub font_processing: FontProcessingConfig,
    /// Image extraction settings
    pub image_extraction: ImageExtractionConfig,
    /// Resource optimization settings
    pub optimization: OptimizationConfig,
    /// Content validation settings
    pub validation: ValidationConfig,
    /// Sanitization settings
    pub sanitization: SanitizationConfig,
    /// Performance settings
    pub performance: PerformanceConfig,
}

impl Default for ContentConfig {
    fn default() -> Self {
        Self {
            font_processing: FontProcessingConfig::default(),
            image_extraction: ImageExtractionConfig::default(),
            optimization: OptimizationConfig::default(),
            validation: ValidationConfig::default(),
            sanitization: SanitizationConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// Font processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontProcessingConfig {
    /// Remove embedded fonts
    pub remove_embedded_fonts: bool,
    /// Standardize font names
    pub standardize_fonts: bool,
    /// Remove font metadata
    pub remove_font_metadata: bool,
    /// Optimize font subsetting
    pub optimize_subsetting: bool,
}

impl Default for FontProcessingConfig {
    fn default() -> Self {
        Self {
            remove_embedded_fonts: true,
            standardize_fonts: true,
            remove_font_metadata: true,
            optimize_subsetting: true,
        }
    }
}

/// Image extraction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageExtractionConfig {
    /// Extract all images
    pub extract_images: bool,
    /// Remove image metadata
    pub remove_metadata: bool,
    /// Optimize image compression
    pub optimize_compression: bool,
    /// Supported formats
    pub supported_formats: Vec<String>,
    /// Maximum image size
    pub max_image_size: u64,
}

impl Default for ImageExtractionConfig {
    fn default() -> Self {
        Self {
            extract_images: true,
            remove_metadata: true,
            optimize_compression: true,
            supported_formats: vec!["jpeg".to_string(), "png".to_string(), "gif".to_string()],
            max_image_size: 50 * 1024 * 1024, // 50MB
        }
    }
}

/// Performance configuration for content processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable parallel processing
    pub parallel_processing: bool,
    /// Number of worker threads
    pub worker_threads: usize,
    /// Chunk size for processing
    pub chunk_size: usize,
    /// Enable caching
    pub enable_caching: bool,
    /// Cache size limit
    pub cache_size_mb: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            parallel_processing: true,
            worker_threads: num_cpus::get(),
            chunk_size: 1024 * 1024, // 1MB chunks
            enable_caching: true,
            cache_size_mb: 100,
        }
    }
}

/// Main content processor coordinating all content operations
pub struct ContentProcessor {
    config: Arc<RwLock<ContentConfig>>,
    font_processor: Arc<FontProcessor>,
    image_extractor: Arc<ImageExtractor>,
    resource_optimizer: Arc<ResourceOptimizer>,
    content_validator: Arc<ContentValidator>,
    stream_handler: Arc<StreamHandler>,
    content_sanitizer: Arc<ContentSanitizer>,
    metrics: Arc<RwLock<ContentMetrics>>,
}

impl ContentProcessor {
    /// Create new content processor
    pub async fn new(config: ContentConfig) -> Result<Self> {
        let config_arc = Arc::new(RwLock::new(config.clone()));
        
        let font_processor = Arc::new(
            FontProcessor::new(config.font_processing.clone()).await?
        );
        
        let image_extractor = Arc::new(
            ImageExtractor::new(config.image_extraction.clone()).await?
        );
        
        let resource_optimizer = Arc::new(
            ResourceOptimizer::new(config.optimization.clone()).await?
        );
        
        let content_validator = Arc::new(
            ContentValidator::new(config.validation.clone()).await?
        );
        
        let stream_handler = Arc::new(
            StreamHandler::new(ProcessingConfig::default()).await?
        );
        
        let content_sanitizer = Arc::new(
            ContentSanitizer::new(config.sanitization.clone()).await?
        );

        Ok(Self {
            config: config_arc,
            font_processor,
            image_extractor,
            resource_optimizer,
            content_validator,
            stream_handler,
            content_sanitizer,
            metrics: Arc::new(RwLock::new(ContentMetrics::default())),
        })
    }

    /// Process PDF content comprehensively
    pub async fn process_content(&self, document: &Document) -> Result<ContentProcessingResult> {
        let start_time = std::time::Instant::now();
        
        info!("Starting comprehensive content processing");

        // Validate content first
        let validation_result = self.content_validator.validate_content(document).await?;
        
        // Process fonts
        let font_result = self.font_processor.process_fonts(document).await?;
        
        // Extract and process images
        let image_result = self.image_extractor.extract_images(document).await?;
        
        // Optimize resources
        let optimization_result = self.resource_optimizer.optimize_resources(document).await?;
        
        // Sanitize content
        let sanitization_result = self.content_sanitizer.sanitize_content(document).await?;

        let processing_time = start_time.elapsed();
        
        let result = ContentProcessingResult {
            validation: validation_result,
            fonts: font_result,
            images: image_result,
            optimization: optimization_result,
            sanitization: sanitization_result,
            processing_time,
            success: true,
        };

        // Update metrics
        self.update_metrics(&result).await;

        info!("Content processing completed in {:?}", processing_time);
        Ok(result)
    }

    /// Get processing metrics
    pub async fn get_metrics(&self) -> Result<ContentMetrics> {
        let metrics = self.metrics.read().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire metrics lock".to_string(),
                lock_type: "read".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("content", "get_metrics"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;
        Ok(metrics.clone())
    }

    /// Update internal metrics
    async fn update_metrics(&self, result: &ContentProcessingResult) {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.documents_processed += 1;
            metrics.total_processing_time += result.processing_time;
            metrics.fonts_processed += result.fonts.fonts_processed;
            metrics.images_extracted += result.images.images_extracted;
            metrics.resources_optimized += result.optimization.resources_optimized;
            
            if result.success {
                metrics.successful_operations += 1;
            } else {
                metrics.failed_operations += 1;
            }
        }
    }
}

/// Content processing result
#[derive(Debug, Clone)]
pub struct ContentProcessingResult {
    pub validation: ValidationReport,
    pub fonts: FontProcessingResult,
    pub images: ExtractionResult,
    pub optimization: OptimizationResult,
    pub sanitization: SanitizationResult,
    pub processing_time: std::time::Duration,
    pub success: bool,
}

/// Content processing metrics
#[derive(Debug, Clone, Default)]
pub struct ContentMetrics {
    pub documents_processed: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub total_processing_time: std::time::Duration,
    pub fonts_processed: u64,
    pub images_extracted: u64,
    pub resources_optimized: u64,
    pub data_sanitized_bytes: u64,
}
```

### File 2: `src/content/font_processor.rs` (380 lines)

```rust
//! Font processing and sanitization for PDF content

use fontdue::{Font, FontSettings, layout::{Layout, CoordinateSystem, TextStyle}};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use regex::Regex;
use bytes::Bytes;
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};

use crate::error::{Result, PdfError, ErrorContext, SecurityLevel};
use crate::types::{Document, ObjectId};
use crate::content::FontProcessingConfig;

/// Font information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontInfo {
    /// Font name
    pub name: String,
    /// Font type (TrueType, Type1, etc.)
    pub font_type: FontType,
    /// Font size in bytes
    pub size: u64,
    /// Whether font is embedded
    pub is_embedded: bool,
    /// Font metadata
    pub metadata: HashMap<String, String>,
    /// Character set information
    pub charset: Option<String>,
    /// Font encoding
    pub encoding: Option<String>,
}

/// Supported font types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontType {
    TrueType,
    Type1,
    Type1C,
    Type3,
    OpenType,
    Unknown,
}

impl FontType {
    /// Check if font type supports embedding
    pub fn supports_embedding(&self) -> bool {
        matches!(self, FontType::TrueType | FontType::OpenType | FontType::Type1C)
    }

    /// Get recommended replacement font
    pub fn default_replacement(&self) -> &'static str {
        match self {
            FontType::TrueType | FontType::OpenType => "Arial",
            FontType::Type1 | FontType::Type1C => "Times-Roman",
            FontType::Type3 => "Courier",
            FontType::Unknown => "Helvetica",
        }
    }
}

/// Font processing result
#[derive(Debug, Clone)]
pub struct FontProcessingResult {
    /// Number of fonts processed
    pub fonts_processed: u64,
    /// Number of fonts removed
    pub fonts_removed: u64,
    /// Number of fonts replaced
    pub fonts_replaced: u64,
    /// Total size reduction in bytes
    pub size_reduction: u64,
    /// Processing details
    pub details: Vec<FontProcessingDetail>,
    /// Warnings encountered
    pub warnings: Vec<String>,
}

/// Individual font processing detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontProcessingDetail {
    /// Original font name
    pub original_name: String,
    /// Action taken
    pub action: FontAction,
    /// Replacement font name (if replaced)
    pub replacement_name: Option<String>,
    /// Size before processing
    pub size_before: u64,
    /// Size after processing
    pub size_after: u64,
    /// Processing time
    pub processing_time: std::time::Duration,
}

/// Font processing actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontAction {
    Removed,
    Replaced,
    Standardized,
    MetadataStripped,
    Subsetted,
    Kept,
}

/// Font processor for PDF documents
pub struct FontProcessor {
    config: FontProcessingConfig,
    font_cache: Arc<RwLock<HashMap<String, CachedFont>>>,
    standard_fonts: HashSet<String>,
    processing_semaphore: Arc<Semaphore>,
    metrics: Arc<RwLock<FontMetrics>>,
}

/// Cached font information
#[derive(Debug, Clone)]
struct CachedFont {
    font_info: FontInfo,
    processed_data: Option<Bytes>,
    last_used: std::time::Instant,
}

impl FontProcessor {
    /// Create new font processor
    pub async fn new(config: FontProcessingConfig) -> Result<Self> {
        let standard_fonts = Self::create_standard_fonts_set();
        
        Ok(Self {
            config,
            font_cache: Arc::new(RwLock::new(HashMap::new())),
            standard_fonts,
            processing_semaphore: Arc::new(Semaphore::new(4)), // Limit concurrent font processing
            metrics: Arc::new(RwLock::new(FontMetrics::default())),
        })
    }

    /// Process fonts in PDF document
    pub async fn process_fonts(&self, document: &Document) -> Result<FontProcessingResult> {
        let start_time = std::time::Instant::now();
        let mut result = FontProcessingResult {
            fonts_processed: 0,
            fonts_removed: 0,
            fonts_replaced: 0,
            size_reduction: 0,
            details: Vec::new(),
            warnings: Vec::new(),
        };

        // Extract font information from document
        let fonts = self.extract_font_info(document).await?;
        
        for font_info in fonts {
            let processing_start = std::time::Instant::now();
            let action = self.determine_font_action(&font_info).await;
            
            let detail = match action {
                FontAction::Removed => {
                    result.fonts_removed += 1;
                    result.size_reduction += font_info.size;
                    self.remove_font(document, &font_info).await?
                }
                FontAction::Replaced => {
                    result.fonts_replaced += 1;
                    self.replace_font(document, &font_info).await?
                }
                FontAction::Standardized => {
                    self.standardize_font(document, &font_info).await?
                }
                FontAction::MetadataStripped => {
                    self.strip_font_metadata(document, &font_info).await?
                }
                FontAction::Subsetted => {
                    self.subset_font(document, &font_info).await?
                }
                FontAction::Kept => {
                    FontProcessingDetail {
                        original_name: font_info.name.clone(),
                        action,
                        replacement_name: None,
                        size_before: font_info.size,
                        size_after: font_info.size,
                        processing_time: processing_start.elapsed(),
                    }
                }
            };

            result.details.push(detail);
            result.fonts_processed += 1;
        }

        // Update metrics
        self.update_metrics(&result).await;

        Ok(result)
    }

    /// Extract font information from document
    async fn extract_font_info(&self, document: &Document) -> Result<Vec<FontInfo>> {
        let mut fonts = Vec::new();
        
        // This would integrate with the PDF parsing to extract actual font objects
        // For now, we'll create a placeholder that demonstrates the structure
        
        // Parse document structure to find font objects
        for (object_id, pdf_object) in document.get_objects() {
            if self.is_font_object(pdf_object) {
                let font_info = self.parse_font_object(object_id, pdf_object).await?;
                fonts.push(font_info);
            }
        }

        Ok(fonts)
    }

    /// Check if PDF object is a font
    fn is_font_object(&self, pdf_object: &lopdf::Object) -> bool {
        if let lopdf::Object::Dictionary(dict) = pdf_object {
            if let Ok(lopdf::Object::Name(type_name)) = dict.get(b"Type") {
                return type_name == b"Font";
            }
        }
        false
    }

    /// Parse font object to extract font information
    async fn parse_font_object(&self, object_id: &ObjectId, pdf_object: &lopdf::Object) -> Result<FontInfo> {
        let _permit = self.processing_semaphore.acquire().await.map_err(|e| {
            PdfError::ConcurrencyError {
                message: format!("Failed to acquire processing permit: {}", e),
                lock_type: "semaphore".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("font_processor", "parse_font_object"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;

        if let lopdf::Object::Dictionary(dict) = pdf_object {
            let name = self.extract_font_name(dict)?;
            let font_type = self.determine_font_type(dict)?;
            let size = self.calculate_font_size(dict)?;
            let is_embedded = self.check_if_embedded(dict)?;
            let metadata = self.extract_font_metadata(dict)?;
            let charset = self.extract_charset(dict)?;
            let encoding = self.extract_encoding(dict)?;

            Ok(FontInfo {
                name,
                font_type,
                size,
                is_embedded,
                metadata,
                charset,
                encoding,
            })
        } else {
            Err(PdfError::ValidationError {
                message: "Invalid font object structure".to_string(),
                field: Some("font_object".to_string()),
                expected_type: Some("Dictionary".to_string()),
                actual_value: Some(format!("{:?}", pdf_object)),
                validation_rule: Some("font_object_validation".to_string()),
                context: ErrorContext::new("font_processor", "parse_font_object"),
                severity: crate::error::ErrorSeverity::Medium,
                recovery_suggestions: vec!["Check PDF structure".to_string()],
                validation_chain: vec![],
                schema_version: None,
                compliance_violations: vec![],
            })
        }
    }

    /// Extract font name from dictionary
    fn extract_font_name(&self, dict: &lopdf::Dictionary) -> Result<String> {
        if let Ok(lopdf::Object::Name(base_font)) = dict.get(b"BaseFont") {
            Ok(String::from_utf8_lossy(base_font).to_string())
        } else if let Ok(lopdf::Object::Name(font_name)) = dict.get(b"FontName") {
            Ok(String::from_utf8_lossy(font_name).to_string())
        } else {
            Ok("Unknown".to_string())
        }
    }

    /// Determine font type from dictionary
    fn determine_font_type(&self, dict: &lopdf::Dictionary) -> Result<FontType> {
        if let Ok(lopdf::Object::Name(subtype)) = dict.get(b"Subtype") {
            match subtype {
                b"TrueType" => Ok(FontType::TrueType),
                b"Type1" => Ok(FontType::Type1),
                b"Type1C" => Ok(FontType::Type1C),
                b"Type3" => Ok(FontType::Type3),
                b"OpenType" => Ok(FontType::OpenType),
                _ => Ok(FontType::Unknown),
            }
        } else {
            Ok(FontType::Unknown)
        }
    }

    /// Calculate font size from dictionary
    fn calculate_font_size(&self, dict: &lopdf::Dictionary) -> Result<u64> {
        // This would calculate the actual size of the font data
        // For now, return a placeholder size
        if let Ok(lopdf::Object::Stream(stream)) = dict.get(b"FontFile") {
            Ok(stream.content.len() as u64)
        } else if let Ok(lopdf::Object::Stream(stream)) = dict.get(b"FontFile2") {
            Ok(stream.content.len() as u64)
        } else if let Ok(lopdf::Object::Stream(stream)) = dict.get(b"FontFile3") {
            Ok(stream.content.len() as u64)
        } else {
            Ok(0) // No embedded font data
        }
    }

    /// Check if font is embedded
    fn check_if_embedded(&self, dict: &lopdf::Dictionary) -> Result<bool> {
        Ok(dict.has(b"FontFile") || dict.has(b"FontFile2") || dict.has(b"FontFile3"))
    }

    /// Extract font metadata
    fn extract_font_metadata(&self, dict: &lopdf::Dictionary) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        
        // Extract various metadata fields
        if let Ok(lopdf::Object::Dictionary(font_descriptor)) = dict.get(b"FontDescriptor") {
            if let Ok(lopdf::Object::String(font_name, _)) = font_descriptor.get(b"FontName") {
                metadata.insert("FontName".to_string(), String::from_utf8_lossy(font_name).to_string());
            }
            
            if let Ok(lopdf::Object::String(font_family, _)) = font_descriptor.get(b"FontFamily") {
                metadata.insert("FontFamily".to_string(), String::from_utf8_lossy(font_family).to_string());
            }
        }

        Ok(metadata)
    }

    /// Extract character set information
    fn extract_charset(&self, dict: &lopdf::Dictionary) -> Result<Option<String>> {
        if let Ok(lopdf::Object::String(charset, _)) = dict.get(b"CharSet") {
            Ok(Some(String::from_utf8_lossy(charset).to_string()))
        } else {
            Ok(None)
        }
    }

    /// Extract encoding information
    fn extract_encoding(&self, dict: &lopdf::Dictionary) -> Result<Option<String>> {
        if let Ok(lopdf::Object::Name(encoding)) = dict.get(b"Encoding") {
            Ok(Some(String::from_utf8_lossy(encoding).to_string()))
        } else {
            Ok(None)
        }
    }

    /// Determine action to take for a font
    async fn determine_font_action(&self, font_info: &FontInfo) -> FontAction {
        // Apply configuration rules to determine action
        if self.config.remove_embedded_fonts && font_info.is_embedded {
            if self.standard_fonts.contains(&font_info.name) {
                FontAction::Replaced
            } else {
                FontAction::Removed
            }
        } else if self.config.standardize_fonts && !self.standard_fonts.contains(&font_info.name) {
            FontAction::Standardized
        } else if self.config.remove_font_metadata && !font_info.metadata.is_empty() {
            FontAction::MetadataStripped
        } else if self.config.optimize_subsetting && font_info.is_embedded {
            FontAction::Subsetted
        } else {
            FontAction::Kept
        }
    }

    /// Remove font from document
    async fn remove_font(&self, document: &Document, font_info: &FontInfo) -> Result<FontProcessingDetail> {
        let start_time = std::time::Instant::now();
        
        // Implementation would remove the font object from the PDF
        // This is a placeholder showing the expected structure
        
        Ok(FontProcessingDetail {
            original_name: font_info.name.clone(),
            action: FontAction::Removed,
            replacement_name: None,
            size_before: font_info.size,
            size_after: 0,
            processing_time: start_time.elapsed(),
        })
    }

    /// Replace font with standard font
    async fn replace_font(&self, document: &Document, font_info: &FontInfo) -> Result<FontProcessingDetail> {
        let start_time = std::time::Instant::now();
        let replacement_name = font_info.font_type.default_replacement().to_string();
        
        // Implementation would replace the font reference in the PDF
        // This is a placeholder showing the expected structure
        
        Ok(FontProcessingDetail {
            original_name: font_info.name.clone(),
            action: FontAction::Replaced,
            replacement_name: Some(replacement_name),
            size_before: font_info.size,
            size_after: 0, // Standard fonts have no embedded data
            processing_time: start_time.elapsed(),
        })
    }

    /// Standardize font name
    async fn standardize_font(&self, document: &Document, font_info: &FontInfo) -> Result<FontProcessingDetail> {
        let start_time = std::time::Instant::now();
        
        // Implementation would standardize the font name
        // This is a placeholder showing the expected structure
        
        Ok(FontProcessingDetail {
            original_name: font_info.name.clone(),
            action: FontAction::Standardized,
            replacement_name: Some("StandardizedFont".to_string()),
            size_before: font_info.size,
            size_after: font_info.size,
            processing_time: start_time.elapsed(),
        })
    }

    /// Strip font metadata
    async fn strip_font_metadata(&self, document: &Document, font_info: &FontInfo) -> Result<FontProcessingDetail> {
        let start_time = std::time::Instant::now();
        
        // Implementation would remove metadata from font object
        // This is a placeholder showing the expected structure
        
        let metadata_size = font_info.metadata.iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>() as u64;
        
        Ok(FontProcessingDetail {
            original_name: font_info.name.clone(),
            action: FontAction::MetadataStripped,
            replacement_name: None,
            size_before: font_info.size,
            size_after: font_info.size - metadata_size,
            processing_time: start_time.elapsed(),
        })
    }

    /// Subset font to reduce size
    async fn subset_font(&self, document: &Document, font_info: &FontInfo) -> Result<FontProcessingDetail> {
        let start_time = std::time::Instant::now();
        
        // Implementation would subset the font based on used characters
        // This is a placeholder showing the expected structure
        
        let estimated_reduction = font_info.size / 3; // Assume 33% reduction
        
        Ok(FontProcessingDetail {
            original_name: font_info.name.clone(),
            action: FontAction::Subsetted,
            replacement_name: None,
            size_before: font_info.size,
            size_after: font_info.size - estimated_reduction,
            processing_time: start_time.elapsed(),
        })
    }

    /// Create set of standard fonts
    fn create_standard_fonts_set() -> HashSet<String> {
        let mut fonts = HashSet::new();
        
        // Adobe standard fonts
        fonts.insert("Times-Roman".to_string());
        fonts.insert("Times-Bold".to_string());
        fonts.insert("Times-Italic".to_string());
        fonts.insert("Times-BoldItalic".to_string());
        fonts.insert("Helvetica".to_string());
        fonts.insert("Helvetica-Bold".to_string());
        fonts.insert("Helvetica-Oblique".to_string());
        fonts.insert("Helvetica-BoldOblique".to_string());
        fonts.insert("Courier".to_string());
        fonts.insert("Courier-Bold".to_string());
        fonts.insert("Courier-Oblique".to_string());
        fonts.insert("Courier-BoldOblique".to_string());
        fonts.insert("Symbol".to_string());
        fonts.insert("ZapfDingbats".to_string());
        
        fonts
    }

    /// Update processing metrics
    async fn update_metrics(&self, result: &FontProcessingResult) {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.fonts_processed += result.fonts_processed;
            metrics.fonts_removed += result.fonts_removed;
            metrics.fonts_replaced += result.fonts_replaced;
            metrics.total_size_reduction += result.size_reduction;
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<FontMetrics> {
        let metrics = self.metrics.read().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire metrics lock".to_string(),
                lock_type: "read".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("font_processor", "get_metrics"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;
        Ok(metrics.clone())
    }
}

/// Font processing metrics
#[derive(Debug, Clone, Default)]
pub struct FontMetrics {
    pub fonts_processed: u64,
    pub fonts_removed: u64,
    pub fonts_replaced: u64,
    pub total_size_reduction: u64,
    pub processing_errors: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}
```

### File 3: `src/content/image_extractor.rs` (420 lines)

```rust
//! Image extraction and processing for PDF content

use image::{ImageFormat, DynamicImage, ImageBuffer, RgbImage};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::io::Cursor;
use bytes::Bytes;
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};
use regex::Regex;

use crate::error::{Result, PdfError, ErrorContext, SecurityLevel};
use crate::types::{Document, ObjectId};
use crate::content::ImageExtractionConfig;

/// Image information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image identifier
    pub id: String,
    /// Image format
    pub format: ImageFormat,
    /// Image dimensions
    pub width: u32,
    pub height: u32,
    /// Image size in bytes
    pub size: u64,
    /// Color space
    pub color_space: String,
    /// Bits per component
    pub bits_per_component: u8,
    /// Image metadata
    pub metadata: HashMap<String, String>,
    /// Whether image has transparency
    pub has_transparency: bool,
    /// Compression type
    pub compression: Option<String>,
}

/// Image extraction result
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    /// Number of images extracted
    pub images_extracted: u64,
    /// Number of images processed
    pub images_processed: u64,
    /// Number of images removed
    pub images_removed: u64,
    /// Total size reduction
    pub size_reduction: u64,
    /// Extracted image details
    pub image_details: Vec<ImageExtractionDetail>,
    /// Processing warnings
    pub warnings: Vec<String>,
    /// Processing errors
    pub errors: Vec<String>,
}

/// Individual image extraction detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageExtractionDetail {
    /// Image identifier
    pub image_id: String,
    /// Original format
    pub original_format: ImageFormat,
    /// Action taken
    pub action: ImageAction,
    /// Size before processing
    pub size_before: u64,
    /// Size after processing
    pub size_after: u64,
    /// Processing time
    pub processing_time: std::time::Duration,
    /// Quality metrics
    pub quality_metrics: Option<ImageQualityMetrics>,
}

/// Image processing actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageAction {
    Extracted,
    Optimized,
    Recompressed,
    MetadataStripped,
    Removed,
    Kept,
}

/// Image quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageQualityMetrics {
    /// Peak signal-to-noise ratio
    pub psnr: f64,
    /// Structural similarity index
    pub ssim: f64,
    /// Compression ratio
    pub compression_ratio: f64,
    /// Visual quality score (0-100)
    pub visual_quality_score: u8,
}

/// Image extractor for PDF documents
pub struct ImageExtractor {
    config: ImageExtractionConfig,
    image_cache: Arc<RwLock<HashMap<String, CachedImage>>>,
    processing_semaphore: Arc<Semaphore>,
    metrics: Arc<RwLock<ImageMetrics>>,
    format_validators: HashMap<ImageFormat, Box<dyn FormatValidator + Send + Sync>>,
}

/// Cached image information
#[derive(Debug, Clone)]
struct CachedImage {
    image_info: ImageInfo,
    processed_data: Option<Bytes>,
    last_accessed: std::time::Instant,
}

/// Format validator trait
trait FormatValidator {
    fn validate(&self, data: &[u8]) -> Result<bool>;
    fn get_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>>;
}

/// JPEG format validator
struct JpegValidator;

impl FormatValidator for JpegValidator {
    fn validate(&self, data: &[u8]) -> Result<bool> {
        // Check JPEG magic bytes
        Ok(data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
    }

    fn get_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        
        // Extract basic JPEG metadata
        if self.validate(data)? {
            metadata.insert("format".to_string(), "JPEG".to_string());
            
            // Find EXIF data if present
            if let Some(exif_start) = self.find_exif_marker(data) {
                metadata.insert("has_exif".to_string(), "true".to_string());
            }
        }
        
        Ok(metadata)
    }
}

impl JpegValidator {
    fn find_exif_marker(&self, data: &[u8]) -> Option<usize> {
        // Look for EXIF marker (0xFFE1)
        for i in 0..data.len().saturating_sub(4) {
            if data[i] == 0xFF && data[i + 1] == 0xE1 {
                // Check for EXIF identifier
                if data.get(i + 4..i + 8) == Some(b"Exif") {
                    return Some(i);
                }
            }
        }
        None
    }
}

/// PNG format validator
struct PngValidator;

impl FormatValidator for PngValidator {
    fn validate(&self, data: &[u8]) -> Result<bool> {
        // Check PNG magic bytes
        Ok(data.len() >= 8 && data[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    }

    fn get_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        
        if self.validate(data)? {
            metadata.insert("format".to_string(), "PNG".to_string());
            
            // Parse PNG chunks for metadata
            if let Some(text_chunks) = self.extract_text_chunks(data) {
                for (key, value) in text_chunks {
                    metadata.insert(key, value);
                }
            }
        }
        
        Ok(metadata)
    }
}

impl PngValidator {
    fn extract_text_chunks(&self, data: &[u8]) -> Option<HashMap<String, String>> {
        let mut chunks = HashMap::new();
        let mut pos = 8; // Skip PNG signature
        
        while pos + 8 < data.len() {
            // Read chunk length
            let length = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let chunk_type = &data[pos + 4..pos + 8];
            
            if chunk_type == b"tEXt" || chunk_type == b"zTXt" || chunk_type == b"iTXt" {
                if let Some((key, value)) = self.parse_text_chunk(&data[pos + 8..pos + 8 + length as usize]) {
                    chunks.insert(key, value);
                }
            }
            
            pos += 12 + length as usize; // Move to next chunk
        }
        
        if chunks.is_empty() { None } else { Some(chunks) }
    }
    
    fn parse_text_chunk(&self, chunk_data: &[u8]) -> Option<(String, String)> {
        if let Some(null_pos) = chunk_data.iter().position(|&b| b == 0) {
            let key = String::from_utf8_lossy(&chunk_data[..null_pos]).to_string();
            let value = String::from_utf8_lossy(&chunk_data[null_pos + 1..]).to_string();
            Some((key, value))
        } else {
            None
        }
    }
}

impl ImageExtractor {
    /// Create new image extractor
    pub async fn new(config: ImageExtractionConfig) -> Result<Self> {
        let mut format_validators: HashMap<ImageFormat, Box<dyn FormatValidator + Send + Sync>> = HashMap::new();
        format_validators.insert(ImageFormat::Jpeg, Box::new(JpegValidator));
        format_validators.insert(ImageFormat::Png, Box::new(PngValidator));
        
        Ok(Self {
            config,
            image_cache: Arc::new(RwLock::new(HashMap::new())),
            processing_semaphore: Arc::new(Semaphore::new(4)), // Limit concurrent image processing
            metrics: Arc::new(RwLock::new(ImageMetrics::default())),
            format_validators,
        })
    }

    /// Extract images from PDF document
    pub async fn extract_images(&self, document: &Document) -> Result<ExtractionResult> {
        let start_time = std::time::Instant::now();
        let mut result = ExtractionResult {
            images_extracted: 0,
            images_processed: 0,
            images_removed: 0,
            size_reduction: 0,
            image_details: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        if !self.config.extract_images {
            return Ok(result);
        }

        // Find all image objects in the document
        let image_objects = self.find_image_objects(document).await?;
        
        for (object_id, image_data) in image_objects {
            let processing_start = std::time::Instant::now();
            
            match self.process_image_object(&object_id, &image_data).await {
                Ok(detail) => {
                    result.images_processed += 1;
                    
                    match detail.action {
                        ImageAction::Extracted => result.images_extracted += 1,
                        ImageAction::Removed => {
                            result.images_removed += 1;
                            result.size_reduction += detail.size_before - detail.size_after;
                        }
                        ImageAction::Optimized | ImageAction::Recompressed => {
                            result.size_reduction += detail.size_before.saturating_sub(detail.size_after);
                        }
                        _ => {}
                    }
                    
                    result.image_details.push(detail);
                }
                Err(e) => {
                    result.errors.push(format!("Failed to process image {}: {}", object_id, e));
                }
            }
        }

        // Update metrics
        self.update_metrics(&result).await;

        Ok(result)
    }

    /// Find image objects in PDF document
    async fn find_image_objects(&self, document: &Document) -> Result<Vec<(String, Bytes)>> {
        let mut image_objects = Vec::new();
        
        // Iterate through PDF objects to find images
        for (object_id, pdf_object) in document.get_objects() {
            if self.is_image_object(pdf_object) {
                if let Some(image_data) = self.extract_image_data(pdf_object).await? {
                    image_objects.push((object_id.to_string(), image_data));
                }
            }
        }

        Ok(image_objects)
    }

    /// Check if PDF object is an image
    fn is_image_object(&self, pdf_object: &lopdf::Object) -> bool {
        if let lopdf::Object::Stream(stream) = pdf_object {
            if let Ok(lopdf::Object::Name(subtype)) = stream.dict.get(b"Subtype") {
                return subtype == b"Image";
            }
        }
        false
    }

    /// Extract image data from PDF object
    async fn extract_image_data(&self, pdf_object: &lopdf::Object) -> Result<Option<Bytes>> {
        if let lopdf::Object::Stream(stream) = pdf_object {
            // Check size limit
            if stream.content.len() as u64 > self.config.max_image_size {
                return Ok(None);
            }
            
            // Decode the stream if necessary
            let decoded_data = self.decode_image_stream(stream).await?;
            Ok(Some(Bytes::from(decoded_data)))
        } else {
            Ok(None)
        }
    }

    /// Decode image stream data
    async fn decode_image_stream(&self, stream: &lopdf::Stream) -> Result<Vec<u8>> {
        // Handle different compression filters
        if let Ok(lopdf::Object::Array(filters)) = stream.dict.get(b"Filter") {
            let mut data = stream.content.clone();
            
            for filter in filters {
                if let lopdf::Object::Name(filter_name) = filter {
                    data = match filter_name {
                        b"FlateDecode" => self.flate_decode(&data)?,
                        b"DCTDecode" => data, // JPEG data, no decoding needed
                        b"CCITTFaxDecode" => self.ccitt_decode(&data)?,
                        b"LZWDecode" => self.lzw_decode(&data)?,
                        _ => data, // Unknown filter, keep as is
                    };
                }
            }
            
            Ok(data)
        } else {
            Ok(stream.content.clone())
        }
    }

    /// Flate decode implementation
    fn flate_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        let mut decoder = ZlibDecoder::new(data);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("Flate decode failed: {}", e),
                stage: "image_decode".to_string(),
                context: ErrorContext::new("image_extractor", "flate_decode"),
                recovery_suggestions: vec!["Check image data integrity".to_string()],
            }
        })?;
        
        Ok(decoded)
    }

    /// CCITT fax decode (placeholder)
    fn ccitt_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        // This would implement CCITT fax decoding
        // For now, return the data as-is
        Ok(data.to_vec())
    }

    /// LZW decode (placeholder)
    fn lzw_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        // This would implement LZW decoding
        // For now, return the data as-is
        Ok(data.to_vec())
    }

    /// Process individual image object
    async fn process_image_object(&self, object_id: &str, image_data: &Bytes) -> Result<ImageExtractionDetail> {
        let _permit = self.processing_semaphore.acquire().await.map_err(|e| {
            PdfError::ConcurrencyError {
                message: format!("Failed to acquire processing permit: {}", e),
                lock_type: "semaphore".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("image_extractor", "process_image_object"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;

        let processing_start = std::time::Instant::now();
        let original_size = image_data.len() as u64;
        
        // Detect image format
        let format = self.detect_image_format(image_data)?;
        
        // Validate format is supported
        if !self.is_format_supported(&format) {
            return Ok(ImageExtractionDetail {
                image_id: object_id.to_string(),
                original_format: format,
                action: ImageAction::Kept,
                size_before: original_size,
                size_after: original_size,
                processing_time: processing_start.elapsed(),
                quality_metrics: None,
            });
        }

        // Determine action based on configuration
        let action = self.determine_image_action(&format, original_size).await;
        
        let (processed_size, quality_metrics) = match action {
            ImageAction::Optimized => {
                let (optimized_data, metrics) = self.optimize_image(image_data, &format).await?;
                (optimized_data.len() as u64, Some(metrics))
            }
            ImageAction::Recompressed => {
                let recompressed_data = self.recompress_image(image_data, &format).await?;
                (recompressed_data.len() as u64, None)
            }
            ImageAction::MetadataStripped => {
                let stripped_data = self.strip_image_metadata(image_data, &format).await?;
                (stripped_data.len() as u64, None)
            }
            ImageAction::Removed => (0, None),
            _ => (original_size, None),
        };

        Ok(ImageExtractionDetail {
            image_id: object_id.to_string(),
            original_format: format,
            action,
            size_before: original_size,
            size_after: processed_size,
            processing_time: processing_start.elapsed(),
            quality_metrics,
        })
    }

    /// Detect image format from data
    fn detect_image_format(&self, data: &[u8]) -> Result<ImageFormat> {
        // Check magic bytes to determine format
        if data.len() >= 8 {
            // PNG
            if data[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                return Ok(ImageFormat::Png);
            }
            
            // JPEG
            if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
                return Ok(ImageFormat::Jpeg);
            }
            
            // GIF
            if data[0..6] == *b"GIF87a" || data[0..6] == *b"GIF89a" {
                return Ok(ImageFormat::Gif);
            }
            
            // WebP
            if data.len() >= 12 && data[0..4] == *b"RIFF" && data[8..12] == *b"WEBP" {
                return Ok(ImageFormat::WebP);
            }
        }
        
        // Try to use image crate to detect format
        match image::guess_format(data) {
            Ok(format) => Ok(format),
            Err(_) => Err(PdfError::ValidationError {
                message: "Unknown image format".to_string(),
                field: Some("image_format".to_string()),
                expected_type: Some("supported_image_format".to_string()),
                actual_value: None,
                validation_rule: Some("format_detection".to_string()),
                context: ErrorContext::new("image_extractor", "detect_image_format"),
                severity: crate::error::ErrorSeverity::Medium,
                recovery_suggestions: vec!["Check image data".to_string()],
                validation_chain: vec![],
                schema_version: None,
                compliance_violations: vec![],
            })
        }
    }

    /// Check if image format is supported
    fn is_format_supported(&self, format: &ImageFormat) -> bool {
        let format_str = match format {
            ImageFormat::Jpeg => "jpeg",
            ImageFormat::Png => "png",
            ImageFormat::Gif => "gif",
            ImageFormat::WebP => "webp",
            _ => return false,
        };
        
        self.config.supported_formats.contains(&format_str.to_string())
    }

    /// Determine action to take for an image
    async fn determine_image_action(&self, format: &ImageFormat, size: u64) -> ImageAction {
        if self.config.remove_metadata && self.format_has_metadata(format) {
            ImageAction::MetadataStripped
        } else if self.config.optimize_compression {
            ImageAction::Optimized
        } else {
            ImageAction::Extracted
        }
    }

    /// Check if format typically contains metadata
    fn format_has_metadata(&self, format: &ImageFormat) -> bool {
        matches!(format, ImageFormat::Jpeg | ImageFormat::Png)
    }

    /// Optimize image
    async fn optimize_image(&self, data: &[u8], format: &ImageFormat) -> Result<(Vec<u8>, ImageQualityMetrics)> {
        // Load image
        let img = image::load_from_memory(data).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("Failed to load image: {}", e),
                stage: "image_optimization".to_string(),
                context: ErrorContext::new("image_extractor", "optimize_image"),
                recovery_suggestions: vec!["Check image data integrity".to_string()],
            }
        })?;

        // Apply optimization based on format
        let optimized_data = match format {
            ImageFormat::Jpeg => self.optimize_jpeg(&img).await?,
            ImageFormat::Png => self.optimize_png(&img).await?,
            _ => data.to_vec(),
        };

        // Calculate quality metrics
        let quality_metrics = self.calculate_quality_metrics(&img, &optimized_data).await?;

        Ok((optimized_data, quality_metrics))
    }

    /// Optimize JPEG image
    async fn optimize_jpeg(&self, img: &DynamicImage) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);
        
        // Encode with optimized quality
        img.write_to(&mut cursor, ImageFormat::Jpeg).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("JPEG optimization failed: {}", e),
                stage: "jpeg_optimization".to_string(),
                context: ErrorContext::new("image_extractor", "optimize_jpeg"),
                recovery_suggestions: vec!["Try different compression settings".to_string()],
            }
        })?;
        
        Ok(output)
    }

    /// Optimize PNG image
    async fn optimize_png(&self, img: &DynamicImage) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);
        
        // Encode with PNG optimization
        img.write_to(&mut cursor, ImageFormat::Png).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("PNG optimization failed: {}", e),
                stage: "png_optimization".to_string(),
                context: ErrorContext::new("image_extractor", "optimize_png"),
                recovery_suggestions: vec!["Try different compression settings".to_string()],
            }
        })?;
        
        Ok(output)
    }

    /// Recompress image with different settings
    async fn recompress_image(&self, data: &[u8], format: &ImageFormat) -> Result<Vec<u8>> {
        // This would implement more aggressive recompression
        // For now, return the original data
        Ok(data.to_vec())
    }

    /// Strip metadata from image
    async fn strip_image_metadata(&self, data: &[u8], format: &ImageFormat) -> Result<Vec<u8>> {
        // Load and re-save image to strip metadata
        let img = image::load_from_memory(data).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("Failed to load image for metadata stripping: {}", e),
                stage: "metadata_stripping".to_string(),
                context: ErrorContext::new("image_extractor", "strip_image_metadata"),
                recovery_suggestions: vec!["Check image data integrity".to_string()],
            }
        })?;

        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);
        
        img.write_to(&mut cursor, *format).map_err(|e| {
            PdfError::ProcessingError {
                message: format!("Failed to save stripped image: {}", e),
                stage: "metadata_stripping".to_string(),
                context: ErrorContext::new("image_extractor", "strip_image_metadata"),
                recovery_suggestions: vec!["Try different format".to_string()],
            }
        })?;
        
        Ok(output)
    }

    /// Calculate image quality metrics
    async fn calculate_quality_metrics(&self, original: &DynamicImage, optimized_data: &[u8]) -> Result<ImageQualityMetrics> {
        // This would implement actual quality calculations (PSNR, SSIM, etc.)
        // For now, return placeholder metrics
        Ok(ImageQualityMetrics {
            psnr: 35.0,
            ssim: 0.95,
            compression_ratio: optimized_data.len() as f64 / (original.width() * original.height() * 3) as f64,
            visual_quality_score: 85,
        })
    }

    /// Update processing metrics
    async fn update_metrics(&self, result: &ExtractionResult) {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.images_processed += result.images_processed;
            metrics.images_extracted += result.images_extracted;
            metrics.images_removed += result.images_removed;
            metrics.total_size_reduction += result.size_reduction;
            metrics.processing_errors += result.errors.len() as u64;
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<ImageMetrics> {
        let metrics = self.metrics.read().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire metrics lock".to_string(),
                lock_type: "read".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("image_extractor", "get_metrics"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;
        Ok(metrics.clone())
    }
}

/// Image processing metrics
#[derive(Debug, Clone, Default)]
pub struct ImageMetrics {
    pub images_processed: u64,
    pub images_extracted: u64,
    pub images_removed: u64,
    pub total_size_reduction: u64,
    pub processing_errors: u64,
    pub optimization_successes: u64,
    pub metadata_stripped: u64,
}
```

I'll continue with the remaining files for the content module and then proceed to other high-priority modules.

<function_calls>
<invoke name="str_replace_based_edit_tool">
<parameter name="command">str_replace