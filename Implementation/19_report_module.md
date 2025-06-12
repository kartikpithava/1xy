# Module 19: Report Module Implementation Guide

## Overview
The report module provides comprehensive report generation capabilities with template engine integration, multiple output formats (JSON, HTML, Markdown), and custom template support. This module generates detailed reports about the PDF anti-forensics processing results.

## File Structure
```text
src/report/
├── mod.rs (80 lines)
├── template_engine.rs (300 lines)
├── formatters.rs (250 lines)
├── generators.rs (200 lines)
└── templates/ (150 lines total)
    ├── html_template.rs (50 lines)
    ├── markdown_template.rs (50 lines)
    └── json_template.rs (50 lines)
```

## Dependencies
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
async-trait = "0.1"
handlebars = "4.0"
tera = "1.0"
pulldown-cmark = "0.9"
```

## Implementation Requirements

### 1. Module Root (src/report/mod.rs) - 80 lines

```rust
//! Comprehensive report generation module
//! 
//! This module provides template-based report generation with support
//! for multiple output formats and custom templates.

use crate::error::{PdfError, Result};
use crate::types::{ProcessingResult, ReportData};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

pub mod template_engine;
pub mod formatters;
pub mod generators;
pub mod templates;

pub use template_engine::*;
pub use formatters::*;
pub use generators::*;
pub use templates::*;

/// Supported report output formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Markdown,
    Json,
    Pdf,
    Xml,
    Csv,
}

/// Report generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub template_path: Option<PathBuf>,
    pub output_path: PathBuf,
    pub include_metadata: bool,
    pub include_statistics: bool,
    pub include_recommendations: bool,
    pub custom_fields: HashMap<String, String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Html,
            template_path: None,
            output_path: PathBuf::from("reports"),
            include_metadata: true,
            include_statistics: true,
            include_recommendations: true,
            custom_fields: HashMap::new(),
        }
    }
}

/// Generated report information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedReport {
    pub id: Uuid,
    pub format: ReportFormat,
    pub output_path: PathBuf,
    pub size_bytes: usize,
    pub generation_time: std::time::Duration,
    pub template_used: String,
    pub metadata: HashMap<String, String>,
}

/// Main report generator
pub struct ReportGenerator {
    template_engine: TemplateEngine,
    formatters: HashMap<ReportFormat, Box<dyn ReportFormatter + Send + Sync>>,
}

impl ReportGenerator {
    pub fn new() -> Result<Self> {
        let mut generator = Self {
            template_engine: TemplateEngine::new()?,
            formatters: HashMap::new(),
        };
        
        generator.register_default_formatters()?;
        Ok(generator)
    }

    fn register_default_formatters(&mut self) -> Result<()> {
        self.formatters.insert(ReportFormat::Html, Box::new(HtmlFormatter::new()));
        self.formatters.insert(ReportFormat::Markdown, Box::new(MarkdownFormatter::new()));
        self.formatters.insert(ReportFormat::Json, Box::new(JsonFormatter::new()));
        Ok(())
    }

    pub async fn generate_report(&self, data: ReportData, config: ReportConfig) -> Result<GeneratedReport> {
        let start_time = std::time::Instant::now();
        
        let formatted_content = self.format_report(&data, &config).await?;
        let output_path = self.write_report(&formatted_content, &config).await?;
        
        Ok(GeneratedReport {
            id: Uuid::new_v4(),
            format: config.format,
            output_path: output_path.clone(),
            size_bytes: formatted_content.len(),
            generation_time: start_time.elapsed(),
            template_used: self.get_template_name(&config),
            metadata: config.custom_fields,
        })
    }

    async fn format_report(&self, data: &ReportData, config: &ReportConfig) -> Result<String> {
        if let Some(formatter) = self.formatters.get(&config.format) {
            formatter.format(data, config).await
        } else {
            Err(PdfError::UnsupportedFormat(format!("Unsupported report format: {:?}", config.format)))
        }
    }

    async fn write_report(&self, content: &str, config: &ReportConfig) -> Result<PathBuf> {
        let filename = format!("report_{}.{}", 
            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            self.get_file_extension(&config.format));
        
        let output_path = config.output_path.join(filename);
        
        tokio::fs::create_dir_all(&config.output_path).await
            .map_err(|e| PdfError::Io(format!("Failed to create output directory: {}", e)))?;
            
        tokio::fs::write(&output_path, content).await
            .map_err(|e| PdfError::Io(format!("Failed to write report: {}", e)))?;
        
        Ok(output_path)
    }

    fn get_template_name(&self, config: &ReportConfig) -> String {
        config.template_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("default_{:?}", config.format).to_lowercase())
    }

    fn get_file_extension(&self, format: &ReportFormat) -> &'static str {
        match format {
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "md",
            ReportFormat::Json => "json",
            ReportFormat::Pdf => "pdf",
            ReportFormat::Xml => "xml",
            ReportFormat::Csv => "csv",
        }
    }
}
```

### 2. Template Engine (src/report/template_engine.rs) - 300 lines

```rust
//! Template engine for report generation

use super::*;
use crate::error::{PdfError, Result};
use handlebars::{Handlebars, Template, RenderError};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{instrument, info, warn, error};

/// Template engine for processing report templates
pub struct TemplateEngine {
    handlebars: Handlebars<'static>,
    custom_helpers: HashMap<String, Box<dyn CustomHelper + Send + Sync>>,
    template_cache: HashMap<String, String>,
}

/// Custom helper trait for template functions
pub trait CustomHelper {
    fn execute(&self, params: &[Value]) -> Result<String>;
    fn name(&self) -> &str;
}

impl TemplateEngine {
    pub fn new() -> Result<Self> {
        let mut engine = Self {
            handlebars: Handlebars::new(),
            custom_helpers: HashMap::new(),
            template_cache: HashMap::new(),
        };
        
        engine.register_default_helpers()?;
        engine.load_default_templates()?;
        
        Ok(engine)
    }

    fn register_default_helpers(&mut self) -> Result<()> {
        // Register format_timestamp helper
        self.handlebars.register_helper("format_timestamp", 
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let timestamp = h.param(0)
                    .and_then(|v| v.value().as_str())
                    .ok_or(handlebars::RenderError::new("format_timestamp requires a string parameter"))?;
                
                let formatted = chrono::DateTime::parse_from_rfc3339(timestamp)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|_| timestamp.to_string());
                
                out.write(&formatted)?;
                Ok(())
            }));

        // Register format_bytes helper
        self.handlebars.register_helper("format_bytes",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let bytes = h.param(0)
                    .and_then(|v| v.value().as_u64())
                    .ok_or(handlebars::RenderError::new("format_bytes requires a number parameter"))?;
                
                let formatted = Self::format_bytes_helper(bytes);
                out.write(&formatted)?;
                Ok(())
            }));

        // Register format_duration helper
        self.handlebars.register_helper("format_duration",
            Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
                let millis = h.param(0)
                    .and_then(|v| v.value().as_u64())
                    .ok_or(handlebars::RenderError::new("format_duration requires a number parameter"))?;
                
                let formatted = Self::format_duration_helper(millis);
                out.write(&formatted)?;
                Ok(())
            }));

        Ok(())
    }

    fn format_bytes_helper(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }

    fn format_duration_helper(millis: u64) -> String {
        let seconds = millis / 1000;
        let minutes = seconds / 60;
        let hours = minutes / 60;
        
        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes % 60, seconds % 60)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds % 60)
        } else {
            format!("{}.{}s", seconds, (millis % 1000) / 100)
        }
    }

    fn load_default_templates(&mut self) -> Result<()> {
        // Load HTML template
        let html_template = include_str!("../templates/default.html");
        self.handlebars.register_template_string("html_default", html_template)
            .map_err(|e| PdfError::TemplateError(format!("Failed to register HTML template: {}", e)))?;

        // Load Markdown template
        let markdown_template = include_str!("../templates/default.md");
        self.handlebars.register_template_string("markdown_default", markdown_template)
            .map_err(|e| PdfError::TemplateError(format!("Failed to register Markdown template: {}", e)))?;

        Ok(())
    }

    #[instrument(skip(self, data))]
    pub async fn render_template(&self, template_name: &str, data: &Value) -> Result<String> {
        self.handlebars.render(template_name, data)
            .map_err(|e| PdfError::TemplateError(format!("Template rendering failed: {}", e)))
    }

    pub async fn register_custom_template(&mut self, name: &str, template_content: &str) -> Result<()> {
        self.handlebars.register_template_string(name, template_content)
            .map_err(|e| PdfError::TemplateError(format!("Failed to register custom template: {}", e)))?;
        
        self.template_cache.insert(name.to_string(), template_content.to_string());
        Ok(())
    }

    pub async fn load_template_from_file(&mut self, name: &str, file_path: &std::path::Path) -> Result<()> {
        let template_content = tokio::fs::read_to_string(file_path).await
            .map_err(|e| PdfError::Io(format!("Failed to read template file: {}", e)))?;
        
        self.register_custom_template(name, &template_content).await
    }

    pub fn get_available_templates(&self) -> Vec<String> {
        self.handlebars.get_templates().keys().cloned().collect()
    }

    pub async fn validate_template(&self, template_content: &str) -> Result<()> {
        Template::compile(template_content)
            .map_err(|e| PdfError::TemplateError(format!("Template validation failed: {}", e)))?;
        Ok(())
    }

    pub async fn render_with_context(&self, template_name: &str, context: &ReportContext) -> Result<String> {
        let data = serde_json::to_value(context)
            .map_err(|e| PdfError::SerializationError(format!("Failed to serialize context: {}", e)))?;
        
        self.render_template(template_name, &data).await
    }
}

/// Report context for template rendering
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportContext {
    pub title: String,
    pub generated_at: String,
    pub processing_summary: ProcessingSummary,
    pub file_information: FileInformation,
    pub security_analysis: SecurityAnalysis,
    pub modifications: Vec<Modification>,
    pub statistics: Statistics,
    pub recommendations: Vec<String>,
    pub custom_data: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessingSummary {
    pub status: String,
    pub duration_ms: u64,
    pub files_processed: u32,
    pub errors_count: u32,
    pub warnings_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileInformation {
    pub original_name: String,
    pub original_size_bytes: u64,
    pub processed_size_bytes: u64,
    pub compression_ratio: f64,
    pub format_version: String,
    pub pages_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAnalysis {
    pub threat_level: String,
    pub vulnerabilities_found: u32,
    pub forensic_traces_removed: u32,
    pub encryption_applied: bool,
    pub metadata_cleaned: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Modification {
    pub category: String,
    pub description: String,
    pub severity: String,
    pub applied: bool,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Statistics {
    pub objects_processed: u32,
    pub streams_analyzed: u32,
    pub metadata_fields_removed: u32,
    pub compression_savings_bytes: u64,
    pub processing_speed_mb_s: f64,
}

impl ReportContext {
    pub fn new(title: String) -> Self {
        Self {
            title,
            generated_at: chrono::Utc::now().to_rfc3339(),
            processing_summary: ProcessingSummary::default(),
            file_information: FileInformation::default(),
            security_analysis: SecurityAnalysis::default(),
            modifications: Vec::new(),
            statistics: Statistics::default(),
            recommendations: Vec::new(),
            custom_data: HashMap::new(),
        }
    }

    pub fn add_custom_data(&mut self, key: String, value: Value) {
        self.custom_data.insert(key, value);
    }

    pub fn add_modification(&mut self, modification: Modification) {
        self.modifications.push(modification);
    }

    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }
}

impl Default for ProcessingSummary {
    fn default() -> Self {
        Self {
            status: "Unknown".to_string(),
            duration_ms: 0,
            files_processed: 0,
            errors_count: 0,
            warnings_count: 0,
        }
    }
}

impl Default for FileInformation {
    fn default() -> Self {
        Self {
            original_name: "Unknown".to_string(),
            original_size_bytes: 0,
            processed_size_bytes: 0,
            compression_ratio: 1.0,
            format_version: "Unknown".to_string(),
            pages_count: 0,
        }
    }
}

impl Default for SecurityAnalysis {
    fn default() -> Self {
        Self {
            threat_level: "Unknown".to_string(),
            vulnerabilities_found: 0,
            forensic_traces_removed: 0,
            encryption_applied: false,
            metadata_cleaned: false,
        }
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            objects_processed: 0,
            streams_analyzed: 0,
            metadata_fields_removed: 0,
            compression_savings_bytes: 0,
            processing_speed_mb_s: 0.0,
        }
    }
}
```

**Total Lines**: 980 lines of production-ready Rust code