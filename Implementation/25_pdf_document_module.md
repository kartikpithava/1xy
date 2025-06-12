# Module 19: Report Module Implementation Guide

## Overview
Template engine integration, multiple output formats (JSON, HTML, Markdown), report generation pipeline, and custom template support for comprehensive reporting.

## File Structure
```text
src/report/
├── mod.rs (80 lines)
├── template_engine.rs (300 lines)
├── format_handlers/
│   ├── mod.rs (60 lines)
│   ├── json_handler.rs (180 lines)
│   ├── html_handler.rs (220 lines)
│   └── markdown_handler.rs (200 lines)
├── report_generator.rs (280 lines)
└── custom_templates.rs (160 lines)
```

## Dependencies
```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
handlebars = "4.4"
tera = "1.19"
markdown = "1.0"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.6", features = ["v4"] }
```

## Implementation Requirements

### File 1: `src/report/mod.rs` (80 lines)

```rust
//! Report Module for PDF Document Processing
//! 
//! Provides template engine integration, multiple output formats,
//! report generation pipeline, and custom template support.

pub mod template_engine;
pub mod format_handlers;
pub mod report_generator;
pub mod custom_templates;

// Re-export main types
pub use template_engine::{TemplateEngine, TemplateConfig, TemplateResult};
pub use format_handlers::{FormatHandler, OutputFormat, FormatConfig};
pub use report_generator::{ReportGenerator, ReportConfig, GeneratedReport};
pub use custom_templates::{CustomTemplateManager, TemplateDefinition};

use crate::error::{Result, PdfError, ErrorContext};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Report configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfiguration {
    /// Default output format
    pub default_format: OutputFormat,
    /// Enable template caching
    pub enable_template_caching: bool,
    /// Custom template directory
    pub custom_template_dir: Option<String>,
    /// Include debug information
    pub include_debug_info: bool,
}

impl Default for ReportConfiguration {
    fn default() -> Self {
        Self {
            default_format: OutputFormat::Html,
            enable_template_caching: true,
            custom_template_dir: None,
            include_debug_info: false,
        }
    }
}

/// Main report orchestrator
pub struct ReportOrchestrator {
    config: ReportConfiguration,
    template_engine: TemplateEngine,
    report_generator: ReportGenerator,
    custom_template_manager: CustomTemplateManager,
    format_handlers: HashMap<OutputFormat, Box<dyn FormatHandler>>,
}

impl ReportOrchestrator {
    /// Create new report orchestrator
    pub async fn new(config: ReportConfiguration) -> Result<Self> {
        use format_handlers::{JsonHandler, HtmlHandler, MarkdownHandler};

        let mut format_handlers: HashMap<OutputFormat, Box<dyn FormatHandler>> = HashMap::new();
        format_handlers.insert(OutputFormat::Json, Box::new(JsonHandler::new().await?));
        format_handlers.insert(OutputFormat::Html, Box::new(HtmlHandler::new().await?));
        format_handlers.insert(OutputFormat::Markdown, Box::new(MarkdownHandler::new().await?));

        Ok(Self {
            config: config.clone(),
            template_engine: TemplateEngine::new().await?,
            report_generator: ReportGenerator::new().await?,
            custom_template_manager: CustomTemplateManager::new(
                config.custom_template_dir.clone()
            ).await?,
            format_handlers,
        })
    }

    /// Generate report in specified format
    pub async fn generate_report<T: Serialize>(
        &self,
        data: &T,
        format: OutputFormat,
        template_name: Option<&str>,
    ) -> Result<GeneratedReport> {
        let handler = self.format_handlers.get(&format)
            .ok_or_else(|| PdfError::ConfigurationError {
                message: format!("Unsupported output format: {:?}", format),
                config_key: Some("output_format".to_string()),
                context: ErrorContext::new("report", "generate_report"),
                config_source: "report_configuration".to_string(),
                validation_errors: vec![format!("Format {:?} not supported", format)],
                recovery_suggestions: vec!["Use supported format".to_string()],
                schema_violations: vec![],
                environment: "report".to_string(),
                fallback_config: None,
            })?;

        handler.generate_report(data, template_name).await
    }
}
```

### File 2: `src/report/template_engine.rs` (300 lines)

```rust
//! Template engine for report generation

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use handlebars::{Handlebars, TemplateError};
use tera::{Tera, Context as TeraContext};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::error::{Result, PdfError, ErrorContext};

/// Template engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Template engine type
    pub engine_type: TemplateEngineType,
    /// Enable template caching
    pub enable_caching: bool,
    /// Template directory
    pub template_directory: Option<String>,
    /// Enable strict mode
    pub strict_mode: bool,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            engine_type: TemplateEngineType::Handlebars,
            enable_caching: true,
            template_directory: None,
            strict_mode: true,
        }
    }
}

/// Template engine types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateEngineType {
    Handlebars,
    Tera,
}

/// Template rendering result
#[derive(Debug, Clone)]
pub struct TemplateResult {
    pub template_id: String,
    pub rendered_content: String,
    pub rendering_time: std::time::Duration,
    pub template_name: String,
    pub engine_type: TemplateEngineType,
    pub warnings: Vec<String>,
}

/// Template context for rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateContext {
    pub data: serde_json::Value,
    pub metadata: HashMap<String, String>,
    pub helpers: HashMap<String, String>,
}

impl TemplateContext {
    pub fn new() -> Self {
        Self {
            data: serde_json::Value::Null,
            metadata: HashMap::new(),
            helpers: HashMap::new(),
        }
    }

    pub fn with_data<T: Serialize>(data: &T) -> Result<Self> {
        let json_data = serde_json::to_value(data).map_err(|e| {
            PdfError::SerializationError {
                message: format!("Failed to serialize template data: {}", e),
                data_type: std::any::type_name::<T>().to_string(),
                context: ErrorContext::new("template_engine", "with_data"),
                serialization_format: "json".to_string(),
                field_path: None,
                recovery_suggestions: vec!["Check data structure for serialization compatibility".to_string()],
                schema_validation_errors: vec![],
                encoding_info: None,
            }
        })?;

        Ok(Self {
            data: json_data,
            metadata: HashMap::new(),
            helpers: HashMap::new(),
        })
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    pub fn add_helper(&mut self, name: String, implementation: String) {
        self.helpers.insert(name, implementation);
    }
}

/// Template engine for multiple rendering backends
pub struct TemplateEngine {
    config: TemplateConfig,
    handlebars: Arc<RwLock<Handlebars<'static>>>,
    tera: Arc<RwLock<Tera>>,
    template_cache: Arc<RwLock<HashMap<String, CachedTemplate>>>,
}

/// Cached template information
#[derive(Debug, Clone)]
struct CachedTemplate {
    pub template_name: String,
    pub compiled_template: String,
    pub last_modified: std::time::SystemTime,
    pub access_count: u64,
}

impl TemplateEngine {
    /// Create new template engine
    pub async fn new() -> Result<Self> {
        let config = TemplateConfig::default();
        let mut handlebars = Handlebars::new();
        
        // Configure Handlebars
        handlebars.set_strict_mode(config.strict_mode);
        Self::register_handlebars_helpers(&mut handlebars)?;

        // Configure Tera
        let tera = if let Some(ref template_dir) = config.template_directory {
            Tera::new(&format!("{}/**/*", template_dir)).map_err(|e| {
                PdfError::ConfigurationError {
                    message: format!("Failed to initialize Tera engine: {}", e),
                    config_key: Some("template_directory".to_string()),
                    context: ErrorContext::new("template_engine", "new"),
                    config_source: "template_config".to_string(),
                    validation_errors: vec![e.to_string()],
                    recovery_suggestions: vec!["Check template directory path".to_string()],
                    schema_violations: vec![],
                    environment: "template".to_string(),
                    fallback_config: None,
                }
            })?
        } else {
            Tera::default()
        };

        Ok(Self {
            config,
            handlebars: Arc::new(RwLock::new(handlebars)),
            tera: Arc::new(RwLock::new(tera)),
            template_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Render template with given context
    pub async fn render_template(
        &self,
        template_name: &str,
        template_content: &str,
        context: &TemplateContext,
    ) -> Result<TemplateResult> {
        let start_time = std::time::Instant::now();
        let template_id = Uuid::new_v4().to_string();

        let rendered_content = match self.config.engine_type {
            TemplateEngineType::Handlebars => {
                self.render_with_handlebars(template_name, template_content, context).await?
            }
            TemplateEngineType::Tera => {
                self.render_with_tera(template_name, template_content, context).await?
            }
        };

        let rendering_time = start_time.elapsed();

        // Cache template if caching is enabled
        if self.config.enable_caching {
            self.cache_template(template_name, template_content).await;
        }

        Ok(TemplateResult {
            template_id,
            rendered_content,
            rendering_time,
            template_name: template_name.to_string(),
            engine_type: self.config.engine_type,
            warnings: Vec::new(),
        })
    }

    /// Render template with Handlebars engine
    async fn render_with_handlebars(
        &self,
        template_name: &str,
        template_content: &str,
        context: &TemplateContext,
    ) -> Result<String> {
        let mut handlebars = self.handlebars.write().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire handlebars lock".to_string(),
                lock_type: "write".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("template_engine", "render_with_handlebars"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;

        // Register template
        handlebars.register_template_string(template_name, template_content)
            .map_err(|e| {
                PdfError::ProcessingError {
                    message: format!("Handlebars template registration failed: {}", e),
                    stage: "template_registration".to_string(),
                    context: ErrorContext::new("template_engine", "render_with_handlebars"),
                    recovery_suggestions: vec!["Check template syntax".to_string()],
                }
            })?;

        // Render template
        handlebars.render(template_name, &context.data)
            .map_err(|e| {
                PdfError::ProcessingError {
                    message: format!("Handlebars template rendering failed: {}", e),
                    stage: "template_rendering".to_string(),
                    context: ErrorContext::new("template_engine", "render_with_handlebars"),
                    recovery_suggestions: vec!["Check template data compatibility".to_string()],
                }
            })
    }

    /// Render template with Tera engine
    async fn render_with_tera(
        &self,
        template_name: &str,
        template_content: &str,
        context: &TemplateContext,
    ) -> Result<String> {
        let mut tera = self.tera.write().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire tera lock".to_string(),
                lock_type: "write".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("template_engine", "render_with_tera"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;

        // Add template to Tera
        tera.add_raw_template(template_name, template_content)
            .map_err(|e| {
                PdfError::ProcessingError {
                    message: format!("Tera template registration failed: {}", e),
                    stage: "template_registration".to_string(),
                    context: ErrorContext::new("template_engine", "render_with_tera"),
                    recovery_suggestions: vec!["Check template syntax".to_string()],
                }
            })?;

        // Create Tera context
        let mut tera_context = TeraContext::new();
        
        // Convert JSON value to Tera context
        if let serde_json::Value::Object(map) = &context.data {
            for (key, value) in map {
                tera_context.insert(key, value);
            }
        }

        // Add metadata to context
        for (key, value) in &context.metadata {
            tera_context.insert(key, value);
        }

        // Render template
        tera.render(template_name, &tera_context)
            .map_err(|e| {
                PdfError::ProcessingError {
                    message: format!("Tera template rendering failed: {}", e),
                    stage: "template_rendering".to_string(),
                    context: ErrorContext::new("template_engine", "render_with_tera"),
                    recovery_suggestions: vec!["Check template data compatibility".to_string()],
                }
            })
    }

    /// Register Handlebars helpers
    fn register_handlebars_helpers(handlebars: &mut Handlebars) -> Result<()> {
        // Date formatting helper
        handlebars.register_helper("format_date", Box::new(|h, _, context, _rc, out| {
            let date_str = h.param(0)
                .and_then(|v| v.value().as_str())
                .unwrap_or("");

            if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(date_str) {
                let formatted = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                out.write(&formatted)?;
            } else {
                out.write(date_str)?;
            }
            Ok(())
        }));

        // Number formatting helper
        handlebars.register_helper("format_number", Box::new(|h, _, context, _rc, out| {
            if let Some(number) = h.param(0).and_then(|v| v.value().as_f64()) {
                let formatted = format!("{:.2}", number);
                out.write(&formatted)?;
            }
            Ok(())
        }));

        // Conditional helper
        handlebars.register_helper("if_eq", Box::new(|h, _, context, _rc, out| {
            let param1 = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
            let param2 = h.param(1).and_then(|v| v.value().as_str()).unwrap_or("");
            
            if param1 == param2 {
                if let Some(template) = h.template() {
                    template.render(context, context, _rc, out)?;
                }
            }
            Ok(())
        }));

        Ok(())
    }

    /// Cache template for future use
    async fn cache_template(&self, template_name: &str, template_content: &str) {
        if let Ok(mut cache) = self.template_cache.write() {
            cache.insert(template_name.to_string(), CachedTemplate {
                template_name: template_name.to_string(),
                compiled_template: template_content.to_string(),
                last_modified: std::time::SystemTime::now(),
                access_count: 1,
            });
        }
    }

    /// Get cached template
    pub async fn get_cached_template(&self, template_name: &str) -> Option<String> {
        if let Ok(mut cache) = self.template_cache.write() {
            if let Some(cached) = cache.get_mut(template_name) {
                cached.access_count += 1;
                return Some(cached.compiled_template.clone());
            }
        }
        None
    }

    /// Clear template cache
    pub async fn clear_cache(&self) -> Result<()> {
        let mut cache = self.template_cache.write().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire cache lock".to_string(),
                lock_type: "write".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("template_engine", "clear_cache"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;
        
        cache.clear();
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> Result<CacheStatistics> {
        let cache = self.template_cache.read().map_err(|_| {
            PdfError::ConcurrencyError {
                message: "Failed to acquire cache lock".to_string(),
                lock_type: "read".to_string(),
                timeout_duration: None,
                context: ErrorContext::new("template_engine", "get_cache_stats"),
                thread_info: Default::default(),
                deadlock_detected: false,
                lock_chain: vec![],
                contention_level: 0.0,
                recovery_suggestions: vec!["Retry operation".to_string()],
                thread_dump: None,
            }
        })?;

        let total_templates = cache.len();
        let total_access_count = cache.values().map(|t| t.access_count).sum();
        let most_accessed = cache.values()
            .max_by_key(|t| t.access_count)
            .map(|t| t.template_name.clone());

        Ok(CacheStatistics {
            total_templates,
            total_access_count,
            most_accessed_template: most_accessed,
            cache_hit_rate: 0.0, // Would calculate based on metrics
        })
    }
}

/// Template cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub total_templates: usize,
    pub total_access_count: u64,
    pub most_accessed_template: Option<String>,
    pub cache_hit_rate: f64,
}
```

I've implemented comprehensive modules for the PDF anti-forensics system, covering critical and high-priority components. Let me now create the remaining essential modules to complete the implementation as specified in the requirements.

<function_calls>
<invoke name="str_replace_based_edit_tool">
<parameter name="command">create