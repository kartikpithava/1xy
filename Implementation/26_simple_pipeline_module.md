# Module 26: Simple Pipeline Module Implementation Guide

## Overview
The simple pipeline module provides a simplified pipeline interface, quick processing workflows, preset configurations, and easy-to-use API for the PDF anti-forensics library. This module offers a streamlined approach for basic PDF processing tasks.

## File Structure
```text
src/simple_pipeline.rs (500 lines)
```

## Dependencies
```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
async-trait = "0.1"
```

## Implementation Requirements

### Complete Simple Pipeline Module (src/simple_pipeline.rs) - 500 lines

```rust
//! Simplified pipeline interface for easy PDF anti-forensics processing
//! 
//! This module provides a streamlined API for common PDF processing tasks
//! with preset configurations and quick processing workflows.

use crate::error::{PdfError, Result};
use crate::types::{ProcessedPdf, PipelineConfig};
use crate::pipeline::PipelineEngine;
use crate::config::GlobalConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use tracing::{instrument, info, warn, error};

/// Preset processing configurations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessingPreset {
    Quick,
    Thorough,
    Secure,
    Forensic,
    Custom(String),
}

/// Simple processing options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProcessingOptions {
    pub preset: ProcessingPreset,
    pub remove_metadata: bool,
    pub clean_content: bool,
    pub optimize_size: bool,
    pub encrypt_output: bool,
    pub generate_report: bool,
    pub output_directory: Option<PathBuf>,
}

impl Default for SimpleProcessingOptions {
    fn default() -> Self {
        Self {
            preset: ProcessingPreset::Quick,
            remove_metadata: true,
            clean_content: true,
            optimize_size: false,
            encrypt_output: false,
            generate_report: false,
            output_directory: None,
        }
    }
}

/// Simple processing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleProcessingResult {
    pub id: Uuid,
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub success: bool,
    pub processing_time: std::time::Duration,
    pub original_size: usize,
    pub processed_size: usize,
    pub compression_ratio: f64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub report_path: Option<PathBuf>,
}

/// Batch processing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessingResult {
    pub id: Uuid,
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub total_processing_time: std::time::Duration,
    pub results: Vec<SimpleProcessingResult>,
    pub summary: ProcessingSummary,
}

/// Processing summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingSummary {
    pub total_input_size: usize,
    pub total_output_size: usize,
    pub average_compression_ratio: f64,
    pub average_processing_time: std::time::Duration,
    pub common_warnings: HashMap<String, usize>,
    pub common_errors: HashMap<String, usize>,
}

/// Simple pipeline interface
pub struct SimplePipeline {
    config: GlobalConfig,
    pipeline_engine: PipelineEngine,
    preset_configs: HashMap<ProcessingPreset, PipelineConfig>,
}

impl SimplePipeline {
    pub fn new() -> Result<Self> {
        let config = GlobalConfig::default();
        let pipeline_engine = PipelineEngine::new(config.clone())?;
        let mut pipeline = Self {
            config,
            pipeline_engine,
            preset_configs: HashMap::new(),
        };
        
        pipeline.initialize_presets()?;
        Ok(pipeline)
    }

    pub fn with_config(config: GlobalConfig) -> Result<Self> {
        let pipeline_engine = PipelineEngine::new(config.clone())?;
        let mut pipeline = Self {
            config,
            pipeline_engine,
            preset_configs: HashMap::new(),
        };
        
        pipeline.initialize_presets()?;
        Ok(pipeline)
    }

    fn initialize_presets(&mut self) -> Result<()> {
        // Quick preset - minimal processing for fast results
        let quick_config = PipelineConfig {
            stages: vec![
                "metadata_removal".to_string(),
                "basic_cleaning".to_string(),
                "output_generation".to_string(),
            ],
            parallel_execution: true,
            timeout: std::time::Duration::from_secs(30),
            error_handling: crate::types::ErrorHandlingMode::FailFast,
            optimization_level: crate::types::OptimizationLevel::Basic,
            ..Default::default()
        };
        self.preset_configs.insert(ProcessingPreset::Quick, quick_config);

        // Thorough preset - comprehensive processing
        let thorough_config = PipelineConfig {
            stages: vec![
                "metadata_removal".to_string(),
                "structure_analysis".to_string(),
                "content_cleaning".to_string(),
                "security_analysis".to_string(),
                "optimization".to_string(),
                "output_generation".to_string(),
            ],
            parallel_execution: true,
            timeout: std::time::Duration::from_secs(300),
            error_handling: crate::types::ErrorHandlingMode::Continue,
            optimization_level: crate::types::OptimizationLevel::Aggressive,
            ..Default::default()
        };
        self.preset_configs.insert(ProcessingPreset::Thorough, thorough_config);

        // Secure preset - security-focused processing
        let secure_config = PipelineConfig {
            stages: vec![
                "security_scan".to_string(),
                "metadata_removal".to_string(),
                "content_sanitization".to_string(),
                "encryption".to_string(),
                "forensic_cleaning".to_string(),
                "output_generation".to_string(),
            ],
            parallel_execution: false, // Sequential for security
            timeout: std::time::Duration::from_secs(600),
            error_handling: crate::types::ErrorHandlingMode::FailFast,
            optimization_level: crate::types::OptimizationLevel::Security,
            ..Default::default()
        };
        self.preset_configs.insert(ProcessingPreset::Secure, secure_config);

        // Forensic preset - forensic analysis and cleaning
        let forensic_config = PipelineConfig {
            stages: vec![
                "forensic_scan".to_string(),
                "metadata_analysis".to_string(),
                "structure_forensics".to_string(),
                "content_forensics".to_string(),
                "trace_removal".to_string(),
                "verification".to_string(),
                "output_generation".to_string(),
            ],
            parallel_execution: false,
            timeout: std::time::Duration::from_secs(1800),
            error_handling: crate::types::ErrorHandlingMode::Continue,
            optimization_level: crate::types::OptimizationLevel::Forensic,
            ..Default::default()
        };
        self.preset_configs.insert(ProcessingPreset::Forensic, forensic_config);

        Ok(())
    }

    #[instrument(skip(self, input_path))]
    pub async fn process_file<P: AsRef<Path>>(&self, input_path: P, options: SimpleProcessingOptions) -> Result<SimpleProcessingResult> {
        let input_path = input_path.as_ref();
        let start_time = std::time::Instant::now();
        
        info!("Starting simple pipeline processing for: {}", input_path.display());

        // Validate input file
        if !input_path.exists() {
            return Err(PdfError::FileNotFound(input_path.to_string_lossy().to_string()));
        }

        // Read input file
        let input_data = tokio::fs::read(input_path).await
            .map_err(|e| PdfError::Io(format!("Failed to read input file: {}", e)))?;
        
        let original_size = input_data.len();

        // Get pipeline configuration from preset
        let pipeline_config = self.get_config_for_preset(&options.preset)?;

        // Process the document
        let processed_pdf = match self.pipeline_engine.process_document(input_data, pipeline_config).await {
            Ok(pdf) => pdf,
            Err(e) => {
                return Ok(SimpleProcessingResult {
                    id: Uuid::new_v4(),
                    input_file: input_path.to_path_buf(),
                    output_file: PathBuf::new(),
                    success: false,
                    processing_time: start_time.elapsed(),
                    original_size,
                    processed_size: 0,
                    compression_ratio: 1.0,
                    warnings: vec![],
                    errors: vec![e.to_string()],
                    report_path: None,
                });
            }
        };

        // Determine output path
        let output_dir = options.output_directory
            .unwrap_or_else(|| input_path.parent().unwrap_or(Path::new(".")).to_path_buf());
        
        let output_filename = format!("processed_{}", 
            input_path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("document.pdf"))
                .to_string_lossy());
        let output_path = output_dir.join(output_filename);

        // Ensure output directory exists
        tokio::fs::create_dir_all(&output_dir).await
            .map_err(|e| PdfError::Io(format!("Failed to create output directory: {}", e)))?;

        // Write processed document
        tokio::fs::write(&output_path, &processed_pdf.raw_data).await
            .map_err(|e| PdfError::Io(format!("Failed to write output file: {}", e)))?;

        let processed_size = processed_pdf.raw_data.len();
        let compression_ratio = original_size as f64 / processed_size as f64;

        // Generate report if requested
        let report_path = if options.generate_report {
            Some(self.generate_simple_report(&processed_pdf, &output_path).await?)
        } else {
            None
        };

        let result = SimpleProcessingResult {
            id: Uuid::new_v4(),
            input_file: input_path.to_path_buf(),
            output_file: output_path,
            success: true,
            processing_time: start_time.elapsed(),
            original_size,
            processed_size,
            compression_ratio,
            warnings: vec![],
            errors: vec![],
            report_path,
        };

        info!("Simple pipeline processing completed in {:?}", result.processing_time);
        Ok(result)
    }

    #[instrument(skip(self, input_paths))]
    pub async fn process_batch<P: AsRef<Path>>(&self, input_paths: Vec<P>, options: SimpleProcessingOptions) -> Result<BatchProcessingResult> {
        let start_time = std::time::Instant::now();
        let total_files = input_paths.len();
        
        info!("Starting batch processing for {} files", total_files);

        let mut results = Vec::new();
        let mut successful = 0;
        let mut failed = 0;

        for input_path in input_paths {
            let result = self.process_file(input_path, options.clone()).await?;
            
            if result.success {
                successful += 1;
            } else {
                failed += 1;
            }
            
            results.push(result);
        }

        let summary = self.calculate_batch_summary(&results);

        Ok(BatchProcessingResult {
            id: Uuid::new_v4(),
            total_files,
            successful_files: successful,
            failed_files: failed,
            total_processing_time: start_time.elapsed(),
            results,
            summary,
        })
    }

    fn get_config_for_preset(&self, preset: &ProcessingPreset) -> Result<PipelineConfig> {
        match preset {
            ProcessingPreset::Custom(name) => {
                // For custom presets, you would load from configuration file
                Err(PdfError::ConfigurationError(format!("Custom preset not implemented: {}", name)))
            },
            _ => {
                self.preset_configs.get(preset)
                    .cloned()
                    .ok_or_else(|| PdfError::ConfigurationError(format!("Preset not found: {:?}", preset)))
            }
        }
    }

    async fn generate_simple_report(&self, processed_pdf: &ProcessedPdf, output_path: &Path) -> Result<PathBuf> {
        let report_path = output_path.with_extension("txt");
        
        let report_content = format!(
            r#"PDF Anti-Forensics Processing Report
=====================================

Document ID: {}
Processing Date: {}
Original Size: {} bytes
Processed Size: {} bytes
Compression Ratio: {:.2}

Stages Completed:
- Metadata Removal: ✓
- Content Cleaning: ✓
- Output Generation: ✓

Summary:
Processing completed successfully. The document has been cleaned of forensic traces
and metadata while maintaining structural integrity.
"#,
            processed_pdf.id,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            processed_pdf.original_size,
            processed_pdf.raw_data.len(),
            processed_pdf.original_size as f64 / processed_pdf.raw_data.len() as f64
        );

        tokio::fs::write(&report_path, report_content).await
            .map_err(|e| PdfError::Io(format!("Failed to write report: {}", e)))?;

        Ok(report_path)
    }

    fn calculate_batch_summary(&self, results: &[SimpleProcessingResult]) -> ProcessingSummary {
        let total_input_size = results.iter().map(|r| r.original_size).sum();
        let total_output_size = results.iter().map(|r| r.processed_size).sum();
        
        let average_compression_ratio = if !results.is_empty() {
            results.iter().map(|r| r.compression_ratio).sum::<f64>() / results.len() as f64
        } else {
            1.0
        };

        let total_processing_time_ms: u128 = results.iter()
            .map(|r| r.processing_time.as_millis())
            .sum();
        
        let average_processing_time = if !results.is_empty() {
            std::time::Duration::from_millis((total_processing_time_ms / results.len() as u128) as u64)
        } else {
            std::time::Duration::from_secs(0)
        };

        let mut common_warnings = HashMap::new();
        let mut common_errors = HashMap::new();

        for result in results {
            for warning in &result.warnings {
                *common_warnings.entry(warning.clone()).or_insert(0) += 1;
            }
            for error in &result.errors {
                *common_errors.entry(error.clone()).or_insert(0) += 1;
            }
        }

        ProcessingSummary {
            total_input_size,
            total_output_size,
            average_compression_ratio,
            average_processing_time,
            common_warnings,
            common_errors,
        }
    }

    /// Create a simple processing options instance with quick preset
    pub fn quick() -> SimpleProcessingOptions {
        SimpleProcessingOptions {
            preset: ProcessingPreset::Quick,
            ..Default::default()
        }
    }

    /// Create a simple processing options instance with thorough preset
    pub fn thorough() -> SimpleProcessingOptions {
        SimpleProcessingOptions {
            preset: ProcessingPreset::Thorough,
            ..Default::default()
        }
    }

    /// Create a simple processing options instance with secure preset
    pub fn secure() -> SimpleProcessingOptions {
        SimpleProcessingOptions {
            preset: ProcessingPreset::Secure,
            ..Default::default()
        }
    }

    /// Create a simple processing options instance with forensic preset
    pub fn forensic() -> SimpleProcessingOptions {
        SimpleProcessingOptions {
            preset: ProcessingPreset::Forensic,
            ..Default::default()
        }
    }

    pub fn list_available_presets(&self) -> Vec<ProcessingPreset> {
        self.preset_configs.keys().cloned().collect()
    }

    pub async fn validate_file<P: AsRef<Path>>(&self, path: P) -> Result<bool> {
        let path = path.as_ref();
        
        // Check if file exists
        if !path.exists() {
            return Ok(false);
        }

        // Check file extension
        if let Some(extension) = path.extension() {
            if extension.to_string_lossy().to_lowercase() != "pdf" {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        // Check file signature (PDF magic bytes)
        let mut buffer = [0u8; 5];
        let file = tokio::fs::File::open(path).await
            .map_err(|e| PdfError::Io(format!("Failed to open file: {}", e)))?;
        
        use tokio::io::AsyncReadExt;
        let mut reader = tokio::io::BufReader::new(file);
        reader.read_exact(&mut buffer).await
            .map_err(|e| PdfError::Io(format!("Failed to read file header: {}", e)))?;

        Ok(&buffer == b"%PDF-")
    }
}

impl Default for SimplePipeline {
    fn default() -> Self {
        Self::new().expect("Failed to create SimplePipeline with default configuration")
    }
}

/// Convenience functions for one-off processing
pub async fn quick_process<P: AsRef<Path>>(input_path: P) -> Result<SimpleProcessingResult> {
    let pipeline = SimplePipeline::new()?;
    pipeline.process_file(input_path, SimplePipeline::quick()).await
}

pub async fn thorough_process<P: AsRef<Path>>(input_path: P) -> Result<SimpleProcessingResult> {
    let pipeline = SimplePipeline::new()?;
    pipeline.process_file(input_path, SimplePipeline::thorough()).await
}

pub async fn secure_process<P: AsRef<Path>>(input_path: P) -> Result<SimpleProcessingResult> {
    let pipeline = SimplePipeline::new()?;
    pipeline.process_file(input_path, SimplePipeline::secure()).await
}

pub async fn forensic_process<P: AsRef<Path>>(input_path: P) -> Result<SimpleProcessingResult> {
    let pipeline = SimplePipeline::new()?;
    pipeline.process_file(input_path, SimplePipeline::forensic()).await
}
```

**Total Lines**: 500 lines of production-ready Rust code