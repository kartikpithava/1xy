
# Module 12: Scanner Module Implementation

## Overview
The scanner module provides comprehensive PDF scanning capabilities including deep scanning, object scanning, stream scanning, and signature scanning with advanced threat detection and forensic analysis.

## Files to Implement

### File 1: PRODUCTION-ENHANCED `src/scanner/mod.rs` (180 lines)
```rust
//! ENTERPRISE-GRADE PDF Scanner Module
//! 
//! Provides production-ready comprehensive scanning capabilities with parallel
//! scanning algorithms, scan result correlation, performance optimization,
//! and accuracy benchmarking for enterprise security operations.
//!
//! # PRODUCTION ENHANCEMENTS
//! - Parallel scanning algorithms with work distribution and load balancing
//! - Scan result correlation with cross-reference analysis and pattern matching
//! - Scan performance optimization with caching and memory management
//! - Scan accuracy benchmarking with statistical validation and quality metrics
//! - Real-time threat detection with ML-based classification and scoring
//! - Multi-layered scanning with progressive depth and selective analysis
//! - Distributed scanning with cluster coordination and result aggregation
//! - Continuous monitoring with health checks and performance tracking
//! - Policy-based scanning with configurable rules and automated responses
//! - Comprehensive reporting with detailed findings and remediation guidance

use std::collections::{HashMap, BTreeMap, VecDeque};
use std::sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use futures::future::BoxFuture;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument, span, Level};

// Machine learning for threat detection
use candle_core::{Tensor, Device, DType};
use candle_nn::{VarBuilder, Module};

// Parallel processing
use rayon::prelude::*;
use tokio::sync::{Semaphore, RwLock as TokioRwLock};
use crossbeam::channel;

// Performance monitoring
use metrics::{counter, histogram, gauge};

use crate::{
    types::{Document, ObjectId, PdfObject, SecurityLevel, ProcessingMode, 
            ScanResult, ThreatAssessment, PerformanceMetrics},
    error::{Result, PdfError, ErrorContext, ErrorCategory},
    config::Config,
};

pub mod deep_scanner;
pub mod object_scanner;
pub mod stream_scanner;
pub mod signature_scanner;
pub mod content_scanner;
pub mod metadata_scanner;
pub mod pdf_scanner;

// Production-enhanced scanning modules
pub mod parallel_scanner;
pub mod correlation_engine;
pub mod performance_optimizer;
pub mod accuracy_validator;
pub mod ml_threat_detector;
pub mod distributed_scanner;
pub mod monitoring_system;
pub mod policy_engine;
pub mod reporting_engine;
pub mod health_checker;

pub use deep_scanner::DeepScanner;
pub use object_scanner::ObjectScanner;
pub use stream_scanner::StreamScanner;
pub use signature_scanner::SignatureScanner;
pub use content_scanner::ContentScanner;
pub use metadata_scanner::MetadataScanner;
pub use pdf_scanner::PdfScanner;

// Production exports
pub use parallel_scanner::{ParallelScanner, WorkDistributor, LoadBalancer};
pub use correlation_engine::{CorrelationEngine, CrossReferenceAnalyzer, PatternMatcher};
pub use performance_optimizer::{PerformanceOptimizer, CacheManager, MemoryManager};
pub use accuracy_validator::{AccuracyValidator, QualityMetrics, ValidationReport};
pub use ml_threat_detector::{MLThreatDetector, ThreatClassifier, ThreatScorer};
pub use distributed_scanner::{DistributedScanner, ClusterCoordinator, ResultAggregator};
pub use monitoring_system::{MonitoringSystem, HealthMonitor, PerformanceTracker};
pub use policy_engine::{PolicyEngine, ScanningPolicy, RuleValidator};
pub use reporting_engine::{ReportingEngine, ScanReport, FindingsAnalyzer};
pub use health_checker::{HealthChecker, SystemHealth, DiagnosticInfo};

/// Scan operation types for comprehensive tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanType {
    Deep,
    Object,
    Stream,
    Signature,
    Content,
    Metadata,
    Threat,
    Performance,
    Integrity,
    Compliance,
}

/// Scanning policy configuration for enterprise deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub enabled_scanners: Vec<ScanType>,
    pub security_level: SecurityLevel,
    pub parallel_processing: bool,
    pub correlation_analysis: bool,
    pub ml_threat_detection: bool,
    pub real_time_monitoring: bool,
    pub comprehensive_reporting: bool,
    pub max_scan_time: Duration,
    pub threat_threshold: f64,
    pub accuracy_requirement: f64,
    pub compliance_frameworks: Vec<String>,
}

impl Default for ScanningPolicy {
    fn default() -> Self {
        Self {
            policy_id: uuid::Uuid::new_v4().to_string(),
            policy_name: "Enterprise Security Scanning Policy".to_string(),
            enabled_scanners: vec![
                ScanType::Deep,
                ScanType::Object,
                ScanType::Stream,
                ScanType::Content,
                ScanType::Threat,
                ScanType::Integrity,
            ],
            security_level: SecurityLevel::Confidential,
            parallel_processing: true,
            correlation_analysis: true,
            ml_threat_detection: true,
            real_time_monitoring: true,
            comprehensive_reporting: true,
            max_scan_time: Duration::from_secs(600), // 10 minutes
            threat_threshold: 0.7,
            accuracy_requirement: 0.95,
            compliance_frameworks: vec!["SOC2".to_string(), "ISO27001".to_string()],
        }
    }
}

/// Global scanning metrics tracker
pub static SCANNING_METRICS: once_cell::sync::Lazy<Arc<RwLock<ScanningMetrics>>> = 
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(ScanningMetrics::new())));

/// Scanning processing performance metrics
#[derive(Debug, Clone, Default)]
pub struct ScanningMetrics {
    pub total_scans: u64,
    pub successful_scans: u64,
    pub failed_scans: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub average_scan_time: Duration,
    pub total_data_scanned: u64,
    pub accuracy_score: f64,
    pub performance_score: f64,
    pub scans_by_type: HashMap<ScanType, u64>,
}

impl ScanningMetrics {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn record_scan(&mut self, scan_type: ScanType, duration: Duration, success: bool, 
                      threats_found: u64, data_size: u64) {
        self.total_scans += 1;
        if success {
            self.successful_scans += 1;
        } else {
            self.failed_scans += 1;
        }
        
        self.threats_detected += threats_found;
        self.total_data_scanned += data_size;
        *self.scans_by_type.entry(scan_type).or_insert(0) += 1;
        
        // Update average scan time
        self.average_scan_time = Duration::from_nanos(
            (self.average_scan_time.as_nanos() as u64 * (self.total_scans - 1) 
             + duration.as_nanos() as u64) / self.total_scans
        );
        
        // Update accuracy score (simplified calculation)
        if threats_found > 0 {
            self.accuracy_score = (self.accuracy_score * 0.9) + (0.1 * 0.95);
        }
    }
}

/// Comprehensive scanner that coordinates all scanning modules with enterprise features
#[derive(Debug, Clone)]
pub struct Scanner {
    config: Config,
    deep_scanner: DeepScanner,
    object_scanner: ObjectScanner,
    stream_scanner: StreamScanner,
    signature_scanner: SignatureScanner,
    content_scanner: ContentScanner,
    metadata_scanner: MetadataScanner,
    pdf_scanner: PdfScanner,
}

/// Combined scan results from all scanning modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveScanResult {
    pub scan_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub document_id: String,
    pub overall_security_score: f64,
    pub threat_level: SecurityLevel,
    pub scan_duration: Duration,
    pub deep_scan_results: deep_scanner::DeepScanResult,
    pub object_scan_results: object_scanner::ObjectScanResult,
    pub stream_scan_results: stream_scanner::StreamScanResult,
    pub signature_scan_results: signature_scanner::SignatureScanResult,
    pub content_scan_results: content_scanner::ContentScanResult,
    pub metadata_scan_results: metadata_scanner::MetadataScanResult,
    pub pdf_scan_results: pdf_scanner::PdfScanResult,
    pub recommendations: Vec<String>,
    pub remediation_steps: Vec<String>,
}

impl Scanner {
    /// Create new scanner with configuration
    pub fn new(config: Config) -> Self {
        Self {
            deep_scanner: DeepScanner::new(config.clone()),
            object_scanner: ObjectScanner::new(config.clone()),
            stream_scanner: StreamScanner::new(config.clone()),
            signature_scanner: SignatureScanner::new(config.clone()),
            content_scanner: ContentScanner::new(config.clone()),
            metadata_scanner: MetadataScanner::new(config.clone()),
            pdf_scanner: PdfScanner::new(config.clone()),
            config,
        }
    }

    /// Perform comprehensive scan of PDF document
    #[instrument(skip(self, document))]
    pub async fn comprehensive_scan(&self, document: &Document) -> Result<ComprehensiveScanResult> {
        let start_time = Instant::now();
        let scan_id = uuid::Uuid::new_v4().to_string();
        
        info!("Starting comprehensive scan for document: {}", document.id);

        // Execute all scans in parallel for efficiency
        let (deep_results, object_results, stream_results, signature_results, content_results, metadata_results, pdf_results) = tokio::try_join!(
            self.deep_scanner.scan(document),
            self.object_scanner.scan(document),
            self.stream_scanner.scan(document),
            self.signature_scanner.scan(document),
            self.content_scanner.scan(document),
            self.metadata_scanner.scan(document),
            self.pdf_scanner.scan(document)
        )?;

        let scan_duration = start_time.elapsed();
        
        // Calculate overall security score
        let overall_security_score = self.calculate_overall_security_score(
            &deep_results, &object_results, &stream_results, 
            &signature_results, &content_results, &metadata_results, &pdf_results
        );

        // Determine threat level
        let threat_level = self.determine_threat_level(overall_security_score);

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &deep_results, &object_results, &stream_results,
            &signature_results, &content_results, &metadata_results, &pdf_results
        );

        // Generate remediation steps
        let remediation_steps = self.generate_remediation_steps(threat_level, &recommendations);

        info!("Comprehensive scan completed. Security score: {:.2}, Threat level: {:?}", 
              overall_security_score, threat_level);

        Ok(ComprehensiveScanResult {
            scan_id,
            timestamp: chrono::Utc::now(),
            document_id: document.id.clone(),
            overall_security_score,
            threat_level,
            scan_duration,
            deep_scan_results: deep_results,
            object_scan_results: object_results,
            stream_scan_results: stream_results,
            signature_scan_results: signature_results,
            content_scan_results: content_results,
            metadata_scan_results: metadata_results,
            pdf_scan_results: pdf_results,
            recommendations,
            remediation_steps,
        })
    }

    /// Calculate overall security score from all scan results
    fn calculate_overall_security_score(
        &self,
        deep: &deep_scanner::DeepScanResult,
        object: &object_scanner::ObjectScanResult,
        stream: &stream_scanner::StreamScanResult,
        signature: &signature_scanner::SignatureScanResult,
        content: &content_scanner::ContentScanResult,
        metadata: &metadata_scanner::MetadataScanResult,
        pdf: &pdf_scanner::PdfScanResult,
    ) -> f64 {
        let weights = match self.config.security_level() {
            SecurityLevel::Low => (0.1, 0.15, 0.1, 0.15, 0.2, 0.15, 0.15),
            SecurityLevel::Medium => (0.15, 0.15, 0.15, 0.15, 0.15, 0.15, 0.1),
            SecurityLevel::High => (0.2, 0.15, 0.15, 0.15, 0.15, 0.1, 0.1),
            SecurityLevel::Critical => (0.25, 0.15, 0.15, 0.15, 0.15, 0.1, 0.05),
            SecurityLevel::Maximum => (0.3, 0.2, 0.15, 0.15, 0.1, 0.05, 0.05),
        };

        (deep.security_score * weights.0 +
         object.security_score * weights.1 +
         stream.security_score * weights.2 +
         signature.security_score * weights.3 +
         content.security_score * weights.4 +
         metadata.security_score * weights.5 +
         pdf.security_score * weights.6).min(1.0).max(0.0)
    }

    /// Determine threat level based on security score
    fn determine_threat_level(&self, security_score: f64) -> SecurityLevel {
        match security_score {
            s if s >= 0.9 => SecurityLevel::Low,
            s if s >= 0.7 => SecurityLevel::Medium,
            s if s >= 0.5 => SecurityLevel::High,
            s if s >= 0.3 => SecurityLevel::Critical,
            _ => SecurityLevel::Maximum,
        }
    }

    /// Generate recommendations based on scan results
    fn generate_recommendations(
        &self,
        deep: &deep_scanner::DeepScanResult,
        object: &object_scanner::ObjectScanResult,
        stream: &stream_scanner::StreamScanResult,
        signature: &signature_scanner::SignatureScanResult,
        content: &content_scanner::ContentScanResult,
        metadata: &metadata_scanner::MetadataScanResult,
        pdf: &pdf_scanner::PdfScanResult,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Collect recommendations from each scanner
        recommendations.extend(deep.recommendations.clone());
        recommendations.extend(object.recommendations.clone());
        recommendations.extend(stream.recommendations.clone());
        recommendations.extend(signature.recommendations.clone());
        recommendations.extend(content.recommendations.clone());
        recommendations.extend(metadata.recommendations.clone());
        recommendations.extend(pdf.recommendations.clone());

        // Deduplicate and prioritize
        recommendations.sort();
        recommendations.dedup();
        recommendations
    }

    /// Generate remediation steps
    fn generate_remediation_steps(&self, threat_level: SecurityLevel, recommendations: &[String]) -> Vec<String> {
        let mut steps = Vec::new();

        match threat_level {
            SecurityLevel::Maximum | SecurityLevel::Critical => {
                steps.push("IMMEDIATE ACTION REQUIRED: Quarantine this document".to_string());
                steps.push("Run full forensic analysis before further processing".to_string());
                steps.push("Notify security team of potential threat".to_string());
            }
            SecurityLevel::High => {
                steps.push("Review document carefully before processing".to_string());
                steps.push("Consider additional security scanning".to_string());
            }
            SecurityLevel::Medium => {
                steps.push("Apply standard security cleaning procedures".to_string());
                steps.push("Monitor document processing closely".to_string());
            }
            SecurityLevel::Low => {
                steps.push("Document appears safe for normal processing".to_string());
            }
        }

        // Add specific recommendations as steps
        for recommendation in recommendations.iter().take(5) {
            steps.push(format!("Consider: {}", recommendation));
        }

        steps
    }
}

/// Scanner factory for creating specialized scanners
pub struct ScannerFactory;

impl ScannerFactory {
    /// Create scanner optimized for security analysis
    pub fn create_security_scanner() -> Scanner {
        let config = Config::new(SecurityLevel::Critical, ProcessingMode::Forensic);
        Scanner::new(config)
    }

    /// Create scanner optimized for performance
    pub fn create_performance_scanner() -> Scanner {
        let config = Config::new(SecurityLevel::Medium, ProcessingMode::Fast);
        Scanner::new(config)
    }

    /// Create scanner for forensic analysis
    pub fn create_forensic_scanner() -> Scanner {
        let config = Config::new(SecurityLevel::Maximum, ProcessingMode::Forensic);
        Scanner::new(config)
    }
}
```

### File 2: `src/scanner/deep_scanner/mod.rs` (150 lines)
```rust
//! Deep Scanner Module
//! 
//! Provides deep scanning capabilities for hidden content, steganography,
//! and advanced threat detection in PDF documents.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};

use crate::{
    types::{Document, ObjectId, PdfObject, SecurityLevel, ProcessingMode},
    error::{Result, PdfError},
    config::Config,
    utils::entropy::calculate_entropy,
};

/// Deep scanner for advanced threat detection
#[derive(Debug, Clone)]
pub struct DeepScanner {
    config: Config,
    steganography_threshold: f64,
    entropy_threshold: f64,
    pattern_database: PatternDatabase,
}

/// Results from deep scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    pub security_score: f64,
    pub threats_detected: u32,
    pub hidden_content: Vec<HiddenContent>,
    pub steganography_indicators: Vec<SteganographyIndicator>,
    pub entropy_analysis: EntropyAnalysis,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub recommendations: Vec<String>,
    pub scan_duration: Duration,
}

/// Hidden content detected in document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenContent {
    pub content_type: String,
    pub location: String,
    pub size_bytes: usize,
    pub confidence: f64,
    pub risk_level: SecurityLevel,
    pub description: String,
}

/// Steganography detection indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteganographyIndicator {
    pub indicator_type: String,
    pub confidence: f64,
    pub location: String,
    pub analysis_method: String,
    pub risk_assessment: String,
}

/// Entropy analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub entropy_distribution: HashMap<String, f64>,
    pub suspicious_regions: Vec<SuspiciousEntropyRegion>,
    pub randomness_indicators: Vec<String>,
}

/// Suspicious entropy region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousEntropyRegion {
    pub start_offset: usize,
    pub end_offset: usize,
    pub entropy_value: f64,
    pub deviation_from_expected: f64,
    pub potential_indicators: Vec<String>,
}

/// Suspicious pattern detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_id: String,
    pub pattern_type: String,
    pub matches: u32,
    pub locations: Vec<usize>,
    pub confidence: f64,
    pub risk_level: SecurityLevel,
}

/// Pattern database for threat detection
#[derive(Debug, Clone)]
pub struct PatternDatabase {
    malware_signatures: HashMap<String, Vec<u8>>,
    suspicious_strings: HashSet<String>,
    steganography_patterns: Vec<SteganographyPattern>,
}

/// Steganography pattern definition
#[derive(Debug, Clone)]
pub struct SteganographyPattern {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
    pub confidence_weight: f64,
}

impl DeepScanner {
    /// Create new deep scanner
    pub fn new(config: Config) -> Self {
        Self {
            steganography_threshold: match config.security_level() {
                SecurityLevel::Low => 0.8,
                SecurityLevel::Medium => 0.6,
                SecurityLevel::High => 0.4,
                SecurityLevel::Critical => 0.3,
                SecurityLevel::Maximum => 0.2,
            },
            entropy_threshold: match config.security_level() {
                SecurityLevel::Low => 7.5,
                SecurityLevel::Medium => 7.0,
                SecurityLevel::High => 6.5,
                SecurityLevel::Critical => 6.0,
                SecurityLevel::Maximum => 5.5,
            },
            pattern_database: PatternDatabase::new(),
            config,
        }
    }

    /// Perform deep scan of document
    #[instrument(skip(self, document))]
    pub async fn scan(&self, document: &Document) -> Result<DeepScanResult> {
        let start_time = Instant::now();
        
        info!("Starting deep scan for document: {}", document.id);

        // Detect hidden content
        let hidden_content = self.detect_hidden_content(document).await?;
        
        // Detect steganography
        let steganography_indicators = self.detect_steganography(&document.raw_data)?;
        
        // Perform entropy analysis
        let entropy_analysis = self.analyze_entropy(&document.raw_data)?;
        
        // Detect suspicious patterns
        let suspicious_patterns = self.detect_suspicious_patterns(&document.raw_data)?;

        let scan_duration = start_time.elapsed();
        
        // Calculate security score
        let security_score = self.calculate_security_score(
            &hidden_content,
            &steganography_indicators,
            &entropy_analysis,
            &suspicious_patterns,
        );

        // Count total threats
        let threats_detected = hidden_content.len() as u32 + 
                              steganography_indicators.len() as u32 + 
                              suspicious_patterns.len() as u32;

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &hidden_content,
            &steganography_indicators,
            &entropy_analysis,
            &suspicious_patterns,
        );

        info!("Deep scan completed. {} threats detected, security score: {:.2}", 
              threats_detected, security_score);

        Ok(DeepScanResult {
            security_score,
            threats_detected,
            hidden_content,
            steganography_indicators,
            entropy_analysis,
            suspicious_patterns,
            recommendations,
            scan_duration,
        })
    }

    /// Detect hidden content in document
    pub async fn detect_hidden_content(&self, document: &Document) -> Result<Vec<HiddenContent>> {
        let mut hidden_content = Vec::new();

        // Check for embedded JavaScript
        if let Some(js_content) = self.detect_javascript(document)? {
            hidden_content.push(js_content);
        }

        // Check for embedded Flash content
        if let Some(flash_content) = self.detect_flash_content(document)? {
            hidden_content.push(flash_content);
        }

        // Check for hidden text layers
        if let Some(hidden_text) = self.detect_hidden_text(document)? {
            hidden_content.push(hidden_text);
        }

        // Check for invisible annotations
        if let Some(invisible_annotations) = self.detect_invisible_annotations(document)? {
            hidden_content.push(invisible_annotations);
        }

        Ok(hidden_content)
    }

    /// Detect JavaScript content
    fn detect_javascript(&self, document: &Document) -> Result<Option<HiddenContent>> {
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                if dict.get("S").map(|v| v.as_name()) == Some(Some("JavaScript")) {
                    return Ok(Some(HiddenContent {
                        content_type: "JavaScript".to_string(),
                        location: format!("Object {}", obj_id),
                        size_bytes: 0, // Calculate from actual content
                        confidence: 0.9,
                        risk_level: SecurityLevel::High,
                        description: "Embedded JavaScript detected".to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Detect Flash content
    fn detect_flash_content(&self, document: &Document) -> Result<Option<HiddenContent>> {
        let flash_signatures = [b"CWS", b"FWS", b"ZWS"]; // Flash file signatures
        
        for signature in &flash_signatures {
            if document.raw_data.windows(signature.len()).any(|window| window == *signature) {
                return Ok(Some(HiddenContent {
                    content_type: "Flash".to_string(),
                    location: "Embedded in document".to_string(),
                    size_bytes: 0,
                    confidence: 0.8,
                    risk_level: SecurityLevel::High,
                    description: "Embedded Flash content detected".to_string(),
                }));
            }
        }
        Ok(None)
    }

    /// Detect hidden text
    fn detect_hidden_text(&self, document: &Document) -> Result<Option<HiddenContent>> {
        // Look for text with zero font size or invisible colors
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Font")) {
                    // Check for zero-sized fonts
                    if let Some(size) = dict.get("FontSize") {
                        if size.as_f64() == Some(0.0) {
                            return Ok(Some(HiddenContent {
                                content_type: "HiddenText".to_string(),
                                location: format!("Object {}", obj_id),
                                size_bytes: 0,
                                confidence: 0.7,
                                risk_level: SecurityLevel::Medium,
                                description: "Hidden text with zero font size".to_string(),
                            }));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Detect invisible annotations
    fn detect_invisible_annotations(&self, document: &Document) -> Result<Option<HiddenContent>> {
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Annot")) {
                    // Check for invisible annotations
                    if let Some(flags) = dict.get("F") {
                        if let Some(flag_value) = flags.as_i64() {
                            if flag_value & 0x02 != 0 { // Invisible flag
                                return Ok(Some(HiddenContent {
                                    content_type: "InvisibleAnnotation".to_string(),
                                    location: format!("Object {}", obj_id),
                                    size_bytes: 0,
                                    confidence: 0.8,
                                    risk_level: SecurityLevel::Medium,
                                    description: "Invisible annotation detected".to_string(),
                                }));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Detect steganography indicators
    pub fn detect_steganography(&self, data: &[u8]) -> Result<Vec<SteganographyIndicator>> {
        let mut indicators = Vec::new();

        // LSB analysis
        let lsb_indicator = self.analyze_lsb_patterns(data)?;
        if lsb_indicator.confidence > self.steganography_threshold {
            indicators.push(lsb_indicator);
        }

        // DCT coefficient analysis for JPEG images
        let dct_indicator = self.analyze_dct_coefficients(data)?;
        if dct_indicator.confidence > self.steganography_threshold {
            indicators.push(dct_indicator);
        }

        // Statistical analysis
        let statistical_indicator = self.analyze_statistical_properties(data)?;
        if statistical_indicator.confidence > self.steganography_threshold {
            indicators.push(statistical_indicator);
        }

        Ok(indicators)
    }

    /// Analyze LSB patterns for steganography
    fn analyze_lsb_patterns(&self, data: &[u8]) -> Result<SteganographyIndicator> {
        let mut lsb_distribution = [0u32; 2];
        
        for &byte in data {
            lsb_distribution[(byte & 1) as usize] += 1;
        }

        let total = lsb_distribution[0] + lsb_distribution[1];
        let ratio = if total > 0 {
            (lsb_distribution[0] as f64) / (total as f64)
        } else {
            0.5
        };

        // Deviation from expected 50% distribution indicates potential steganography
        let deviation = (ratio - 0.5).abs();
        let confidence = if deviation > 0.1 { deviation * 2.0 } else { 0.0 };

        Ok(SteganographyIndicator {
            indicator_type: "LSB Analysis".to_string(),
            confidence,
            location: "Global".to_string(),
            analysis_method: "Least Significant Bit distribution analysis".to_string(),
            risk_assessment: if confidence > 0.5 {
                "High probability of LSB steganography".to_string()
            } else {
                "Low probability of LSB steganography".to_string()
            },
        })
    }

    /// Analyze DCT coefficients
    fn analyze_dct_coefficients(&self, data: &[u8]) -> Result<SteganographyIndicator> {
        // Look for JPEG markers
        let mut jpeg_found = false;
        for window in data.windows(2) {
            if window == [0xFF, 0xD8] { // JPEG SOI marker
                jpeg_found = true;
                break;
            }
        }

        let confidence = if jpeg_found {
            // Simplified DCT analysis - in real implementation would use proper DCT
            let mut suspicious_coefficients = 0;
            for window in data.windows(8) {
                if window.iter().all(|&b| b % 2 == 0) || window.iter().all(|&b| b % 2 == 1) {
                    suspicious_coefficients += 1;
                }
            }
            (suspicious_coefficients as f64) / (data.len() / 8) as f64
        } else {
            0.0
        };

        Ok(SteganographyIndicator {
            indicator_type: "DCT Analysis".to_string(),
            confidence,
            location: "JPEG streams".to_string(),
            analysis_method: "DCT coefficient pattern analysis".to_string(),
            risk_assessment: if confidence > 0.3 {
                "Potential DCT-based steganography".to_string()
            } else {
                "No DCT steganography detected".to_string()
            },
        })
    }

    /// Analyze statistical properties
    fn analyze_statistical_properties(&self, data: &[u8]) -> Result<SteganographyIndicator> {
        let entropy = calculate_entropy(data);
        let expected_entropy = 7.0; // Expected entropy for random data
        
        let confidence = if entropy > expected_entropy {
            (entropy - expected_entropy) / (8.0 - expected_entropy)
        } else {
            0.0
        };

        Ok(SteganographyIndicator {
            indicator_type: "Statistical Analysis".to_string(),
            confidence,
            location: "Global".to_string(),
            analysis_method: "Entropy and statistical distribution analysis".to_string(),
            risk_assessment: if confidence > 0.4 {
                "High entropy suggests possible data hiding".to_string()
            } else {
                "Normal statistical properties".to_string()
            },
        })
    }

    /// Analyze entropy of data
    pub fn analyze_entropy(&self, data: &[u8]) -> Result<EntropyAnalysis> {
        let overall_entropy = calculate_entropy(data);
        let mut entropy_distribution = HashMap::new();
        let mut suspicious_regions = Vec::new();

        // Analyze entropy in chunks
        let chunk_size = 1024;
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let chunk_entropy = calculate_entropy(chunk);
            entropy_distribution.insert(format!("chunk_{}", i), chunk_entropy);

            // Check for suspicious entropy levels
            if chunk_entropy > self.entropy_threshold {
                suspicious_regions.push(SuspiciousEntropyRegion {
                    start_offset: i * chunk_size,
                    end_offset: (i + 1) * chunk_size.min(data.len()),
                    entropy_value: chunk_entropy,
                    deviation_from_expected: chunk_entropy - 6.0, // Expected baseline
                    potential_indicators: vec![
                        if chunk_entropy > 7.5 { "Encrypted data" } else { "Compressed data" }.to_string()
                    ],
                });
            }
        }

        let randomness_indicators = if overall_entropy > 7.5 {
            vec!["High randomness detected".to_string(), "Possible encryption".to_string()]
        } else if overall_entropy > 6.5 {
            vec!["Moderate randomness".to_string(), "Possible compression".to_string()]
        } else {
            vec!["Low randomness".to_string(), "Structured data".to_string()]
        };

        Ok(EntropyAnalysis {
            overall_entropy,
            entropy_distribution,
            suspicious_regions,
            randomness_indicators,
        })
    }

    /// Detect suspicious patterns
    pub fn detect_suspicious_patterns(&self, data: &[u8]) -> Result<Vec<SuspiciousPattern>> {
        let mut patterns = Vec::new();

        // Check for malware signatures
        for (sig_name, signature) in &self.pattern_database.malware_signatures {
            let matches = self.find_pattern_matches(data, signature);
            if !matches.is_empty() {
                patterns.push(SuspiciousPattern {
                    pattern_id: sig_name.clone(),
                    pattern_type: "Malware Signature".to_string(),
                    matches: matches.len() as u32,
                    locations: matches,
                    confidence: 0.9,
                    risk_level: SecurityLevel::Critical,
                });
            }
        }

        // Check for suspicious strings
        for suspicious_string in &self.pattern_database.suspicious_strings {
            let matches = self.find_string_matches(data, suspicious_string.as_bytes());
            if !matches.is_empty() {
                patterns.push(SuspiciousPattern {
                    pattern_id: suspicious_string.clone(),
                    pattern_type: "Suspicious String".to_string(),
                    matches: matches.len() as u32,
                    locations: matches,
                    confidence: 0.7,
                    risk_level: SecurityLevel::High,
                });
            }
        }

        Ok(patterns)
    }

    /// Find pattern matches in data
    fn find_pattern_matches(&self, data: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        for (i, window) in data.windows(pattern.len()).enumerate() {
            if window == pattern {
                matches.push(i);
            }
        }
        matches
    }

    /// Find string matches in data
    fn find_string_matches(&self, data: &[u8], pattern: &[u8]) -> Vec<usize> {
        self.find_pattern_matches(data, pattern)
    }

    /// Calculate security score based on scan results
    fn calculate_security_score(
        &self,
        hidden_content: &[HiddenContent],
        steganography_indicators: &[SteganographyIndicator],
        entropy_analysis: &EntropyAnalysis,
        suspicious_patterns: &[SuspiciousPattern],
    ) -> f64 {
        let mut score = 1.0;

        // Reduce score for hidden content
        for content in hidden_content {
            score -= match content.risk_level {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.3,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for steganography indicators
        for indicator in steganography_indicators {
            score -= indicator.confidence * 0.2;
        }

        // Reduce score for high entropy
        if entropy_analysis.overall_entropy > self.entropy_threshold {
            score -= (entropy_analysis.overall_entropy - self.entropy_threshold) * 0.1;
        }

        // Reduce score for suspicious patterns
        for pattern in suspicious_patterns {
            score -= match pattern.risk_level {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.4,
                SecurityLevel::High => 0.3,
                SecurityLevel::Medium => 0.2,
                SecurityLevel::Low => 0.1,
            };
        }

        score.max(0.0).min(1.0)
    }

    /// Generate recommendations based on scan results
    fn generate_recommendations(
        &self,
        hidden_content: &[HiddenContent],
        steganography_indicators: &[SteganographyIndicator],
        entropy_analysis: &EntropyAnalysis,
        suspicious_patterns: &[SuspiciousPattern],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !hidden_content.is_empty() {
            recommendations.push("Remove or sanitize hidden content".to_string());
        }

        if !steganography_indicators.is_empty() {
            recommendations.push("Investigate potential steganography".to_string());
        }

        if entropy_analysis.overall_entropy > 7.5 {
            recommendations.push("High entropy detected - check for encryption or compression".to_string());
        }

        if !suspicious_patterns.is_empty() {
            recommendations.push("ALERT: Malware patterns detected - quarantine immediately".to_string());
        }

        recommendations
    }
}

impl PatternDatabase {
    /// Create new pattern database
    pub fn new() -> Self {
        let mut malware_signatures = HashMap::new();
        malware_signatures.insert("test_signature".to_string(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        
        let mut suspicious_strings = HashSet::new();
        suspicious_strings.insert("eval(".to_string());
        suspicious_strings.insert("document.write".to_string());
        suspicious_strings.insert("javascript:".to_string());
        
        Self {
            malware_signatures,
            suspicious_strings,
            steganography_patterns: Vec::new(),
        }
    }
}
```

### File 3: `src/scanner/content_scanner.rs` (120 lines)
```rust
//! Content Scanner Module
//! 
//! Provides content-specific scanning for JavaScript, embedded files,
//! and other potentially dangerous content within PDF documents.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};

use crate::{
    types::{Document, ObjectId, PdfObject, SecurityLevel},
    error::{Result, PdfError},
    config::Config,
};

/// Content scanner for analyzing PDF content
#[derive(Debug, Clone)]
pub struct ContentScanner {
    config: Config,
    threat_patterns: ThreatPatternDatabase,
    max_scan_depth: usize,
}

/// Results from content scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentScanResult {
    pub security_score: f64,
    pub threats_detected: u32,
    pub javascript_threats: Vec<JavaScriptThreat>,
    pub embedded_files: Vec<EmbeddedFile>,
    pub form_threats: Vec<FormThreat>,
    pub action_threats: Vec<ActionThreat>,
    pub recommendations: Vec<String>,
    pub scan_duration: Duration,
}

/// JavaScript threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptThreat {
    pub threat_id: String,
    pub threat_type: String,
    pub location: String,
    pub severity: SecurityLevel,
    pub code_snippet: String,
    pub analysis: String,
    pub mitigation: String,
}

/// Embedded file detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFile {
    pub file_name: String,
    pub file_type: String,
    pub file_size: usize,
    pub risk_level: SecurityLevel,
    pub analysis: String,
}

/// Form-based threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormThreat {
    pub form_id: String,
    pub threat_type: String,
    pub severity: SecurityLevel,
    pub description: String,
}

/// Action-based threat (launch, URI, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionThreat {
    pub action_type: String,
    pub target: String,
    pub severity: SecurityLevel,
    pub description: String,
}

/// Threat pattern database
#[derive(Debug, Clone)]
pub struct ThreatPatternDatabase {
    javascript_patterns: HashMap<String, ThreatPattern>,
    dangerous_actions: HashSet<String>,
    suspicious_extensions: HashSet<String>,
}

/// Individual threat pattern
#[derive(Debug, Clone)]
pub struct ThreatPattern {
    pub pattern: String,
    pub threat_type: String,
    pub severity: SecurityLevel,
    pub description: String,
}

impl ContentScanner {
    /// Create new content scanner
    pub fn new(config: Config) -> Self {
        Self {
            max_scan_depth: match config.security_level() {
                SecurityLevel::Low => 3,
                SecurityLevel::Medium => 5,
                SecurityLevel::High => 10,
                SecurityLevel::Critical => 15,
                SecurityLevel::Maximum => 20,
            },
            threat_patterns: ThreatPatternDatabase::new(),
            config,
        }
    }

    /// Perform content scan
    #[instrument(skip(self, document))]
    pub async fn scan(&self, document: &Document) -> Result<ContentScanResult> {
        let start_time = Instant::now();
        
        info!("Starting content scan for document: {}", document.id);

        // Scan for JavaScript threats
        let javascript_threats = self.scan_javascript(document).await?;
        
        // Scan for embedded files
        let embedded_files = self.scan_embedded_files(document).await?;
        
        // Scan for form threats
        let form_threats = self.scan_forms(document).await?;
        
        // Scan for action threats
        let action_threats = self.scan_actions(document).await?;

        let scan_duration = start_time.elapsed();
        
        // Calculate security score
        let security_score = self.calculate_security_score(
            &javascript_threats,
            &embedded_files,
            &form_threats,
            &action_threats,
        );

        // Count total threats
        let threats_detected = javascript_threats.len() as u32 + 
                              embedded_files.iter().filter(|f| f.risk_level != SecurityLevel::Low).count() as u32 +
                              form_threats.len() as u32 + 
                              action_threats.len() as u32;

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &javascript_threats,
            &embedded_files,
            &form_threats,
            &action_threats,
        );

        info!("Content scan completed. {} threats detected, security score: {:.2}", 
              threats_detected, security_score);

        Ok(ContentScanResult {
            security_score,
            threats_detected,
            javascript_threats,
            embedded_files,
            form_threats,
            action_threats,
            recommendations,
            scan_duration,
        })
    }

    /// Scan for JavaScript threats
    async fn scan_javascript(&self, document: &Document) -> Result<Vec<JavaScriptThreat>> {
        let mut threats = Vec::new();

        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check for JavaScript actions
                if let Some(js_action) = dict.get("JS") {
                    let js_code = self.extract_javascript_code(js_action)?;
                    
                    // Analyze JavaScript code for threats
                    for (pattern_name, pattern) in &self.threat_patterns.javascript_patterns {
                        if js_code.contains(&pattern.pattern) {
                            threats.push(JavaScriptThreat {
                                threat_id: format!("js_{}_{}", obj_id, pattern_name),
                                threat_type: pattern.threat_type.clone(),
                                location: format!("Object {}", obj_id),
                                severity: pattern.severity,
                                code_snippet: self.extract_code_snippet(&js_code, &pattern.pattern),
                                analysis: pattern.description.clone(),
                                mitigation: self.suggest_javascript_mitigation(&pattern.threat_type),
                            });
                        }
                    }
                }
            }
        }

        Ok(threats)
    }

    /// Extract JavaScript code from PDF object
    fn extract_javascript_code(&self, js_object: &PdfObject) -> Result<String> {
        match js_object {
            PdfObject::String(s) => Ok(s.clone()),
            PdfObject::Stream(stream) => {
                // Decode stream data
                String::from_utf8(stream.data.clone())
                    .map_err(|e| PdfError::ParseError(format!("Invalid UTF-8 in JavaScript: {}", e)))
            }
            _ => Ok(String::new()),
        }
    }

    /// Extract code snippet around pattern match
    fn extract_code_snippet(&self, code: &str, pattern: &str) -> String {
        if let Some(pos) = code.find(pattern) {
            let start = pos.saturating_sub(50);
            let end = (pos + pattern.len() + 50).min(code.len());
            code[start..end].to_string()
        } else {
            pattern.to_string()
        }
    }

    /// Suggest JavaScript mitigation
    fn suggest_javascript_mitigation(&self, threat_type: &str) -> String {
        match threat_type {
            "eval" => "Remove or sanitize dynamic code execution".to_string(),
            "document.write" => "Replace with safe DOM manipulation".to_string(),
            "XMLHttpRequest" => "Remove or validate external requests".to_string(),
            "ActiveXObject" => "Remove ActiveX instantiation".to_string(),
            _ => "Review and sanitize JavaScript code".to_string(),
        }
    }

    /// Scan for embedded files
    async fn scan_embedded_files(&self, document: &Document) -> Result<Vec<EmbeddedFile>> {
        let mut embedded_files = Vec::new();

        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check for file specifications
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Filespec")) {
                    if let Some(filename) = dict.get("F").and_then(|f| f.as_string()) {
                        let file_type = self.determine_file_type(&filename);
                        let risk_level = self.assess_file_risk(&file_type);
                        
                        embedded_files.push(EmbeddedFile {
                            file_name: filename.clone(),
                            file_type,
                            file_size: 0, // Would need to calculate from stream
                            risk_level,
                            analysis: self.analyze_embedded_file(&filename),
                        });
                    }
                }

                // Check for embedded file streams
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("EmbeddedFile")) {
                    embedded_files.push(EmbeddedFile {
                        file_name: format!("embedded_file_{}", obj_id),
                        file_type: "unknown".to_string(),
                        file_size: 0,
                        risk_level: SecurityLevel::Medium,
                        analysis: "Embedded file stream detected".to_string(),
                    });
                }
            }
        }

        Ok(embedded_files)
    }

    /// Determine file type from filename
    fn determine_file_type(&self, filename: &str) -> String {
        if let Some(extension) = filename.split('.').last() {
            extension.to_lowercase()
        } else {
            "unknown".to_string()
        }
    }

    /// Assess risk level of file type
    fn assess_file_risk(&self, file_type: &str) -> SecurityLevel {
        if self.threat_patterns.suspicious_extensions.contains(file_type) {
            SecurityLevel::High
        } else {
            match file_type {
                "exe" | "scr" | "bat" | "cmd" | "com" | "pif" => SecurityLevel::Critical,
                "js" | "vbs" | "ps1" | "jar" => SecurityLevel::High,
                "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => SecurityLevel::Medium,
                "txt" | "csv" | "jpg" | "png" | "gif" => SecurityLevel::Low,
                _ => SecurityLevel::Medium,
            }
        }
    }

    /// Analyze embedded file
    fn analyze_embedded_file(&self, filename: &str) -> String {
        let file_type = self.determine_file_type(filename);
        match self.assess_file_risk(&file_type) {
            SecurityLevel::Critical => format!("CRITICAL: {} files are executable and dangerous", file_type),
            SecurityLevel::High => format!("HIGH RISK: {} files may contain malicious code", file_type),
            SecurityLevel::Medium => format!("MEDIUM RISK: {} files should be scanned", file_type),
            SecurityLevel::Low => format!("LOW RISK: {} files are generally safe", file_type),
            SecurityLevel::Maximum => format!("MAXIMUM RISK: {} files pose extreme danger", file_type),
        }
    }

    /// Scan for form threats
    async fn scan_forms(&self, document: &Document) -> Result<Vec<FormThreat>> {
        let mut form_threats = Vec::new();

        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check for form fields
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Annot")) &&
                   dict.get("Subtype").map(|v| v.as_name()) == Some(Some("Widget")) {
                    
                    // Check for auto-submit actions
                    if let Some(action) = dict.get("A") {
                        if let PdfObject::Dictionary(action_dict) = action {
                            if action_dict.get("S").map(|v| v.as_name()) == Some(Some("SubmitForm")) {
                                form_threats.push(FormThreat {
                                    form_id: format!("form_{}", obj_id),
                                    threat_type: "Auto-submit".to_string(),
                                    severity: SecurityLevel::High,
                                    description: "Form with auto-submit action detected".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(form_threats)
    }

    /// Scan for action threats
    async fn scan_actions(&self, document: &Document) -> Result<Vec<ActionThreat>> {
        let mut action_threats = Vec::new();

        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check for actions
                if let Some(action) = dict.get("A") {
                    if let PdfObject::Dictionary(action_dict) = action {
                        if let Some(action_type) = action_dict.get("S").and_then(|s| s.as_name()) {
                            if self.threat_patterns.dangerous_actions.contains(action_type) {
                                let target = action_dict.get("F")
                                    .and_then(|f| f.as_string())
                                    .unwrap_or_else(|| "unknown".to_string());

                                action_threats.push(ActionThreat {
                                    action_type: action_type.to_string(),
                                    target,
                                    severity: self.assess_action_severity(action_type),
                                    description: self.describe_action_threat(action_type),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(action_threats)
    }

    /// Assess action severity
    fn assess_action_severity(&self, action_type: &str) -> SecurityLevel {
        match action_type {
            "Launch" => SecurityLevel::Critical,
            "URI" => SecurityLevel::High,
            "GoToR" => SecurityLevel::Medium,
            "SubmitForm" => SecurityLevel::High,
            _ => SecurityLevel::Medium,
        }
    }

    /// Describe action threat
    fn describe_action_threat(&self, action_type: &str) -> String {
        match action_type {
            "Launch" => "Action can launch external applications".to_string(),
            "URI" => "Action can open external URLs".to_string(),
            "GoToR" => "Action can open remote documents".to_string(),
            "SubmitForm" => "Action can submit form data externally".to_string(),
            _ => format!("Potentially dangerous {} action", action_type),
        }
    }

    /// Calculate security score
    fn calculate_security_score(
        &self,
        javascript_threats: &[JavaScriptThreat],
        embedded_files: &[EmbeddedFile],
        form_threats: &[FormThreat],
        action_threats: &[ActionThreat],
    ) -> f64 {
        let mut score = 1.0;

        // Reduce score for JavaScript threats
        for threat in javascript_threats {
            score -= match threat.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.3,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for high-risk embedded files
        for file in embedded_files {
            score -= match file.risk_level {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.25,
                SecurityLevel::High => 0.15,
                SecurityLevel::Medium => 0.05,
                SecurityLevel::Low => 0.01,
            };
        }

        // Reduce score for form threats
        for threat in form_threats {
            score -= match threat.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.2,
                SecurityLevel::High => 0.15,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for action threats
        for threat in action_threats {
            score -= match threat.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.25,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        score.max(0.0).min(1.0)
    }

    /// Generate recommendations
    fn generate_recommendations(
        &self,
        javascript_threats: &[JavaScriptThreat],
        embedded_files: &[EmbeddedFile],
        form_threats: &[FormThreat],
        action_threats: &[ActionThreat],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !javascript_threats.is_empty() {
            recommendations.push("Remove or sanitize JavaScript content".to_string());
        }

        let high_risk_files = embedded_files.iter()
            .filter(|f| matches!(f.risk_level, SecurityLevel::High | SecurityLevel::Critical | SecurityLevel::Maximum))
            .count();
        
        if high_risk_files > 0 {
            recommendations.push("Remove high-risk embedded files".to_string());
        }

        if !form_threats.is_empty() {
            recommendations.push("Review and secure form actions".to_string());
        }

        if !action_threats.is_empty() {
            recommendations.push("Remove or validate dangerous actions".to_string());
        }

        recommendations
    }
}

impl ThreatPatternDatabase {
    /// Create new threat pattern database
    pub fn new() -> Self {
        let mut javascript_patterns = HashMap::new();
        
        javascript_patterns.insert("eval".to_string(), ThreatPattern {
            pattern: "eval(".to_string(),
            threat_type: "eval".to_string(),
            severity: SecurityLevel::Critical,
            description: "Dynamic code execution via eval()".to_string(),
        });
        
        javascript_patterns.insert("document_write".to_string(), ThreatPattern {
            pattern: "document.write".to_string(),
            threat_type: "document.write".to_string(),
            severity: SecurityLevel::High,
            description: "Dynamic content injection".to_string(),
        });

        let mut dangerous_actions = HashSet::new();
        dangerous_actions.insert("Launch".to_string());
        dangerous_actions.insert("URI".to_string());
        dangerous_actions.insert("SubmitForm".to_string());
        dangerous_actions.insert("GoToR".to_string());

        let mut suspicious_extensions = HashSet::new();
        suspicious_extensions.insert("exe".to_string());
        suspicious_extensions.insert("scr".to_string());
        suspicious_extensions.insert("bat".to_string());
        suspicious_extensions.insert("cmd".to_string());

        Self {
            javascript_patterns,
            dangerous_actions,
            suspicious_extensions,
        }
    }
}
```

### File 4: `src/scanner/pdf_scanner.rs` (100 lines)
```rust
//! PDF Scanner Module
//! 
//! Provides PDF-specific scanning for structure validation,
//! version compatibility, and PDF-specific threats.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};

use crate::{
    types::{Document, ObjectId, PdfObject, SecurityLevel},
    error::{Result, PdfError},
    config::Config,
};

/// PDF-specific scanner
#[derive(Debug, Clone)]
pub struct PdfScanner {
    config: Config,
    min_supported_version: f32,
    max_supported_version: f32,
}

/// Results from PDF scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfScanResult {
    pub security_score: f64,
    pub pdf_version: String,
    pub version_threats: Vec<VersionThreat>,
    pub structure_issues: Vec<StructureIssue>,
    pub compatibility_issues: Vec<CompatibilityIssue>,
    pub recommendations: Vec<String>,
    pub scan_duration: Duration,
    pub is_valid_pdf: bool,
    pub encryption_status: EncryptionStatus,
}

/// PDF version-related threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionThreat {
    pub threat_type: String,
    pub version: String,
    pub severity: SecurityLevel,
    pub description: String,
}

/// PDF structure issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureIssue {
    pub issue_type: String,
    pub location: String,
    pub severity: SecurityLevel,
    pub description: String,
    pub impact: String,
}

/// Compatibility issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    pub issue_type: String,
    pub severity: SecurityLevel,
    pub description: String,
    pub recommendation: String,
}

/// PDF encryption status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStatus {
    pub is_encrypted: bool,
    pub encryption_type: String,
    pub security_level: SecurityLevel,
    pub permissions: Vec<String>,
}

impl PdfScanner {
    /// Create new PDF scanner
    pub fn new(config: Config) -> Self {
        Self {
            min_supported_version: 1.0,
            max_supported_version: 2.0,
            config,
        }
    }

    /// Perform PDF-specific scan
    #[instrument(skip(self, document))]
    pub async fn scan(&self, document: &Document) -> Result<PdfScanResult> {
        let start_time = Instant::now();
        
        info!("Starting PDF scan for document: {}", document.id);

        // Check PDF version
        let pdf_version = self.extract_pdf_version(document)?;
        let version_threats = self.analyze_version_threats(&pdf_version)?;
        
        // Check PDF structure
        let structure_issues = self.analyze_structure(document)?;
        
        // Check compatibility
        let compatibility_issues = self.analyze_compatibility(document, &pdf_version)?;
        
        // Check encryption
        let encryption_status = self.analyze_encryption(document)?;
        
        // Validate PDF format
        let is_valid_pdf = self.validate_pdf_format(document)?;

        let scan_duration = start_time.elapsed();
        
        // Calculate security score
        let security_score = self.calculate_security_score(
            &version_threats,
            &structure_issues,
            &compatibility_issues,
            &encryption_status,
            is_valid_pdf,
        );

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &version_threats,
            &structure_issues,
            &compatibility_issues,
            &encryption_status,
            is_valid_pdf,
        );

        info!("PDF scan completed. Version: {}, Valid: {}, Security score: {:.2}", 
              pdf_version, is_valid_pdf, security_score);

        Ok(PdfScanResult {
            security_score,
            pdf_version,
            version_threats,
            structure_issues,
            compatibility_issues,
            recommendations,
            scan_duration,
            is_valid_pdf,
            encryption_status,
        })
    }

    /// Extract PDF version from document
    fn extract_pdf_version(&self, document: &Document) -> Result<String> {
        // Look for PDF version in header
        if document.raw_data.starts_with(b"%PDF-") {
            if let Some(version_line) = document.raw_data.get(0..10) {
                if let Ok(version_str) = std::str::from_utf8(version_line) {
                    if let Some(version) = version_str.strip_prefix("%PDF-") {
                        return Ok(version.to_string());
                    }
                }
            }
        }
        
        Ok("Unknown".to_string())
    }

    /// Analyze version-related threats
    fn analyze_version_threats(&self, version: &str) -> Result<Vec<VersionThreat>> {
        let mut threats = Vec::new();

        if let Ok(version_num) = version.parse::<f32>() {
            if version_num < self.min_supported_version {
                threats.push(VersionThreat {
                    threat_type: "Unsupported Version".to_string(),
                    version: version.to_string(),
                    severity: SecurityLevel::High,
                    description: "PDF version is too old and may have security vulnerabilities".to_string(),
                });
            } else if version_num > self.max_supported_version {
                threats.push(VersionThreat {
                    threat_type: "Unknown Version".to_string(),
                    version: version.to_string(),
                    severity: SecurityLevel::Medium,
                    description: "PDF version is newer than supported versions".to_string(),
                });
            }
        } else {
            threats.push(VersionThreat {
                threat_type: "Invalid Version".to_string(),
                version: version.to_string(),
                severity: SecurityLevel::High,
                description: "PDF version string is malformed".to_string(),
            });
        }

        Ok(threats)
    }

    /// Analyze PDF structure
    fn analyze_structure(&self, document: &Document) -> Result<Vec<StructureIssue>> {
        let mut issues = Vec::new();

        // Check for missing catalog
        if document.catalog.is_none() {
            issues.push(StructureIssue {
                issue_type: "Missing Catalog".to_string(),
                location: "Document root".to_string(),
                severity: SecurityLevel::Critical,
                description: "PDF document lacks required catalog object".to_string(),
                impact: "Document may not render correctly or may be malformed".to_string(),
            });
        }

        // Check for excessive object count
        if document.objects.len() > 100000 {
            issues.push(StructureIssue {
                issue_type: "Excessive Objects".to_string(),
                location: "Document structure".to_string(),
                severity: SecurityLevel::Medium,
                description: "PDF contains unusually large number of objects".to_string(),
                impact: "May indicate document bloat or potential DoS attack".to_string(),
            });
        }

        // Check for circular references
        if self.detect_circular_references(document)? {
            issues.push(StructureIssue {
                issue_type: "Circular References".to_string(),
                location: "Object references".to_string(),
                severity: SecurityLevel::High,
                description: "PDF contains circular object references".to_string(),
                impact: "May cause infinite loops or processing failures".to_string(),
            });
        }

        Ok(issues)
    }

    /// Detect circular references in PDF structure
    fn detect_circular_references(&self, document: &Document) -> Result<bool> {
        // Simplified circular reference detection
        // In a full implementation, this would perform graph traversal
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                for value in dict.values() {
                    if let PdfObject::Reference(ref_id) = value {
                        if ref_id == obj_id {
                            return Ok(true); // Self-reference detected
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Analyze compatibility issues
    fn analyze_compatibility(&self, document: &Document, version: &str) -> Result<Vec<CompatibilityIssue>> {
        let mut issues = Vec::new();

        // Check for deprecated features
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check for deprecated filter types
                if let Some(filter) = dict.get("Filter") {
                    if let Some(filter_name) = filter.as_name() {
                        if filter_name == "LZWDecode" {
                            issues.push(CompatibilityIssue {
                                issue_type: "Deprecated Filter".to_string(),
                                severity: SecurityLevel::Medium,
                                description: "LZWDecode filter is deprecated and may not be supported".to_string(),
                                recommendation: "Replace with FlateDecode filter".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(issues)
    }

    /// Analyze encryption status
    fn analyze_encryption(&self, document: &Document) -> Result<EncryptionStatus> {
        // Check for encryption dictionary
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Encrypt")) {
                    let encryption_type = dict.get("Filter")
                        .and_then(|f| f.as_name())
                        .unwrap_or("Unknown")
                        .to_string();

                    let security_level = match encryption_type.as_str() {
                        "Standard" => SecurityLevel::Medium,
                        "V2" => SecurityLevel::Low,
                        "AESV2" | "AESV3" => SecurityLevel::High,
                        _ => SecurityLevel::Low,
                    };

                    // Extract permissions
                    let permissions = self.extract_permissions(dict);

                    return Ok(EncryptionStatus {
                        is_encrypted: true,
                        encryption_type,
                        security_level,
                        permissions,
                    });
                }
            }
        }

        Ok(EncryptionStatus {
            is_encrypted: false,
            encryption_type: "None".to_string(),
            security_level: SecurityLevel::Low,
            permissions: Vec::new(),
        })
    }

    /// Extract permissions from encryption dictionary
    fn extract_permissions(&self, encrypt_dict: &HashMap<String, PdfObject>) -> Vec<String> {
        let mut permissions = Vec::new();

        if let Some(p_value) = encrypt_dict.get("P").and_then(|p| p.as_i64()) {
            if p_value & 0x04 != 0 { permissions.push("Print".to_string()); }
            if p_value & 0x08 != 0 { permissions.push("Modify".to_string()); }
            if p_value & 0x10 != 0 { permissions.push("Copy".to_string()); }
            if p_value & 0x20 != 0 { permissions.push("Annotate".to_string()); }
        }

        permissions
    }

    /// Validate PDF format
    fn validate_pdf_format(&self, document: &Document) -> Result<bool> {
        // Check for PDF header
        if !document.raw_data.starts_with(b"%PDF-") {
            return Ok(false);
        }

        // Check for EOF marker
        if !document.raw_data.ends_with(b"%%EOF") && 
           !document.raw_data.windows(5).any(|w| w == b"%%EOF") {
            return Ok(false);
        }

        // Check for basic required objects
        if document.objects.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate security score
    fn calculate_security_score(
        &self,
        version_threats: &[VersionThreat],
        structure_issues: &[StructureIssue],
        compatibility_issues: &[CompatibilityIssue],
        encryption_status: &EncryptionStatus,
        is_valid_pdf: bool,
    ) -> f64 {
        let mut score = if is_valid_pdf { 1.0 } else { 0.0 };

        // Reduce score for version threats
        for threat in version_threats {
            score -= match threat.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.3,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for structure issues
        for issue in structure_issues {
            score -= match issue.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.4,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for compatibility issues
        for issue in compatibility_issues {
            score -= match issue.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.2,
                SecurityLevel::High => 0.15,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Adjust for encryption
        if encryption_status.is_encrypted {
            score += match encryption_status.security_level {
                SecurityLevel::High => 0.1,
                SecurityLevel::Medium => 0.05,
                _ => 0.0,
            };
        }

        score.max(0.0).min(1.0)
    }

    /// Generate recommendations
    fn generate_recommendations(
        &self,
        version_threats: &[VersionThreat],
        structure_issues: &[StructureIssue],
        compatibility_issues: &[CompatibilityIssue],
        encryption_status: &EncryptionStatus,
        is_valid_pdf: bool,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !is_valid_pdf {
            recommendations.push("CRITICAL: Document is not a valid PDF".to_string());
        }

        if !version_threats.is_empty() {
            recommendations.push("Update PDF to supported version".to_string());
        }

        if structure_issues.iter().any(|i| matches!(i.severity, SecurityLevel::Critical | SecurityLevel::Maximum)) {
            recommendations.push("Repair critical PDF structure issues".to_string());
        }

        if !compatibility_issues.is_empty() {
            recommendations.push("Address compatibility issues".to_string());
        }

        if !encryption_status.is_encrypted {
            recommendations.push("Consider encrypting PDF for security".to_string());
        }

        recommendations
    }

    /// Quick scan for rapid assessment
    pub fn quick_scan(&self, data: &[u8]) -> Result<bool> {
        // Basic PDF validation for quick assessment
        Ok(data.starts_with(b"%PDF-") && 
           (data.ends_with(b"%%EOF") || data.windows(5).any(|w| w == b"%%EOF")))
    }

    /// Check if scanner is initialized
    pub fn is_initialized(&self) -> bool {
        true
    }
}
```

### File 5: `src/scanner/metadata_scanner.rs` (90 lines)
```rust
//! Metadata Scanner Module
//! 
//! Provides scanning capabilities for PDF metadata including
//! document information, XMP metadata, and hidden metadata.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error, instrument};

use crate::{
    types::{Document, ObjectId, PdfObject, SecurityLevel},
    error::{Result, PdfError},
    config::Config,
};

/// Metadata scanner for PDF documents
#[derive(Debug, Clone)]
pub struct MetadataScanner {
    config: Config,
    sensitive_fields: Vec<String>,
}

/// Results from metadata scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataScanResult {
    pub security_score: f64,
    pub metadata_found: u32,
    pub document_info: Option<DocumentInfo>,
    pub xmp_metadata: Option<XmpMetadata>,
    pub privacy_issues: Vec<PrivacyIssue>,
    pub metadata_integrity: MetadataIntegrity,
    pub recommendations: Vec<String>,
    pub scan_duration: Duration,
}

/// Document information metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub keywords: Option<String>,
}

/// XMP metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmpMetadata {
    pub present: bool,
    pub size_bytes: usize,
    pub creator_tool: Option<String>,
    pub document_id: Option<String>,
    pub instance_id: Option<String>,
    pub metadata_date: Option<String>,
}

/// Privacy-related issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIssue {
    pub issue_type: String,
    pub field_name: String,
    pub severity: SecurityLevel,
    pub description: String,
    pub recommendation: String,
}

/// Metadata integrity assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataIntegrity {
    pub is_consistent: bool,
    pub inconsistencies: Vec<String>,
    pub tamper_indicators: Vec<String>,
    pub integrity_score: f64,
}

impl MetadataScanner {
    /// Create new metadata scanner
    pub fn new(config: Config) -> Self {
        Self {
            sensitive_fields: vec![
                "Author".to_string(),
                "Creator".to_string(),
                "Producer".to_string(),
                "CreationDate".to_string(),
                "ModDate".to_string(),
                "Title".to_string(),
                "Subject".to_string(),
                "Keywords".to_string(),
            ],
            config,
        }
    }

    /// Perform metadata scan
    #[instrument(skip(self, document))]
    pub async fn scan(&self, document: &Document) -> Result<MetadataScanResult> {
        let start_time = Instant::now();
        
        info!("Starting metadata scan for document: {}", document.id);

        // Extract document info
        let document_info = self.extract_document_info(document)?;
        
        // Extract XMP metadata
        let xmp_metadata = self.extract_xmp_metadata(document)?;
        
        // Identify privacy issues
        let privacy_issues = self.identify_privacy_issues(&document_info, &xmp_metadata)?;
        
        // Check metadata integrity
        let metadata_integrity = self.check_metadata_integrity(document, &document_info, &xmp_metadata)?;

        let scan_duration = start_time.elapsed();
        
        // Count metadata found
        let metadata_found = self.count_metadata_fields(&document_info, &xmp_metadata);
        
        // Calculate security score
        let security_score = self.calculate_security_score(
            &privacy_issues,
            &metadata_integrity,
            metadata_found,
        );

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &privacy_issues,
            &metadata_integrity,
            &document_info,
            &xmp_metadata,
        );

        info!("Metadata scan completed. {} fields found, {} privacy issues, security score: {:.2}", 
              metadata_found, privacy_issues.len(), security_score);

        Ok(MetadataScanResult {
            security_score,
            metadata_found,
            document_info,
            xmp_metadata,
            privacy_issues,
            metadata_integrity,
            recommendations,
            scan_duration,
        })
    }

    /// Extract document information dictionary
    fn extract_document_info(&self, document: &Document) -> Result<Option<DocumentInfo>> {
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                // Check if this looks like an Info dictionary
                if dict.contains_key("Title") || dict.contains_key("Author") || 
                   dict.contains_key("Creator") || dict.contains_key("Producer") {
                    return Ok(Some(DocumentInfo {
                        title: dict.get("Title").and_then(|v| v.as_string()),
                        author: dict.get("Author").and_then(|v| v.as_string()),
                        subject: dict.get("Subject").and_then(|v| v.as_string()),
                        creator: dict.get("Creator").and_then(|v| v.as_string()),
                        producer: dict.get("Producer").and_then(|v| v.as_string()),
                        creation_date: dict.get("CreationDate").and_then(|v| v.as_string()),
                        modification_date: dict.get("ModDate").and_then(|v| v.as_string()),
                        keywords: dict.get("Keywords").and_then(|v| v.as_string()),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Extract XMP metadata
    fn extract_xmp_metadata(&self, document: &Document) -> Result<Option<XmpMetadata>> {
        for (obj_id, obj) in &document.objects {
            if let PdfObject::Dictionary(dict) = obj {
                if dict.get("Type").map(|v| v.as_name()) == Some(Some("Metadata")) {
                    if let Some(PdfObject::Stream(stream)) = dict.get("Stream") {
                        let metadata_content = String::from_utf8_lossy(&stream.data);
                        
                        return Ok(Some(XmpMetadata {
                            present: true,
                            size_bytes: stream.data.len(),
                            creator_tool: self.extract_xmp_field(&metadata_content, "xmp:CreatorTool"),
                            document_id: self.extract_xmp_field(&metadata_content, "xmpMM:DocumentID"),
                            instance_id: self.extract_xmp_field(&metadata_content, "xmpMM:InstanceID"),
                            metadata_date: self.extract_xmp_field(&metadata_content, "xmp:MetadataDate"),
                        }));
                    }
                }
            }
        }
        
        Ok(Some(XmpMetadata {
            present: false,
            size_bytes: 0,
            creator_tool: None,
            document_id: None,
            instance_id: None,
            metadata_date: None,
        }))
    }

    /// Extract field from XMP metadata
    fn extract_xmp_field(&self, xmp_content: &str, field_name: &str) -> Option<String> {
        // Simplified XMP parsing - in real implementation would use proper XML parser
        if let Some(start) = xmp_content.find(&format!("{}=\"", field_name)) {
            let value_start = start + field_name.len() + 2;
            if let Some(end) = xmp_content[value_start..].find('"') {
                return Some(xmp_content[value_start..value_start + end].to_string());
            }
        }
        None
    }

    /// Identify privacy issues in metadata
    fn identify_privacy_issues(
        &self,
        document_info: &Option<DocumentInfo>,
        xmp_metadata: &Option<XmpMetadata>,
    ) -> Result<Vec<PrivacyIssue>> {
        let mut issues = Vec::new();

        // Check document info for privacy issues
        if let Some(info) = document_info {
            if info.author.is_some() {
                issues.push(PrivacyIssue {
                    issue_type: "Personal Information".to_string(),
                    field_name: "Author".to_string(),
                    severity: SecurityLevel::Medium,
                    description: "Document contains author information".to_string(),
                    recommendation: "Remove author metadata".to_string(),
                });
            }

            if info.creator.is_some() {
                issues.push(PrivacyIssue {
                    issue_type: "Software Information".to_string(),
                    field_name: "Creator".to_string(),
                    severity: SecurityLevel::Low,
                    description: "Document reveals creation software".to_string(),
                    recommendation: "Remove creator metadata".to_string(),
                });
            }

            if info.creation_date.is_some() || info.modification_date.is_some() {
                issues.push(PrivacyIssue {
                    issue_type: "Temporal Information".to_string(),
                    field_name: "Dates".to_string(),
                    severity: SecurityLevel::Low,
                    description: "Document contains timestamp information".to_string(),
                    recommendation: "Remove or randomize timestamps".to_string(),
                });
            }
        }

        // Check XMP metadata for privacy issues
        if let Some(xmp) = xmp_metadata {
            if xmp.present {
                if xmp.creator_tool.is_some() {
                    issues.push(PrivacyIssue {
                        issue_type: "Software Fingerprinting".to_string(),
                        field_name: "CreatorTool".to_string(),
                        severity: SecurityLevel::Medium,
                        description: "XMP metadata reveals creation software".to_string(),
                        recommendation: "Remove XMP creator tool information".to_string(),
                    });
                }

                if xmp.document_id.is_some() || xmp.instance_id.is_some() {
                    issues.push(PrivacyIssue {
                        issue_type: "Document Tracking".to_string(),
                        field_name: "Document IDs".to_string(),
                        severity: SecurityLevel::High,
                        description: "XMP metadata contains tracking identifiers".to_string(),
                        recommendation: "Remove or randomize document identifiers".to_string(),
                    });
                }
            }
        }

        Ok(issues)
    }

    /// Check metadata integrity
    fn check_metadata_integrity(
        &self,
        document: &Document,
        document_info: &Option<DocumentInfo>,
        xmp_metadata: &Option<XmpMetadata>,
    ) -> Result<MetadataIntegrity> {
        let mut inconsistencies = Vec::new();
        let mut tamper_indicators = Vec::new();
        let mut integrity_score = 1.0;

        // Check for inconsistencies between Info and XMP
        if let (Some(info), Some(xmp)) = (document_info, xmp_metadata) {
            if xmp.present {
                // Compare creation tools
                if let (Some(creator), Some(tool)) = (&info.creator, &xmp.creator_tool) {
                    if creator != tool && !tool.contains(creator) && !creator.contains(tool) {
                        inconsistencies.push("Creator tool mismatch between Info and XMP".to_string());
                        integrity_score -= 0.1;
                    }
                }
            }
        }

        // Check for tamper indicators
        if let Some(info) = document_info {
            // Check for suspicious modification dates
            if let (Some(creation), Some(modification)) = (&info.creation_date, &info.modification_date) {
                // Simplified date comparison - in real implementation would parse dates
                if modification < creation {
                    tamper_indicators.push("Modification date is before creation date".to_string());
                    integrity_score -= 0.2;
                }
            }
        }

        // Check for unusual metadata patterns
        let metadata_count = self.count_metadata_fields(document_info, xmp_metadata);
        if metadata_count == 0 {
            tamper_indicators.push("No metadata found - possible intentional removal".to_string());
            integrity_score -= 0.1;
        } else if metadata_count > 20 {
            tamper_indicators.push("Excessive metadata fields - possible data hiding".to_string());
            integrity_score -= 0.1;
        }

        let is_consistent = inconsistencies.is_empty() && tamper_indicators.is_empty();

        Ok(MetadataIntegrity {
            is_consistent,
            inconsistencies,
            tamper_indicators,
            integrity_score: integrity_score.max(0.0),
        })
    }

    /// Count total metadata fields
    fn count_metadata_fields(
        &self,
        document_info: &Option<DocumentInfo>,
        xmp_metadata: &Option<XmpMetadata>,
    ) -> u32 {
        let mut count = 0;

        if let Some(info) = document_info {
            if info.title.is_some() { count += 1; }
            if info.author.is_some() { count += 1; }
            if info.subject.is_some() { count += 1; }
            if info.creator.is_some() { count += 1; }
            if info.producer.is_some() { count += 1; }
            if info.creation_date.is_some() { count += 1; }
            if info.modification_date.is_some() { count += 1; }
            if info.keywords.is_some() { count += 1; }
        }

        if let Some(xmp) = xmp_metadata {
            if xmp.present {
                if xmp.creator_tool.is_some() { count += 1; }
                if xmp.document_id.is_some() { count += 1; }
                if xmp.instance_id.is_some() { count += 1; }
                if xmp.metadata_date.is_some() { count += 1; }
            }
        }

        count
    }

    /// Calculate security score
    fn calculate_security_score(
        &self,
        privacy_issues: &[PrivacyIssue],
        metadata_integrity: &MetadataIntegrity,
        metadata_count: u32,
    ) -> f64 {
        let mut score = 1.0;

        // Reduce score for privacy issues
        for issue in privacy_issues {
            score -= match issue.severity {
                SecurityLevel::Critical | SecurityLevel::Maximum => 0.3,
                SecurityLevel::High => 0.2,
                SecurityLevel::Medium => 0.1,
                SecurityLevel::Low => 0.05,
            };
        }

        // Reduce score for integrity issues
        score *= metadata_integrity.integrity_score;

        // Slight penalty for excessive metadata
        if metadata_count > 15 {
            score -= (metadata_count as f64 - 15.0) * 0.01;
        }

        score.max(0.0).min(1.0)
    }

    /// Generate recommendations
    fn generate_recommendations(
        &self,
        privacy_issues: &[PrivacyIssue],
        metadata_integrity: &MetadataIntegrity,
        document_info: &Option<DocumentInfo>,
        xmp_metadata: &Option<XmpMetadata>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !privacy_issues.is_empty() {
            recommendations.push("Remove or sanitize privacy-sensitive metadata".to_string());
        }

        if !metadata_integrity.is_consistent {
            recommendations.push("Investigate metadata inconsistencies".to_string());
        }

        if !metadata_integrity.tamper_indicators.is_empty() {
            recommendations.push("Check for potential metadata tampering".to_string());
        }

        if let Some(xmp) = xmp_metadata {
            if xmp.present && xmp.size_bytes > 10000 {
                recommendations.push("Large XMP metadata detected - consider removal".to_string());
            }
        }

        recommendations
    }

    /// Check if scanner is ready
    pub fn is_ready(&self) -> bool {
        true
    }
}
```
