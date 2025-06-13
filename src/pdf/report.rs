use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub timestamp: DateTime<Utc>,
    pub summary: Summary,
    pub details: Details,
    pub recommendations: Vec<Recommendation>,
    pub metadata: MetadataReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub is_valid: bool,
    pub total_issues: usize,
    pub critical_issues: usize,
    pub validation_time: DateTime<Utc>,
    pub pdf_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Details {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub content_issues: Vec<ContentIssue>,
    pub security_issues: Vec<SecurityIssue>,
    pub size_violations: Vec<SizeViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub category: String,
    pub description: String,
    pub impact: String,
    pub suggested_action: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataReport {
    pub validation_version: String,
    pub validation_date: DateTime<Utc>,
    pub validator_settings: ValidatorSettings,
    pub document_info: DocumentInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSettings {
    pub strict_mode: bool,
    pub max_stream_size: usize,
    pub max_object_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub pdf_version: String,
    pub file_size: u64,
    pub object_count: usize,
    pub is_encrypted: bool,
    pub has_signatures: bool,
}

impl Report {
    pub fn generate_markdown(&self) -> String {
        let mut md = String::new();
        
        // Header
        md.push_str("# PDF Validation Report\n\n");
        md.push_str(&format!("Generated: {}\n\n", self.timestamp));
        
        // Summary section
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- Validation Status: **{}**\n", 
            if self.summary.is_valid { "PASSED" } else { "FAILED" }));
        md.push_str(&format!("- Total Issues: {}\n", self.summary.total_issues));
        md.push_str(&format!("- Critical Issues: {}\n", self.summary.critical_issues));
        md.push_str(&format!("- PDF Version: {}\n\n", self.summary.pdf_version));

        // Issues section
        if !self.details.errors.is_empty() {
            md.push_str("## Critical Errors\n\n");
            for error in &self.details.errors {
                md.push_str(&format!("### {}\n", error.error_type));
                md.push_str(&format!("- Description: {}\n", error.description));
                md.push_str(&format!("- Severity: {}\n", error.severity));
                if let Some(location) = &error.location {
                    md.push_str(&format!("- Location: Object {}\n", location));
                }
                md.push_str("\n");
            }
        }

        // Security Issues
        if !self.details.security_issues.is_empty() {
            md.push_str("## Security Issues\n\n");
            for issue in &self.details.security_issues {
                md.push_str(&format!("### {}\n", issue.issue_type));
                md.push_str(&format!("- Description: {}\n", issue.description));
                md.push_str(&format!("- Risk Level: {}\n", issue.risk_level));
                md.push_str(&format!("- Recommendation: {}\n\n", issue.recommendation));
            }
        }

        // Content Issues
        if !self.details.content_issues.is_empty() {
            md.push_str("## Content Issues\n\n");
            for issue in &self.details.content_issues {
                md.push_str(&format!("### {}\n", issue.issue_type));
                md.push_str(&format!("- Description: {}\n", issue.description));
                md.push_str(&format!("- Content Type: {}\n", issue.content_type));
                md.push_str(&format!("- Object ID: {}\n\n", issue.object_id));
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            md.push_str("## Recommendations\n\n");
            for rec in &self.recommendations {
                md.push_str(&format!("### {} Priority - {}\n", rec.priority, rec.category));
                md.push_str(&format!("- Issue: {}\n", rec.description));
                md.push_str(&format!("- Impact: {}\n", rec.impact));
                md.push_str(&format!("- Suggested Action: {}\n\n", rec.suggested_action));
            }
        }

        // Metadata
        md.push_str("## Document Information\n\n");
        md.push_str("### Document Details\n");
        md.push_str(&format!("- PDF Version: {}\n", self.metadata.document_info.pdf_version));
        md.push_str(&format!("- File Size: {} bytes\n", self.metadata.document_info.file_size));
        md.push_str(&format!("- Object Count: {}\n", self.metadata.document_info.object_count));
        md.push_str(&format!("- Encrypted: {}\n", self.metadata.document_info.is_encrypted));
        md.push_str(&format!("- Has Signatures: {}\n\n", self.metadata.document_info.has_signatures));

        // Validator Information
        md.push_str("### Validation Details\n");
        md.push_str(&format!("- Validator Version: {}\n", self.metadata.validation_version));
        md.push_str(&format!("- Strict Mode: {}\n", self.metadata.validator_settings.strict_mode));
        md.push_str(&format!("- Maximum Stream Size: {} bytes\n", 
            self.metadata.validator_settings.max_stream_size));
        md.push_str(&format!("- Maximum Object Size: {} bytes\n", 
            self.metadata.validator_settings.max_object_size));

        md
    }

}
impl Report {
    pub fn generate_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn generate_html(&self) -> String {
        let mut html = String::new();
        
        // HTML header
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #f8f9fa; padding: 1rem; border-radius: 4px; }
        .section { margin: 2rem 0; }
        .issue { background-color: #fff; border: 1px solid #ddd; padding: 1rem; margin: 1rem 0; border-radius: 4px; }
        .critical { border-left: 4px solid #dc3545; }
        .warning { border-left: 4px solid #ffc107; }
        .security { border-left: 4px solid #fd7e14; }
        .recommendation { border-left: 4px solid #28a745; }
        .metadata { background-color: #e9ecef; padding: 1rem; border-radius: 4px; }
    </style>
</head>
<body>
<div class="container">
"#);

        // Report header
        html.push_str(&format!(r#"
    <div class="header">
        <h1>PDF Validation Report</h1>
        <p>Generated: {}</p>
    </div>
"#, self.timestamp));

        // Summary section
        html.push_str(&format!(r#"
    <div class="section">
        <h2>Summary</h2>
        <div class="issue">
            <p><strong>Validation Status:</strong> {}</p>
            <p><strong>Total Issues:</strong> {}</p>
            <p><strong>Critical Issues:</strong> {}</p>
            <p><strong>PDF Version:</strong> {}</p>
        </div>
    </div>
"#, 
            if self.summary.is_valid { "<span style='color: #28a745'>PASSED</span>" } 
            else { "<span style='color: #dc3545'>FAILED</span>" },
            self.summary.total_issues,
            self.summary.critical_issues,
            self.summary.pdf_version
        ));

        // Critical Errors section
        if !self.details.errors.is_empty() {
            html.push_str(r#"<div class="section"><h2>Critical Errors</h2>"#);
            for error in &self.details.errors {
                html.push_str(&format!(r#"
                    <div class="issue critical">
                        <h3>{}</h3>
                        <p><strong>Description:</strong> {}</p>
                        <p><strong>Severity:</strong> {}</p>
                        {}
                    </div>
                "#,
                    error.error_type,
                    error.description,
                    error.severity,
                    if let Some(location) = &error.location {
                        format!("<p><strong>Location:</strong> Object {}</p>", location)
                    } else {
                        String::new()
                    }
                ));
            }
            html.push_str("</div>");
        }

        // Security Issues section
        if !self.details.security_issues.is_empty() {
            html.push_str(r#"<div class="section"><h2>Security Issues</h2>"#);
            for issue in &self.details.security_issues {
                html.push_str(&format!(r#"
                    <div class="issue security">
                        <h3>{}</h3>
                        <p><strong>Description:</strong> {}</p>
                        <p><strong>Risk Level:</strong> {}</p>
                        <p><strong>Recommendation:</strong> {}</p>
                    </div>
                "#,
                    issue.issue_type,
                    issue.description,
                    issue.risk_level,
                    issue.recommendation
                ));
            }
            html.push_str("</div>");
        }

        html
    }
  impl Report {
    fn generate_html_content_issues(&self) -> String {
        let mut html = String::new();
        
        if !self.details.content_issues.is_empty() {
            html.push_str(r#"<div class="section"><h2>Content Issues</h2>"#);
            for issue in &self.details.content_issues {
                html.push_str(&format!(r#"
                    <div class="issue warning">
                        <h3>{}</h3>
                        <p><strong>Description:</strong> {}</p>
                        <p><strong>Content Type:</strong> {}</p>
                        <p><strong>Object ID:</strong> {}</p>
                    </div>
                "#,
                    issue.issue_type,
                    issue.description,
                    issue.content_type,
                    issue.object_id
                ));
            }
            html.push_str("</div>");
        }
        html
    }

    fn generate_html_recommendations(&self) -> String {
        let mut html = String::new();
        
        if !self.recommendations.is_empty() {
            html.push_str(r#"<div class="section"><h2>Recommendations</h2>"#);
            for rec in &self.recommendations {
                let priority_color = match rec.priority.as_str() {
                    "Immediate" => "#dc3545",
                    "High" => "#fd7e14",
                    "Medium" => "#ffc107",
                    _ => "#28a745",
                };
                
                html.push_str(&format!(r#"
                    <div class="issue recommendation">
                        <h3 style="color: {};">{} Priority - {}</h3>
                        <p><strong>Issue:</strong> {}</p>
                        <p><strong>Impact:</strong> {}</p>
                        <p><strong>Suggested Action:</strong> {}</p>
                    </div>
                "#,
                    priority_color,
                    rec.priority,
                    rec.category,
                    rec.description,
                    rec.impact,
                    rec.suggested_action
                ));
            }
            html.push_str("</div>");
        }
        html
    }

    fn generate_html_metadata(&self) -> String {
        format!(r#"
            <div class="section">
                <h2>Document Information</h2>
                <div class="metadata">
                    <h3>Document Details</h3>
                    <p><strong>PDF Version:</strong> {}</p>
                    <p><strong>File Size:</strong> {} bytes</p>
                    <p><strong>Object Count:</strong> {}</p>
                    <p><strong>Encrypted:</strong> {}</p>
                    <p><strong>Has Signatures:</strong> {}</p>
                    
                    <h3>Validation Details</h3>
                    <p><strong>Validator Version:</strong> {}</p>
                    <p><strong>Strict Mode:</strong> {}</p>
                    <p><strong>Maximum Stream Size:</strong> {} bytes</p>
                    <p><strong>Maximum Object Size:</strong> {} bytes</p>
                </div>
            </div>
        "#,
            self.metadata.document_info.pdf_version,
            self.metadata.document_info.file_size,
            self.metadata.document_info.object_count,
            self.metadata.document_info.is_encrypted,
            self.metadata.document_info.has_signatures,
            self.metadata.validation_version,
            self.metadata.validator_settings.strict_mode,
            self.metadata.validator_settings.max_stream_size,
            self.metadata.validator_settings.max_object_size
        )
    }

    pub fn complete_html_report(&self) -> String {
        let mut complete_report = String::new();
        
        // Start with the base HTML template
        complete_report.push_str(&self.generate_html());
        
        // Add content issues
        complete_report.push_str(&self.generate_html_content_issues());
        
        // Add recommendations
        complete_report.push_str(&self.generate_html_recommendations());
        
        // Add metadata
        complete_report.push_str(&self.generate_html_metadata());
        
        // Close HTML tags
        complete_report.push_str(r#"
            </div>
        </body>
        </html>
        "#);
        
        complete_report
    }

    pub fn generate_csv(&self) -> String {
        let mut csv = String::new();
        
        // CSV Headers
        csv.push_str("Type,Category,Description,Severity/Priority,Location/Impact,Timestamp\n");
        
        // Add errors
        for error in &self.details.errors {
            csv.push_str(&format!("Error,{},{},{},{},{}\n",
                error.error_type,
                error.description.replace(",", ";"),
                error.severity,
                error.location.map_or("N/A".to_string(), |l| l.to_string()),
                error.detection_time
            ));
        }
        
        // Add security issues
        for issue in &self.details.security_issues {
            csv.push_str(&format!("Security,{},{},{},{},{}\n",
                issue.issue_type,
                issue.description.replace(",", ";"),
                issue.risk_level,
                issue.recommendation.replace(",", ";"),
                self.timestamp
            ));
        }
        
        // Add content issues
        for issue in &self.details.content_issues {
            csv.push_str(&format!("Content,{},{},{},{},{}\n",
                issue.content_type,
                issue.description.replace(",", ";"),
                issue.issue_type,
                issue.object_id,
                self.timestamp
            ));
        }
        
        csv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_report_generation() {
        let timestamp = Utc.ymd(2025, 6, 13).and_hms(17, 20, 5);
        let report = Report {
            timestamp,
            summary: Summary {
                is_valid: true,
                total_issues: 0,
                critical_issues: 0,
                validation_time: timestamp,
                pdf_version: "1.7".to_string(),
            },
            details: Details {
                errors: vec![],
                warnings: vec![],
                content_issues: vec![],
                security_issues: vec![],
                size_violations: vec![],
            },
            recommendations: vec![],
            metadata: MetadataReport {
                validation_version: "1.0.0".to_string(),
                validation_date: timestamp,
                validator_settings: ValidatorSettings {
                    strict_mode: true,
                    max_stream_size: 1000000,
                    max_object_size: 500000,
                },
                document_info: DocumentInfo {
                    pdf_version: "1.7".to_string(),
                    file_size: 1000,
                    object_count: 10,
                    is_encrypted: false,
                    has_signatures: false,
                },
            },
        };

        assert!(!report.generate_markdown().is_empty());
        assert!(!report.complete_html_report().is_empty());
        assert!(report.generate_json().is_ok());
        assert!(!report.generate_csv().is_empty());
    }
}
