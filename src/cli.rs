use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, EncryptionMethod},
};
use chrono::DateTime;

/// PDF Document Metadata Standardizer
/// 
/// Professional tool for corporate PDF metadata compliance and standardization.
/// Ensures consistent metadata across document workflows while maintaining
/// document integrity and professional appearance.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "pdf-standardizer")]
pub struct CliArgs {
    /// Input PDF file (PDF A) - source document for processing  
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output PDF file (PDF B) - standardized document output
    #[arg(short, long, value_name = "FILE", default_value = "standardized_output.pdf")]
    pub output: PathBuf,

    /// Document title for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub title: Option<String>,

    /// Document author for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub author: Option<String>,

    /// Document subject for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub subject: Option<String>,

    /// Document keywords for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub keywords: Option<String>,

    /// Document creator application for metadata standardization
    #[arg(long, value_name = "TEXT")]
    pub creator: Option<String>,

    /// Document creation date (ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ)
    #[arg(long, value_name = "DATETIME")] 
    pub created: Option<String>,

    /// Encryption password for document security
    #[arg(long, value_name = "PASSWORD")]
    pub encrypt_password: Option<String>,

    /// Owner password for document administration
    #[arg(long, value_name = "PASSWORD")]
    pub encrypt_owner: Option<String>,

    /// Encryption method for document security
    #[arg(long, value_enum, default_value_t = EncryptionMethodArg::Aes128)]
    pub encrypt_method: EncryptionMethodArg,

    /// Remove digital signatures for standardization
    #[arg(long)]
    pub remove_signature: bool,

    /// Enable detailed processing logs for troubleshooting
    #[arg(long)]
    pub debug: bool,

    /// Clean all existing metadata before applying new values
    #[arg(long)]
    pub clean_metadata: bool,

    /// Preserve original creation date when standardizing
    #[arg(long)]
    pub preserve_creation_date: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum EncryptionMethodArg {
    None,
    Rc4_128,
    Aes128,
    Aes256,
}

impl From<EncryptionMethodArg> for EncryptionMethod {
    fn from(arg: EncryptionMethodArg) -> Self {
        match arg {
            EncryptionMethodArg::None => EncryptionMethod::None,
            EncryptionMethodArg::Rc4_128 => EncryptionMethod::RC4_128,
            EncryptionMethodArg::Aes128 => EncryptionMethod::AES_128,
            EncryptionMethodArg::Aes256 => EncryptionMethod::AES_256,
        }
    }
}

impl CliArgs {
    /// Check if any encryption parameters are specified
    pub fn has_encryption(&self) -> bool {
        !matches!(self.encrypt_method, EncryptionMethodArg::None) ||
        self.encrypt_password.is_some() ||
        self.encrypt_owner.is_some()
    }

    /// Get encryption method as internal type
    pub fn get_encryption_method(&self) -> EncryptionMethod {
        self.encrypt_method.clone().into()
    }

    /// Validate command line arguments
    pub fn validate(&self) -> Result<()> {
        // Validate input file exists
        if !self.input.exists() {
            return Err(ForensicError::FileSystemError {
                operation: format!("Input file does not exist: {}", self.input.display())
            });
        }

        // Validate input file extension
        if let Some(ext) = self.input.extension() {
            if ext != "pdf" {
                return Err(ForensicError::FileSystemError {
                    operation: "Input file must have .pdf extension".to_string()
                });
            }
        } else {
            return Err(ForensicError::FileSystemError {
                operation: "Input file must have .pdf extension".to_string()
            });
        }

        // Validate output directory is writable
        if let Some(parent) = self.output.parent() {
            if !parent.exists() {
                return Err(ForensicError::FileSystemError {
                    operation: format!("Output directory does not exist: {}", parent.display())
                });
            }
        }

        // Validate creation date format if provided
        if let Some(ref date_str) = self.created {
            if DateTime::parse_from_rfc3339(date_str).is_err() {
                return Err(ForensicError::ConfigError {
                    parameter: "Creation date must be in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)".to_string()
                });
            }
        }

        // Validate encryption configuration
        if self.has_encryption() && self.encrypt_password.is_none() {
            return Err(ForensicError::ConfigError {
                parameter: "Encryption password required when encryption method is specified".to_string()
            });
        }

        Ok(())
    }

    /// Get metadata fields that should be updated
    pub fn get_metadata_updates(&self) -> Vec<(MetadataField, Option<String>)> {
        let mut updates = Vec::new();

        if let Some(ref title) = self.title {
            updates.push((MetadataField::Title, Some(title.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Title, None));
        }

        if let Some(ref author) = self.author {
            updates.push((MetadataField::Author, Some(author.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Author, None));
        }

        if let Some(ref subject) = self.subject {
            updates.push((MetadataField::Subject, Some(subject.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Subject, None));
        }

        if let Some(ref keywords) = self.keywords {
            updates.push((MetadataField::Keywords, Some(keywords.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Keywords, None));
        }

        if let Some(ref creator) = self.creator {
            updates.push((MetadataField::Creator, Some(creator.clone())));
        } else if self.clean_metadata {
            updates.push((MetadataField::Creator, None));
        }

        if let Some(ref created) = self.created {
            updates.push((MetadataField::CreationDate, Some(created.clone())));
        }

        updates
    }
      }
