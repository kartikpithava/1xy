//! Metadata Processing System
//! 
//! Comprehensive forensic metadata editing and synchronization system.
//! Provides universal metadata synchronization across all PDF storage locations
//! with complete forensic invisibility and authenticity preservation.

pub mod scanner;
pub mod editor;
pub mod synchronizer;
pub mod cleaner;
pub mod authenticator;

// Re-export commonly used types and functions
pub use self::scanner::{MetadataScanner, ScanResult, LocationMap};
pub use self::editor::{MetadataEditor, EditOperation, EditResult};
pub use self::synchronizer::{MetadataSynchronizer, SyncResult, SyncStrategy};
pub use self::cleaner::{MetadataCleaner, CleaningResult, CleaningStrategy};
pub use self::authenticator::{MetadataAuthenticator, AuthenticationResult, AuthenticityCheck};

use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataMap, MetadataLocation},
};
use std::collections::HashMap;

/// Metadata processing configuration
#[derive(Debug, Clone)]
pub struct MetadataProcessingConfig {
    pub deep_scan_enabled: bool,
    pub hidden_metadata_detection: bool,
    pub universal_synchronization: bool,
    pub forensic_cleaning: bool,
    pub authenticity_preservation: bool,
}

impl Default for MetadataProcessingConfig {
    fn default() -> Self {
        Self {
            deep_scan_enabled: true,
            hidden_metadata_detection: true,
            universal_synchronization: true,
            forensic_cleaning: true,
            authenticity_preservation: true,
        }
    }
}

/// Common metadata processing result wrapper
pub type MetadataResult<T> = Result<T>;
