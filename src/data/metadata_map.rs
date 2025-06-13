use crate::{
    errors::{ForensicError, Result},
    types::{MetadataField, MetadataLocation, MetadataMap, MetadataValue},
};
use lopdf::ObjectId;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

/// Comprehensive metadata location tracking system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataLocationTracker {
    pub field_locations: LocationMapping,
    pub synchronization_status: HashMap<MetadataField, SynchronizationStatus>,
    pub coverage_tracker: CoverageTracker,
    pub field_sync_map: FieldSynchronizationMap,
    pub location_priorities: HashMap<MetadataLocation, u8>,
}

/// Mapping of metadata fields to their storage locations
pub type LocationMapping = HashMap<MetadataField, Vec<LocationEntry>>;

/// Synchronization mapping for coordinated updates
pub type FieldSynchronizationMap = HashMap<MetadataField, SynchronizationGroup>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationEntry {
    pub location: MetadataLocation,
    pub object_id: Option<ObjectId>,
    pub current_value: Option<String>,
    pub last_modified: Option<String>,
    pub is_writable: bool,
    pub requires_synchronization: bool,
    pub access_path: String,
    pub validation_status: ValidationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationGroup {
    pub primary_location: MetadataLocation,
    pub secondary_locations: Vec<MetadataLocation>,
    pub sync_strategy: SyncStrategy,
    pub last_sync_timestamp: Option<String>,
    pub sync_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStrategy {
    MasterSlave,    // One primary location, others follow
    Bidirectional,  // All locations stay synchronized
    Hierarchical,   // Priority-based synchronization
    Custom(String), // Application-specific strategy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationStatus {
    pub is_synchronized: bool,
    pub last_sync_check: Option<String>,
    pub sync_conflicts: Vec<SyncConflict>,
    pub pending_updates: Vec<PendingUpdate>,
    pub sync_quality_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub location1: MetadataLocation,
    pub location2: MetadataLocation,
    pub value1: Option<String>,
    pub value2: Option<String>,
    pub conflict_type: ConflictType,
    pub resolution_strategy: ResolutionStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    ValueMismatch,
    MissingValue,
    FormatInconsistency,
    EncodingDifference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolutionStrategy {
    UseFirst,
    UseLast,
    UsePrimary,
    Merge,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    pub target_location: MetadataLocation,
    pub new_value: Option<String>,
    pub operation_type: UpdateOperation,
    pub priority: u8,
    pub retry_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateOperation {
    Set,
    Clear,
    Modify,
    Synchronize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Valid,
    Invalid(String),
    Pending,
    NotChecked,
}

/// Coverage tracking for metadata synchronization completeness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTracker {
    pub total_fields_discovered: usize,
    pub fields_with_multiple_locations: usize,
    pub synchronized_fields: usize,
    pub unsynchronized_fields: Vec<MetadataField>,
    pub coverage_percentage: f32,
    pub missing_standard_locations: Vec<(MetadataField, MetadataLocation)>,
}

impl MetadataLocationTracker {
    pub fn new() -> Self {
        Self {
            field_locations: HashMap::new(),
            synchronization_status: HashMap::new(),
            coverage_tracker: CoverageTracker::new(),
            field_sync_map: HashMap::new(),
            location_priorities: Self::default_location_priorities(),
        }
    }

    fn default_location_priorities() -> HashMap<MetadataLocation, u8> {
        let mut priorities = HashMap::new();
        priorities.insert(MetadataLocation::DocInfo, 10);        // Highest priority
        priorities.insert(MetadataLocation::XmpStream, 9);
        priorities.insert(MetadataLocation::ObjectStream(0), 5); // Medium priority
        priorities.insert(MetadataLocation::Annotation(0), 3);
        priorities.insert(MetadataLocation::FormField("".to_string()), 2);
        priorities.insert(MetadataLocation::CustomLocation("".to_string()), 1); // Lowest priority
        priorities
    }

    /// Add metadata location discovery
    pub fn add_location(&mut self, field: MetadataField, location: MetadataLocation, object_id: Option<ObjectId>, current_value: Option<String>, access_path: String) -> Result<()> {
        let entry_timestamp = chrono::Utc::now().to_rfc3339();
        let location_entry = LocationEntry {
            location: location.clone(),
            object_id,
            current_value: current_value.clone(),
            last_modified: Some(entry_timestamp),
            is_writable: self.is_location_writable(&location),
            requires_synchronization: self.requires_synchronization(&field, &location),
            access_path,
            validation_status: ValidationStatus::NotChecked,
        };

        self.field_locations
            .entry(field.clone())
            .or_insert_with(Vec::new)
            .push(location_entry);

        self.update_synchronization_status(&field);
        self.update_coverage_tracking();

        Ok(())
    }

    fn is_location_writable(&self, location: &MetadataLocation) -> bool {
        match location {
            MetadataLocation::DocInfo => true,
            MetadataLocation::XmpStream => true,
            MetadataLocation::ObjectStream(_) => true,
            MetadataLocation::Annotation(_) => true,
            MetadataLocation::FormField(_) => true,
            MetadataLocation::CustomLocation(_) => false,
        }
    }

    fn requires_synchronization(&self, field: &MetadataField, location: &MetadataLocation) -> bool {
        matches!(field, 
            MetadataField::Title | 
            MetadataField::Author | 
            MetadataField::Subject | 
            MetadataField::Keywords | 
            MetadataField::Creator | 
            MetadataField::Producer | 
            MetadataField::CreationDate
        ) && matches!(location, 
            MetadataLocation::DocInfo | 
            MetadataLocation::XmpStream
        )
    }

    fn update_synchronization_status(&mut self, field: &MetadataField) {
        let locations = self.field_locations.get(field).unwrap_or(&Vec::new());
        
        if locations.len() <= 1 {
            self.synchronization_status.insert(field.clone(), SynchronizationStatus {
                is_synchronized: true,
                last_sync_check: Some(chrono::Utc::now().to_rfc3339()),
                sync_conflicts: Vec::new(),
                pending_updates: Vec::new(),
                sync_quality_score: 1.0,
            });
            return;
        }

        let values: Vec<_> = locations.iter()
            .map(|loc| &loc.current_value)
            .collect();
        
        let is_synchronized = values.windows(2).all(|pair| pair[0] == pair[1]);
        let sync_conflicts = if !is_synchronized {
            self.detect_sync_conflicts(locations)
        } else {
            Vec::new()
        };

        let sync_quality_score = self.calculate_sync_quality_score(locations, &sync_conflicts);

        self.synchronization_status.insert(field.clone(), SynchronizationStatus {
            is_synchronized,
            last_sync_check: Some(chrono::Utc::now().to_rfc3339()),
            sync_conflicts,
            pending_updates: Vec::new(),
            sync_quality_score,
        });
    }

    fn detect_sync_conflicts(&self, locations: &[LocationEntry]) -> Vec<SyncConflict> {
        let mut conflicts = Vec::new();
        
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let loc1 = &locations[i];
                let loc2 = &locations[j];
                
                if loc1.current_value != loc2.current_value {
                    let conflict_type = if loc1.current_value.is_none() || loc2.current_value.is_none() {
                        ConflictType::MissingValue
                    } else {
                        ConflictType::ValueMismatch
                    };
                    
                    conflicts.push(SyncConflict {
                        location1: loc1.location.clone(),
                        location2: loc2.location.clone(),
                        value1: loc1.current_value.clone(),
                        value2: loc2.current_value.clone(),
                        conflict_type,
                        resolution_strategy: ResolutionStrategy::UsePrimary,
                    });
                }
            }
        }
        
        conflicts
    }

    fn calculate_sync_quality_score(&self, locations: &[LocationEntry], conflicts: &[SyncConflict]) -> f32 {
        if locations.is_empty() {
            return 1.0;
        }
        
        let synchronized_pairs = (locations.len() * (locations.len() - 1)) / 2;
        let conflict_count = conflicts.len();
        
        if synchronized_pairs == 0 {
            1.0
        } else {
            1.0 - (conflict_count as f32 / synchronized_pairs as f32)
        }
    }

    fn update_coverage_tracking(&mut self) {
        let total_fields_discovered = self.field_locations.len();
        let fields_with_multiple_locations = self.field_locations.values()
            .filter(|locations| locations.len() > 1)
            .count();
        
        let synchronized_fields = self.synchronization_status.values()
            .filter(|status| status.is_synchronized)
            .count();
        
        let unsynchronized_fields = self.synchronization_status.iter()
            .filter_map(|(field, status)| {
                if !status.is_synchronized {
                    Some(field.clone())
                } else {
                    None
                }
            })
            .collect();
        
        let coverage_percentage = if total_fields_discovered > 0 {
            (synchronized_fields as f32 / total_fields_discovered as f32) * 100.0
        } else {
            0.0
        };
        
        let missing_standard_locations = self.find_missing_standard_locations();
        
        self.coverage_tracker = CoverageTracker {
            total_fields_discovered,
            fields_with_multiple_locations,
            synchronized_fields,
            unsynchronized_fields,
            coverage_percentage,
            missing_standard_locations,
        };
    }

    fn find_missing_standard_locations(&self) -> Vec<(MetadataField, MetadataLocation)> {
        let mut missing = Vec::new();
        let standard_fields = [
            MetadataField::Title,
            MetadataField::Author,
            MetadataField::Subject,
            MetadataField::Keywords,
            MetadataField::Creator,
            MetadataField::Producer,
            MetadataField::CreationDate,
        ];
        
        let standard_locations = [
            MetadataLocation::DocInfo,
            MetadataLocation::XmpStream,
        ];
        
        for field in &standard_fields {
            if let Some(locations) = self.field_locations.get(field) {
                for standard_location in &standard_locations {
                    if !locations.iter().any(|loc| std::mem::discriminant(&loc.location) == std::mem::discriminant(standard_location)) {
                        missing.push((field.clone(), standard_location.clone()));
                    }
                }
            } else {
                for standard_location in &standard_locations {
                    missing.push((field.clone(), standard_location.clone()));
                }
            }
        }
        
        missing
    }

    pub fn get_location_priority(&self, location: &MetadataLocation) -> u8 {
        match location {
            MetadataLocation::DocInfo => 10,
            MetadataLocation::XmpStream => 9,
            MetadataLocation::ObjectStream(_) => 5,
            MetadataLocation::Annotation(_) => 3,
            MetadataLocation::FormField(_) => 2,
            MetadataLocation::CustomLocation(_) => 1,
        }
    }

    pub fn to_metadata_map(&self) -> MetadataMap {
        let mut metadata_map = HashMap::new();
        
        for (field, locations) in &self.field_locations {
            let primary_value = self.get_primary_value(locations);
            let all_locations: Vec<MetadataLocation> = locations.iter()
                .map(|entry| entry.location.clone())
                .collect();
            
            let is_synchronized = self.synchronization_status
                .get(field)
                .map(|status| status.is_synchronized)
                .unwrap_or(true);
            
            metadata_map.insert(field.clone(), MetadataValue {
                field: field.clone(),
                value: primary_value,
                locations: all_locations,
                is_synchronized,
            });
        }
        
        metadata_map
    }

    fn get_primary_value(&self, locations: &[LocationEntry]) -> Option<String> {
        locations.iter()
            .filter(|entry| entry.current_value.is_some())
            .max_by_key(|entry| self.get_location_priority(&entry.location))
            .and_then(|entry| entry.current_value.clone())
    }
}

impl CoverageTracker {
    fn new() -> Self {
        Self {
            total_fields_discovered: 0,
            fields_with_multiple_locations: 0,
            synchronized_fields: 0,
            unsynchronized_fields: Vec::new(),
            coverage_percentage: 0.0,
            missing_standard_locations: Vec::new(),
        }
    }
}

impl Default for MetadataLocationTracker {
    fn default() -> Self {
        Self::new()
    }
          }
