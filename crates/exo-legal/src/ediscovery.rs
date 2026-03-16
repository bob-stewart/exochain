//! E-Discovery export and production workflow (LEG-010).
//!
//! Supports litigation hold, document collection, review, and production
//! in standard formats (EDRM XML, load files).

use chrono::{DateTime, Utc};
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Production format for e-discovery exports.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProductionFormat {
    /// EDRM XML standard format.
    EdrmXml,
    /// Concordance DAT load file.
    ConcordanceDat,
    /// Relativity load file.
    RelativityLoadFile,
    /// Native format with metadata sidecar.
    NativeWithMetadata,
    /// JSON export.
    Json,
}

/// Status of an e-discovery request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EDiscoveryStatus {
    /// Hold placed — preservation duty active.
    HoldPlaced,
    /// Collection in progress.
    Collecting,
    /// Review in progress.
    UnderReview,
    /// Production ready.
    ReadyForProduction,
    /// Produced to requesting party.
    Produced,
    /// Hold released.
    HoldReleased,
}

/// An e-discovery request tied to a legal matter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EDiscoveryRequest {
    pub id: Uuid,
    pub tenant_id: String,
    pub matter_name: String,
    pub matter_number: String,
    pub requesting_party: String,
    pub status: EDiscoveryStatus,
    pub hold_placed_at: DateTime<Utc>,
    pub date_range_start: Option<DateTime<Utc>>,
    pub date_range_end: Option<DateTime<Utc>>,
    pub custodians: Vec<String>,
    pub search_terms: Vec<String>,
    pub decision_ids: Vec<Blake3Hash>,
    pub produced_at: Option<DateTime<Utc>>,
}

/// An e-discovery export package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EDiscoveryExport {
    pub request_id: Uuid,
    pub format: ProductionFormat,
    pub document_count: u64,
    pub total_size_bytes: u64,
    pub content_hash: Blake3Hash,
    pub produced_at: DateTime<Utc>,
    pub bates_range_start: String,
    pub bates_range_end: String,
    pub privilege_log_entries: u64,
}

impl EDiscoveryRequest {
    /// Create a new e-discovery request and place a litigation hold.
    pub fn new(
        tenant_id: String,
        matter_name: String,
        matter_number: String,
        requesting_party: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            matter_name,
            matter_number,
            requesting_party,
            status: EDiscoveryStatus::HoldPlaced,
            hold_placed_at: Utc::now(),
            date_range_start: None,
            date_range_end: None,
            custodians: Vec::new(),
            search_terms: Vec::new(),
            decision_ids: Vec::new(),
            produced_at: None,
        }
    }

    /// Add custodians to the collection scope.
    pub fn add_custodians(&mut self, custodians: Vec<String>) {
        self.custodians.extend(custodians);
    }

    /// Add search terms for filtering.
    pub fn add_search_terms(&mut self, terms: Vec<String>) {
        self.search_terms.extend(terms);
    }

    /// Set the date range for collection.
    pub fn set_date_range(&mut self, start: DateTime<Utc>, end: DateTime<Utc>) {
        self.date_range_start = Some(start);
        self.date_range_end = Some(end);
    }

    /// Add specific decision IDs to the collection.
    pub fn add_decision_ids(&mut self, ids: Vec<Blake3Hash>) {
        self.decision_ids.extend(ids);
    }

    /// Advance to collection phase.
    pub fn begin_collection(&mut self) -> bool {
        if self.status == EDiscoveryStatus::HoldPlaced {
            self.status = EDiscoveryStatus::Collecting;
            true
        } else {
            false
        }
    }

    /// Advance to review phase.
    pub fn begin_review(&mut self) -> bool {
        if self.status == EDiscoveryStatus::Collecting {
            self.status = EDiscoveryStatus::UnderReview;
            true
        } else {
            false
        }
    }

    /// Mark as ready for production.
    pub fn mark_ready(&mut self) -> bool {
        if self.status == EDiscoveryStatus::UnderReview {
            self.status = EDiscoveryStatus::ReadyForProduction;
            true
        } else {
            false
        }
    }

    /// Record production.
    pub fn record_production(&mut self) -> bool {
        if self.status == EDiscoveryStatus::ReadyForProduction {
            self.status = EDiscoveryStatus::Produced;
            self.produced_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    /// Release the litigation hold.
    pub fn release_hold(&mut self) -> bool {
        if self.status == EDiscoveryStatus::Produced {
            self.status = EDiscoveryStatus::HoldReleased;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ediscovery_lifecycle() {
        let mut req = EDiscoveryRequest::new(
            "tenant-1".into(),
            "Smith v. Corp".into(),
            "2024-CV-001".into(),
            "Plaintiff counsel".into(),
        );

        assert_eq!(req.status, EDiscoveryStatus::HoldPlaced);
        assert!(req.begin_collection());
        assert_eq!(req.status, EDiscoveryStatus::Collecting);
        assert!(req.begin_review());
        assert_eq!(req.status, EDiscoveryStatus::UnderReview);
        assert!(req.mark_ready());
        assert_eq!(req.status, EDiscoveryStatus::ReadyForProduction);
        assert!(req.record_production());
        assert_eq!(req.status, EDiscoveryStatus::Produced);
        assert!(req.release_hold());
        assert_eq!(req.status, EDiscoveryStatus::HoldReleased);
    }

    #[test]
    fn test_invalid_transitions() {
        let mut req = EDiscoveryRequest::new(
            "tenant-1".into(),
            "Matter".into(),
            "001".into(),
            "Party".into(),
        );

        // Can't skip to review without collecting
        assert!(!req.begin_review());
        // Can't produce without review
        assert!(!req.record_production());
    }
}
