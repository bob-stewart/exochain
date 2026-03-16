//! Duty of care evidence capture (LEG-004, LEG-006).
//!
//! Captures and preserves evidence of due diligence in governance decisions,
//! including deliberation records, expert consultations, and risk assessments.

use chrono::{DateTime, Utc};
use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Categories of duty-of-care evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceCategory {
    /// Expert consultation or opinion.
    ExpertConsultation,
    /// Risk assessment documentation.
    RiskAssessment,
    /// Financial analysis or projections.
    FinancialAnalysis,
    /// Legal review or opinion.
    LegalReview,
    /// Stakeholder impact analysis.
    StakeholderImpact,
    /// Prior decision precedent.
    Precedent,
    /// Deliberation transcript or minutes.
    Deliberation,
    /// Custom evidence type.
    Custom(String),
}

/// A captured piece of duty-of-care evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DutyCareEvidence {
    pub id: Uuid,
    pub decision_id: Blake3Hash,
    pub tenant_id: String,
    pub category: EvidenceCategory,
    pub title: String,
    pub description: String,
    pub content: Vec<u8>,
    pub content_hash: Blake3Hash,
    pub captured_by: String,
    pub captured_at: DateTime<Utc>,
    pub source: String,
}

/// Evidence capture service for building duty-of-care packages.
pub struct EvidenceCapture {
    evidence: Vec<DutyCareEvidence>,
}

impl EvidenceCapture {
    pub fn new() -> Self {
        Self {
            evidence: Vec::new(),
        }
    }

    /// Capture a new piece of evidence for a decision.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        &mut self,
        decision_id: Blake3Hash,
        tenant_id: String,
        category: EvidenceCategory,
        title: String,
        description: String,
        content: Vec<u8>,
        captured_by: String,
        source: String,
    ) -> &DutyCareEvidence {
        let content_hash = hash_bytes(&content);
        let evidence = DutyCareEvidence {
            id: Uuid::new_v4(),
            decision_id,
            tenant_id,
            category,
            title,
            description,
            content,
            content_hash,
            captured_by,
            captured_at: Utc::now(),
            source,
        };
        self.evidence.push(evidence);
        self.evidence.last().unwrap()
    }

    /// Get all evidence for a specific decision.
    pub fn for_decision(&self, decision_id: &Blake3Hash) -> Vec<&DutyCareEvidence> {
        self.evidence
            .iter()
            .filter(|e| &e.decision_id == decision_id)
            .collect()
    }

    /// Verify integrity of all captured evidence.
    pub fn verify_all(&self) -> Vec<(Uuid, bool)> {
        self.evidence
            .iter()
            .map(|e| (e.id, hash_bytes(&e.content) == e.content_hash))
            .collect()
    }

    /// Get total evidence count.
    pub fn count(&self) -> usize {
        self.evidence.len()
    }
}

impl Default for EvidenceCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_capture_and_retrieval() {
        let mut capture = EvidenceCapture::new();
        let decision_id = Blake3Hash([1u8; 32]);

        capture.capture(
            decision_id,
            "tenant-1".into(),
            EvidenceCategory::RiskAssessment,
            "Risk Report".into(),
            "Q4 risk assessment".into(),
            b"risk data".to_vec(),
            "did:exo:analyst".into(),
            "internal".into(),
        );

        assert_eq!(capture.count(), 1);
        let results = capture.for_decision(&decision_id);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Risk Report");
    }

    #[test]
    fn test_evidence_integrity_verification() {
        let mut capture = EvidenceCapture::new();
        capture.capture(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            EvidenceCategory::LegalReview,
            "Legal Opinion".into(),
            "Outside counsel opinion".into(),
            b"legal content".to_vec(),
            "did:exo:counsel".into(),
            "external".into(),
        );

        let results = capture.verify_all();
        assert!(results.iter().all(|(_, ok)| *ok));
    }
}
