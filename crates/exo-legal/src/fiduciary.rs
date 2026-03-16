//! Fiduciary defense package generation (LEG-012).
//!
//! Assembles comprehensive defense packages demonstrating that fiduciary
//! duties were fulfilled through the governance process.

use chrono::{DateTime, Utc};
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A fiduciary defense package aggregating governance evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefensePackage {
    pub id: Uuid,
    pub decision_id: Blake3Hash,
    pub tenant_id: String,
    pub generated_at: DateTime<Utc>,
    pub elements: Vec<DefenseElement>,
    pub content_hash: Blake3Hash,
}

/// Individual element of a fiduciary defense package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefenseElement {
    pub element_type: DefenseElementType,
    pub description: String,
    pub evidence_hash: Blake3Hash,
    pub satisfied: bool,
}

/// Types of fiduciary defense elements.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefenseElementType {
    /// Duty of care — reasonable inquiry and deliberation.
    DutyOfCare,
    /// Duty of loyalty — no self-dealing, conflicts disclosed.
    DutyOfLoyalty,
    /// Duty of good faith — honest purpose.
    DutyOfGoodFaith,
    /// Business judgment rule — informed, rational decision.
    BusinessJudgmentRule,
    /// Proper authority — valid delegation chain.
    ProperAuthority,
    /// Constitutional compliance — within governance framework.
    ConstitutionalCompliance,
    /// Quorum — proper voting procedures.
    QuorumCompliance,
    /// Record keeping — adequate documentation.
    RecordKeeping,
}

/// Service for generating fiduciary defense packages.
pub struct FiduciaryDefense;

impl FiduciaryDefense {
    /// Generate a defense package for a decision, checking each fiduciary element.
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        decision_id: Blake3Hash,
        tenant_id: String,
        has_evidence: bool,
        conflicts_disclosed: bool,
        authority_verified: bool,
        constitution_compliant: bool,
        quorum_met: bool,
        records_complete: bool,
    ) -> DefensePackage {
        let elements = vec![
            DefenseElement {
                element_type: DefenseElementType::DutyOfCare,
                description: "Evidence of reasonable inquiry and deliberation".into(),
                evidence_hash: decision_id,
                satisfied: has_evidence,
            },
            DefenseElement {
                element_type: DefenseElementType::DutyOfLoyalty,
                description: "Conflict disclosures filed and reviewed".into(),
                evidence_hash: decision_id,
                satisfied: conflicts_disclosed,
            },
            DefenseElement {
                element_type: DefenseElementType::DutyOfGoodFaith,
                description: "Decision made with honest purpose".into(),
                evidence_hash: decision_id,
                satisfied: has_evidence && conflicts_disclosed,
            },
            DefenseElement {
                element_type: DefenseElementType::BusinessJudgmentRule,
                description: "Informed decision with rational basis".into(),
                evidence_hash: decision_id,
                satisfied: has_evidence,
            },
            DefenseElement {
                element_type: DefenseElementType::ProperAuthority,
                description: "Valid authority chain verified".into(),
                evidence_hash: decision_id,
                satisfied: authority_verified,
            },
            DefenseElement {
                element_type: DefenseElementType::ConstitutionalCompliance,
                description: "Decision within constitutional bounds".into(),
                evidence_hash: decision_id,
                satisfied: constitution_compliant,
            },
            DefenseElement {
                element_type: DefenseElementType::QuorumCompliance,
                description: "Proper quorum and voting procedures".into(),
                evidence_hash: decision_id,
                satisfied: quorum_met,
            },
            DefenseElement {
                element_type: DefenseElementType::RecordKeeping,
                description: "Complete and tamper-evident records".into(),
                evidence_hash: decision_id,
                satisfied: records_complete,
            },
        ];

        // Compute real content hash by hashing all element evidence_hashes concatenated
        let mut hash_preimage = Vec::new();
        for element in &elements {
            hash_preimage.extend_from_slice(&element.evidence_hash.0);
        }
        let content_hash = exo_core::crypto::hash_bytes(&hash_preimage);

        DefensePackage {
            id: Uuid::new_v4(),
            decision_id,
            tenant_id,
            generated_at: Utc::now(),
            elements,
            content_hash,
        }
    }

    /// Check if a defense package is complete (all elements satisfied).
    pub fn is_complete(package: &DefensePackage) -> bool {
        package.elements.iter().all(|e| e.satisfied)
    }

    /// Get unsatisfied elements from a defense package.
    pub fn gaps(package: &DefensePackage) -> Vec<&DefenseElement> {
        package.elements.iter().filter(|e| !e.satisfied).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_defense_package() {
        let pkg = FiduciaryDefense::generate(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            true, // has_evidence
            true, // conflicts_disclosed
            true, // authority_verified
            true, // constitution_compliant
            true, // quorum_met
            true, // records_complete
        );

        assert!(FiduciaryDefense::is_complete(&pkg));
        assert!(FiduciaryDefense::gaps(&pkg).is_empty());
        assert_eq!(pkg.elements.len(), 8);
    }

    #[test]
    fn test_incomplete_defense_package() {
        let pkg = FiduciaryDefense::generate(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            true,
            false, // conflicts NOT disclosed
            true,
            true,
            false, // quorum NOT met
            true,
        );

        assert!(!FiduciaryDefense::is_complete(&pkg));
        let gaps = FiduciaryDefense::gaps(&pkg);
        assert!(!gaps.is_empty());
        let gap_types: Vec<_> = gaps.iter().map(|g| &g.element_type).collect();
        assert!(gap_types.contains(&&DefenseElementType::DutyOfLoyalty));
        assert!(gap_types.contains(&&DefenseElementType::QuorumCompliance));
    }
}
