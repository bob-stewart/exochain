//! Shared governance types used across the decision.forum domain.

use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Tenant identifier — opaque string, unique per organization.
pub type TenantId = String;

/// DID identifier — reuses exo-core's Did type.
pub type Did = exo_core::event::Did;

/// Semantic version for constitutional documents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns true if this version is compatible with (>=) `other`.
    pub fn is_compatible_with(&self, other: &SemVer) -> bool {
        self.major == other.major
            && (self.minor > other.minor
                || (self.minor == other.minor && self.patch >= other.patch))
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Classification of decisions determining governance requirements.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DecisionClass {
    /// Operational decisions — routine, low-risk.
    Operational,
    /// Strategic decisions — significant impact, require broader approval.
    Strategic,
    /// Constitutional decisions — amendments to governance framework itself.
    Constitutional,
    /// Financial decisions — monetary commitments above threshold.
    Financial { threshold_cents: u64 },
    /// Emergency decisions — bypass normal process, require ratification.
    Emergency,
    /// Custom tenant-defined decision class.
    Custom(String),
}

impl DecisionClass {
    /// Returns true if this class requires a human gate (TNC-02).
    pub fn requires_human_gate(&self) -> bool {
        matches!(
            self,
            DecisionClass::Constitutional | DecisionClass::Strategic | DecisionClass::Emergency
        )
    }
}

/// Signer type — cryptographically distinguishes human vs AI signatures (TNC-02).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerType {
    /// Human signer — verified through authentication.
    Human,
    /// AI agent signer — acting under a specific delegation with expiry.
    AiAgent {
        delegation_id: Blake3Hash,
        expires_at: u64,
    },
}

/// Governance-aware signature that includes signer type metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceSignature {
    /// DID of the signer.
    pub signer: Did,
    /// Whether this is a human or AI agent signature.
    pub signer_type: SignerType,
    /// Ed25519 signature bytes.
    pub signature: ed25519_dalek::Signature,
    /// Key version used for signing.
    pub key_version: u64,
    /// Timestamp of signature.
    pub timestamp: HybridLogicalClock,
}

/// Actions that can be authorized via delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuthorizedAction {
    CreateDecision,
    AdvanceDecision,
    CastVote,
    GrantDelegation,
    RevokeDelegation,
    RaiseChallenge,
    TakeEmergencyAction,
    AmendConstitution,
    DiscloseConflict,
    Custom(String),
}

/// Reference to evidence attached to a decision (LEG-004, LEG-006).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub id: String,
    pub description: String,
    /// Hash of the evidence content for integrity verification.
    pub content_hash: Blake3Hash,
    pub timestamp: HybridLogicalClock,
    pub author: Did,
}

/// Failure action when a constitutional constraint is violated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureAction {
    /// Block the action entirely.
    Block,
    /// Warn but allow the action to proceed.
    Warn,
    /// Escalate to a higher authority for review.
    Escalate { escalation_target: Did },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_display() {
        let v = SemVer::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_semver_compatibility() {
        let v1 = SemVer::new(1, 2, 0);
        let v2 = SemVer::new(1, 1, 0);
        let v3 = SemVer::new(2, 0, 0);
        assert!(v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_decision_class_human_gate() {
        assert!(DecisionClass::Constitutional.requires_human_gate());
        assert!(DecisionClass::Strategic.requires_human_gate());
        assert!(DecisionClass::Emergency.requires_human_gate());
        assert!(!DecisionClass::Operational.requires_human_gate());
        assert!(!DecisionClass::Financial {
            threshold_cents: 1000
        }
        .requires_human_gate());
    }
}
