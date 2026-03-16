//! Challenge Objects — contestation, reversal, and resolution.
//!
//! Satisfies: GOV-008

use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Status of a challenge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Challenge filed — decision execution is paused.
    Filed,
    /// Under review by appropriate authority.
    UnderReview,
    /// Challenge upheld — decision will be reversed.
    Upheld,
    /// Challenge denied — decision stands.
    Denied,
    /// Challenge withdrawn by challenger.
    Withdrawn,
}

/// A Challenge Object linked to a contested decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeObject {
    /// Unique identifier.
    pub id: Blake3Hash,
    /// Tenant context.
    pub tenant_id: TenantId,
    /// The decision being challenged.
    pub contested_decision_id: Blake3Hash,
    /// Who filed the challenge.
    pub challenger: Did,
    /// Grounds for the challenge.
    pub grounds: ChallengeGrounds,
    /// Detailed rationale.
    pub rationale: String,
    /// Supporting evidence.
    pub evidence: Vec<EvidenceRef>,
    /// Current status.
    pub status: ChallengeStatus,
    /// Resolution (if resolved).
    pub resolution: Option<ChallengeResolution>,
    /// Filing timestamp.
    pub filed_at: HybridLogicalClock,
    /// Challenger's signature.
    pub signature: GovernanceSignature,
}

/// Grounds for challenging a decision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeGrounds {
    /// Authority chain was invalid at time of decision.
    AuthorityChainInvalid,
    /// Constitutional constraint was violated.
    ConstitutionalViolation,
    /// Quorum was not properly verified.
    QuorumViolation,
    /// Conflict of interest was undisclosed.
    UndisclosedConflict,
    /// Procedural error in the decision process.
    ProceduralError,
    /// New evidence materially changes the outcome.
    NewEvidence,
    /// Other grounds.
    Other(String),
}

/// Resolution of a challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeResolution {
    /// Who resolved the challenge.
    pub resolver: Did,
    /// The resolution decision (itself a new Decision Object).
    pub resolution_decision_id: Blake3Hash,
    /// Whether the original decision is reversed.
    pub reversal: bool,
    /// If reversed, the reversal linkage (immutable).
    pub reversal_decision_id: Option<Blake3Hash>,
    /// Resolution timestamp.
    pub resolved_at: HybridLogicalClock,
    /// Explanation.
    pub explanation: String,
    /// Resolver's signature.
    pub signature: GovernanceSignature,
}

impl ChallengeObject {
    /// File a new challenge against a decision.
    ///
    /// Returns the challenge and the new Contested status that must be applied
    /// to the decision (GOV-008: contestation pauses execution).
    #[allow(clippy::too_many_arguments)]
    pub fn file(
        id: Blake3Hash,
        tenant_id: TenantId,
        contested_decision_id: Blake3Hash,
        challenger: Did,
        grounds: ChallengeGrounds,
        rationale: String,
        evidence: Vec<EvidenceRef>,
        filed_at: HybridLogicalClock,
        signature: GovernanceSignature,
    ) -> Self {
        Self {
            id,
            tenant_id,
            contested_decision_id,
            challenger,
            grounds,
            rationale,
            evidence,
            status: ChallengeStatus::Filed,
            resolution: None,
            filed_at,
            signature,
        }
    }

    /// Move challenge to UnderReview.
    pub fn begin_review(&mut self) -> Result<(), &'static str> {
        if self.status != ChallengeStatus::Filed {
            return Err("Can only begin review from Filed status");
        }
        self.status = ChallengeStatus::UnderReview;
        Ok(())
    }

    /// Resolve the challenge (upheld or denied).
    ///
    /// If upheld with reversal=true, creates an immutable REVERSAL linkage (GOV-008).
    pub fn resolve(&mut self, resolution: ChallengeResolution) -> Result<(), &'static str> {
        if self.status != ChallengeStatus::UnderReview {
            return Err("Can only resolve from UnderReview status");
        }
        self.status = if resolution.reversal {
            ChallengeStatus::Upheld
        } else {
            ChallengeStatus::Denied
        };
        self.resolution = Some(resolution);
        Ok(())
    }

    /// Withdraw the challenge.
    pub fn withdraw(&mut self) -> Result<(), &'static str> {
        if matches!(
            self.status,
            ChallengeStatus::Upheld | ChallengeStatus::Denied
        ) {
            return Err("Cannot withdraw a resolved challenge");
        }
        self.status = ChallengeStatus::Withdrawn;
        Ok(())
    }

    /// Check if this challenge requires the decision to be paused.
    pub fn requires_pause(&self) -> bool {
        matches!(
            self.status,
            ChallengeStatus::Filed | ChallengeStatus::UnderReview
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_statuses() {
        let statuses = vec![
            ChallengeStatus::Filed,
            ChallengeStatus::UnderReview,
            ChallengeStatus::Upheld,
            ChallengeStatus::Denied,
            ChallengeStatus::Withdrawn,
        ];
        // All statuses should be distinct
        for (i, a) in statuses.iter().enumerate() {
            for (j, b) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_challenge_grounds_variants() {
        let g = ChallengeGrounds::ConstitutionalViolation;
        assert_eq!(g, ChallengeGrounds::ConstitutionalViolation);
        assert_ne!(g, ChallengeGrounds::AuthorityChainInvalid);
    }

    fn test_sig(signer: &str) -> GovernanceSignature {
        GovernanceSignature {
            signer: signer.to_string(),
            signer_type: SignerType::Human,
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            key_version: 1,
            timestamp: HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
        }
    }

    #[test]
    fn test_file_and_review_challenge() {
        let mut ch = ChallengeObject::file(
            Blake3Hash([1u8; 32]),
            "t1".into(),
            Blake3Hash([2u8; 32]),
            "did:exo:bob".into(),
            ChallengeGrounds::ConstitutionalViolation,
            "The decision violated bylaws section 3.2".into(),
            vec![],
            HybridLogicalClock {
                physical_ms: 5000,
                logical: 0,
            },
            test_sig("did:exo:bob"),
        );

        assert_eq!(ch.status, ChallengeStatus::Filed);
        assert!(ch.requires_pause());

        ch.begin_review().unwrap();
        assert_eq!(ch.status, ChallengeStatus::UnderReview);
        assert!(ch.requires_pause());
    }

    #[test]
    fn test_resolve_upheld_reversal() {
        let mut ch = ChallengeObject::file(
            Blake3Hash([1u8; 32]),
            "t1".into(),
            Blake3Hash([2u8; 32]),
            "did:exo:bob".into(),
            ChallengeGrounds::UndisclosedConflict,
            "Undisclosed financial interest".into(),
            vec![],
            HybridLogicalClock {
                physical_ms: 5000,
                logical: 0,
            },
            test_sig("did:exo:bob"),
        );

        ch.begin_review().unwrap();
        ch.resolve(ChallengeResolution {
            resolver: "did:exo:admin".into(),
            resolution_decision_id: Blake3Hash([10u8; 32]),
            reversal: true,
            reversal_decision_id: Some(Blake3Hash([11u8; 32])),
            resolved_at: HybridLogicalClock {
                physical_ms: 6000,
                logical: 0,
            },
            explanation: "Conflict confirmed, decision reversed".into(),
            signature: test_sig("did:exo:admin"),
        })
        .unwrap();

        assert_eq!(ch.status, ChallengeStatus::Upheld);
        assert!(!ch.requires_pause());
        assert!(ch.resolution.as_ref().unwrap().reversal);
    }

    #[test]
    fn test_withdraw_challenge() {
        let mut ch = ChallengeObject::file(
            Blake3Hash([1u8; 32]),
            "t1".into(),
            Blake3Hash([2u8; 32]),
            "did:exo:bob".into(),
            ChallengeGrounds::ProceduralError,
            "Procedural error".into(),
            vec![],
            HybridLogicalClock {
                physical_ms: 5000,
                logical: 0,
            },
            test_sig("did:exo:bob"),
        );

        ch.withdraw().unwrap();
        assert_eq!(ch.status, ChallengeStatus::Withdrawn);
        assert!(!ch.requires_pause());
    }
}
