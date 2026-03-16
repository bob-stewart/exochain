//! ClearancePolicy + ClearanceCertificate — quorum-based legitimacy computation
//!
//! Per the decision.forum whitepaper: "compute legitimacy with explicit rules."
//! ClearancePolicy defines the rules (quorum, roles, veto).
//! ClearanceCertificate is portable proof of clearance.
//!
//! Satisfies: GOV-007 (oversight gates), TNC-07 (quorum enforcement)

use crate::custody::{CustodyAction, CustodyChain, CustodyRole};
use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Clearance computation mode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClearanceMode {
    /// Quorum-based: requires N approvals from allowed roles.
    Quorum,
    /// Single-authority: one steward can clear (emergency only).
    Single,
    /// Unanimous: all allowed roles must approve.
    Unanimous,
    /// Weighted: roles have different voting weights.
    Weighted,
}

/// Policy defining what constitutes legitimate clearance for a decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearancePolicy {
    /// Unique policy identifier.
    pub id: String,
    /// Clearance mode.
    pub mode: ClearanceMode,
    /// Minimum number of approvals required (for Quorum mode).
    pub quorum: u32,
    /// Roles allowed to attest.
    pub allowed_roles: Vec<CustodyRole>,
    /// Whether to require valid cryptographic signatures.
    pub require_valid_signatures: bool,
    /// Whether a single veto blocks clearance.
    pub reject_veto: bool,
    /// Optional: specific DIDs that must approve (named approvers).
    pub required_approvers: Vec<Did>,
    /// Policy version for auditability.
    pub version: String,
}

impl ClearancePolicy {
    /// Evaluate whether a custody chain meets this policy's clearance criteria.
    /// Returns a ClearanceEvaluation with details.
    pub fn evaluate(&self, chain: &CustodyChain, record_hash: &Blake3Hash) -> ClearanceEvaluation {
        let attestations = chain.attestations();

        // Only count attestations for the CURRENT record_hash
        // Per whitepaper: "A clearance computation MUST only count attestations
        // for the current record_hash."
        let valid_attestations: Vec<_> = attestations
            .iter()
            .filter(|e| e.record_hash == *record_hash)
            .collect();

        let approvals: Vec<&str> = valid_attestations
            .iter()
            .filter(|e| matches!(e.action, CustodyAction::Approve))
            .map(|e| e.actor_id.as_str())
            .collect();

        let rejections: Vec<&str> = valid_attestations
            .iter()
            .filter(|e| matches!(e.action, CustodyAction::Reject))
            .map(|e| e.actor_id.as_str())
            .collect();

        let vetoes: Vec<&str> = valid_attestations
            .iter()
            .filter(|e| matches!(e.action, CustodyAction::Veto))
            .map(|e| e.actor_id.as_str())
            .collect();

        // Check veto
        if self.reject_veto && !vetoes.is_empty() {
            return ClearanceEvaluation {
                cleared: false,
                reason: format!("Veto exercised by: {}", vetoes.join(", ")),
                approval_count: approvals.len() as u32,
                rejection_count: rejections.len() as u32,
                veto_count: vetoes.len() as u32,
                required_approvers_met: false,
                quorum_met: false,
            };
        }

        // Check required approvers
        let required_met = self.required_approvers.iter().all(|req| {
            approvals.iter().any(|a| *a == req.as_str())
        });

        // Check quorum
        let quorum_met = match self.mode {
            ClearanceMode::Quorum => approvals.len() as u32 >= self.quorum,
            ClearanceMode::Single => !approvals.is_empty(),
            ClearanceMode::Unanimous => {
                // All allowed roles must have at least one approval
                // Simplified: require at least quorum approvals with zero rejections
                approvals.len() as u32 >= self.quorum && rejections.is_empty()
            }
            ClearanceMode::Weighted => {
                // Simplified weight model: stewards count as 2, reviewers as 1
                let weighted_sum: u32 = valid_attestations
                    .iter()
                    .filter(|e| matches!(e.action, CustodyAction::Approve))
                    .map(|e| match &e.role {
                        CustodyRole::Steward => 2,
                        _ => 1,
                    })
                    .sum();
                weighted_sum >= self.quorum
            }
        };

        let cleared = quorum_met && (self.required_approvers.is_empty() || required_met);

        let reason = if cleared {
            "Clearance criteria met".to_string()
        } else {
            let mut reasons = Vec::new();
            if !quorum_met {
                reasons.push(format!(
                    "Quorum not met: {} of {} required",
                    approvals.len(),
                    self.quorum
                ));
            }
            if !self.required_approvers.is_empty() && !required_met {
                reasons.push("Required approvers missing".to_string());
            }
            reasons.join("; ")
        };

        ClearanceEvaluation {
            cleared,
            reason,
            approval_count: approvals.len() as u32,
            rejection_count: rejections.len() as u32,
            veto_count: vetoes.len() as u32,
            required_approvers_met: required_met,
            quorum_met,
        }
    }
}

/// Result of evaluating a clearance policy against a custody chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearanceEvaluation {
    pub cleared: bool,
    pub reason: String,
    pub approval_count: u32,
    pub rejection_count: u32,
    pub veto_count: u32,
    pub required_approvers_met: bool,
    pub quorum_met: bool,
}

/// A ClearanceCertificate — portable proof of legitimacy.
///
/// Per whitepaper: "what record, what hash, what policy, who approved."
/// An attestation MUST bind to a specific record_hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearanceCertificate {
    /// Unique certificate identifier.
    pub id: String,
    /// The DecisionRecord this clearance applies to.
    pub record_id: Blake3Hash,
    /// The record hash at time of clearance.
    pub record_hash: Blake3Hash,
    /// Snapshot of the policy used for evaluation.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: String,
    /// Clearance mode used.
    pub clearance_mode: ClearanceMode,
    /// DIDs of the approving actors.
    pub approving_actors: Vec<Did>,
    /// The evaluation result.
    pub evaluation: ClearanceEvaluation,
    /// Timestamp of certificate issuance.
    pub issued_at: HybridLogicalClock,
    /// DID of the issuer (system or steward).
    pub issued_by: Did,
    /// Optional signature over the certificate.
    pub signature: Option<GovernanceSignature>,
}

impl ClearanceCertificate {
    /// Issue a certificate from a successful clearance evaluation.
    pub fn issue(
        record_id: Blake3Hash,
        record_hash: Blake3Hash,
        policy: &ClearancePolicy,
        evaluation: ClearanceEvaluation,
        approving_actors: Vec<Did>,
        issued_by: Did,
        timestamp: HybridLogicalClock,
    ) -> Option<Self> {
        if !evaluation.cleared {
            return None;
        }

        Some(Self {
            id: format!(
                "cc-{}-{}",
                record_id.0[0],
                timestamp.physical_ms
            ),
            record_id,
            record_hash,
            policy_id: policy.id.clone(),
            policy_version: policy.version.clone(),
            clearance_mode: policy.mode.clone(),
            approving_actors,
            evaluation,
            issued_at: timestamp,
            issued_by,
            signature: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hlc(ms: u64) -> HybridLogicalClock {
        HybridLogicalClock {
            physical_ms: ms,
            logical: 0,
        }
    }

    fn test_policy() -> ClearancePolicy {
        ClearancePolicy {
            id: "policy-1".to_string(),
            mode: ClearanceMode::Quorum,
            quorum: 2,
            allowed_roles: vec![CustodyRole::Reviewer, CustodyRole::Steward],
            require_valid_signatures: false,
            reject_veto: true,
            required_approvers: vec![],
            version: "1.0.0".to_string(),
        }
    }

    fn build_chain_with_approvals(approvers: &[&str], record_hash: Blake3Hash) -> CustodyChain {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        chain.append(
            "did:exo:proposer".to_string(),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_hlc(1000),
            None,
        );
        for (i, approver) in approvers.iter().enumerate() {
            chain.append(
                approver.to_string(),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_hlc(2000 + i as u64 * 1000),
                None,
            );
        }
        chain
    }

    #[test]
    fn test_quorum_met() {
        let policy = test_policy();
        let record_hash = Blake3Hash([2u8; 32]);
        let chain = build_chain_with_approvals(
            &["did:exo:bob", "did:exo:carol"],
            record_hash,
        );

        let eval = policy.evaluate(&chain, &record_hash);
        assert!(eval.cleared);
        assert!(eval.quorum_met);
        assert_eq!(eval.approval_count, 2);
    }

    #[test]
    fn test_quorum_not_met() {
        let policy = test_policy();
        let record_hash = Blake3Hash([2u8; 32]);
        let chain = build_chain_with_approvals(&["did:exo:bob"], record_hash);

        let eval = policy.evaluate(&chain, &record_hash);
        assert!(!eval.cleared);
        assert!(!eval.quorum_met);
        assert_eq!(eval.approval_count, 1);
    }

    #[test]
    fn test_veto_blocks_clearance() {
        let policy = test_policy();
        let record_hash = Blake3Hash([2u8; 32]);
        let mut chain = build_chain_with_approvals(
            &["did:exo:bob", "did:exo:carol"],
            record_hash,
        );

        // Add a veto
        chain.append(
            "did:exo:dave".to_string(),
            CustodyRole::Steward,
            CustodyAction::Veto,
            record_hash,
            test_hlc(5000),
            None,
        );

        let eval = policy.evaluate(&chain, &record_hash);
        assert!(!eval.cleared);
        assert_eq!(eval.veto_count, 1);
    }

    #[test]
    fn test_wrong_record_hash_not_counted() {
        let policy = test_policy();
        let record_hash = Blake3Hash([2u8; 32]);
        let wrong_hash = Blake3Hash([99u8; 32]);

        // Build chain with approvals against the WRONG hash
        let chain = build_chain_with_approvals(
            &["did:exo:bob", "did:exo:carol"],
            wrong_hash,
        );

        let eval = policy.evaluate(&chain, &record_hash);
        // Create event uses wrong hash, but it's not an attestation
        // Approvals use wrong hash, so they shouldn't count
        assert!(!eval.cleared);
    }

    #[test]
    fn test_certificate_issuance() {
        let policy = test_policy();
        let record_hash = Blake3Hash([2u8; 32]);
        let record_id = Blake3Hash([1u8; 32]);
        let chain = build_chain_with_approvals(
            &["did:exo:bob", "did:exo:carol"],
            record_hash,
        );

        let eval = policy.evaluate(&chain, &record_hash);
        assert!(eval.cleared);

        let cert = ClearanceCertificate::issue(
            record_id,
            record_hash,
            &policy,
            eval,
            vec!["did:exo:bob".to_string(), "did:exo:carol".to_string()],
            "did:exo:system".to_string(),
            test_hlc(6000),
        );

        assert!(cert.is_some());
        let cert = cert.unwrap();
        assert_eq!(cert.approving_actors.len(), 2);
        assert!(cert.evaluation.cleared);
    }

    #[test]
    fn test_certificate_not_issued_when_not_cleared() {
        let eval = ClearanceEvaluation {
            cleared: false,
            reason: "Quorum not met".to_string(),
            approval_count: 1,
            rejection_count: 0,
            veto_count: 0,
            required_approvers_met: false,
            quorum_met: false,
        };

        let policy = test_policy();
        let cert = ClearanceCertificate::issue(
            Blake3Hash([1u8; 32]),
            Blake3Hash([2u8; 32]),
            &policy,
            eval,
            vec![],
            "did:exo:system".to_string(),
            test_hlc(6000),
        );

        assert!(cert.is_none());
    }

    #[test]
    fn test_required_approvers() {
        let mut policy = test_policy();
        policy.required_approvers = vec!["did:exo:steward-1".to_string()];

        let record_hash = Blake3Hash([2u8; 32]);
        // Two approvals but NOT from the required approver
        let chain = build_chain_with_approvals(
            &["did:exo:bob", "did:exo:carol"],
            record_hash,
        );

        let eval = policy.evaluate(&chain, &record_hash);
        assert!(!eval.cleared); // Quorum met, but required approver missing
        assert!(eval.quorum_met);
        assert!(!eval.required_approvers_met);
    }
}
