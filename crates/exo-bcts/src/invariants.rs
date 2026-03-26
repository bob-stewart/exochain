//! The 9 constitutional invariants enforced by the CGR kernel.
//!
//! These invariants are immutable — they cannot be modified without a
//! constitutional amendment process. Every transaction is checked against
//! all 9 before execution.
//!
//! | ID | Name | Protection |
//! |----|------|------------|
//! | INV-001 | No Self-Modify | Holon cannot modify its own invariants |
//! | INV-002 | No Self-Grant | Cannot grant capabilities to oneself |
//! | INV-003 | Consent Precedes Access | Data access requires prior bailment |
//! | INV-004 | Training Consent | AI training requires explicit consent |
//! | INV-005 | Alignment Floor | Actions below threshold are blocked |
//! | INV-006 | Audit Completeness | Every change cryptographically recorded |
//! | INV-007 | Human Override | Cannot remove human override capability |
//! | INV-008 | Kernel Immutable | Kernel modification requires amendment |
//! | INV-009 | Registry Immutable | Registry modification requires amendment |

use serde::{Deserialize, Serialize};

use crate::transaction::BctsTransaction;

/// The 9 constitutional invariants from EXOCHAIN's architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstitutionalInvariant {
    /// Holon cannot modify its own invariants
    Inv001NoSelfModify,
    /// Cannot grant capabilities to oneself
    Inv002NoSelfGrant,
    /// Data access requires prior consent record
    Inv003ConsentPrecedesAccess,
    /// Data training requires explicit consent
    Inv004TrainingConsentRequired,
    /// Actions blocked if alignment score below threshold
    Inv005AlignmentFloor,
    /// Every state change recorded with cryptographic evidence
    Inv006AuditCompleteness,
    /// System cannot remove human override capability
    Inv007HumanOverridePreserved,
    /// Kernel modification requires constitutional amendment
    Inv008KernelImmutable,
    /// Invariant registry modification requires amendment
    Inv009RegistryImmutable,
}

impl std::fmt::Display for ConstitutionalInvariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inv001NoSelfModify => write!(f, "INV-001 No Self-Modify"),
            Self::Inv002NoSelfGrant => write!(f, "INV-002 No Self-Grant"),
            Self::Inv003ConsentPrecedesAccess => write!(f, "INV-003 Consent Precedes Access"),
            Self::Inv004TrainingConsentRequired => write!(f, "INV-004 Training Consent Required"),
            Self::Inv005AlignmentFloor => write!(f, "INV-005 Alignment Floor"),
            Self::Inv006AuditCompleteness => write!(f, "INV-006 Audit Completeness"),
            Self::Inv007HumanOverridePreserved => write!(f, "INV-007 Human Override Preserved"),
            Self::Inv008KernelImmutable => write!(f, "INV-008 Kernel Immutable"),
            Self::Inv009RegistryImmutable => write!(f, "INV-009 Registry Immutable"),
        }
    }
}

pub const ALL_INVARIANTS: &[ConstitutionalInvariant] = &[
    ConstitutionalInvariant::Inv001NoSelfModify,
    ConstitutionalInvariant::Inv002NoSelfGrant,
    ConstitutionalInvariant::Inv003ConsentPrecedesAccess,
    ConstitutionalInvariant::Inv004TrainingConsentRequired,
    ConstitutionalInvariant::Inv005AlignmentFloor,
    ConstitutionalInvariant::Inv006AuditCompleteness,
    ConstitutionalInvariant::Inv007HumanOverridePreserved,
    ConstitutionalInvariant::Inv008KernelImmutable,
    ConstitutionalInvariant::Inv009RegistryImmutable,
];

/// Context for invariant checking
#[derive(Debug, Clone)]
pub struct InvariantContext {
    pub actor_did: String,
    pub actor_capabilities: Vec<String>,
    pub active_bailment_ids: Vec<String>,
    pub is_human_override_available: bool,
    pub alignment_score: Option<f64>,
    pub alignment_threshold: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheckResult {
    pub invariant: ConstitutionalInvariant,
    pub passed: bool,
    pub evidence: Option<String>,
    pub violation: Option<String>,
}

pub fn check_invariant(
    inv: ConstitutionalInvariant,
    tx: &BctsTransaction,
    ctx: &InvariantContext,
) -> InvariantCheckResult {
    match inv {
        ConstitutionalInvariant::Inv001NoSelfModify => {
            let violates = tx.envelope.action.starts_with("modify:invariant")
                && tx.envelope.actor_did == ctx.actor_did;
            result(inv, !violates, "no self-modification attempted", "actor attempted to modify its own invariants")
        }
        ConstitutionalInvariant::Inv002NoSelfGrant => {
            let target = tx.envelope.payload.get("target_did").and_then(|v| v.as_str());
            let violates = (tx.envelope.action.starts_with("grant:") || tx.envelope.action.starts_with("escalate:"))
                && target == Some(tx.envelope.actor_did.as_str());
            result(inv, !violates, "no self-grant attempted", "actor attempted to grant capabilities to itself")
        }
        ConstitutionalInvariant::Inv003ConsentPrecedesAccess => {
            let has = !ctx.active_bailment_ids.is_empty();
            result(inv, has, &format!("active bailments: {}", ctx.active_bailment_ids.len()), "no active bailment — consent must precede access")
        }
        ConstitutionalInvariant::Inv004TrainingConsentRequired => {
            let is_training = tx.envelope.action.starts_with("train:") || tx.envelope.action.starts_with("fine-tune:");
            if !is_training {
                return result(inv, true, "not a training action", "");
            }
            let has = !ctx.active_bailment_ids.is_empty();
            result(inv, has, "training consent confirmed", "AI training requires explicit consent via bailment")
        }
        ConstitutionalInvariant::Inv005AlignmentFloor => {
            match (ctx.alignment_score, ctx.alignment_threshold) {
                (Some(score), Some(threshold)) => {
                    let passed = score >= threshold;
                    result(inv, passed, &format!("alignment {score} >= {threshold}"), &format!("alignment {score} below threshold {threshold}"))
                }
                _ => result(inv, true, "no alignment threshold configured", ""),
            }
        }
        ConstitutionalInvariant::Inv006AuditCompleteness => {
            let passed = !tx.ledger.is_empty() || tx.state == crate::states::BctsState::Draft;
            result(inv, passed, &format!("{} ledger events recorded", tx.ledger.len()), "state change without audit record")
        }
        ConstitutionalInvariant::Inv007HumanOverridePreserved => {
            result(inv, ctx.is_human_override_available, "human override available", "system must preserve human override capability")
        }
        ConstitutionalInvariant::Inv008KernelImmutable => {
            let violates = tx.envelope.action.starts_with("modify:kernel");
            result(inv, !violates, "no kernel modification attempted", "kernel modification requires constitutional amendment")
        }
        ConstitutionalInvariant::Inv009RegistryImmutable => {
            let violates = tx.envelope.action.starts_with("modify:registry");
            result(inv, !violates, "no registry modification attempted", "registry modification requires constitutional amendment")
        }
    }
}

fn result(inv: ConstitutionalInvariant, passed: bool, evidence: &str, violation: &str) -> InvariantCheckResult {
    InvariantCheckResult {
        invariant: inv,
        passed,
        evidence: if passed { Some(evidence.to_string()) } else { None },
        violation: if !passed { Some(violation.to_string()) } else { None },
    }
}

/// Check all 9 invariants
pub fn check_all_invariants(
    tx: &BctsTransaction,
    ctx: &InvariantContext,
) -> Vec<InvariantCheckResult> {
    ALL_INVARIANTS.iter().map(|inv| check_invariant(*inv, tx, ctx)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{create_transaction, SignerType};

    fn default_ctx() -> InvariantContext {
        InvariantContext {
            actor_did: "did:user:1".to_string(),
            actor_capabilities: vec![],
            active_bailment_ids: vec!["b1".to_string()],
            is_human_override_available: true,
            alignment_score: None,
            alignment_threshold: None,
        }
    }

    #[test]
    fn test_all_pass_for_normal_action() {
        let tx = create_transaction("did:user:1", "submit:case", serde_json::json!({}), SignerType::Human, vec![]);
        let results = check_all_invariants(&tx, &default_ctx());
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn test_consent_fails_without_bailment() {
        let tx = create_transaction("did:user:1", "read:data", serde_json::json!({}), SignerType::Human, vec![]);
        let mut ctx = default_ctx();
        ctx.active_bailment_ids.clear();
        let r = check_invariant(ConstitutionalInvariant::Inv003ConsentPrecedesAccess, &tx, &ctx);
        assert!(!r.passed);
    }

    #[test]
    fn test_self_grant_blocked() {
        let tx = create_transaction("did:user:1", "grant:admin", serde_json::json!({"target_did": "did:user:1"}), SignerType::Human, vec![]);
        let r = check_invariant(ConstitutionalInvariant::Inv002NoSelfGrant, &tx, &default_ctx());
        assert!(!r.passed);
    }
}
