use super::decision_object::{DecisionClass, DecisionObject, SignerType, Status, VoteChoice};

/// All 10 Trust-Critical Non-Negotiable Controls enforced here.
pub struct TNCEnforcer;

const MAX_AUTHORITY_CHAIN_DEPTH: usize = 5;

impl TNCEnforcer {
    pub fn enforce_all(obj: &DecisionObject) -> Result<(), String> {
        Self::tnc01_authority_chain(obj)?;
        Self::tnc02_human_gate(obj)?;
        Self::tnc03_audit_continuity(obj)?;
        Self::tnc04_sync_constraints(obj)?;
        Self::tnc05_delegation_expiry(obj)?;
        Self::tnc06_conflict_disclosure(obj)?;
        Self::tnc07_quorum(obj)?;
        Self::tnc08_immutability(obj)?;
        Self::tnc09_ai_ceiling(obj)?;
        Self::tnc10_ratification(obj)?;
        Ok(())
    }

    /// TNC-01: Authority chain must be non-empty, all links must have non-empty
    /// pubkey and signature, and chain length must not exceed MAX_AUTHORITY_CHAIN_DEPTH.
    fn tnc01_authority_chain(obj: &DecisionObject) -> Result<(), String> {
        if obj.authority_chain.is_empty() {
            return Err("TNC-01 violated: authority chain is empty".into());
        }
        if obj.authority_chain.len() > MAX_AUTHORITY_CHAIN_DEPTH {
            return Err(format!(
                "TNC-01 violated: authority chain length {} exceeds max depth {}",
                obj.authority_chain.len(),
                MAX_AUTHORITY_CHAIN_DEPTH
            ));
        }
        for (i, link) in obj.authority_chain.iter().enumerate() {
            if link.pubkey.is_empty() {
                return Err(format!(
                    "TNC-01 violated: authority link {} has empty pubkey",
                    i
                ));
            }
            if link.signature.is_empty() {
                return Err(format!(
                    "TNC-01 violated: authority link {} has empty signature",
                    i
                ));
            }
        }
        Ok(())
    }

    /// TNC-02: Strategic and Constitutional decisions require a Human signer.
    fn tnc02_human_gate(obj: &DecisionObject) -> Result<(), String> {
        match obj.decision_class {
            DecisionClass::Strategic | DecisionClass::Constitutional => {
                if let SignerType::AiAgent { .. } = obj.signer_type {
                    return Err(format!(
                        "TNC-02 violated: {:?} decisions require a human signer, got AI agent",
                        obj.decision_class
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// TNC-03: Audit sequence must be > 0 and prev_audit_hash must be non-empty,
    /// ensuring a continuous audit hash chain.
    fn tnc03_audit_continuity(obj: &DecisionObject) -> Result<(), String> {
        if obj.audit_sequence == 0 {
            return Err("TNC-03 violated: audit_sequence must be > 0".into());
        }
        if obj.prev_audit_hash.is_empty() {
            return Err("TNC-03 violated: prev_audit_hash is empty (broken audit chain)".into());
        }
        Ok(())
    }

    /// TNC-04: Constitution binding — constitution_hash and constitution_version
    /// must both be non-empty.
    fn tnc04_sync_constraints(obj: &DecisionObject) -> Result<(), String> {
        if obj.constitution_hash.is_empty() {
            return Err("TNC-04 violated: constitution_hash is empty".into());
        }
        if obj.constitution_version.is_empty() {
            return Err("TNC-04 violated: constitution_version is empty".into());
        }
        Ok(())
    }

    /// TNC-05: Every delegation in the chain must have an expiry in the future
    /// relative to the decision's created_at timestamp.
    fn tnc05_delegation_expiry(obj: &DecisionObject) -> Result<(), String> {
        for (i, d) in obj.delegation_chain.iter().enumerate() {
            if d.expires_at <= obj.created_at {
                return Err(format!(
                    "TNC-05 violated: delegation {} (delegator={}) expired at {} before decision created at {}",
                    i, d.delegator, d.expires_at, obj.created_at
                ));
            }
        }
        Ok(())
    }

    /// TNC-06: For Operational, Strategic, and Constitutional decisions,
    /// at least one conflict disclosure must be filed.
    fn tnc06_conflict_disclosure(obj: &DecisionObject) -> Result<(), String> {
        match obj.decision_class {
            DecisionClass::Operational
            | DecisionClass::Strategic
            | DecisionClass::Constitutional => {
                if obj.conflicts_disclosed.is_empty() {
                    return Err(format!(
                        "TNC-06 violated: {:?} decisions require at least one conflict disclosure",
                        obj.decision_class
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// TNC-07: For terminal statuses (Approved/Rejected), verify vote count
    /// meets quorum and approval percentage meets threshold.
    fn tnc07_quorum(obj: &DecisionObject) -> Result<(), String> {
        match obj.status {
            Status::Approved | Status::Rejected => {
                let vote_count = obj.votes.len() as u32;
                if vote_count < obj.quorum_required {
                    return Err(format!(
                        "TNC-07 violated: {} votes cast but {} required for quorum",
                        vote_count, obj.quorum_required
                    ));
                }
                if obj.quorum_required > 0 && !obj.votes.is_empty() {
                    let approve_count = obj
                        .votes
                        .iter()
                        .filter(|v| v.choice == VoteChoice::Approve)
                        .count() as f64;
                    let total = obj.votes.len() as f64;
                    let pct = (approve_count / total) * 100.0;
                    if obj.status == Status::Approved && pct < obj.quorum_threshold_pct {
                        return Err(format!(
                            "TNC-07 violated: approval percentage {:.1}% is below threshold {:.1}%",
                            pct, obj.quorum_threshold_pct
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// TNC-08: Terminal statuses (Approved, Rejected, Void) require a non-empty
    /// merkle_root and at least one piece of evidence.
    fn tnc08_immutability(obj: &DecisionObject) -> Result<(), String> {
        match obj.status {
            Status::Approved | Status::Rejected | Status::Void => {
                if obj.merkle_root.is_empty() {
                    return Err(
                        "TNC-08 violated: terminal status without immutable merkle root".into(),
                    );
                }
                if obj.evidence.is_empty() {
                    return Err(
                        "TNC-08 violated: terminal status without evidence record".into(),
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// TNC-09: If the signer is an AI agent, the decision_class must not exceed
    /// the agent's ceiling_class.
    fn tnc09_ai_ceiling(obj: &DecisionObject) -> Result<(), String> {
        if let SignerType::AiAgent {
            ref ceiling_class, ..
        } = obj.signer_type
        {
            if obj.decision_class > *ceiling_class {
                return Err(format!(
                    "TNC-09 violated: decision class {:?} exceeds AI ceiling {:?}",
                    obj.decision_class, ceiling_class
                ));
            }
        }
        Ok(())
    }

    /// TNC-10: If ratification is required, a deadline must be set and be in the future.
    fn tnc10_ratification(obj: &DecisionObject) -> Result<(), String> {
        if obj.requires_ratification {
            match &obj.ratification_deadline {
                None => {
                    return Err(
                        "TNC-10 violated: ratification required but no deadline set".into(),
                    );
                }
                Some(deadline) => {
                    if *deadline <= chrono::Utc::now() {
                        return Err(format!(
                            "TNC-10 violated: ratification deadline {} has passed",
                            deadline
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthorityLink;
    use crate::decision_object::*;

    fn base_decision() -> DecisionObject {
        DecisionObject::new("Test Decision")
    }

    #[test]
    fn test_tnc01_empty_chain_fails() {
        let mut obj = base_decision();
        obj.authority_chain = vec![];
        let result = TNCEnforcer::tnc01_authority_chain(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNC-01"));
    }

    #[test]
    fn test_tnc01_too_long_chain_fails() {
        let mut obj = base_decision();
        obj.authority_chain = (0..6)
            .map(|i| AuthorityLink {
                pubkey: format!("key-{}", i),
                signature: format!("sig-{}", i),
            })
            .collect();
        let result = TNCEnforcer::tnc01_authority_chain(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max depth"));
    }

    #[test]
    fn test_tnc01_empty_pubkey_fails() {
        let mut obj = base_decision();
        obj.authority_chain = vec![AuthorityLink {
            pubkey: "".to_string(),
            signature: "sig".to_string(),
        }];
        let result = TNCEnforcer::tnc01_authority_chain(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty pubkey"));
    }

    #[test]
    fn test_tnc01_valid_chain_passes() {
        let obj = base_decision();
        assert!(TNCEnforcer::tnc01_authority_chain(&obj).is_ok());
    }

    #[test]
    fn test_tnc02_strategic_ai_fails() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Strategic;
        obj.signer_type = SignerType::AiAgent {
            delegation_id: "d1".into(),
            ceiling_class: DecisionClass::Strategic,
        };
        let result = TNCEnforcer::tnc02_human_gate(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNC-02"));
    }

    #[test]
    fn test_tnc02_routine_ai_passes() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Routine;
        obj.signer_type = SignerType::AiAgent {
            delegation_id: "d1".into(),
            ceiling_class: DecisionClass::Routine,
        };
        assert!(TNCEnforcer::tnc02_human_gate(&obj).is_ok());
    }

    #[test]
    fn test_tnc03_zero_sequence_fails() {
        let mut obj = base_decision();
        obj.audit_sequence = 0;
        let result = TNCEnforcer::tnc03_audit_continuity(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc03_empty_prev_hash_fails() {
        let mut obj = base_decision();
        obj.prev_audit_hash = "".to_string();
        let result = TNCEnforcer::tnc03_audit_continuity(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc04_empty_constitution_hash_fails() {
        let mut obj = base_decision();
        obj.constitution_hash = "".to_string();
        let result = TNCEnforcer::tnc04_sync_constraints(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc04_empty_version_fails() {
        let mut obj = base_decision();
        obj.constitution_version = "".to_string();
        let result = TNCEnforcer::tnc04_sync_constraints(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc05_expired_delegation_fails() {
        let mut obj = base_decision();
        obj.delegation_chain = vec![DelegationRecord {
            delegator: "alice".into(),
            delegate: "bob".into(),
            scope: "all".into(),
            expires_at: obj.created_at - chrono::Duration::hours(1),
            allows_sub_delegation: false,
        }];
        let result = TNCEnforcer::tnc05_delegation_expiry(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNC-05"));
    }

    #[test]
    fn test_tnc05_valid_delegation_passes() {
        let mut obj = base_decision();
        obj.delegation_chain = vec![DelegationRecord {
            delegator: "alice".into(),
            delegate: "bob".into(),
            scope: "all".into(),
            expires_at: obj.created_at + chrono::Duration::hours(24),
            allows_sub_delegation: false,
        }];
        assert!(TNCEnforcer::tnc05_delegation_expiry(&obj).is_ok());
    }

    #[test]
    fn test_tnc06_operational_no_disclosure_fails() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Operational;
        obj.conflicts_disclosed = vec![];
        let result = TNCEnforcer::tnc06_conflict_disclosure(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc06_routine_no_disclosure_passes() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Routine;
        obj.conflicts_disclosed = vec![];
        assert!(TNCEnforcer::tnc06_conflict_disclosure(&obj).is_ok());
    }

    #[test]
    fn test_tnc07_insufficient_votes_fails() {
        let mut obj = base_decision();
        obj.status = Status::Approved;
        obj.quorum_required = 3;
        obj.quorum_threshold_pct = 50.0;
        obj.votes = vec![Vote {
            voter_did: "did:ex:1".into(),
            choice: VoteChoice::Approve,
            signer_type: SignerType::Human,
        }];
        let result = TNCEnforcer::tnc07_quorum(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNC-07"));
    }

    #[test]
    fn test_tnc07_below_threshold_fails() {
        let mut obj = base_decision();
        obj.status = Status::Approved;
        obj.quorum_required = 2;
        obj.quorum_threshold_pct = 75.0;
        obj.votes = vec![
            Vote { voter_did: "did:ex:1".into(), choice: VoteChoice::Approve, signer_type: SignerType::Human },
            Vote { voter_did: "did:ex:2".into(), choice: VoteChoice::Reject, signer_type: SignerType::Human },
        ];
        let result = TNCEnforcer::tnc07_quorum(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("approval percentage"));
    }

    #[test]
    fn test_tnc07_draft_skips_quorum() {
        let obj = base_decision();
        assert!(TNCEnforcer::tnc07_quorum(&obj).is_ok());
    }

    #[test]
    fn test_tnc08_approved_no_evidence_fails() {
        let mut obj = base_decision();
        obj.status = Status::Approved;
        obj.evidence = vec![];
        let result = TNCEnforcer::tnc08_immutability(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc08_draft_no_evidence_passes() {
        let mut obj = base_decision();
        obj.status = Status::Draft;
        obj.evidence = vec![];
        assert!(TNCEnforcer::tnc08_immutability(&obj).is_ok());
    }

    #[test]
    fn test_tnc09_ai_exceeds_ceiling_fails() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Strategic;
        obj.signer_type = SignerType::AiAgent {
            delegation_id: "d1".into(),
            ceiling_class: DecisionClass::Operational,
        };
        let result = TNCEnforcer::tnc09_ai_ceiling(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNC-09"));
    }

    #[test]
    fn test_tnc09_ai_within_ceiling_passes() {
        let mut obj = base_decision();
        obj.decision_class = DecisionClass::Routine;
        obj.signer_type = SignerType::AiAgent {
            delegation_id: "d1".into(),
            ceiling_class: DecisionClass::Operational,
        };
        assert!(TNCEnforcer::tnc09_ai_ceiling(&obj).is_ok());
    }

    #[test]
    fn test_tnc10_ratification_required_no_deadline_fails() {
        let mut obj = base_decision();
        obj.requires_ratification = true;
        obj.ratification_deadline = None;
        let result = TNCEnforcer::tnc10_ratification(&obj);
        assert!(result.is_err());
    }

    #[test]
    fn test_tnc10_ratification_not_required_passes() {
        let obj = base_decision();
        assert!(TNCEnforcer::tnc10_ratification(&obj).is_ok());
    }

    #[test]
    fn test_tnc10_ratification_future_deadline_passes() {
        let mut obj = base_decision();
        obj.requires_ratification = true;
        obj.ratification_deadline = Some(chrono::Utc::now() + chrono::Duration::days(30));
        assert!(TNCEnforcer::tnc10_ratification(&obj).is_ok());
    }

    #[test]
    fn test_enforce_all_passes_for_default() {
        let obj = base_decision();
        assert!(TNCEnforcer::enforce_all(&obj).is_ok());
    }
}
