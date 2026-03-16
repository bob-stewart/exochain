//! Authority Chain Verification — the core gate for every governance action.
//!
//! Satisfies: TNC-01 (no bypass ever), GOV-005
//!
//! Every state change in the governance system MUST pass through authority chain
//! verification. The chain traces from the acting agent back through delegations
//! to the constitutional root, verifying at each level:
//! 1. Delegation is active (not expired, not revoked) — TNC-05
//! 2. Scope covers the requested action and decision class
//! 3. Human gate is satisfied where required — TNC-02
//! 4. AI ceiling is not exceeded — TNC-09
//! 5. Chain depth does not exceed constitutional maximum

use exo_core::crypto::Blake3Hash;
use exo_governance::constitution::Constitution;
use exo_governance::delegation::Delegation;
use exo_governance::errors::GovernanceError;
use exo_governance::types::*;

/// Maximum authority chain depth (configurable per constitution, hard cap here).
pub const MAX_CHAIN_DEPTH: usize = 10;

/// Proof that an authority chain was successfully verified.
#[derive(Clone, Debug)]
pub struct ChainProof {
    /// The chain of delegation IDs from root to actor.
    pub chain: Vec<Blake3Hash>,
    /// Depth of the chain.
    pub depth: usize,
    /// Whether a human signer was present in the chain.
    pub has_human_signer: bool,
    /// The actor at the end of the chain.
    pub actor: Did,
    /// The action being authorized.
    pub action: AuthorizedAction,
    /// The decision class being authorized.
    pub decision_class: DecisionClass,
}

/// A break in the authority chain — returned when verification fails.
#[derive(Clone, Debug)]
pub struct ChainBreak {
    /// Where in the chain the break occurred.
    pub depth: usize,
    /// The delegation ID that failed (if applicable).
    pub delegation_id: Option<Blake3Hash>,
    /// The reason for the break.
    pub reason: String,
}

/// Verify the authority chain from an actor back to the constitutional root.
///
/// TNC-01: This function is the SOLE gate. No bypass path exists.
///
/// Parameters:
/// - `actor`: The DID attempting to perform the action
/// - `actor_signer_type`: Whether the actor is human or AI
/// - `action`: The governance action being attempted
/// - `decision_class`: The class of decision being acted upon
/// - `delegations`: All active delegations in scope (caller provides relevant set)
/// - `constitution`: The active constitution for the tenant
/// - `current_time_ms`: Current timestamp for expiry checking
///
/// Returns `ChainProof` on success or `GovernanceError` on failure.
pub fn verify_chain(
    actor: &Did,
    actor_signer_type: &SignerType,
    action: &AuthorizedAction,
    decision_class: &DecisionClass,
    delegations: &[Delegation],
    constitution: &Constitution,
    current_time_ms: u64,
) -> Result<ChainProof, GovernanceError> {
    // TNC-02: Check human gate requirement
    if decision_class.requires_human_gate()
        || constitution.human_gate_classes.contains(decision_class)
    {
        check_human_gate(actor, actor_signer_type, decision_class)?;
    }

    // TNC-09: Check AI ceiling
    if let SignerType::AiAgent { .. } = actor_signer_type {
        check_ai_ceiling(action)?;
    }

    // Find delegation chain from actor back to root
    let chain = trace_chain(
        actor,
        action,
        decision_class,
        delegations,
        current_time_ms,
        constitution.max_delegation_depth as usize,
    )?;

    // Check constitutional constraints (TNC-04: synchronous)
    constitution.check_blocking_constraints(
        decision_class,
        chain.len() as u32,
        None, // quorum checked separately
        None, // approval threshold checked separately
        None, // monetary amount checked at decision level
        matches!(actor_signer_type, SignerType::Human),
    )?;

    let has_human = chain.iter().any(|d_id| {
        delegations
            .iter()
            .find(|d| d.id == *d_id)
            .is_some_and(|d| matches!(d.signature.signer_type, SignerType::Human))
    }) || matches!(actor_signer_type, SignerType::Human);

    Ok(ChainProof {
        depth: chain.len(),
        chain,
        has_human_signer: has_human,
        actor: actor.clone(),
        action: action.clone(),
        decision_class: decision_class.clone(),
    })
}

/// Trace the delegation chain from actor back to a root authority.
fn trace_chain(
    actor: &Did,
    action: &AuthorizedAction,
    decision_class: &DecisionClass,
    delegations: &[Delegation],
    current_time_ms: u64,
    max_depth: usize,
) -> Result<Vec<Blake3Hash>, GovernanceError> {
    let mut chain = Vec::new();
    let mut current_actor = actor.clone();
    let mut depth = 0;

    loop {
        if depth > max_depth {
            return Err(GovernanceError::ChainTooDeep(max_depth));
        }

        // Find a delegation that grants `current_actor` the required authority
        let delegation = delegations
            .iter()
            .find(|d| d.delegatee == current_actor && d.is_active(current_time_ms));

        match delegation {
            Some(d) => {
                // TNC-05: Verify delegation is active (strict expiry)
                if !d.is_active(current_time_ms) {
                    return Err(GovernanceError::DelegationExpired(d.id));
                }

                // Verify scope covers the action
                d.authorizes(action, decision_class, current_time_ms)?;

                chain.push(d.id);
                current_actor = d.delegator.clone();
                depth += 1;

                // If delegator has no parent delegation, they must be a root authority
                if d.parent_delegation.is_none() {
                    break;
                }
            }
            None => {
                if depth == 0 {
                    // Actor has no delegation at all
                    return Err(GovernanceError::AuthorityChainBroken {
                        reason: format!(
                            "No active delegation found for actor {} to perform {:?}",
                            actor, action
                        ),
                    });
                }
                // Current actor has no further delegation — they're the root
                break;
            }
        }
    }

    Ok(chain)
}

/// Check human gate requirement (TNC-02).
fn check_human_gate(
    actor: &Did,
    signer_type: &SignerType,
    decision_class: &DecisionClass,
) -> Result<(), GovernanceError> {
    if let SignerType::AiAgent { .. } = signer_type {
        return Err(GovernanceError::HumanGateViolation {
            class: decision_class.clone(),
            signer: actor.clone(),
        });
    }
    Ok(())
}

/// Check AI delegation ceiling (TNC-09).
/// Certain actions cannot be delegated to AI agents.
fn check_ai_ceiling(action: &AuthorizedAction) -> Result<(), GovernanceError> {
    let forbidden_for_ai = matches!(
        action,
        AuthorizedAction::AmendConstitution | AuthorizedAction::GrantDelegation
    );

    if forbidden_for_ai {
        return Err(GovernanceError::AiCeilingExceeded {
            action: format!("{:?}", action),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use exo_core::hlc::HybridLogicalClock;
    use exo_governance::delegation::DelegationScope;

    fn test_hlc(ms: u64) -> HybridLogicalClock {
        HybridLogicalClock {
            physical_ms: ms,
            logical: 0,
        }
    }

    fn test_sig(signer: &str, signer_type: SignerType) -> GovernanceSignature {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let dummy = Blake3Hash([0u8; 32]);
        let sig = exo_core::compute_signature(&sk, &dummy);
        GovernanceSignature {
            signer: signer.to_string(),
            signer_type,
            signature: sig,
            key_version: 1,
            timestamp: test_hlc(1000),
        }
    }

    fn test_constitution() -> Constitution {
        Constitution {
            tenant_id: "tenant-1".to_string(),
            version: SemVer::new(1, 0, 0),
            hash: Blake3Hash([0u8; 32]),
            documents: vec![],
            decision_classes: vec![],
            human_gate_classes: vec![DecisionClass::Strategic, DecisionClass::Constitutional],
            emergency_authorities: vec![],
            default_delegation_expiry_hours: 720,
            max_delegation_depth: 5,
            created_at: test_hlc(1000),
            signatures: vec![],
        }
    }

    fn test_delegation_chain() -> Vec<Delegation> {
        vec![
            // Root -> Manager
            Delegation {
                id: Blake3Hash([10u8; 32]),
                tenant_id: "tenant-1".to_string(),
                delegator: "did:exo:root".to_string(),
                delegatee: "did:exo:manager".to_string(),
                scope: DelegationScope {
                    decision_classes: vec![DecisionClass::Operational, DecisionClass::Strategic],
                    monetary_cap: Some(100_000_00),
                    resource_ids: vec![],
                    actions: vec![
                        AuthorizedAction::CreateDecision,
                        AuthorizedAction::CastVote,
                        AuthorizedAction::GrantDelegation,
                    ],
                },
                sub_delegation_allowed: true,
                sub_delegation_scope_cap: None,
                created_at: test_hlc(1000),
                expires_at: 10_000_000,
                revoked_at: None,
                constitution_version: SemVer::new(1, 0, 0),
                signature: test_sig("did:exo:root", SignerType::Human),
                parent_delegation: None,
            },
            // Manager -> Alice
            Delegation {
                id: Blake3Hash([11u8; 32]),
                tenant_id: "tenant-1".to_string(),
                delegator: "did:exo:manager".to_string(),
                delegatee: "did:exo:alice".to_string(),
                scope: DelegationScope {
                    decision_classes: vec![DecisionClass::Operational],
                    monetary_cap: Some(10_000_00),
                    resource_ids: vec![],
                    actions: vec![AuthorizedAction::CreateDecision, AuthorizedAction::CastVote],
                },
                sub_delegation_allowed: false,
                sub_delegation_scope_cap: None,
                created_at: test_hlc(2000),
                expires_at: 10_000_000,
                revoked_at: None,
                constitution_version: SemVer::new(1, 0, 0),
                signature: test_sig("did:exo:manager", SignerType::Human),
                parent_delegation: Some(Blake3Hash([10u8; 32])),
            },
        ]
    }

    #[test]
    fn test_tnc01_successful_chain_verification() {
        let delegations = test_delegation_chain();
        let constitution = test_constitution();

        let result = verify_chain(
            &"did:exo:alice".to_string(),
            &SignerType::Human,
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Operational,
            &delegations,
            &constitution,
            5_000_000,
        );

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.depth, 2); // alice -> manager -> root
        assert!(proof.has_human_signer);
    }

    #[test]
    fn test_tnc01_no_delegation_fails() {
        let constitution = test_constitution();

        let result = verify_chain(
            &"did:exo:stranger".to_string(),
            &SignerType::Human,
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Operational,
            &[],
            &constitution,
            5_000_000,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::AuthorityChainBroken { .. }
        ));
    }

    #[test]
    fn test_tnc02_human_gate_blocks_ai() {
        let delegations = test_delegation_chain();
        let constitution = test_constitution();

        // AI agent trying to act on Strategic decision — should fail
        let result = verify_chain(
            &"did:exo:alice".to_string(),
            &SignerType::AiAgent {
                delegation_id: Blake3Hash([99u8; 32]),
                expires_at: 10_000_000,
            },
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Strategic,
            &delegations,
            &constitution,
            5_000_000,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::HumanGateViolation { .. }
        ));
    }

    #[test]
    fn test_tnc05_expired_delegation_fails() {
        let mut delegations = test_delegation_chain();
        // Expire alice's delegation
        delegations[1].expires_at = 1_000;

        let constitution = test_constitution();

        let result = verify_chain(
            &"did:exo:alice".to_string(),
            &SignerType::Human,
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Operational,
            &delegations,
            &constitution,
            5_000_000, // well past expiry
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_tnc09_ai_ceiling() {
        let delegations = test_delegation_chain();
        let constitution = test_constitution();

        // AI agent trying to amend constitution — ceiling violation
        let result = verify_chain(
            &"did:exo:alice".to_string(),
            &SignerType::AiAgent {
                delegation_id: Blake3Hash([99u8; 32]),
                expires_at: 10_000_000,
            },
            &AuthorizedAction::AmendConstitution,
            &DecisionClass::Operational,
            &delegations,
            &constitution,
            5_000_000,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::AiCeilingExceeded { .. }
        ));
    }

    #[test]
    fn test_chain_depth_limit() {
        // Create a chain that's too deep (7 levels, exceeding max_delegation_depth=5)
        let depth = 7u8;
        let mut delegations = Vec::new();
        for i in 0..depth {
            delegations.push(Delegation {
                id: Blake3Hash([i; 32]),
                tenant_id: "tenant-1".to_string(),
                delegator: format!("did:exo:level{}", i + 1),
                delegatee: format!("did:exo:level{}", i),
                scope: DelegationScope {
                    decision_classes: vec![DecisionClass::Operational],
                    monetary_cap: None,
                    resource_ids: vec![],
                    actions: vec![AuthorizedAction::CreateDecision],
                },
                sub_delegation_allowed: true,
                sub_delegation_scope_cap: None,
                created_at: test_hlc(1000),
                expires_at: 10_000_000,
                revoked_at: None,
                constitution_version: SemVer::new(1, 0, 0),
                signature: test_sig(&format!("did:exo:level{}", i + 1), SignerType::Human),
                // Only the last delegation (deepest root) has no parent
                parent_delegation: if i < depth - 1 {
                    Some(Blake3Hash([i + 1; 32]))
                } else {
                    None
                },
            });
        }

        let constitution = test_constitution(); // max_delegation_depth = 5

        let result = verify_chain(
            &"did:exo:level0".to_string(),
            &SignerType::Human,
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Operational,
            &delegations,
            &constitution,
            5_000_000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_scope_mismatch_fails() {
        let delegations = test_delegation_chain();
        let constitution = test_constitution();

        // Alice only has CreateDecision and CastVote — not RaiseChallenge
        let result = verify_chain(
            &"did:exo:alice".to_string(),
            &SignerType::Human,
            &AuthorizedAction::RaiseChallenge,
            &DecisionClass::Operational,
            &delegations,
            &constitution,
            5_000_000,
        );

        assert!(result.is_err());
    }
}
