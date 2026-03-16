//! Authority Delegations — signed, scoped, time-bound, revocable.
//!
//! Satisfies: GOV-003, GOV-004, TNC-05, TNC-09

use crate::errors::GovernanceError;
use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Scope of an authority delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationScope {
    /// Decision classes this delegation covers.
    pub decision_classes: Vec<DecisionClass>,
    /// Maximum monetary authority in cents (if applicable).
    pub monetary_cap: Option<u64>,
    /// Specific resource IDs this delegation applies to.
    pub resource_ids: Vec<String>,
    /// Actions authorized under this delegation.
    pub actions: Vec<AuthorizedAction>,
}

impl DelegationScope {
    /// Check whether this scope covers a given action on a given decision class.
    pub fn covers(&self, action: &AuthorizedAction, class: &DecisionClass) -> bool {
        self.actions.contains(action) && self.decision_classes.contains(class)
    }

    /// Check whether this scope is a subset of (contained within) another scope.
    /// Used to validate sub-delegation doesn't exceed parent scope.
    pub fn is_subset_of(&self, parent: &DelegationScope) -> bool {
        // All actions must be in parent
        let actions_ok = self.actions.iter().all(|a| parent.actions.contains(a));

        // All decision classes must be in parent
        let classes_ok = self
            .decision_classes
            .iter()
            .all(|c| parent.decision_classes.contains(c));

        // Monetary cap must be <= parent's cap
        let monetary_ok = match (self.monetary_cap, parent.monetary_cap) {
            (Some(child), Some(parent_cap)) => child <= parent_cap,
            (Some(_), None) => true, // Parent has no cap, child has cap — fine
            (None, Some(_)) => false, // Parent has cap, child has none — violation
            (None, None) => true,
        };

        actions_ok && classes_ok && monetary_ok
    }
}

/// An authority delegation from one DID to another.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    /// Content-addressed unique identifier.
    pub id: Blake3Hash,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// DID granting the delegation.
    pub delegator: Did,
    /// DID receiving the delegation.
    pub delegatee: Did,
    /// Scope of authority being delegated.
    pub scope: DelegationScope,
    /// Whether the delegatee can sub-delegate.
    pub sub_delegation_allowed: bool,
    /// Maximum scope for any sub-delegation (must be subset of `scope`).
    pub sub_delegation_scope_cap: Option<DelegationScope>,
    /// Creation timestamp.
    pub created_at: HybridLogicalClock,
    /// Hard expiry timestamp — no grace period (TNC-05).
    pub expires_at: u64,
    /// Revocation timestamp (None if active).
    pub revoked_at: Option<u64>,
    /// Constitution version at time of delegation.
    pub constitution_version: SemVer,
    /// Cryptographic signature from delegator.
    pub signature: GovernanceSignature,
    /// Parent delegation ID (for sub-delegations).
    pub parent_delegation: Option<Blake3Hash>,
}

impl Delegation {
    /// Check whether this delegation is currently active (not expired, not revoked).
    /// TNC-05: Immediate expiry, no grace period.
    pub fn is_active(&self, current_time_ms: u64) -> bool {
        // Not revoked
        if self.revoked_at.is_some() {
            return false;
        }
        // Not expired — TNC-05: strict enforcement
        current_time_ms < self.expires_at
    }

    /// Revoke this delegation.
    pub fn revoke(&mut self, timestamp: u64) {
        self.revoked_at = Some(timestamp);
    }

    /// Validate that a proposed sub-delegation is within this delegation's scope.
    pub fn validate_sub_delegation(
        &self,
        sub_scope: &DelegationScope,
        current_time_ms: u64,
    ) -> Result<(), GovernanceError> {
        // Must be active
        if !self.is_active(current_time_ms) {
            if self.revoked_at.is_some() {
                return Err(GovernanceError::DelegationRevoked(self.id));
            }
            return Err(GovernanceError::DelegationExpired(self.id));
        }

        // Sub-delegation must be permitted
        if !self.sub_delegation_allowed {
            return Err(GovernanceError::SubDelegationNotPermitted(self.id));
        }

        // Sub-delegation scope must be within cap (or parent scope if no cap)
        let cap = self
            .sub_delegation_scope_cap
            .as_ref()
            .unwrap_or(&self.scope);
        if !sub_scope.is_subset_of(cap) {
            return Err(GovernanceError::SubDelegationNotPermitted(self.id));
        }

        Ok(())
    }

    /// Check whether this delegation authorizes a specific action on a decision class.
    pub fn authorizes(
        &self,
        action: &AuthorizedAction,
        class: &DecisionClass,
        current_time_ms: u64,
    ) -> Result<(), GovernanceError> {
        if !self.is_active(current_time_ms) {
            if self.revoked_at.is_some() {
                return Err(GovernanceError::DelegationRevoked(self.id));
            }
            return Err(GovernanceError::DelegationExpired(self.id));
        }

        if !self.scope.covers(action, class) {
            return Err(GovernanceError::AuthorityChainBroken {
                reason: format!(
                    "Delegation {:?} does not cover action {:?} on class {:?}",
                    self.id, action, class
                ),
            });
        }

        Ok(())
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

    fn test_sig(signer: &str) -> GovernanceSignature {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let dummy = Blake3Hash([0u8; 32]);
        let sig = exo_core::compute_signature(&sk, &dummy);
        GovernanceSignature {
            signer: signer.to_string(),
            signer_type: SignerType::Human,
            signature: sig,
            key_version: 1,
            timestamp: test_hlc(1000),
        }
    }

    fn test_delegation() -> Delegation {
        Delegation {
            id: Blake3Hash([10u8; 32]),
            tenant_id: "tenant-1".to_string(),
            delegator: "did:exo:root".to_string(),
            delegatee: "did:exo:alice".to_string(),
            scope: DelegationScope {
                decision_classes: vec![DecisionClass::Operational, DecisionClass::Strategic],
                monetary_cap: Some(100_000_00), // $100,000
                resource_ids: vec![],
                actions: vec![
                    AuthorizedAction::CreateDecision,
                    AuthorizedAction::CastVote,
                    AuthorizedAction::GrantDelegation,
                ],
            },
            sub_delegation_allowed: true,
            sub_delegation_scope_cap: Some(DelegationScope {
                decision_classes: vec![DecisionClass::Operational],
                monetary_cap: Some(10_000_00), // $10,000
                resource_ids: vec![],
                actions: vec![AuthorizedAction::CreateDecision, AuthorizedAction::CastVote],
            }),
            created_at: test_hlc(1000),
            expires_at: 2_000_000,
            revoked_at: None,
            constitution_version: SemVer::new(1, 0, 0),
            signature: test_sig("did:exo:root"),
            parent_delegation: None,
        }
    }

    #[test]
    fn test_delegation_active() {
        let d = test_delegation();
        assert!(d.is_active(1_000_000));
        assert!(!d.is_active(3_000_000)); // expired
    }

    #[test]
    fn test_tnc05_immediate_expiry() {
        let d = test_delegation();
        // At exactly expires_at, delegation is no longer active
        assert!(!d.is_active(d.expires_at));
        // One ms before expiry — still active
        assert!(d.is_active(d.expires_at - 1));
    }

    #[test]
    fn test_delegation_revocation() {
        let mut d = test_delegation();
        assert!(d.is_active(1_000_000));
        d.revoke(1_500_000);
        assert!(!d.is_active(1_600_000));
    }

    #[test]
    fn test_delegation_authorization() {
        let d = test_delegation();
        assert!(d
            .authorizes(
                &AuthorizedAction::CreateDecision,
                &DecisionClass::Operational,
                1_000_000,
            )
            .is_ok());

        // Action not in scope
        assert!(d
            .authorizes(
                &AuthorizedAction::AmendConstitution,
                &DecisionClass::Operational,
                1_000_000,
            )
            .is_err());

        // Class not in scope
        assert!(d
            .authorizes(
                &AuthorizedAction::CreateDecision,
                &DecisionClass::Constitutional,
                1_000_000,
            )
            .is_err());
    }

    #[test]
    fn test_sub_delegation_validation() {
        let d = test_delegation();

        // Valid sub-delegation within cap
        let valid_sub = DelegationScope {
            decision_classes: vec![DecisionClass::Operational],
            monetary_cap: Some(5_000_00),
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision],
        };
        assert!(d.validate_sub_delegation(&valid_sub, 1_000_000).is_ok());

        // Invalid: exceeds monetary cap
        let invalid_monetary = DelegationScope {
            decision_classes: vec![DecisionClass::Operational],
            monetary_cap: Some(50_000_00), // > $10,000 cap
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision],
        };
        assert!(d
            .validate_sub_delegation(&invalid_monetary, 1_000_000)
            .is_err());

        // Invalid: includes class not in cap
        let invalid_class = DelegationScope {
            decision_classes: vec![DecisionClass::Strategic], // not in sub-cap
            monetary_cap: Some(5_000_00),
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision],
        };
        assert!(d
            .validate_sub_delegation(&invalid_class, 1_000_000)
            .is_err());
    }

    #[test]
    fn test_scope_subset() {
        let parent = DelegationScope {
            decision_classes: vec![DecisionClass::Operational, DecisionClass::Strategic],
            monetary_cap: Some(100_000),
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision, AuthorizedAction::CastVote],
        };

        let child = DelegationScope {
            decision_classes: vec![DecisionClass::Operational],
            monetary_cap: Some(50_000),
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision],
        };

        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }
}
