//! Emergency Actions — bypass normal process, require ratification.
//!
//! Satisfies: GOV-009, TNC-10

use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Status of an emergency action's ratification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RatificationStatus {
    /// Awaiting ratification.
    Pending,
    /// Ratified by required authority.
    Ratified,
    /// Ratification deadline expired without ratification.
    Expired,
}

/// An emergency action that bypasses normal governance process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyAction {
    /// Unique identifier.
    pub id: Blake3Hash,
    /// Tenant context.
    pub tenant_id: TenantId,
    /// The decision created under emergency authority.
    pub decision_id: Blake3Hash,
    /// Who invoked emergency authority.
    pub invoker: Did,
    /// Justification for emergency action.
    pub justification: String,
    /// Scope of the emergency action.
    pub scope_description: String,
    /// When the emergency action was taken.
    pub invoked_at: HybridLogicalClock,
    /// Deadline for ratification (absolute timestamp ms).
    pub ratification_deadline: u64,
    /// ID of the ratification decision (auto-created — TNC-10).
    pub ratification_decision_id: Blake3Hash,
    /// Current ratification status.
    pub ratification_status: RatificationStatus,
    /// Invoker's signature.
    pub signature: GovernanceSignature,
}

/// Tracker for emergency action frequency within a tenant.
#[derive(Clone, Debug, Default)]
pub struct EmergencyFrequencyTracker {
    /// Emergency actions in the current quarter.
    actions_this_quarter: Vec<(Blake3Hash, u64)>, // (action_id, timestamp_ms)
    /// Maximum allowed per quarter before triggering review.
    pub threshold: u32,
}

impl EmergencyFrequencyTracker {
    pub fn new(threshold: u32) -> Self {
        Self {
            actions_this_quarter: Vec::new(),
            threshold,
        }
    }

    /// Record a new emergency action.
    pub fn record(&mut self, action_id: Blake3Hash, timestamp_ms: u64) {
        self.actions_this_quarter.push((action_id, timestamp_ms));
    }

    /// Get count of emergency actions this quarter.
    pub fn count(&self) -> u32 {
        self.actions_this_quarter.len() as u32
    }

    /// Check if threshold is exceeded (>3/quarter triggers review).
    pub fn is_threshold_exceeded(&self) -> bool {
        self.count() > self.threshold
    }

    /// Reset for new quarter.
    pub fn reset_quarter(&mut self) {
        self.actions_this_quarter.clear();
    }
}

impl EmergencyAction {
    /// Create an emergency action with auto-generated ratification requirement (TNC-10).
    ///
    /// The ratification_decision_id is auto-created — the caller must
    /// create a corresponding RatificationRequired decision with this ID.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: Blake3Hash,
        tenant_id: TenantId,
        decision_id: Blake3Hash,
        invoker: Did,
        justification: String,
        scope_description: String,
        invoked_at: HybridLogicalClock,
        ratification_deadline: u64,
        ratification_decision_id: Blake3Hash,
        signature: GovernanceSignature,
    ) -> Self {
        Self {
            id,
            tenant_id,
            decision_id,
            invoker,
            justification,
            scope_description,
            invoked_at,
            ratification_deadline,
            ratification_decision_id,
            ratification_status: RatificationStatus::Pending,
            signature,
        }
    }

    /// Check if ratification deadline has passed.
    pub fn is_ratification_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.ratification_deadline
            && self.ratification_status == RatificationStatus::Pending
    }

    /// Mark the emergency action as ratified.
    pub fn ratify(&mut self) -> Result<(), &'static str> {
        if self.ratification_status != RatificationStatus::Pending {
            return Err("Can only ratify a pending emergency action");
        }
        self.ratification_status = RatificationStatus::Ratified;
        Ok(())
    }

    /// Mark the emergency action as expired (ratification deadline passed).
    pub fn expire(&mut self, current_time_ms: u64) -> Result<(), &'static str> {
        if self.ratification_status != RatificationStatus::Pending {
            return Err("Can only expire a pending emergency action");
        }
        if current_time_ms < self.ratification_deadline {
            return Err("Deadline has not yet passed");
        }
        self.ratification_status = RatificationStatus::Expired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_tracker() {
        let mut tracker = EmergencyFrequencyTracker::new(3);
        assert_eq!(tracker.count(), 0);
        assert!(!tracker.is_threshold_exceeded());

        for i in 0..3 {
            tracker.record(Blake3Hash([i as u8; 32]), 1000 + i as u64);
        }
        assert_eq!(tracker.count(), 3);
        assert!(!tracker.is_threshold_exceeded());

        // Fourth action exceeds threshold
        tracker.record(Blake3Hash([10u8; 32]), 2000);
        assert_eq!(tracker.count(), 4);
        assert!(tracker.is_threshold_exceeded());
    }

    #[test]
    fn test_quarter_reset() {
        let mut tracker = EmergencyFrequencyTracker::new(3);
        tracker.record(Blake3Hash([1u8; 32]), 1000);
        tracker.record(Blake3Hash([2u8; 32]), 2000);
        assert_eq!(tracker.count(), 2);

        tracker.reset_quarter();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_create_and_ratify() {
        let mut action = EmergencyAction::create(
            Blake3Hash([1u8; 32]),
            "t1".to_string(),
            Blake3Hash([2u8; 32]),
            "did:exo:admin".to_string(),
            "Critical security incident".to_string(),
            "Suspend user access".to_string(),
            HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
            5000,
            Blake3Hash([3u8; 32]),
            GovernanceSignature {
                signer: "did:exo:admin".to_string(),
                signer_type: SignerType::Human,
                signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
                key_version: 1,
                timestamp: HybridLogicalClock {
                    physical_ms: 1000,
                    logical: 0,
                },
            },
        );

        assert_eq!(action.ratification_status, RatificationStatus::Pending);
        assert!(!action.is_ratification_expired(4000));

        action.ratify().unwrap();
        assert_eq!(action.ratification_status, RatificationStatus::Ratified);

        // Cannot ratify again
        assert!(action.ratify().is_err());
    }

    #[test]
    fn test_expire_emergency_action() {
        let mut action = EmergencyAction::create(
            Blake3Hash([1u8; 32]),
            "t1".to_string(),
            Blake3Hash([2u8; 32]),
            "did:exo:admin".to_string(),
            "Emergency".to_string(),
            "Scope".to_string(),
            HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
            5000,
            Blake3Hash([3u8; 32]),
            GovernanceSignature {
                signer: "did:exo:admin".to_string(),
                signer_type: SignerType::Human,
                signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
                key_version: 1,
                timestamp: HybridLogicalClock {
                    physical_ms: 1000,
                    logical: 0,
                },
            },
        );

        // Cannot expire before deadline
        assert!(action.expire(4000).is_err());

        // Can expire after deadline
        action.expire(5000).unwrap();
        assert_eq!(action.ratification_status, RatificationStatus::Expired);
    }

    #[test]
    fn test_ratification_expiry() {
        let action = EmergencyAction {
            id: Blake3Hash([1u8; 32]),
            tenant_id: "t1".to_string(),
            decision_id: Blake3Hash([2u8; 32]),
            invoker: "did:exo:admin".to_string(),
            justification: "Critical security incident".to_string(),
            scope_description: "Suspend user access".to_string(),
            invoked_at: HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
            ratification_deadline: 5000,
            ratification_decision_id: Blake3Hash([3u8; 32]),
            ratification_status: RatificationStatus::Pending,
            signature: GovernanceSignature {
                signer: "did:exo:admin".to_string(),
                signer_type: SignerType::Human,
                signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
                key_version: 1,
                timestamp: HybridLogicalClock {
                    physical_ms: 1000,
                    logical: 0,
                },
            },
        };

        assert!(!action.is_ratification_expired(4999));
        assert!(action.is_ratification_expired(5000));
        assert!(action.is_ratification_expired(6000));
    }
}
