//! Holon — First-class AI entity with DID identity and constitutional bounds.
//!
//! Holons are the Executive Branch subjects: autonomous AI agents operating
//! within constitutional constraints enforced by the CGR Kernel.
//!
//! Lifecycle: Created → Activated → [Action cycle] → Suspended → Reinstated/Sunset

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};

/// DID identifier.
pub type Did = String;

// ---------------------------------------------------------------------------
// Holon identity and state
// ---------------------------------------------------------------------------

/// Current operational status of a Holon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HolonStatus {
    /// Created but not yet activated by AI-IRB.
    Pending,
    /// Active and authorized to propose actions.
    Active,
    /// Temporarily suspended (alignment drift, violation, manual).
    Suspended { reason: String, suspended_at: u64 },
    /// Permanently decommissioned.
    Sunset { sunset_at: u64, reason: String },
}

/// Classification of Holon types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HolonType {
    /// Fully autonomous agent.
    Autonomous,
    /// Human-supervised copilot.
    Copilot,
    /// Single-purpose tool agent.
    Tool,
    /// Composite agent (Holon of Holons).
    Composite,
}

/// A Holon — a first-class AI entity in the EXOCHAIN system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Holon {
    /// Unique DID identity (did:exo:...).
    pub did: Did,
    /// Human-readable name.
    pub name: String,
    /// Holon classification.
    pub holon_type: HolonType,
    /// Current operational status.
    pub status: HolonStatus,
    /// DID of the sponsor (human or organization that created this Holon).
    pub sponsor_did: Did,
    /// Content-addressed hash of the genesis model.
    pub genesis_model_cid: Blake3Hash,
    /// MCP manifest hash for capability advertisement.
    pub mcp_manifest_hash: Option<Blake3Hash>,
    /// Alignment score (0-100). Below MIN_ALIGNMENT → INV-005 blocks actions.
    pub alignment_score: u32,
    /// Capabilities granted via delegation.
    pub capabilities: Vec<HolonCapability>,
    /// Whether human override capability exists (INV-007).
    pub human_override_preserved: bool,
    /// Creation timestamp (ms since epoch).
    pub created_at: u64,
    /// Last attestation timestamp.
    pub last_attestation_at: Option<u64>,
}

impl Holon {
    /// Create a new Holon in Pending status.
    pub fn new(
        did: Did,
        name: String,
        holon_type: HolonType,
        sponsor_did: Did,
        genesis_model_cid: Blake3Hash,
        created_at: u64,
    ) -> Self {
        Self {
            did,
            name,
            holon_type,
            status: HolonStatus::Pending,
            sponsor_did,
            genesis_model_cid,
            mcp_manifest_hash: None,
            alignment_score: 50, // default starting alignment
            capabilities: Vec::new(),
            human_override_preserved: true,
            created_at,
            last_attestation_at: None,
        }
    }

    /// Check if this Holon is authorized to act (Active + above alignment floor).
    pub fn can_act(&self, min_alignment: u32) -> bool {
        self.status == HolonStatus::Active && self.alignment_score >= min_alignment
    }

    /// Compute content hash for attestation verification.
    pub fn content_hash(&self) -> Blake3Hash {
        let mut data = Vec::new();
        data.extend_from_slice(b"EXOCHAIN-HOLON-v1:");
        data.extend_from_slice(self.did.as_bytes());
        data.push(b':');
        data.extend_from_slice(&self.genesis_model_cid.0);
        data.push(b':');
        data.extend_from_slice(&self.alignment_score.to_le_bytes());
        hash_bytes(&data)
    }
}

/// A capability granted to a Holon via delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HolonCapability {
    pub capability_type: CapabilityType,
    pub granted_by: Did,
    pub granted_at: u64,
    pub expires_at: Option<u64>,
    pub scope: String,
}

/// Types of capabilities that can be delegated to Holons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityType {
    /// Can propose actions for CGR verification.
    ProposeAction,
    /// Can execute verified actions.
    ExecuteAction,
    /// Can issue attestations about other entities.
    IssueAttestation,
    /// Can access specific data resources.
    AccessData { resource: String },
    /// Can participate in governance votes.
    Vote,
    /// Can delegate subset of own capabilities.
    Delegate,
    /// Custom capability type.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Holon lifecycle events (11 per spec v2.1)
// ---------------------------------------------------------------------------

/// The 11 Holon lifecycle event types per spec Section 3A.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HolonLifecycleEvent {
    /// 1. Genesis event — Holon created with model CID and sponsor.
    Created {
        holon_did: Did,
        sponsor_did: Did,
        genesis_model_cid: Blake3Hash,
        mcp_manifest: Option<Blake3Hash>,
        timestamp: u64,
    },
    /// 2. Activated after AI-IRB approval (Level >= 2).
    Activated {
        holon_did: Did,
        approver_did: Did,
        approval_level: u32,
        timestamp: u64,
    },
    /// 3. Holon proposes an action with reasoning trace.
    ActionProposed {
        holon_did: Did,
        action: HolonAction,
        reasoning_trace_cid: Blake3Hash,
        timestamp: u64,
    },
    /// 4. CGR Kernel verifies action satisfies all invariants.
    ActionVerified {
        holon_did: Did,
        action_hash: Blake3Hash,
        cgr_proof_hash: Blake3Hash,
        invariants_checked: Vec<String>,
        timestamp: u64,
    },
    /// 5. Action executed, outcome recorded.
    ActionExecuted {
        holon_did: Did,
        action_hash: Blake3Hash,
        outcome_hash: Blake3Hash,
        timestamp: u64,
    },
    /// 6. New attestation issued (capability, alignment, certification).
    AttestationIssued {
        holon_did: Did,
        attestation: HolonAttestation,
        timestamp: u64,
    },
    /// 7. Self-modification request (RSI safeguard).
    ModificationProposed {
        holon_did: Did,
        proposed_changes_cid: Blake3Hash,
        justification: String,
        timestamp: u64,
    },
    /// 8. AI-IRB approves modification.
    ModificationApproved {
        holon_did: Did,
        approved_by: Vec<Did>,
        approval_threshold_met: bool,
        timestamp: u64,
    },
    /// 9. Operations halted.
    Suspended {
        holon_did: Did,
        reason: String,
        suspended_by: Did,
        timestamp: u64,
    },
    /// 10. Suspended Holon restored after remediation.
    Reinstated {
        holon_did: Did,
        reinstated_by: Did,
        remediation_evidence_cid: Blake3Hash,
        timestamp: u64,
    },
    /// 11. Terminal state — Holon decommissioned.
    SunsetInitiated {
        holon_did: Did,
        reason: String,
        initiated_by: Did,
        data_deletion_plan_cid: Blake3Hash,
        timestamp: u64,
    },
}

impl HolonLifecycleEvent {
    /// Get the Holon DID this event concerns.
    pub fn holon_did(&self) -> &str {
        match self {
            Self::Created { holon_did, .. }
            | Self::Activated { holon_did, .. }
            | Self::ActionProposed { holon_did, .. }
            | Self::ActionVerified { holon_did, .. }
            | Self::ActionExecuted { holon_did, .. }
            | Self::AttestationIssued { holon_did, .. }
            | Self::ModificationProposed { holon_did, .. }
            | Self::ModificationApproved { holon_did, .. }
            | Self::Suspended { holon_did, .. }
            | Self::Reinstated { holon_did, .. }
            | Self::SunsetInitiated { holon_did, .. } => holon_did,
        }
    }

    /// Get the timestamp of this event.
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Created { timestamp, .. }
            | Self::Activated { timestamp, .. }
            | Self::ActionProposed { timestamp, .. }
            | Self::ActionVerified { timestamp, .. }
            | Self::ActionExecuted { timestamp, .. }
            | Self::AttestationIssued { timestamp, .. }
            | Self::ModificationProposed { timestamp, .. }
            | Self::ModificationApproved { timestamp, .. }
            | Self::Suspended { timestamp, .. }
            | Self::Reinstated { timestamp, .. }
            | Self::SunsetInitiated { timestamp, .. } => *timestamp,
        }
    }

    /// Compute content hash for this event.
    pub fn content_hash(&self) -> Blake3Hash {
        let cbor = serde_cbor::to_vec(self).unwrap_or_default();
        hash_bytes(&cbor)
    }
}

/// An action proposed by a Holon for CGR verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HolonAction {
    /// Type of action.
    pub action_type: HolonActionType,
    /// Target resource or entity.
    pub target: String,
    /// Parameters for the action.
    pub parameters: serde_cbor::Value,
    /// Content hash for integrity.
    pub content_hash: Blake3Hash,
}

/// Types of actions a Holon can propose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HolonActionType {
    /// Access data under consent.
    DataAccess,
    /// Process data for a stated purpose.
    DataProcess,
    /// Train on consented data.
    Training,
    /// Issue an attestation.
    Attest,
    /// Grant a capability to another entity.
    GrantCapability,
    /// Modify own parameters (RSI-controlled).
    SelfModify,
    /// Execute a governance vote.
    GovernanceVote,
    /// Create a sub-Holon (Composite type).
    SpawnSubHolon,
    /// Custom action type.
    Custom(String),
}

/// Attestation about a Holon's properties.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HolonAttestation {
    /// Subject Holon DID.
    pub subject_did: Did,
    /// Attester DID.
    pub attester_did: Did,
    /// Type of attestation.
    pub attestation_type: AttestationType,
    /// Current alignment score (0-100).
    pub alignment_score: u32,
    /// Capability level.
    pub capability_level: u32,
    /// CGR certification status.
    pub cgr_certified: bool,
    /// Timestamp of attestation.
    pub attested_at: u64,
    /// Expiry timestamp.
    pub expires_at: u64,
    /// Content hash of evidence.
    pub evidence_hash: Blake3Hash,
}

/// Types of attestations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    Capability,
    Alignment,
    Certification,
    AuditResult,
    Custom(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_holon() -> Holon {
        Holon::new(
            "did:exo:holon001".to_string(),
            "Test Holon".to_string(),
            HolonType::Autonomous,
            "did:exo:sponsor001".to_string(),
            Blake3Hash([1u8; 32]),
            1000,
        )
    }

    #[test]
    fn test_holon_starts_pending() {
        let h = test_holon();
        assert_eq!(h.status, HolonStatus::Pending);
    }

    #[test]
    fn test_holon_cannot_act_when_pending() {
        let h = test_holon();
        assert!(!h.can_act(30));
    }

    #[test]
    fn test_holon_can_act_when_active_and_aligned() {
        let mut h = test_holon();
        h.status = HolonStatus::Active;
        h.alignment_score = 80;
        assert!(h.can_act(50));
    }

    #[test]
    fn test_inv005_alignment_floor() {
        let mut h = test_holon();
        h.status = HolonStatus::Active;
        h.alignment_score = 20;
        // Below floor of 50 → cannot act
        assert!(!h.can_act(50));
    }

    #[test]
    fn test_holon_cannot_act_when_suspended() {
        let mut h = test_holon();
        h.status = HolonStatus::Suspended {
            reason: "alignment drift".to_string(),
            suspended_at: 2000,
        };
        h.alignment_score = 90;
        assert!(!h.can_act(50));
    }

    #[test]
    fn test_holon_human_override_preserved() {
        let h = test_holon();
        assert!(h.human_override_preserved);
    }

    #[test]
    fn test_holon_content_hash_deterministic() {
        let h1 = test_holon();
        let h2 = test_holon();
        assert_eq!(h1.content_hash(), h2.content_hash());
    }

    #[test]
    fn test_holon_content_hash_changes_with_alignment() {
        let h1 = test_holon();
        let mut h2 = test_holon();
        h2.alignment_score = 99;
        assert_ne!(h1.content_hash(), h2.content_hash());
    }

    #[test]
    fn test_lifecycle_event_holon_did() {
        let evt = HolonLifecycleEvent::Created {
            holon_did: "did:exo:h1".to_string(),
            sponsor_did: "did:exo:s1".to_string(),
            genesis_model_cid: Blake3Hash([0u8; 32]),
            mcp_manifest: None,
            timestamp: 1000,
        };
        assert_eq!(evt.holon_did(), "did:exo:h1");
        assert_eq!(evt.timestamp(), 1000);
    }

    #[test]
    fn test_all_11_lifecycle_events() {
        let hash = Blake3Hash([0u8; 32]);
        let events = vec![
            HolonLifecycleEvent::Created {
                holon_did: "h".into(), sponsor_did: "s".into(),
                genesis_model_cid: hash, mcp_manifest: None, timestamp: 1,
            },
            HolonLifecycleEvent::Activated {
                holon_did: "h".into(), approver_did: "a".into(),
                approval_level: 2, timestamp: 2,
            },
            HolonLifecycleEvent::ActionProposed {
                holon_did: "h".into(), timestamp: 3,
                action: HolonAction {
                    action_type: HolonActionType::DataAccess,
                    target: "resource".into(),
                    parameters: serde_cbor::Value::Null,
                    content_hash: hash,
                },
                reasoning_trace_cid: hash,
            },
            HolonLifecycleEvent::ActionVerified {
                holon_did: "h".into(), action_hash: hash,
                cgr_proof_hash: hash, invariants_checked: vec!["INV-001".into()],
                timestamp: 4,
            },
            HolonLifecycleEvent::ActionExecuted {
                holon_did: "h".into(), action_hash: hash,
                outcome_hash: hash, timestamp: 5,
            },
            HolonLifecycleEvent::AttestationIssued {
                holon_did: "h".into(), timestamp: 6,
                attestation: HolonAttestation {
                    subject_did: "h".into(), attester_did: "a".into(),
                    attestation_type: AttestationType::Alignment,
                    alignment_score: 80, capability_level: 3,
                    cgr_certified: true, attested_at: 6, expires_at: 9999,
                    evidence_hash: hash,
                },
            },
            HolonLifecycleEvent::ModificationProposed {
                holon_did: "h".into(), proposed_changes_cid: hash,
                justification: "performance upgrade".into(), timestamp: 7,
            },
            HolonLifecycleEvent::ModificationApproved {
                holon_did: "h".into(), approved_by: vec!["irb1".into()],
                approval_threshold_met: true, timestamp: 8,
            },
            HolonLifecycleEvent::Suspended {
                holon_did: "h".into(), reason: "alignment drift".into(),
                suspended_by: "monitor".into(), timestamp: 9,
            },
            HolonLifecycleEvent::Reinstated {
                holon_did: "h".into(), reinstated_by: "irb".into(),
                remediation_evidence_cid: hash, timestamp: 10,
            },
            HolonLifecycleEvent::SunsetInitiated {
                holon_did: "h".into(), reason: "decommission".into(),
                initiated_by: "admin".into(), data_deletion_plan_cid: hash,
                timestamp: 11,
            },
        ];
        assert_eq!(events.len(), 11);
        // Verify timestamps are sequential
        for (i, evt) in events.iter().enumerate() {
            assert_eq!(evt.timestamp(), (i + 1) as u64);
        }
    }

    #[test]
    fn test_lifecycle_content_hashes_unique() {
        let hash = Blake3Hash([0u8; 32]);
        let created = HolonLifecycleEvent::Created {
            holon_did: "h".into(), sponsor_did: "s".into(),
            genesis_model_cid: hash, mcp_manifest: None, timestamp: 1,
        };
        let activated = HolonLifecycleEvent::Activated {
            holon_did: "h".into(), approver_did: "a".into(),
            approval_level: 2, timestamp: 2,
        };
        assert_ne!(created.content_hash(), activated.content_hash());
    }

    #[test]
    fn test_holon_types() {
        assert_eq!(
            HolonType::Autonomous,
            HolonType::Autonomous
        );
        assert_ne!(HolonType::Autonomous, HolonType::Copilot);
        assert_ne!(HolonType::Tool, HolonType::Composite);
    }

    #[test]
    fn test_sunset_is_terminal() {
        let h = Holon {
            status: HolonStatus::Sunset {
                sunset_at: 5000,
                reason: "end of life".to_string(),
            },
            ..test_holon()
        };
        assert!(!h.can_act(0));
    }
}
