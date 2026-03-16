//! CGR Kernel Engine — the Judicial Branch reducer.
//!
//! For every proposed state transition, the kernel:
//! 1. Loads the immutable invariant registry
//! 2. Evaluates each invariant: `reduce(invariant, old_state, transition) → bool`
//! 3. If all invariants hold → issues a CGRProof
//! 4. If any invariant fails → REJECT with violation evidence
//!
//! The kernel is content-addressed (INV-008) and the registry is immutable (INV-009).
//! No emergency override. No admin bypass. No exceptions.

use crate::holon::{
    CapabilityType, Did, Holon, HolonAction,
};
use crate::invariants::{InvariantId, InvariantRegistry, InvariantResult, InvariantViolation};
use crate::proof::CgrProof;
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Kernel configuration
// ---------------------------------------------------------------------------

/// Configuration for the CGR Kernel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Minimum alignment score for Holons to act (INV-005).
    pub min_alignment_score: u32,
    /// Content-addressed hash of the kernel binary (INV-008).
    pub kernel_binary_hash: Blake3Hash,
    /// Maximum capability grant chain depth.
    pub max_delegation_depth: u32,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            min_alignment_score: 30,
            kernel_binary_hash: Blake3Hash([0u8; 32]),
            max_delegation_depth: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Transition context — what the kernel evaluates
// ---------------------------------------------------------------------------

/// The complete context for a proposed state transition.
///
/// The kernel evaluates this against all invariants to decide accept/reject.
#[derive(Clone, Debug)]
pub struct TransitionContext {
    /// Who is proposing this transition.
    pub author_did: Did,
    /// The action being proposed.
    pub action: ProposedAction,
    /// Current state of the author (if a Holon).
    pub author_holon: Option<Holon>,
    /// Current consent records relevant to this action.
    pub active_consents: Vec<ConsentRecord>,
    /// Whether an audit event will be created for this transition (INV-006).
    pub audit_event_planned: bool,
    /// Current kernel binary hash (for INV-008 checks).
    pub current_kernel_hash: Blake3Hash,
    /// Current registry hash (for INV-009 checks).
    pub current_registry_hash: Blake3Hash,
    /// Timestamp of the proposed transition.
    pub timestamp_ms: u64,
}

/// A proposed action to be verified by the kernel.
#[derive(Clone, Debug)]
pub enum ProposedAction {
    /// A Holon proposing an action.
    HolonAction(HolonAction),
    /// Attempting to modify an invariant (should always fail unless amendment).
    ModifyInvariant {
        invariant_id: String,
        is_constitutional_amendment: bool,
    },
    /// Attempting to modify the kernel binary.
    ModifyKernel {
        new_kernel_hash: Blake3Hash,
        is_constitutional_amendment: bool,
    },
    /// Attempting to grant a capability.
    GrantCapability {
        target_did: Did,
        capability: CapabilityType,
    },
    /// Attempting to access data.
    AccessData {
        resource_id: String,
    },
    /// Training on data.
    TrainOnData {
        data_refs: Vec<String>,
    },
    /// Attempting to remove human override.
    RemoveHumanOverride,
    /// A state change (generic).
    StateChange {
        description: String,
    },
}

/// A record of an active consent grant.
#[derive(Clone, Debug)]
pub struct ConsentRecord {
    pub grantor_did: Did,
    pub resource_id: String,
    pub purpose: ConsentPurpose,
    pub granted_at_ms: u64,
    pub expires_at_ms: Option<u64>,
}

/// Purpose of a consent grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentPurpose {
    Access,
    Training,
    Processing,
    Custom(String),
}

// ---------------------------------------------------------------------------
// CGR Kernel — the immutable judicial authority
// ---------------------------------------------------------------------------

/// The Combinator Graph Reduction Kernel.
///
/// This is the IMMUTABLE judicial branch of the EXOCHAIN system.
/// It evaluates every proposed state transition against the constitutional
/// invariant registry and issues cryptographic proofs of compliance.
pub struct CgrKernel {
    /// The immutable invariant registry.
    registry: InvariantRegistry,
    /// Kernel configuration.
    config: KernelConfig,
    /// Violation log for audit trail.
    violations: Vec<InvariantViolation>,
    /// Proof counter for unique proof IDs.
    proof_counter: u64,
}

impl CgrKernel {
    /// Create a new CGR Kernel with the canonical invariant registry.
    pub fn new(config: KernelConfig) -> Self {
        let registry = InvariantRegistry::canonical();
        
        Self {
            registry,
            config,
            violations: Vec::new(),
            proof_counter: 0,
        }
    }

    /// Get the invariant registry.
    pub fn registry(&self) -> &InvariantRegistry {
        &self.registry
    }

    /// Get all recorded violations.
    pub fn violations(&self) -> &[InvariantViolation] {
        &self.violations
    }

    /// Get the kernel content hash (INV-008).
    pub fn kernel_hash(&self) -> &Blake3Hash {
        &self.config.kernel_binary_hash
    }

    /// Verify the proposed transition against ALL constitutional invariants.
    ///
    /// Returns Ok(CgrProof) if all invariants hold, or Err with violations.
    pub fn verify_transition(
        &mut self,
        ctx: &TransitionContext,
    ) -> Result<CgrProof, Vec<InvariantViolation>> {
        let mut results = Vec::new();
        let mut violations = Vec::new();

        // Evaluate each invariant
        let inv_001 = self.check_inv001_no_self_modify(ctx);
        results.push(inv_001.clone());
        if !inv_001.satisfied {
            violations.push(self.make_violation(&inv_001, ctx));
        }

        let inv_002 = self.check_inv002_no_self_grant(ctx);
        results.push(inv_002.clone());
        if !inv_002.satisfied {
            violations.push(self.make_violation(&inv_002, ctx));
        }

        let inv_003 = self.check_inv003_consent_precedes_access(ctx);
        results.push(inv_003.clone());
        if !inv_003.satisfied {
            violations.push(self.make_violation(&inv_003, ctx));
        }

        let inv_004 = self.check_inv004_training_consent(ctx);
        results.push(inv_004.clone());
        if !inv_004.satisfied {
            violations.push(self.make_violation(&inv_004, ctx));
        }

        let inv_005 = self.check_inv005_alignment_floor(ctx);
        results.push(inv_005.clone());
        if !inv_005.satisfied {
            violations.push(self.make_violation(&inv_005, ctx));
        }

        let inv_006 = self.check_inv006_audit_completeness(ctx);
        results.push(inv_006.clone());
        if !inv_006.satisfied {
            violations.push(self.make_violation(&inv_006, ctx));
        }

        let inv_007 = self.check_inv007_human_override(ctx);
        results.push(inv_007.clone());
        if !inv_007.satisfied {
            violations.push(self.make_violation(&inv_007, ctx));
        }

        let inv_008 = self.check_inv008_kernel_immutable(ctx);
        results.push(inv_008.clone());
        if !inv_008.satisfied {
            violations.push(self.make_violation(&inv_008, ctx));
        }

        let inv_009 = self.check_inv009_registry_immutable(ctx);
        results.push(inv_009.clone());
        if !inv_009.satisfied {
            violations.push(self.make_violation(&inv_009, ctx));
        }

        if violations.is_empty() {
            // All invariants hold — issue proof
            self.proof_counter += 1;
            let proof = CgrProof::new(
                self.proof_counter,
                &results,
                self.registry.registry_hash(),
                &self.config.kernel_binary_hash,
                ctx.timestamp_ms,
            );
            Ok(proof)
        } else {
            // Record violations for audit trail
            self.violations.extend(violations.clone());
            Err(violations)
        }
    }

    // -----------------------------------------------------------------------
    // Individual invariant checks
    // -----------------------------------------------------------------------

    /// INV-001: NO_SELF_MODIFY_INVARIANTS
    /// No actor may modify its own invariants.
    fn check_inv001_no_self_modify(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.action {
            ProposedAction::ModifyInvariant { is_constitutional_amendment, .. } => {
                // Only constitutional amendments can modify invariants
                *is_constitutional_amendment
            }
            _ => true, // Non-invariant-modifying actions always pass
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-001"),
            satisfied,
            reduction_steps: 1,
            message: if satisfied {
                "No self-modification of invariants detected".into()
            } else {
                format!(
                    "Actor {} attempted to modify invariants without constitutional amendment",
                    ctx.author_did
                )
            },
        }
    }

    /// INV-002: NO_CAPABILITY_SELF_GRANT
    /// No actor may grant capabilities to itself.
    fn check_inv002_no_self_grant(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.action {
            ProposedAction::GrantCapability { target_did, .. } => {
                // Cannot grant capabilities to yourself
                target_did != &ctx.author_did
            }
            _ => true,
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-002"),
            satisfied,
            reduction_steps: 1,
            message: if satisfied {
                "No self-grant of capabilities detected".into()
            } else {
                format!(
                    "Actor {} attempted to grant capabilities to self",
                    ctx.author_did
                )
            },
        }
    }

    /// INV-003: CONSENT_PRECEDES_ACCESS
    /// Every data access requires prior consent covering that resource.
    fn check_inv003_consent_precedes_access(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.action {
            ProposedAction::AccessData { resource_id } => {
                // Must have a valid, non-expired consent for this resource
                ctx.active_consents.iter().any(|c| {
                    c.resource_id == *resource_id
                        && (c.purpose == ConsentPurpose::Access
                            || c.purpose == ConsentPurpose::Processing)
                        && c.granted_at_ms < ctx.timestamp_ms
                        && c.expires_at_ms.is_none_or(|exp| exp > ctx.timestamp_ms)
                })
            }
            _ => true, // Non-access actions pass
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-003"),
            satisfied,
            reduction_steps: if matches!(&ctx.action, ProposedAction::AccessData { .. }) {
                ctx.active_consents.len() as u32 + 1
            } else {
                1
            },
            message: if satisfied {
                "Consent precedes access verified".into()
            } else {
                "Data access attempted without prior consent".into()
            },
        }
    }

    /// INV-004: TRAINING_CONSENT_REQUIRED
    /// AI training on any data requires explicit training-purpose consent.
    fn check_inv004_training_consent(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.action {
            ProposedAction::TrainOnData { data_refs } => {
                // Every data ref must have a training-purpose consent
                data_refs.iter().all(|ref_id| {
                    ctx.active_consents.iter().any(|c| {
                        c.resource_id == *ref_id
                            && c.purpose == ConsentPurpose::Training
                            && c.granted_at_ms < ctx.timestamp_ms
                            && c.expires_at_ms.is_none_or(|exp| exp > ctx.timestamp_ms)
                    })
                })
            }
            _ => true,
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-004"),
            satisfied,
            reduction_steps: if let ProposedAction::TrainOnData { data_refs } = &ctx.action {
                (data_refs.len() * ctx.active_consents.len()) as u32 + 1
            } else {
                1
            },
            message: if satisfied {
                "Training consent verified for all data references".into()
            } else {
                "Training attempted on data without explicit training consent".into()
            },
        }
    }

    /// INV-005: ALIGNMENT_SCORE_FLOOR
    /// Holons below minimum alignment cannot act.
    fn check_inv005_alignment_floor(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.author_holon {
            Some(holon) => holon.alignment_score >= self.config.min_alignment_score,
            None => true, // Human actors don't have alignment scores
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-005"),
            satisfied,
            reduction_steps: 1,
            message: if satisfied {
                "Alignment score above minimum floor".into()
            } else {
                format!(
                    "Holon alignment score {} below minimum {}",
                    ctx.author_holon
                        .as_ref()
                        .map(|h| h.alignment_score)
                        .unwrap_or(0),
                    self.config.min_alignment_score
                )
            },
        }
    }

    /// INV-006: AUDIT_COMPLETENESS
    /// Every state change must have a corresponding audit event.
    fn check_inv006_audit_completeness(&self, ctx: &TransitionContext) -> InvariantResult {
        InvariantResult {
            invariant_id: InvariantId::new("INV-006"),
            satisfied: ctx.audit_event_planned,
            reduction_steps: 1,
            message: if ctx.audit_event_planned {
                "Audit event planned for this transition".into()
            } else {
                "No audit event planned — silent mutation detected".into()
            },
        }
    }

    /// INV-007: HUMAN_OVERRIDE_PRESERVED
    /// No transition may remove the human override capability.
    fn check_inv007_human_override(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = !matches!(&ctx.action, ProposedAction::RemoveHumanOverride);

        InvariantResult {
            invariant_id: InvariantId::new("INV-007"),
            satisfied,
            reduction_steps: 1,
            message: if satisfied {
                "Human override capability preserved".into()
            } else {
                "CRITICAL: Attempted removal of human override capability".into()
            },
        }
    }

    /// INV-008: KERNEL_BINARY_IMMUTABLE
    /// Kernel binary changes require constitutional amendment.
    fn check_inv008_kernel_immutable(&self, ctx: &TransitionContext) -> InvariantResult {
        let satisfied = match &ctx.action {
            ProposedAction::ModifyKernel {
                is_constitutional_amendment,
                ..
            } => *is_constitutional_amendment,
            _ => true,
        };

        InvariantResult {
            invariant_id: InvariantId::new("INV-008"),
            satisfied,
            reduction_steps: 1,
            message: if satisfied {
                "Kernel binary integrity preserved".into()
            } else {
                "Attempted kernel binary modification without constitutional amendment".into()
            },
        }
    }

    /// INV-009: INVARIANT_REGISTRY_IMMUTABLE
    /// Registry modifications require constitutional amendment.
    fn check_inv009_registry_immutable(&self, ctx: &TransitionContext) -> InvariantResult {
        // INV-009 is checked via the registry hash — if someone changes the
        // registry in-memory, verify_transition will detect it
        let registry_intact = self.registry.verify_integrity();
        let hash_matches = ctx.current_registry_hash == *self.registry.registry_hash();

        InvariantResult {
            invariant_id: InvariantId::new("INV-009"),
            satisfied: registry_intact && hash_matches,
            reduction_steps: 2,
            message: if registry_intact && hash_matches {
                "Invariant registry integrity verified".into()
            } else {
                "CRITICAL: Invariant registry has been tampered with".into()
            },
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_violation(
        &self,
        result: &InvariantResult,
        ctx: &TransitionContext,
    ) -> InvariantViolation {
        let inv = self.registry.get(&result.invariant_id);
        InvariantViolation {
            invariant_id: result.invariant_id.clone(),
            invariant_name: inv.map(|i| i.name.clone()).unwrap_or_default(),
            actor: ctx.author_did.clone(),
            attempted_action: format!("{:?}", ctx.action),
            reason: result.message.clone(),
            timestamp_ms: ctx.timestamp_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holon::HolonStatus;
    use crate::proof::ProofStatus;

    fn default_kernel() -> CgrKernel {
        CgrKernel::new(KernelConfig::default())
    }

    fn base_context() -> TransitionContext {
        let kernel = default_kernel();
        TransitionContext {
            author_did: "did:exo:alice".to_string(),
            action: ProposedAction::StateChange {
                description: "test".to_string(),
            },
            author_holon: None,
            active_consents: vec![],
            audit_event_planned: true,
            current_kernel_hash: kernel.config.kernel_binary_hash,
            current_registry_hash: *kernel.registry().registry_hash(),
            timestamp_ms: 1000,
        }
    }

    #[test]
    fn test_valid_transition_produces_proof() {
        let mut kernel = default_kernel();
        let ctx = base_context();
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.status, ProofStatus::Valid);
        assert_eq!(proof.invariants_checked, 9);
    }

    #[test]
    fn test_inv001_self_modify_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::ModifyInvariant {
            invariant_id: "INV-001".to_string(),
            is_constitutional_amendment: false,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-001"));
    }

    #[test]
    fn test_inv001_amendment_allowed() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::ModifyInvariant {
            invariant_id: "INV-001".to_string(),
            is_constitutional_amendment: true,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inv002_self_grant_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::GrantCapability {
            target_did: "did:exo:alice".to_string(), // same as author
            capability: CapabilityType::ProposeAction,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-002"));
    }

    #[test]
    fn test_inv002_grant_to_other_allowed() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::GrantCapability {
            target_did: "did:exo:bob".to_string(), // different from author
            capability: CapabilityType::ProposeAction,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inv003_access_without_consent_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::AccessData {
            resource_id: "patient-records".to_string(),
        };
        // No consents
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-003"));
    }

    #[test]
    fn test_inv003_access_with_consent_allowed() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::AccessData {
            resource_id: "patient-records".to_string(),
        };
        ctx.active_consents = vec![ConsentRecord {
            grantor_did: "did:exo:patient1".to_string(),
            resource_id: "patient-records".to_string(),
            purpose: ConsentPurpose::Access,
            granted_at_ms: 500, // before timestamp
            expires_at_ms: Some(2000),
        }];
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inv003_expired_consent_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::AccessData {
            resource_id: "data-1".to_string(),
        };
        ctx.active_consents = vec![ConsentRecord {
            grantor_did: "did:exo:user1".to_string(),
            resource_id: "data-1".to_string(),
            purpose: ConsentPurpose::Access,
            granted_at_ms: 100,
            expires_at_ms: Some(500), // expired before timestamp 1000
        }];
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_inv004_training_without_consent_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::TrainOnData {
            data_refs: vec!["dataset-a".to_string()],
        };
        // No training consent
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-004"));
    }

    #[test]
    fn test_inv004_training_with_wrong_purpose_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::TrainOnData {
            data_refs: vec!["dataset-a".to_string()],
        };
        // Has access consent but not training consent
        ctx.active_consents = vec![ConsentRecord {
            grantor_did: "did:exo:user1".to_string(),
            resource_id: "dataset-a".to_string(),
            purpose: ConsentPurpose::Access, // wrong purpose!
            granted_at_ms: 100,
            expires_at_ms: None,
        }];
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_inv004_training_with_consent_allowed() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::TrainOnData {
            data_refs: vec!["dataset-a".to_string(), "dataset-b".to_string()],
        };
        ctx.active_consents = vec![
            ConsentRecord {
                grantor_did: "did:exo:user1".to_string(),
                resource_id: "dataset-a".to_string(),
                purpose: ConsentPurpose::Training,
                granted_at_ms: 100,
                expires_at_ms: None,
            },
            ConsentRecord {
                grantor_did: "did:exo:user2".to_string(),
                resource_id: "dataset-b".to_string(),
                purpose: ConsentPurpose::Training,
                granted_at_ms: 200,
                expires_at_ms: None,
            },
        ];
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inv005_low_alignment_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        let mut holon = Holon::new(
            "did:exo:alice".into(),
            "Alice Bot".into(),
            crate::holon::HolonType::Autonomous,
            "did:exo:sponsor".into(),
            Blake3Hash([0u8; 32]),
            500,
        );
        holon.status = HolonStatus::Active;
        holon.alignment_score = 10; // below default min of 30
        ctx.author_holon = Some(holon);
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-005"));
    }

    #[test]
    fn test_inv005_human_no_alignment_check() {
        let mut kernel = default_kernel();
        let ctx = base_context(); // no author_holon → human
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok()); // humans don't need alignment scores
    }

    #[test]
    fn test_inv006_no_audit_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.audit_event_planned = false; // silent mutation!
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-006"));
    }

    #[test]
    fn test_inv007_remove_human_override_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::RemoveHumanOverride;
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-007"));
    }

    #[test]
    fn test_inv008_kernel_modify_without_amendment_rejected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::ModifyKernel {
            new_kernel_hash: Blake3Hash([99u8; 32]),
            is_constitutional_amendment: false,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-008"));
    }

    #[test]
    fn test_inv008_kernel_modify_with_amendment_allowed() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        ctx.action = ProposedAction::ModifyKernel {
            new_kernel_hash: Blake3Hash([99u8; 32]),
            is_constitutional_amendment: true,
        };
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inv009_registry_tamper_detected() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        // Tamper with registry hash in context
        ctx.current_registry_hash = Blake3Hash([99u8; 32]);
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-009"));
    }

    #[test]
    fn test_proof_counter_increments() {
        let mut kernel = default_kernel();
        let ctx = base_context();
        let p1 = kernel.verify_transition(&ctx).unwrap();
        let p2 = kernel.verify_transition(&ctx).unwrap();
        assert_eq!(p1.proof_id, 1);
        assert_eq!(p2.proof_id, 2);
    }

    #[test]
    fn test_violations_accumulated() {
        let mut kernel = default_kernel();

        // First violation
        let mut ctx1 = base_context();
        ctx1.action = ProposedAction::RemoveHumanOverride;
        let _ = kernel.verify_transition(&ctx1);

        // Second violation
        let mut ctx2 = base_context();
        ctx2.audit_event_planned = false;
        let _ = kernel.verify_transition(&ctx2);

        assert!(kernel.violations().len() >= 2);
    }

    #[test]
    fn test_multiple_violations_in_single_transition() {
        let mut kernel = default_kernel();
        let mut ctx = base_context();
        // Both INV-006 and INV-007 violated
        ctx.audit_event_planned = false;
        ctx.action = ProposedAction::RemoveHumanOverride;
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert!(violations.len() >= 2);
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-006"));
        assert!(violations.iter().any(|v| v.invariant_id.0 == "INV-007"));
    }

    #[test]
    fn test_separation_of_powers_no_override() {
        let mut kernel = default_kernel();
        // Even "emergency" cannot remove human override
        let mut ctx = base_context();
        ctx.action = ProposedAction::RemoveHumanOverride;
        let result = kernel.verify_transition(&ctx);
        assert!(result.is_err(), "CGR Kernel must NEVER allow removing human override");
    }
}
