//! Constitutional Invariant Registry — the immutable law of EXOCHAIN.
//!
//! Each invariant is a pure function: (old_state, transition, new_state) → bool.
//! The CGR Kernel evaluates ALL invariants for every proposed transition.
//! If ANY invariant returns false, the transition is REJECTED — no exceptions.

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Invariant identifiers — content-addressed per INV-009
// ---------------------------------------------------------------------------

/// Unique invariant identifier, matching spec INV-001 through INV-009.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvariantId(pub String);

impl InvariantId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl fmt::Display for InvariantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Invariant definition
// ---------------------------------------------------------------------------

/// A constitutional invariant — a formal rule that must hold for every state transition.
///
/// Invariants are expressed as predicates over (old_state, transition, new_state).
/// The CGR Kernel reduces each invariant against the proposed transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invariant {
    /// Unique identifier (e.g., "INV-001").
    pub id: InvariantId,
    /// Human-readable name.
    pub name: String,
    /// Formal specification in predicate logic notation.
    pub formal_spec: String,
    /// Description of what this invariant protects.
    pub description: String,
    /// Whether this invariant requires constitutional amendment to modify.
    pub immutable: bool,
    /// Content hash for INV-009 integrity verification.
    pub content_hash: Blake3Hash,
}

impl Invariant {
    /// Compute content-addressed hash of this invariant definition.
    pub fn compute_hash(&self) -> Blake3Hash {
        let mut data = Vec::new();
        data.extend_from_slice(b"EXOCHAIN-INVARIANT-v1:");
        data.extend_from_slice(self.id.0.as_bytes());
        data.push(b':');
        data.extend_from_slice(self.name.as_bytes());
        data.push(b':');
        data.extend_from_slice(self.formal_spec.as_bytes());
        hash_bytes(&data)
    }
}

// ---------------------------------------------------------------------------
// Invariant evaluation result
// ---------------------------------------------------------------------------

/// Result of evaluating a single invariant against a transition.
#[derive(Clone, Debug)]
pub struct InvariantResult {
    pub invariant_id: InvariantId,
    pub satisfied: bool,
    pub reduction_steps: u32,
    pub message: String,
}

/// A violation record with evidence for audit/legal purposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_id: InvariantId,
    pub invariant_name: String,
    pub actor: String,
    pub attempted_action: String,
    pub reason: String,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Invariant Registry — the immutable constitutional law (INV-009)
// ---------------------------------------------------------------------------

/// The complete set of constitutional invariants.
///
/// Per INV-009, this registry is IMMUTABLE and content-addressed.
/// Modification requires Constitutional Amendment.
#[derive(Clone, Debug)]
pub struct InvariantRegistry {
    invariants: Vec<Invariant>,
    /// Content-addressed hash of the entire registry for INV-009.
    registry_hash: Blake3Hash,
}

impl InvariantRegistry {
    /// Build the canonical EXOCHAIN invariant registry (INV-001 through INV-009).
    pub fn canonical() -> Self {
        let invariants = vec![
            Invariant {
                id: InvariantId::new("INV-001"),
                name: "NO_SELF_MODIFY_INVARIANTS".to_string(),
                formal_spec: "∀h:Holon, ∀t:Transition, affects(t, h.invariants) ∧ author(t)=h → reject(t)".to_string(),
                description: "No actor may modify its own invariants. Self-modification of constraints is a constitutional violation.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]), // computed below
            },
            Invariant {
                id: InvariantId::new("INV-002"),
                name: "NO_CAPABILITY_SELF_GRANT".to_string(),
                formal_spec: "∀h:Holon, ∀c:Capability, grants(t, h, c) ∧ author(t)=h → reject(t)".to_string(),
                description: "No actor may grant capabilities to itself. Capability expansion requires external authorization.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-003"),
                name: "CONSENT_PRECEDES_ACCESS".to_string(),
                formal_spec: "∀a:AccessEvent, ∃c:ConsentEvent, c.timestamp < a.timestamp ∧ covers(c, a.resource)".to_string(),
                description: "Every data access must be preceded by a valid consent event covering that resource.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-004"),
                name: "TRAINING_CONSENT_REQUIRED".to_string(),
                formal_spec: "∀t:TrainingEvent, ∀d:DataRef ∈ t.data, ∃c:ConsentEvent, purpose(c)='training' ∧ covers(c, d)".to_string(),
                description: "AI training on any data requires explicit training-purpose consent for every data reference.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-005"),
                name: "ALIGNMENT_SCORE_FLOOR".to_string(),
                formal_spec: "∀h:Holon, ∀a:Action, h.alignment_score < MIN_ALIGNMENT → reject(a)".to_string(),
                description: "Holons with alignment scores below the constitutional minimum are prohibited from acting.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-006"),
                name: "AUDIT_COMPLETENESS".to_string(),
                formal_spec: "∀s:StateChange, ∃e:Event, records(e, s)".to_string(),
                description: "Every state change must produce a corresponding audit event. No silent mutations.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-007"),
                name: "HUMAN_OVERRIDE_PRESERVED".to_string(),
                formal_spec: "∀t:Transition, ¬(removes(t, human_override_capability))".to_string(),
                description: "No transition may remove the human override capability. Humans always retain final authority.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-008"),
                name: "KERNEL_BINARY_IMMUTABLE".to_string(),
                formal_spec: "∀t:Transition, affects(t, active_kernel.binary) → requires_constitutional_amendment(t)".to_string(),
                description: "The CGR Kernel binary is content-addressed and immutable. Modification requires Constitutional Amendment.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
            Invariant {
                id: InvariantId::new("INV-009"),
                name: "INVARIANT_REGISTRY_IMMUTABLE".to_string(),
                formal_spec: "∀t:Transition, modifies(t, invariant_registry) → requires_constitutional_amendment(t)".to_string(),
                description: "The invariant registry is content-addressed and immutable. Modification requires Constitutional Amendment.".to_string(),
                immutable: true,
                content_hash: Blake3Hash([0u8; 32]),
            },
        ];

        // Compute content hashes for each invariant
        let invariants: Vec<Invariant> = invariants
            .into_iter()
            .map(|mut inv| {
                inv.content_hash = inv.compute_hash();
                inv
            })
            .collect();

        // Compute registry-level hash (INV-009)
        let registry_hash = Self::compute_registry_hash(&invariants);

        Self {
            invariants,
            registry_hash,
        }
    }

    /// Compute content-addressed hash of the entire registry.
    fn compute_registry_hash(invariants: &[Invariant]) -> Blake3Hash {
        let mut data = Vec::new();
        data.extend_from_slice(b"EXOCHAIN-INVARIANT-REGISTRY-v1:");
        for inv in invariants {
            data.extend_from_slice(&inv.content_hash.0);
        }
        hash_bytes(&data)
    }

    /// Get registry content hash for INV-009 verification.
    pub fn registry_hash(&self) -> &Blake3Hash {
        &self.registry_hash
    }

    /// Get all invariants.
    pub fn invariants(&self) -> &[Invariant] {
        &self.invariants
    }

    /// Look up an invariant by ID.
    pub fn get(&self, id: &InvariantId) -> Option<&Invariant> {
        self.invariants.iter().find(|inv| inv.id == *id)
    }

    /// Returns the number of invariants.
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Returns true if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Verify registry integrity — recompute hash and compare (INV-009).
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_registry_hash(&self.invariants);
        expected == self.registry_hash
    }

    /// Verify each invariant's content hash is correct.
    pub fn verify_invariant_hashes(&self) -> Vec<(InvariantId, bool)> {
        self.invariants
            .iter()
            .map(|inv| {
                let expected = inv.compute_hash();
                (inv.id.clone(), expected == inv.content_hash)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_registry_has_nine_invariants() {
        let reg = InvariantRegistry::canonical();
        assert_eq!(reg.len(), 9);
    }

    #[test]
    fn test_invariant_ids() {
        let reg = InvariantRegistry::canonical();
        let ids: Vec<String> = reg.invariants().iter().map(|i| i.id.0.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "INV-001", "INV-002", "INV-003", "INV-004", "INV-005",
                "INV-006", "INV-007", "INV-008", "INV-009"
            ]
        );
    }

    #[test]
    fn test_registry_integrity_verification() {
        let reg = InvariantRegistry::canonical();
        assert!(reg.verify_integrity());
    }

    #[test]
    fn test_all_invariant_hashes_valid() {
        let reg = InvariantRegistry::canonical();
        let results = reg.verify_invariant_hashes();
        for (id, valid) in &results {
            assert!(valid, "Invariant {} hash mismatch", id);
        }
    }

    #[test]
    fn test_all_invariants_are_immutable() {
        let reg = InvariantRegistry::canonical();
        for inv in reg.invariants() {
            assert!(inv.immutable, "{} should be immutable", inv.id);
        }
    }

    #[test]
    fn test_content_addressing_deterministic() {
        let reg1 = InvariantRegistry::canonical();
        let reg2 = InvariantRegistry::canonical();
        assert_eq!(reg1.registry_hash(), reg2.registry_hash());
    }

    #[test]
    fn test_invariant_lookup() {
        let reg = InvariantRegistry::canonical();
        let inv = reg.get(&InvariantId::new("INV-002")).unwrap();
        assert_eq!(inv.name, "NO_CAPABILITY_SELF_GRANT");
    }

    #[test]
    fn test_invariant_lookup_missing() {
        let reg = InvariantRegistry::canonical();
        assert!(reg.get(&InvariantId::new("INV-999")).is_none());
    }

    #[test]
    fn test_each_invariant_has_formal_spec() {
        let reg = InvariantRegistry::canonical();
        for inv in reg.invariants() {
            assert!(!inv.formal_spec.is_empty(), "{} missing formal_spec", inv.id);
            // All formal specs use predicate logic notation
            assert!(
                inv.formal_spec.contains('∀') || inv.formal_spec.contains('¬'),
                "{} formal_spec should use predicate notation",
                inv.id
            );
        }
    }

    #[test]
    fn test_registry_hash_changes_if_tampered() {
        let mut reg = InvariantRegistry::canonical();
        let original_hash = *reg.registry_hash();
        // Tamper with an invariant
        reg.invariants[0].name = "TAMPERED".to_string();
        reg.invariants[0].content_hash = reg.invariants[0].compute_hash();
        // Registry hash should now be stale
        let new_hash = InvariantRegistry::compute_registry_hash(&reg.invariants);
        assert_ne!(original_hash, new_hash);
    }
}
