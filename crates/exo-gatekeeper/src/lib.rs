//! exo-gatekeeper: CGR Kernel — The Judicial Branch of EXOCHAIN.
//!
//! The Combinator Graph Reduction (CGR) Kernel is the IMMUTABLE judicial authority
//! that enforces constitutional invariants on every state transition. No event
//! achieves finality without a valid CGRProof attesting that all invariants hold.
//!
//! ## Constitutional Invariants (INV-001 through INV-009)
//!
//! | ID      | Name                          | Enforcement                               |
//! |---------|-------------------------------|-------------------------------------------|
//! | INV-001 | NO_SELF_MODIFY_INVARIANTS     | Actors cannot modify their own invariants  |
//! | INV-002 | NO_CAPABILITY_SELF_GRANT      | Actors cannot grant capabilities to self   |
//! | INV-003 | CONSENT_PRECEDES_ACCESS       | Data access requires prior consent event   |
//! | INV-004 | TRAINING_CONSENT_REQUIRED     | AI training requires explicit consent      |
//! | INV-005 | ALIGNMENT_SCORE_FLOOR         | Holons below alignment floor are rejected  |
//! | INV-006 | AUDIT_COMPLETENESS            | Every state change has a recorded event    |
//! | INV-007 | HUMAN_OVERRIDE_PRESERVED      | No transition removes human override       |
//! | INV-008 | KERNEL_BINARY_IMMUTABLE       | Kernel binary changes need amendment       |
//! | INV-009 | INVARIANT_REGISTRY_IMMUTABLE  | Registry changes need amendment            |
//!
//! ## Separation of Powers
//!
//! - **Legislative** (AI-IRB): Defines policy schemas and constitutional bounds
//! - **Executive** (Holons): Proposes and executes actions within bounds
//! - **Judicial** (CGR Kernel): Verifies every transition preserves invariants
//!
//! The Judicial branch cannot be overridden, bypassed, or modified without
//! Constitutional Amendment (unanimous validators + 80% AI-IRB supermajority).

pub mod kernel;
pub mod invariants;
pub mod holon;
pub mod proof;
pub mod tee;
pub mod combinator;

pub use kernel::{CgrKernel, KernelConfig, TransitionContext};
pub use invariants::{
    Invariant, InvariantId, InvariantRegistry, InvariantResult, InvariantViolation,
};
pub use holon::{
    Holon, HolonAction, HolonAttestation, HolonStatus, HolonLifecycleEvent,
};
pub use proof::{CgrProof, ProofStatus};
pub use tee::{TeeAttestation, TeeReport, MockGatekeeper};
pub use combinator::{
    CombinatorTerm, CombinatorEngine, TypedValue, ReductionContext,
    ReductionTrace, ReductionStep, encode_invariant,
};
