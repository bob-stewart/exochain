//! # exo-bcts
//!
//! EXOCHAIN Bailment-Conditioned Transaction Set lifecycle engine.
//!
//! Every governance action flows through a deterministic pipeline of state
//! transitions, validated against 9 constitutional invariants. This crate
//! provides the transaction model, state machine, pipeline executor, and
//! invariant checker.
//!
//! ## Crate layout
//!
//! - [`states`] — 14 transaction states with valid transition map
//! - [`transaction`] — `EventEnvelope`, `LedgerEvent`, `BctsTransaction` types
//! - [`pipeline`] — 9-stage pipeline executor (propose → audit)
//! - [`invariants`] — 9 constitutional invariants (INV-001 through INV-009)
//!
//! ## The BCTS pipeline
//!
//! ```text
//! Draft → Submitted → IdentityResolved → ConsentValidated → Deliberated
//!   → Verified → Governed → Approved → Executed → Recorded → Closed
//! ```
//!
//! Alternate paths: Denied (from most stages), Escalated (human review),
//! Remediated (resubmission after denial).

#![deny(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::float_cmp, clippy::float_cmp_const)]
#![warn(clippy::as_conversions)]

pub mod invariants;
pub mod pipeline;
pub mod states;
pub mod transaction;

// Selective re-exports
pub use invariants::{
    check_all_invariants, check_invariant, ConstitutionalInvariant,
    InvariantCheckResult, InvariantContext, ALL_INVARIANTS,
};
pub use pipeline::{
    run_pipeline, stage_description, PipelineResult, PipelineStage,
    StageResult, PIPELINE_STAGES,
};
pub use states::{
    can_transition, is_terminal, pipeline_stage, state_description,
    valid_transitions, BctsState, TERMINAL_STATES,
};
pub use transaction::{
    create_transaction, transition, verify_ledger, BctsTransaction,
    EventEnvelope, LedgerEvent, SignerType,
};
