//! exo-governance: Decision Objects, Constitutional Corpus, Authority Delegations,
//! Challenges, Emergency Actions, and Tamper-Evident Audit Trail.
//!
//! This crate implements the core governance domain for the decision.forum platform,
//! where every decision is a first-class sovereign object — cryptographically signed,
//! constitutionally bound, auditable, and contestable.

pub mod anchor;
pub mod audit;
pub mod challenge;
pub mod clearance;
pub mod conflict;
pub mod constitution;
pub mod crosscheck;
pub mod custody;
pub mod decision;
pub mod delegation;
pub mod emergency;
pub mod errors;
pub mod quorum;
pub mod types;

// Re-export key types for ergonomic use
pub use anchor::{AnchorProvider, AnchorReceipt, AnchorRegistry, AnchorVerificationStatus};
pub use audit::{AuditEntry, AuditEventType, AuditLog};
pub use challenge::{ChallengeGrounds, ChallengeObject, ChallengeStatus};
pub use clearance::{ClearanceCertificate, ClearanceEvaluation, ClearanceMode, ClearancePolicy};
pub use constitution::{Constitution, ConstitutionalDocument, Constraint, ConstraintExpression};
pub use crosscheck::{
    AgentKind, CrosscheckMethod, CrosscheckOpinion, CrosscheckReport, OpinionProvenance,
};
pub use custody::{CustodyAction, CustodyChain, CustodyChainError, CustodyEvent, CustodyRole};
pub use decision::{DecisionObject, DecisionStatus, QuorumSpec, Vote, VoteChoice};
pub use delegation::{Delegation, DelegationScope};
pub use emergency::{EmergencyAction, EmergencyFrequencyTracker, RatificationStatus};
pub use errors::GovernanceError;
pub use types::*;
