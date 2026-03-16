//! exo-authority: Authority chain verification engine for decision.forum.
//!
//! This crate implements the SOLE gate through which all governance actions must pass.
//! No bypass path exists (TNC-01). Every state change requires a verified authority chain
//! from the acting agent back through delegations to the constitutional root.

pub mod cache;
pub mod chain;

pub use cache::ChainCache;
pub use chain::{verify_chain, ChainBreak, ChainProof};
