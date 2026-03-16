//! exo-proofs: Zero-knowledge proof layer for decision.forum.
//!
//! Provides zk-SNARK and zk-STARK proof generation and verification
//! for governance compliance, decision integrity, and AI provenance.
//!
//! Satisfies: ARCH-002, LEG-007, UX-004

pub mod snark;
pub mod stark;
pub mod verifier;
pub mod zkml;

pub use snark::{SnarkCircuit, SnarkProof};
pub use stark::{StarkProof, StarkProver};
pub use verifier::{ProofType, UnifiedVerifier, VerificationResult};
pub use zkml::{AiProvenanceProof, ZkMlProver};
