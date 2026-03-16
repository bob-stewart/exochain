//! exo-identity: DID lifecycle, RiskAttestation, and PACE enrollment.

pub mod did;
pub mod key;
pub mod pace;
pub mod risk;
pub mod shamir;

pub use pace::{
    ContactRelationship, PaceContact, PaceEnrollment, PaceError, PaceEventType, PaceStage,
};
pub use shamir::{Share, ShamirError, ShamirScheme};

pub fn hello() -> String {
    "Hello from exo-identity".to_string()
}
