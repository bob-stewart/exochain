//! decision.forum — The sovereign governance engine
//! Every decision is a first-class cryptographically verifiable object.
//! Enforces all 10 TNCs + GOV-001..013 + LEG-001..013.

pub mod decision_object;
pub mod constitution;
pub mod authority;
pub mod tnc_enforcer;
pub mod fiduciary_package;
pub mod cli;

pub use decision_object::{DecisionObject, DecisionClass, SignerType, Status};
pub use constitution::ConstitutionRef;
pub use tnc_enforcer::TNCEnforcer;
pub use fiduciary_package::FiduciaryDefensePackage;

/// Birth a new Decision Object (example entry point)
pub fn create_genesis_decision(title: &str) -> Result<DecisionObject, Box<dyn std::error::Error>> {
    let obj = DecisionObject::new(title);
    TNCEnforcer::enforce_all(&obj)?;
    Ok(obj)
}
