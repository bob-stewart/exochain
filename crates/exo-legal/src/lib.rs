//! exo-legal: Legal compliance layer for decision.forum.
//!
//! Self-authenticating records, e-discovery, privilege compartmentalization,
//! fiduciary defense, conflict disclosure automation.
//!
//! Satisfies: LEG-001 through LEG-013

pub mod conflict_disclosure;
pub mod ediscovery;
pub mod evidence;
pub mod fiduciary;
pub mod privilege;
pub mod records;

pub use conflict_disclosure::{DgclSafeHarbor, SafeHarborStatus};
pub use ediscovery::{EDiscoveryExport, EDiscoveryRequest, ProductionFormat};
pub use evidence::{DutyCareEvidence, EvidenceCapture};
pub use fiduciary::{DefensePackage, FiduciaryDefense};
pub use privilege::{PrivilegeCompartment, PrivilegeLevel};
pub use records::{AuthenticatedRecord, RecordAuthentication, RecordType};
