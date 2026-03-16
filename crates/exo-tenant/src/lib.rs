//! exo-tenant: Multi-tenant isolation, storage abstraction, and cold archival.
//!
//! Satisfies: ARCH-005, ARCH-007

pub mod cold;
pub mod sharding;
pub mod store;
pub mod tenant;

pub use cold::{ArchivalPolicy, ColdStorage, StorageTier};
pub use sharding::{ShardAssignment, ShardStrategy};
pub use store::TenantStore;
pub use tenant::{TenantConfig, TenantContext, TenantStatus};
