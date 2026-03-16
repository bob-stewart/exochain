//! Tenant context, configuration, and isolation boundary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tenant lifecycle status.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TenantStatus {
    /// Active and operational.
    Active,
    /// Provisioning in progress.
    Provisioning,
    /// Suspended (billing, compliance, etc.).
    Suspended,
    /// Archived — read-only access to cold storage.
    Archived,
    /// Deleted — all data purged.
    Deleted,
}

/// Configuration for a tenant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantConfig {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub status: TenantStatus,
    pub created_at: DateTime<Utc>,
    pub storage_quota_bytes: u64,
    pub max_decisions: u64,
    pub max_delegations: u64,
    pub retention_days: u32,
    pub cold_archive_after_days: u32,
    pub shard_key: String,
    pub features: TenantFeatures,
}

/// Feature flags per tenant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantFeatures {
    pub zk_proofs_enabled: bool,
    pub ai_agents_enabled: bool,
    pub e_discovery_enabled: bool,
    pub emergency_protocol_enabled: bool,
    pub custom_decision_classes: bool,
}

impl Default for TenantFeatures {
    fn default() -> Self {
        Self {
            zk_proofs_enabled: false,
            ai_agents_enabled: false,
            e_discovery_enabled: true,
            emergency_protocol_enabled: true,
            custom_decision_classes: false,
        }
    }
}

/// Tenant execution context — threaded through all operations for isolation.
#[derive(Clone, Debug)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub config: TenantConfig,
}

impl TenantContext {
    pub fn new(config: TenantConfig) -> Self {
        Self {
            tenant_id: config.id,
            tenant_slug: config.slug.clone(),
            config,
        }
    }

    /// Check if the tenant is active.
    pub fn is_active(&self) -> bool {
        self.config.status == TenantStatus::Active
    }

    /// Check if a feature is enabled for this tenant.
    pub fn has_feature(&self, check: impl Fn(&TenantFeatures) -> bool) -> bool {
        check(&self.config.features)
    }
}

impl TenantConfig {
    /// Create a new tenant with default settings.
    pub fn new(name: String, slug: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            slug,
            status: TenantStatus::Provisioning,
            created_at: Utc::now(),
            storage_quota_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            max_decisions: 1_000_000,
            max_delegations: 100_000,
            retention_days: 365 * 50, // 50 years
            cold_archive_after_days: 365,
            shard_key: Uuid::new_v4().to_string(),
            features: TenantFeatures::default(),
        }
    }

    /// Activate the tenant.
    pub fn activate(&mut self) -> bool {
        if self.status == TenantStatus::Provisioning {
            self.status = TenantStatus::Active;
            true
        } else {
            false
        }
    }

    /// Suspend the tenant.
    pub fn suspend(&mut self) -> bool {
        if self.status == TenantStatus::Active {
            self.status = TenantStatus::Suspended;
            true
        } else {
            false
        }
    }

    /// Archive the tenant.
    pub fn archive(&mut self) -> bool {
        if self.status == TenantStatus::Active || self.status == TenantStatus::Suspended {
            self.status = TenantStatus::Archived;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_lifecycle() {
        let mut config = TenantConfig::new("Test Org".into(), "test-org".into());
        assert_eq!(config.status, TenantStatus::Provisioning);

        assert!(config.activate());
        assert_eq!(config.status, TenantStatus::Active);

        assert!(config.suspend());
        assert_eq!(config.status, TenantStatus::Suspended);

        assert!(config.archive());
        assert_eq!(config.status, TenantStatus::Archived);
    }

    #[test]
    fn test_tenant_context() {
        let mut config = TenantConfig::new("Test".into(), "test".into());
        config.activate();
        config.features.zk_proofs_enabled = true;

        let ctx = TenantContext::new(config);
        assert!(ctx.is_active());
        assert!(ctx.has_feature(|f| f.zk_proofs_enabled));
        assert!(!ctx.has_feature(|f| f.ai_agents_enabled));
    }
}
