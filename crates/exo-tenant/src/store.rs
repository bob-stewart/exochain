//! Persistent storage trait for tenant-scoped DAG operations.

use async_trait::async_trait;
use exo_core::crypto::Blake3Hash;
use exo_core::event::EventEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Storage errors.
#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Event not found: {0:?}")]
    EventNotFound(Blake3Hash),
    #[error("Tenant not found: {0}")]
    TenantNotFound(Uuid),
    #[error("Storage quota exceeded")]
    QuotaExceeded,
    #[error("Tenant isolation violation: attempted cross-tenant access")]
    IsolationViolation,
    #[error("Storage backend error: {0}")]
    Backend(String),
}

/// Query parameters for listing events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventQuery {
    pub tenant_id: Uuid,
    pub event_types: Option<Vec<String>>,
    pub after_sequence: Option<u64>,
    pub limit: Option<u64>,
}

/// Tenant-scoped storage trait.
#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Store an event for a tenant.
    async fn put_event(
        &self,
        tenant_id: Uuid,
        event: &EventEnvelope,
    ) -> Result<Blake3Hash, StoreError>;

    /// Retrieve an event by hash, scoped to a tenant.
    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_hash: &Blake3Hash,
    ) -> Result<EventEnvelope, StoreError>;

    /// List events matching a query.
    async fn list_events(&self, query: EventQuery) -> Result<Vec<EventEnvelope>, StoreError>;

    /// Get the current event count for a tenant.
    async fn event_count(&self, tenant_id: Uuid) -> Result<u64, StoreError>;

    /// Check storage usage in bytes for a tenant.
    async fn storage_usage(&self, tenant_id: Uuid) -> Result<u64, StoreError>;
}

/// In-memory tenant store for testing.
pub struct MemoryTenantStore {
    events: tokio::sync::RwLock<std::collections::HashMap<(Uuid, Blake3Hash), EventEnvelope>>,
}

impl MemoryTenantStore {
    pub fn new() -> Self {
        Self {
            events: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemoryTenantStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TenantStore for MemoryTenantStore {
    async fn put_event(
        &self,
        tenant_id: Uuid,
        event: &EventEnvelope,
    ) -> Result<Blake3Hash, StoreError> {
        let hash = exo_core::crypto::hash_bytes(&serde_json::to_vec(event).unwrap_or_default());
        let mut store = self.events.write().await;
        store.insert((tenant_id, hash), event.clone());
        Ok(hash)
    }

    async fn get_event(
        &self,
        tenant_id: Uuid,
        event_hash: &Blake3Hash,
    ) -> Result<EventEnvelope, StoreError> {
        let store = self.events.read().await;
        store
            .get(&(tenant_id, *event_hash))
            .cloned()
            .ok_or(StoreError::EventNotFound(*event_hash))
    }

    async fn list_events(&self, query: EventQuery) -> Result<Vec<EventEnvelope>, StoreError> {
        let store = self.events.read().await;
        let events: Vec<_> = store
            .iter()
            .filter(|((tid, _), _)| *tid == query.tenant_id)
            .map(|(_, e)| e.clone())
            .take(query.limit.unwrap_or(100) as usize)
            .collect();
        Ok(events)
    }

    async fn event_count(&self, tenant_id: Uuid) -> Result<u64, StoreError> {
        let store = self.events.read().await;
        let count = store.keys().filter(|(tid, _)| *tid == tenant_id).count();
        Ok(count as u64)
    }

    async fn storage_usage(&self, tenant_id: Uuid) -> Result<u64, StoreError> {
        let store = self.events.read().await;
        let usage: u64 = store
            .iter()
            .filter(|((tid, _), _)| *tid == tenant_id)
            .map(|(_, e)| serde_json::to_vec(e).map(|v| v.len() as u64).unwrap_or(0))
            .sum();
        Ok(usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exo_core::event::{EventEnvelope, EventPayload};
    use exo_core::hlc::HybridLogicalClock;

    fn test_event(network_id: &str) -> EventEnvelope {
        EventEnvelope {
            parents: vec![],
            logical_time: HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
            author: "did:exo:test".into(),
            key_version: 1,
            payload: EventPayload::Genesis {
                network_id: network_id.to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_put_and_get_event() {
        let store = MemoryTenantStore::new();
        let tenant = Uuid::new_v4();
        let event = test_event("test");

        let hash = store.put_event(tenant, &event).await.unwrap();
        let retrieved = store.get_event(tenant, &hash).await.unwrap();
        assert_eq!(retrieved.author, event.author);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = MemoryTenantStore::new();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let event = test_event("isolated");

        let hash = store.put_event(tenant_a, &event).await.unwrap();

        // Tenant B cannot see Tenant A's events
        let result = store.get_event(tenant_b, &hash).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_event_count() {
        let store = MemoryTenantStore::new();
        let tenant = Uuid::new_v4();

        store.put_event(tenant, &test_event("a")).await.unwrap();
        store.put_event(tenant, &test_event("b")).await.unwrap();

        let count = store.event_count(tenant).await.unwrap();
        assert_eq!(count, 2);
    }
}
