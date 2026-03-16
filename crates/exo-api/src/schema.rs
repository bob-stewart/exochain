use crate::types::EventView;
use async_graphql::{Context, EmptySubscription, Object, Schema};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared API state holding an in-memory event store.
pub struct ApiState {
    pub events: HashMap<String, EventView>,
}

impl ApiState {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
        }
    }
}

impl Default for ApiState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Fetch an event by ID (hex encoded).
    async fn event(&self, ctx: &Context<'_>, id: String) -> Option<EventView> {
        let state = ctx.data::<Arc<RwLock<ApiState>>>().ok()?;
        let guard = state.read().await;
        guard.events.get(&id).cloned()
    }

    /// Health check.
    async fn health(&self) -> String {
        "OK".to_string()
    }
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Submit a raw event (hex-encoded bytes).
    async fn submit_event(&self, ctx: &Context<'_>, raw_bytes: String) -> bool {
        // Parse hex bytes
        let bytes = match hex::decode(&raw_bytes) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // We need at least 32 bytes for a meaningful ID
        if bytes.len() < 32 {
            return false;
        }

        // Use the first 32 bytes as the event ID
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&bytes[..32]);
        let id_hex = hex::encode(id_bytes);

        let event_view = EventView {
            id: id_hex.clone(),
            parents: vec![],
            author: "submitted".to_string(),
            payload_type: "Opaque".to_string(),
        };

        if let Ok(state) = ctx.data::<Arc<RwLock<ApiState>>>() {
            let mut guard = state.write().await;
            guard.events.insert(id_hex, event_view);
            true
        } else {
            false
        }
    }
}

pub type ApiSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Create a schema without state (for backward compatibility).
pub fn create_schema() -> ApiSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish()
}

/// Create a schema with shared API state.
pub fn create_schema_with_state(state: Arc<RwLock<ApiState>>) -> ApiSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish()
}
