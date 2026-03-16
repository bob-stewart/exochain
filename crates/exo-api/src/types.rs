use async_graphql::SimpleObject;
use exo_core::{Blake3Hash, EventEnvelope};

/// GraphQL wrapper for EventEnvelope.
#[derive(Clone, SimpleObject)]
pub struct EventView {
    pub id: String,
    pub parents: Vec<String>,
    pub author: String,
    pub payload_type: String,
    // We omit raw payload for now or expose as JSON string
}

impl From<&EventEnvelope> for EventView {
    fn from(env: &EventEnvelope) -> Self {
        // Calculate ID (simulated or real if we passed it)
        // Ideally we pass the hash and the envelope.
        let id_hash = exo_core::compute_event_id(env).unwrap_or(Blake3Hash([0u8; 32]));

        Self {
            id: hex::encode(id_hash.0),
            parents: env.parents.iter().map(|h| hex::encode(h.0)).collect(),
            author: env.author.clone(),
            payload_type: "Generic".to_string(), // Todo: match payload enum
        }
    }
}

// Todo: Custom Scalars for Hash, DID?
