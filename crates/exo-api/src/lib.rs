//! exo-api: API types and interfaces.

// pub mod graphql;
// pub mod rest;

pub mod p2p;
pub mod schema;
pub mod types;

pub use schema::{create_schema, create_schema_with_state, ApiSchema, ApiState};

pub fn hello() -> String {
    "Hello from exo-api".to_string()
}
