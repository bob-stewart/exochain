//! exo-gateway: API gateway for decision.forum.
//!
//! GraphQL/REST API, authentication middleware, tenant context injection,
//! rate limiting, and tiered notification system.
//!
//! Satisfies: ENT-004, UX-005, UX-006

pub mod auth;
pub mod db;
pub mod graphql;
pub mod livesafe;
pub mod middleware;
pub mod notifications;
pub mod rest;
pub mod server;

pub use auth::{AuthProvider, AuthToken, AuthenticatedUser};
pub use middleware::RateLimiter;
pub use notifications::{Notification, NotificationChannel, NotificationService};
