//! Tenant sharding strategy for horizontal scaling.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Sharding strategy for distributing tenants across storage backends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShardStrategy {
    /// Hash-based sharding on tenant ID.
    HashBased { total_shards: u32 },
    /// Range-based sharding on tenant creation order.
    RangeBased { shard_size: u32 },
    /// Geographic sharding for data residency compliance.
    Geographic { region: String },
    /// Single shard — all tenants in one database.
    Single,
}

/// Assignment of a tenant to a specific shard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub tenant_id: Uuid,
    pub shard_id: u32,
    pub strategy: ShardStrategy,
    pub connection_pool: String,
}

impl ShardStrategy {
    /// Compute shard ID for a tenant.
    pub fn assign(&self, tenant_id: Uuid) -> u32 {
        match self {
            ShardStrategy::HashBased { total_shards } => {
                let bytes = tenant_id.as_bytes();
                let hash = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                hash % total_shards
            }
            ShardStrategy::RangeBased { .. } => {
                // Range-based would use creation order — simplified to hash
                let bytes = tenant_id.as_bytes();
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 256
            }
            ShardStrategy::Geographic { .. } => 0, // Single region shard
            ShardStrategy::Single => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_based_sharding() {
        let strategy = ShardStrategy::HashBased { total_shards: 16 };
        let tenant = Uuid::new_v4();
        let shard = strategy.assign(tenant);
        assert!(shard < 16);
    }

    #[test]
    fn test_deterministic_assignment() {
        let strategy = ShardStrategy::HashBased { total_shards: 8 };
        let tenant = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let shard1 = strategy.assign(tenant);
        let shard2 = strategy.assign(tenant);
        assert_eq!(shard1, shard2);
    }

    #[test]
    fn test_single_shard() {
        let strategy = ShardStrategy::Single;
        let shard = strategy.assign(Uuid::new_v4());
        assert_eq!(shard, 0);
    }
}
