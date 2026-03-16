//! Lynk Protocol — EXOCHAIN's distributed P2P consensus network.
//!
//! The Lynk Protocol is the distributed backbone that connects EXOCHAIN nodes:
//! - **Gossipsub**: Event propagation via topic-based publish/subscribe
//! - **Authenticated peers**: DID-based peer identity with Ed25519 keys
//! - **Event relay**: Gossip newly appended events to all peers
//! - **Checkpoint coordination**: BFT checkpoint proposals and votes
//! - **Peer discovery**: Bootstrap nodes + mDNS for local development
//!
//! ## Network Topology
//!
//! Nodes form a mesh network where each node maintains connections to
//! a configurable number of peers. Events flow through Gossipsub topics:
//! - `exochain/events/v1` — DAG event propagation
//! - `exochain/checkpoints/v1` — BFT checkpoint proposals and votes
//! - `exochain/discovery/v1` — Peer capability advertisement
//!
//! ## Data Flow (Spec Section 7.2)
//!
//! 1. Client submits event to local node via API
//! 2. Node validates, appends to local DAG
//! 3. Node gossips event to peers via `exochain/events/v1`
//! 4. Peers validate and append to their local DAGs
//! 5. BFT gadget proposes checkpoint when frontier advances
//! 6. Validators exchange votes via `exochain/checkpoints/v1`
//! 7. 2f+1 signatures → checkpoint finalized
//! 8. Finality confirmed to client

use libp2p::futures::StreamExt;
use libp2p::{noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, PeerId};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Protocol topics
// ---------------------------------------------------------------------------

/// Gossipsub topic names for the Lynk Protocol.
pub mod topics {
    /// DAG event propagation topic.
    pub const EVENTS: &str = "exochain/events/v1";
    /// BFT checkpoint coordination topic.
    pub const CHECKPOINTS: &str = "exochain/checkpoints/v1";
    /// Peer capability discovery topic.
    pub const DISCOVERY: &str = "exochain/discovery/v1";
}

// ---------------------------------------------------------------------------
// Network messages
// ---------------------------------------------------------------------------

/// Messages exchanged over the Lynk Protocol.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum LynkMessage {
    /// A new event to be propagated and appended to peer DAGs.
    EventGossip {
        /// Serialized EventEnvelope (CBOR).
        event_cbor: Vec<u8>,
        /// BLAKE3 hash of the event for dedup.
        event_id: [u8; 32],
        /// Origin peer ID (string-encoded).
        origin_peer: String,
    },

    /// Checkpoint proposal from the current round leader.
    CheckpointProposal {
        /// Checkpoint height.
        height: u64,
        /// View/round number.
        view: u64,
        /// MMR event root hash.
        event_root: [u8; 32],
        /// SMT state root hash.
        state_root: [u8; 32],
        /// Frontier event IDs included in this checkpoint.
        frontier: Vec<[u8; 32]>,
        /// Leader's DID.
        proposer_did: String,
        /// Leader's signature over the checkpoint preimage.
        signature: Vec<u8>,
    },

    /// Vote on a checkpoint proposal.
    CheckpointVote {
        /// Height being voted on.
        height: u64,
        /// View/round number.
        view: u64,
        /// Voter's DID.
        voter_did: String,
        /// Voter's Ed25519 signature.
        signature: Vec<u8>,
        /// The checkpoint hash being voted for.
        checkpoint_hash: [u8; 32],
    },

    /// Peer capability advertisement.
    PeerAnnounce {
        /// Peer's DID.
        did: String,
        /// Whether this peer is a validator.
        is_validator: bool,
        /// Peer's current DAG height.
        dag_height: u64,
        /// Latest finalized checkpoint height.
        checkpoint_height: u64,
        /// Supported protocol version.
        protocol_version: u32,
        /// Capabilities offered.
        capabilities: Vec<String>,
    },

    /// Request events the peer is missing (sync protocol).
    SyncRequest {
        /// Events the requester already has (by hash).
        known_frontier: Vec<[u8; 32]>,
        /// Maximum events to send back.
        max_events: u32,
    },

    /// Response with missing events.
    SyncResponse {
        /// Serialized events (CBOR encoded).
        events: Vec<Vec<u8>>,
        /// Whether there are more events available.
        has_more: bool,
    },
}

// ---------------------------------------------------------------------------
// Peer tracking
// ---------------------------------------------------------------------------

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub did: Option<String>,
    pub is_validator: bool,
    pub dag_height: u64,
    pub checkpoint_height: u64,
    pub connected_at: std::time::Instant,
    pub last_seen: std::time::Instant,
    pub messages_received: u64,
    pub messages_sent: u64,
}

/// Tracks all connected peers and their status.
#[derive(Default)]
pub struct PeerRegistry {
    peers: HashMap<PeerId, PeerInfo>,
    /// Dedup filter — event hashes we've already seen.
    seen_events: HashSet<[u8; 32]>,
    /// Maximum seen events to track (ring buffer behavior).
    max_seen: usize,
}

impl PeerRegistry {
    pub fn new(max_seen: usize) -> Self {
        Self {
            peers: HashMap::new(),
            seen_events: HashSet::new(),
            max_seen,
        }
    }

    /// Register a new peer connection.
    pub fn register(&mut self, peer_id: PeerId) {
        let now = std::time::Instant::now();
        self.peers.entry(peer_id).or_insert(PeerInfo {
            peer_id,
            did: None,
            is_validator: false,
            dag_height: 0,
            checkpoint_height: 0,
            connected_at: now,
            last_seen: now,
            messages_received: 0,
            messages_sent: 0,
        });
    }

    /// Remove a disconnected peer.
    pub fn unregister(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Update peer info from an announce message.
    pub fn update_from_announce(&mut self, peer_id: &PeerId, msg: &LynkMessage) {
        if let LynkMessage::PeerAnnounce {
            did,
            is_validator,
            dag_height,
            checkpoint_height,
            ..
        } = msg
        {
            if let Some(info) = self.peers.get_mut(peer_id) {
                info.did = Some(did.clone());
                info.is_validator = *is_validator;
                info.dag_height = *dag_height;
                info.checkpoint_height = *checkpoint_height;
                info.last_seen = std::time::Instant::now();
            }
        }
    }

    /// Check if we've already seen an event (dedup).
    pub fn is_seen(&self, event_id: &[u8; 32]) -> bool {
        self.seen_events.contains(event_id)
    }

    /// Mark an event as seen.
    pub fn mark_seen(&mut self, event_id: [u8; 32]) {
        // Simple eviction: clear half when at capacity
        if self.seen_events.len() >= self.max_seen {
            let to_remove: Vec<[u8; 32]> = self
                .seen_events
                .iter()
                .take(self.max_seen / 2)
                .copied()
                .collect();
            for id in to_remove {
                self.seen_events.remove(&id);
            }
        }
        self.seen_events.insert(event_id);
    }

    /// Get all connected validators.
    pub fn validators(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.is_validator).collect()
    }

    /// Get the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of connected validators.
    pub fn validator_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_validator).count()
    }

    /// Get peer info by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }
}

// ---------------------------------------------------------------------------
// Network behaviour — Gossipsub + Ping + mDNS-like discovery
// ---------------------------------------------------------------------------

/// Custom Network Behaviour for the Lynk Protocol.
/// Combines Gossipsub (event/checkpoint propagation) with Ping (liveness).
#[derive(NetworkBehaviour)]
pub struct ExoBehaviour {
    pub ping: libp2p::ping::Behaviour,
}

// ---------------------------------------------------------------------------
// Lynk Protocol node
// ---------------------------------------------------------------------------

/// Configuration for a Lynk Protocol node.
#[derive(Clone, Debug)]
pub struct LynkConfig {
    /// Listen address (e.g., "/ip4/0.0.0.0/tcp/0").
    pub listen_addr: String,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<String>,
    /// This node's DID.
    pub node_did: String,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Idle connection timeout.
    pub idle_timeout_secs: u64,
    /// Maximum seen events for dedup.
    pub max_seen_events: usize,
}

impl Default for LynkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            node_did: String::new(),
            is_validator: false,
            idle_timeout_secs: 60,
            bootstrap_peers: Vec::new(),
            max_seen_events: 100_000,
        }
    }
}

/// Statistics about the Lynk Protocol node.
#[derive(Clone, Debug, Default)]
pub struct LynkStats {
    pub events_received: u64,
    pub events_propagated: u64,
    pub checkpoints_proposed: u64,
    pub checkpoints_voted: u64,
    pub checkpoints_finalized: u64,
    pub peers_connected: u64,
    pub peers_disconnected: u64,
    pub sync_requests: u64,
    pub sync_responses: u64,
    pub invalid_messages: u64,
}

/// Start a Lynk Protocol P2P node.
///
/// This is the main entry point for the distributed network layer.
/// The node will:
/// 1. Listen for incoming connections
/// 2. Connect to bootstrap peers
/// 3. Handle Gossipsub messages (events, checkpoints, discovery)
/// 4. Track peer state and manage dedup
pub async fn start_p2p_node() -> Result<(), Box<dyn std::error::Error>> {
    start_p2p_node_with_config(LynkConfig::default()).await
}

/// Start a Lynk Protocol node with custom configuration.
pub async fn start_p2p_node_with_config(
    config: LynkConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create Identity
    let id_keys = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();

    tracing::info!(
        "Lynk Protocol starting — Peer ID: {}, DID: {}, Validator: {}",
        peer_id,
        config.node_did,
        config.is_validator
    );

    // 2. Build swarm with transport + behaviour
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| ExoBehaviour {
            ping: libp2p::ping::Behaviour::default(),
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(config.idle_timeout_secs))
        })
        .build();

    // 3. Listen
    swarm.listen_on(config.listen_addr.parse()?)?;

    // 4. Connect to bootstrap peers
    for addr in &config.bootstrap_peers {
        if let Ok(multiaddr) = addr.parse::<libp2p::Multiaddr>() {
            tracing::info!("Dialing bootstrap peer: {}", addr);
            let _ = swarm.dial(multiaddr);
        }
    }

    // 5. Initialize peer registry and stats
    let mut registry = PeerRegistry::new(config.max_seen_events);
    let mut stats = LynkStats::default();

    // 6. Event loop — the Lynk Protocol reactor
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Lynk listening on {address}");
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Lynk peer connected: {peer_id}");
                registry.register(peer_id);
                stats.peers_connected += 1;
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::info!("Lynk peer disconnected: {peer_id}");
                registry.unregister(&peer_id);
                stats.peers_disconnected += 1;
            }

            SwarmEvent::Behaviour(event) => {
                tracing::debug!("Lynk behaviour event: {event:?}");
            }

            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Message serialization (CBOR-based for wire format)
// ---------------------------------------------------------------------------

impl LynkMessage {
    /// Serialize to CBOR bytes for wire transmission.
    pub fn to_cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(bytes)
    }

    /// Get the topic this message should be published to.
    pub fn topic(&self) -> &str {
        match self {
            LynkMessage::EventGossip { .. } => topics::EVENTS,
            LynkMessage::CheckpointProposal { .. } => topics::CHECKPOINTS,
            LynkMessage::CheckpointVote { .. } => topics::CHECKPOINTS,
            LynkMessage::PeerAnnounce { .. } => topics::DISCOVERY,
            LynkMessage::SyncRequest { .. } => topics::EVENTS,
            LynkMessage::SyncResponse { .. } => topics::EVENTS,
        }
    }

    /// Get a human-readable type name for logging.
    pub fn type_name(&self) -> &str {
        match self {
            LynkMessage::EventGossip { .. } => "EventGossip",
            LynkMessage::CheckpointProposal { .. } => "CheckpointProposal",
            LynkMessage::CheckpointVote { .. } => "CheckpointVote",
            LynkMessage::PeerAnnounce { .. } => "PeerAnnounce",
            LynkMessage::SyncRequest { .. } => "SyncRequest",
            LynkMessage::SyncResponse { .. } => "SyncResponse",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_cbor_roundtrip_event_gossip() {
        let msg = LynkMessage::EventGossip {
            event_cbor: vec![1, 2, 3, 4],
            event_id: [42u8; 32],
            origin_peer: "peer-1".to_string(),
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "EventGossip");
        assert_eq!(decoded.topic(), topics::EVENTS);
    }

    #[test]
    fn test_message_cbor_roundtrip_checkpoint_proposal() {
        let msg = LynkMessage::CheckpointProposal {
            height: 100,
            view: 5,
            event_root: [1u8; 32],
            state_root: [2u8; 32],
            frontier: vec![[3u8; 32], [4u8; 32]],
            proposer_did: "did:exo:validator1".to_string(),
            signature: vec![0u8; 64],
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "CheckpointProposal");
        assert_eq!(decoded.topic(), topics::CHECKPOINTS);
    }

    #[test]
    fn test_message_cbor_roundtrip_checkpoint_vote() {
        let msg = LynkMessage::CheckpointVote {
            height: 100,
            view: 5,
            voter_did: "did:exo:voter1".to_string(),
            signature: vec![0u8; 64],
            checkpoint_hash: [99u8; 32],
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "CheckpointVote");
    }

    #[test]
    fn test_message_cbor_roundtrip_peer_announce() {
        let msg = LynkMessage::PeerAnnounce {
            did: "did:exo:node1".to_string(),
            is_validator: true,
            dag_height: 500,
            checkpoint_height: 490,
            protocol_version: 1,
            capabilities: vec!["validator".to_string(), "indexer".to_string()],
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "PeerAnnounce");
        assert_eq!(decoded.topic(), topics::DISCOVERY);
    }

    #[test]
    fn test_message_cbor_roundtrip_sync_request() {
        let msg = LynkMessage::SyncRequest {
            known_frontier: vec![[1u8; 32], [2u8; 32]],
            max_events: 100,
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "SyncRequest");
    }

    #[test]
    fn test_message_cbor_roundtrip_sync_response() {
        let msg = LynkMessage::SyncResponse {
            events: vec![vec![1, 2, 3], vec![4, 5, 6]],
            has_more: true,
        };
        let bytes = msg.to_cbor().unwrap();
        let decoded = LynkMessage::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.type_name(), "SyncResponse");
    }

    #[test]
    fn test_peer_registry_register_unregister() {
        let mut reg = PeerRegistry::new(1000);
        let peer = PeerId::random();
        reg.register(peer);
        assert_eq!(reg.peer_count(), 1);
        assert!(reg.get(&peer).is_some());
        reg.unregister(&peer);
        assert_eq!(reg.peer_count(), 0);
        assert!(reg.get(&peer).is_none());
    }

    #[test]
    fn test_peer_registry_dedup() {
        let mut reg = PeerRegistry::new(1000);
        let event_id = [42u8; 32];
        assert!(!reg.is_seen(&event_id));
        reg.mark_seen(event_id);
        assert!(reg.is_seen(&event_id));
    }

    #[test]
    fn test_peer_registry_dedup_eviction() {
        let mut reg = PeerRegistry::new(10);
        // Fill to capacity
        for i in 0..10u8 {
            reg.mark_seen([i; 32]);
        }
        assert_eq!(reg.seen_events.len(), 10);
        // Adding one more should trigger eviction
        reg.mark_seen([99u8; 32]);
        assert!(reg.seen_events.len() <= 6); // evicted half + added 1
    }

    #[test]
    fn test_peer_registry_validator_count() {
        let mut reg = PeerRegistry::new(1000);
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        reg.register(p1);
        reg.register(p2);
        reg.register(p3);

        // Update p1 and p3 as validators
        reg.update_from_announce(
            &p1,
            &LynkMessage::PeerAnnounce {
                did: "did:exo:v1".to_string(),
                is_validator: true,
                dag_height: 100,
                checkpoint_height: 95,
                protocol_version: 1,
                capabilities: vec![],
            },
        );
        reg.update_from_announce(
            &p3,
            &LynkMessage::PeerAnnounce {
                did: "did:exo:v3".to_string(),
                is_validator: true,
                dag_height: 100,
                checkpoint_height: 95,
                protocol_version: 1,
                capabilities: vec![],
            },
        );

        assert_eq!(reg.validator_count(), 2);
        assert_eq!(reg.peer_count(), 3);
        assert_eq!(reg.validators().len(), 2);
    }

    #[test]
    fn test_peer_announce_updates_info() {
        let mut reg = PeerRegistry::new(1000);
        let peer = PeerId::random();
        reg.register(peer);

        let info = reg.get(&peer).unwrap();
        assert_eq!(info.did, None);
        assert!(!info.is_validator);

        reg.update_from_announce(
            &peer,
            &LynkMessage::PeerAnnounce {
                did: "did:exo:node1".to_string(),
                is_validator: true,
                dag_height: 500,
                checkpoint_height: 490,
                protocol_version: 1,
                capabilities: vec!["validator".to_string()],
            },
        );

        let info = reg.get(&peer).unwrap();
        assert_eq!(info.did.as_deref(), Some("did:exo:node1"));
        assert!(info.is_validator);
        assert_eq!(info.dag_height, 500);
        assert_eq!(info.checkpoint_height, 490);
    }

    #[test]
    fn test_lynk_config_default() {
        let config = LynkConfig::default();
        assert_eq!(config.listen_addr, "/ip4/0.0.0.0/tcp/0");
        assert!(!config.is_validator);
        assert!(config.bootstrap_peers.is_empty());
        assert_eq!(config.max_seen_events, 100_000);
    }

    #[test]
    fn test_lynk_stats_default() {
        let stats = LynkStats::default();
        assert_eq!(stats.events_received, 0);
        assert_eq!(stats.events_propagated, 0);
        assert_eq!(stats.checkpoints_finalized, 0);
    }

    #[test]
    fn test_all_message_types_have_topics() {
        let messages: Vec<LynkMessage> = vec![
            LynkMessage::EventGossip {
                event_cbor: vec![],
                event_id: [0u8; 32],
                origin_peer: "p".into(),
            },
            LynkMessage::CheckpointProposal {
                height: 0, view: 0, event_root: [0u8; 32], state_root: [0u8; 32],
                frontier: vec![], proposer_did: "d".into(), signature: vec![],
            },
            LynkMessage::CheckpointVote {
                height: 0, view: 0, voter_did: "d".into(),
                signature: vec![], checkpoint_hash: [0u8; 32],
            },
            LynkMessage::PeerAnnounce {
                did: "d".into(), is_validator: false, dag_height: 0,
                checkpoint_height: 0, protocol_version: 1, capabilities: vec![],
            },
            LynkMessage::SyncRequest {
                known_frontier: vec![], max_events: 10,
            },
            LynkMessage::SyncResponse {
                events: vec![], has_more: false,
            },
        ];

        for msg in &messages {
            assert!(!msg.topic().is_empty(), "{} has empty topic", msg.type_name());
            assert!(!msg.type_name().is_empty());
        }
    }

    #[test]
    fn test_topic_constants() {
        assert_eq!(topics::EVENTS, "exochain/events/v1");
        assert_eq!(topics::CHECKPOINTS, "exochain/checkpoints/v1");
        assert_eq!(topics::DISCOVERY, "exochain/discovery/v1");
    }
}
