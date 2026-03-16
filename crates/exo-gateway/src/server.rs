//! Real HTTP API server backed by governance crates.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::auth::{AuthProvider, AuthenticatedUser, JwtService, TokenClaims};
use exo_core::crypto::{hash_bytes, Blake3Hash};
use exo_core::hlc::HybridLogicalClock;
use exo_governance::audit::{AuditEventType, AuditLog};
use exo_governance::constitution::*;
use exo_governance::decision::*;
use exo_governance::delegation::*;
use exo_governance::types::*;

// ---------------------------------------------------------------------------
// Identity & PACE types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAccount {
    pub did: String,
    pub display_name: String,
    pub email: String,
    pub roles: Vec<String>,
    pub tenant_id: String,
    pub created_at: u64,
    pub status: AccountStatus,
    pub pace_status: PaceStatus,
    pub password_hash: String,
    pub salt: String,
    pub mfa_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    Active,
    Suspended,
    PendingVerification,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PaceStatus {
    Unenrolled,
    Provable,
    Auditable,
    Compliant,
    Enforceable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub did: String,
    pub agent_name: String,
    pub agent_type: String,
    pub owner_did: String,
    pub tenant_id: String,
    pub capabilities: Vec<String>,
    pub trust_tier: TrustTier,
    pub trust_score: u32,
    pub delegation_id: Option<String>,
    pub pace_status: PaceStatus,
    pub created_at: u64,
    pub status: AccountStatus,
    pub max_decision_class: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum TrustTier {
    Untrusted,
    Probationary,
    Standard,
    Trusted,
    Verified,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityScore {
    pub did: String,
    pub score: u32,
    pub tier: TrustTier,
    pub factors: ScoreFactors,
    pub last_updated: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreFactors {
    pub tenure_days: u32,
    pub decisions_participated: u32,
    pub votes_cast: u32,
    pub compliance_violations: u32,
    pub delegation_depth: u32,
    pub pace_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRecord {
    pub did: String,
    pub entity_type: String,
    pub step: String,
    pub timestamp: u64,
    pub verified_by: String,
    pub audit_hash: String,
}

// ---------------------------------------------------------------------------
// Application State — real governance objects, in-memory
// ---------------------------------------------------------------------------

pub struct AppState {
    pub decisions: Vec<DecisionObject>,
    pub delegations: Vec<Delegation>,
    pub audit_log: AuditLog,
    pub constitution: Constitution,
    pub hlc_counter: u64,
    pub users: Vec<UserAccount>,
    pub agents: Vec<AgentIdentity>,
    pub identity_scores: HashMap<String, IdentityScore>,
    pub jwt_service: JwtService,
    pub enrollment_log: Vec<EnrollmentRecord>,
    /// Optional PostgreSQL pool for write-through persistence.
    pub pool: Option<sqlx::PgPool>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let constitution = seed_constitution();
        let jwt_service = JwtService::new("decision.forum".into(), 3600);
        let mut state = Self {
            decisions: Vec::new(),
            delegations: Vec::new(),
            audit_log: AuditLog::new(),
            constitution,
            hlc_counter: 1000,
            users: Vec::new(),
            agents: Vec::new(),
            identity_scores: HashMap::new(),
            jwt_service,
            enrollment_log: Vec::new(),
            pool: None,
        };
        seed_users(&mut state);
        seed_agents(&mut state);
        seed_delegations(&mut state);
        seed_decisions(&mut state);
        state
    }

    fn next_hlc(&mut self) -> HybridLogicalClock {
        self.hlc_counter += 1;
        HybridLogicalClock {
            physical_ms: self.hlc_counter,
            logical: 0,
        }
    }

    fn next_hash(&mut self, data: &[u8]) -> Blake3Hash {
        hash_bytes(data)
    }
}

// ---------------------------------------------------------------------------
// Helper: BLAKE3 password hashing
// ---------------------------------------------------------------------------

fn blake3_password_hash(password: &str, salt: &str) -> String {
    let input = format!("{}{}", password, salt);
    let hash = hash_bytes(input.as_bytes());
    hex::encode(hash.0)
}

fn generate_salt(seed: &str) -> String {
    let hash = hash_bytes(seed.as_bytes());
    hex::encode(&hash.0[..16])
}

// ---------------------------------------------------------------------------
// Helper: compute identity score for a DID
// ---------------------------------------------------------------------------

fn compute_identity_score(state: &AppState, did: &str) -> IdentityScore {
    let pace_status = state
        .users
        .iter()
        .find(|u| u.did == did)
        .map(|u| &u.pace_status)
        .or_else(|| {
            state
                .agents
                .iter()
                .find(|a| a.did == did)
                .map(|a| &a.pace_status)
        });

    let created_at = state
        .users
        .iter()
        .find(|u| u.did == did)
        .map(|u| u.created_at)
        .or_else(|| {
            state
                .agents
                .iter()
                .find(|a| a.did == did)
                .map(|a| a.created_at)
        })
        .unwrap_or(0);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let tenure_days = if created_at > 0 {
        ((now_ms.saturating_sub(created_at)) / 86_400_000) as u32
    } else {
        0
    };

    // Count decisions participated and votes cast from audit log
    let decisions_participated = state
        .audit_log
        .entries()
        .iter()
        .filter(|e| e.actor == did && matches!(e.event_type, AuditEventType::DecisionCreated | AuditEventType::DecisionAdvanced))
        .count() as u32;

    let votes_cast = state
        .audit_log
        .entries()
        .iter()
        .filter(|e| e.actor == did && matches!(e.event_type, AuditEventType::VoteCast))
        .count() as u32;

    let compliance_violations: u32 = 0; // No violation tracking yet

    let delegation_depth = state
        .delegations
        .iter()
        .filter(|d| d.delegatee == did || d.delegator == did)
        .count() as u32;

    let pace_complete = pace_status == Some(&PaceStatus::Enforceable);

    // Score calculation
    let mut score: u32 = 200; // base for existing account

    // PACE bonuses
    if let Some(ps) = pace_status {
        match ps {
            PaceStatus::Enforceable => score += 400, // P+A+C+E
            PaceStatus::Compliant => score += 300,   // P+A+C
            PaceStatus::Auditable => score += 200,   // P+A
            PaceStatus::Provable => score += 100,    // P
            PaceStatus::Unenrolled => {}
        }
    }

    // Decision participation bonus: +50 per decision, max 200
    score += std::cmp::min(decisions_participated * 50, 200);

    // Votes cast bonus: +20 per vote, max 100
    score += std::cmp::min(votes_cast * 20, 100);

    // Compliance violation penalty
    score = score.saturating_sub(compliance_violations * 100);

    // Tenure bonus: min(tenure_days, 200)
    score += std::cmp::min(tenure_days, 200);

    // Cap at 1000
    score = std::cmp::min(score, 1000);

    let tier = score_to_tier(score);

    IdentityScore {
        did: did.to_string(),
        score,
        tier,
        factors: ScoreFactors {
            tenure_days,
            decisions_participated,
            votes_cast,
            compliance_violations,
            delegation_depth,
            pace_complete,
        },
        last_updated: now_ms,
    }
}

fn score_to_tier(score: u32) -> TrustTier {
    match score {
        0..=299 => TrustTier::Untrusted,
        300..=499 => TrustTier::Probationary,
        500..=699 => TrustTier::Standard,
        700..=899 => TrustTier::Trusted,
        _ => TrustTier::Verified,
    }
}

// ---------------------------------------------------------------------------
// Auth middleware helper
// ---------------------------------------------------------------------------

fn extract_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<TokenClaims, (StatusCode, Json<ErrorJson>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorJson {
                    error: "Missing Authorization header".into(),
                }),
            )
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorJson {
                    error: "Invalid Authorization header format".into(),
                }),
            )
        })?;

    state.jwt_service.validate_token(token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorJson {
                error: format!("Token validation failed: {}", e),
            }),
        )
    })
}

// ---------------------------------------------------------------------------
// Seed data — real governance objects
// ---------------------------------------------------------------------------

fn seed_users(state: &mut AppState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Root Authority
    let salt_root = generate_salt("root-salt-seed");
    state.users.push(UserAccount {
        did: "did:exo:root".into(),
        display_name: "Root Authority".into(),
        email: "root@exochain.io".into(),
        roles: vec!["admin".into()],
        tenant_id: "tenant-1".into(),
        created_at: now - 90 * 86_400_000, // 90 days ago
        status: AccountStatus::Active,
        pace_status: PaceStatus::Enforceable,
        password_hash: blake3_password_hash("root-pass", &salt_root),
        salt: salt_root,
        mfa_enabled: true,
    });
    state.enrollment_log.push(EnrollmentRecord {
        did: "did:exo:root".into(),
        entity_type: "user".into(),
        step: "E".into(),
        timestamp: now - 89 * 86_400_000,
        verified_by: "system".into(),
        audit_hash: hex::encode(&hash_bytes(b"root-enrollment").0[..16]),
    });
    state.identity_scores.insert(
        "did:exo:root".into(),
        IdentityScore {
            did: "did:exo:root".into(),
            score: 950,
            tier: TrustTier::Verified,
            factors: ScoreFactors {
                tenure_days: 90,
                decisions_participated: 5,
                votes_cast: 10,
                compliance_violations: 0,
                delegation_depth: 2,
                pace_complete: true,
            },
            last_updated: now,
        },
    );

    // Alice Chen
    let salt_alice = generate_salt("alice-salt-seed");
    state.users.push(UserAccount {
        did: "did:exo:alice".into(),
        display_name: "Alice Chen".into(),
        email: "alice@exochain.io".into(),
        roles: vec!["admin".into(), "voter".into()],
        tenant_id: "tenant-1".into(),
        created_at: now - 60 * 86_400_000,
        status: AccountStatus::Active,
        pace_status: PaceStatus::Enforceable,
        password_hash: blake3_password_hash("alice-pass", &salt_alice),
        salt: salt_alice,
        mfa_enabled: true,
    });
    state.enrollment_log.push(EnrollmentRecord {
        did: "did:exo:alice".into(),
        entity_type: "user".into(),
        step: "E".into(),
        timestamp: now - 59 * 86_400_000,
        verified_by: "did:exo:root".into(),
        audit_hash: hex::encode(&hash_bytes(b"alice-enrollment").0[..16]),
    });
    state.identity_scores.insert(
        "did:exo:alice".into(),
        IdentityScore {
            did: "did:exo:alice".into(),
            score: 820,
            tier: TrustTier::Trusted,
            factors: ScoreFactors {
                tenure_days: 60,
                decisions_participated: 4,
                votes_cast: 8,
                compliance_violations: 0,
                delegation_depth: 2,
                pace_complete: true,
            },
            last_updated: now,
        },
    );

    // Bob Martinez
    let salt_bob = generate_salt("bob-salt-seed");
    state.users.push(UserAccount {
        did: "did:exo:bob".into(),
        display_name: "Bob Martinez".into(),
        email: "bob@exochain.io".into(),
        roles: vec!["voter".into()],
        tenant_id: "tenant-1".into(),
        created_at: now - 45 * 86_400_000,
        status: AccountStatus::Active,
        pace_status: PaceStatus::Compliant,
        password_hash: blake3_password_hash("bob-pass", &salt_bob),
        salt: salt_bob,
        mfa_enabled: false,
    });
    state.enrollment_log.push(EnrollmentRecord {
        did: "did:exo:bob".into(),
        entity_type: "user".into(),
        step: "C".into(),
        timestamp: now - 44 * 86_400_000,
        verified_by: "did:exo:root".into(),
        audit_hash: hex::encode(&hash_bytes(b"bob-enrollment").0[..16]),
    });
    state.identity_scores.insert(
        "did:exo:bob".into(),
        IdentityScore {
            did: "did:exo:bob".into(),
            score: 680,
            tier: TrustTier::Standard,
            factors: ScoreFactors {
                tenure_days: 45,
                decisions_participated: 3,
                votes_cast: 5,
                compliance_violations: 0,
                delegation_depth: 1,
                pace_complete: false,
            },
            last_updated: now,
        },
    );

    // Carol Williams
    let salt_carol = generate_salt("carol-salt-seed");
    state.users.push(UserAccount {
        did: "did:exo:carol".into(),
        display_name: "Carol Williams".into(),
        email: "carol@exochain.io".into(),
        roles: vec!["voter".into(), "auditor".into()],
        tenant_id: "tenant-1".into(),
        created_at: now - 55 * 86_400_000,
        status: AccountStatus::Active,
        pace_status: PaceStatus::Enforceable,
        password_hash: blake3_password_hash("carol-pass", &salt_carol),
        salt: salt_carol,
        mfa_enabled: true,
    });
    state.enrollment_log.push(EnrollmentRecord {
        did: "did:exo:carol".into(),
        entity_type: "user".into(),
        step: "E".into(),
        timestamp: now - 54 * 86_400_000,
        verified_by: "did:exo:root".into(),
        audit_hash: hex::encode(&hash_bytes(b"carol-enrollment").0[..16]),
    });
    state.identity_scores.insert(
        "did:exo:carol".into(),
        IdentityScore {
            did: "did:exo:carol".into(),
            score: 790,
            tier: TrustTier::Trusted,
            factors: ScoreFactors {
                tenure_days: 55,
                decisions_participated: 3,
                votes_cast: 6,
                compliance_violations: 0,
                delegation_depth: 1,
                pace_complete: true,
            },
            last_updated: now,
        },
    );
}

fn seed_agents(state: &mut AppState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    state.agents.push(AgentIdentity {
        did: "did:exo:agent-copilot-1".into(),
        agent_name: "Governance Copilot".into(),
        agent_type: "copilot".into(),
        owner_did: "did:exo:alice".into(),
        tenant_id: "tenant-1".into(),
        capabilities: vec![
            "read:decisions".into(),
            "suggest:votes".into(),
            "draft:proposals".into(),
        ],
        trust_tier: TrustTier::Standard,
        trust_score: 550,
        delegation_id: None,
        pace_status: PaceStatus::Auditable,
        created_at: now - 30 * 86_400_000,
        status: AccountStatus::Active,
        max_decision_class: "Operational".into(),
    });
    state.enrollment_log.push(EnrollmentRecord {
        did: "did:exo:agent-copilot-1".into(),
        entity_type: "agent".into(),
        step: "A".into(),
        timestamp: now - 29 * 86_400_000,
        verified_by: "did:exo:alice".into(),
        audit_hash: hex::encode(&hash_bytes(b"copilot-enrollment").0[..16]),
    });
    state.identity_scores.insert(
        "did:exo:agent-copilot-1".into(),
        IdentityScore {
            did: "did:exo:agent-copilot-1".into(),
            score: 550,
            tier: TrustTier::Standard,
            factors: ScoreFactors {
                tenure_days: 30,
                decisions_participated: 2,
                votes_cast: 0,
                compliance_violations: 0,
                delegation_depth: 0,
                pace_complete: false,
            },
            last_updated: now,
        },
    );
}

fn seed_constitution() -> Constitution {
    Constitution {
        tenant_id: "tenant-1".into(),
        version: SemVer::new(1, 0, 0),
        hash: hash_bytes(b"constitution-v1"),
        documents: vec![ConstitutionalDocument {
            id: "bylaws-v1".into(),
            precedence: PrecedenceLevel::Bylaws,
            content: serde_json::json!({
                "title": "Corporate Bylaws",
                "adopted": "2024-01-01"
            }),
            constraints: vec![
                Constraint {
                    id: "C-001".into(),
                    description: "Strategic decisions require human gate".into(),
                    expression: ConstraintExpression::RequireHumanGate {
                        decision_class: DecisionClass::Strategic,
                    },
                    failure_action: FailureAction::Block,
                },
                Constraint {
                    id: "C-002".into(),
                    description: "Minimum quorum of 2 for strategic".into(),
                    expression: ConstraintExpression::RequireMinQuorum {
                        decision_class: DecisionClass::Strategic,
                        minimum: 2,
                    },
                    failure_action: FailureAction::Block,
                },
                Constraint {
                    id: "C-003".into(),
                    description: "Max delegation depth 5".into(),
                    expression: ConstraintExpression::MaxDelegationDepth { max_depth: 5 },
                    failure_action: FailureAction::Block,
                },
            ],
        }],
        decision_classes: vec![],
        human_gate_classes: vec![DecisionClass::Strategic, DecisionClass::Constitutional],
        emergency_authorities: vec![],
        default_delegation_expiry_hours: 720,
        max_delegation_depth: 5,
        created_at: HybridLogicalClock {
            physical_ms: 1000,
            logical: 0,
        },
        signatures: vec![],
    }
}

fn dummy_sig(signer: &str, hlc: HybridLogicalClock) -> GovernanceSignature {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let dummy = Blake3Hash([0u8; 32]);
    let sig = exo_core::compute_signature(&sk, &dummy);
    GovernanceSignature {
        signer: signer.to_string(),
        signer_type: SignerType::Human,
        signature: sig,
        key_version: 1,
        timestamp: hlc,
    }
}

fn seed_delegations(state: &mut AppState) {
    let hlc = state.next_hlc();
    state.delegations.push(Delegation {
        id: hash_bytes(b"del-001"),
        tenant_id: "tenant-1".into(),
        delegator: "did:exo:root".into(),
        delegatee: "did:exo:alice".into(),
        scope: DelegationScope {
            decision_classes: vec![
                DecisionClass::Operational,
                DecisionClass::Strategic,
                DecisionClass::Financial {
                    threshold_cents: 100_000_000,
                },
            ],
            monetary_cap: Some(100_000_000),
            resource_ids: vec![],
            actions: vec![
                AuthorizedAction::CreateDecision,
                AuthorizedAction::AdvanceDecision,
                AuthorizedAction::CastVote,
                AuthorizedAction::GrantDelegation,
            ],
        },
        sub_delegation_allowed: true,
        sub_delegation_scope_cap: None,
        created_at: hlc,
        expires_at: 9_999_999_999_000,
        revoked_at: None,
        constitution_version: SemVer::new(1, 0, 0),
        signature: dummy_sig("did:exo:root", hlc),
        parent_delegation: None,
    });

    let hlc = state.next_hlc();
    state.delegations.push(Delegation {
        id: hash_bytes(b"del-002"),
        tenant_id: "tenant-1".into(),
        delegator: "did:exo:alice".into(),
        delegatee: "did:exo:bob".into(),
        scope: DelegationScope {
            decision_classes: vec![DecisionClass::Operational],
            monetary_cap: Some(10_000_000),
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision, AuthorizedAction::CastVote],
        },
        sub_delegation_allowed: false,
        sub_delegation_scope_cap: None,
        created_at: hlc,
        expires_at: 9_999_999_999_000,
        revoked_at: None,
        constitution_version: SemVer::new(1, 0, 0),
        signature: dummy_sig("did:exo:alice", hlc),
        parent_delegation: Some(hash_bytes(b"del-001")),
    });

    let hlc = state.next_hlc();
    state.delegations.push(Delegation {
        id: hash_bytes(b"del-003"),
        tenant_id: "tenant-1".into(),
        delegator: "did:exo:root".into(),
        delegatee: "did:exo:carol".into(),
        scope: DelegationScope {
            decision_classes: vec![DecisionClass::Operational, DecisionClass::Strategic],
            monetary_cap: None,
            resource_ids: vec![],
            actions: vec![
                AuthorizedAction::CreateDecision,
                AuthorizedAction::CastVote,
                AuthorizedAction::AdvanceDecision,
            ],
        },
        sub_delegation_allowed: false,
        sub_delegation_scope_cap: None,
        created_at: hlc,
        expires_at: 9_999_999_999_000,
        revoked_at: None,
        constitution_version: SemVer::new(1, 0, 0),
        signature: dummy_sig("did:exo:carol", hlc),
        parent_delegation: None,
    });
}

fn seed_decisions(state: &mut AppState) {
    let eligible = vec![
        "did:exo:alice".into(),
        "did:exo:bob".into(),
        "did:exo:carol".into(),
    ];

    // Decision 1: in Deliberation
    let hlc = state.next_hlc();
    let id1 = hash_bytes(b"dec-001");
    let mut d1 = DecisionObject {
        id: id1,
        tenant_id: "tenant-1".into(),
        status: DecisionStatus::Created,
        title: "Q4 Budget Allocation".into(),
        body: serde_cbor::to_vec(&"Allocate $2.5M for Q4 operations").unwrap(),
        decision_class: DecisionClass::Financial {
            threshold_cents: 25_000_000,
        },
        constitution_hash: state.constitution.hash,
        constitution_version: SemVer::new(1, 0, 0),
        author: "did:exo:alice".into(),
        created_at: hlc,
        delegations_snapshot: vec![hash_bytes(b"del-001")],
        evidence: vec![],
        conflicts_disclosed: vec![],
        votes: vec![],
        quorum_requirement: QuorumSpec {
            minimum_participants: 2,
            approval_threshold_pct: 51,
            eligible_voters: eligible.clone(),
        },
        parent_decisions: vec![],
        challenge_ids: vec![],
        signatures: vec![],
        transition_log: vec![],
        crosscheck_reports: vec![],
        clearance_certificates: vec![],
        anchor_receipts: vec![],
    };
    state.audit_log.append(
        id1,
        AuditEventType::DecisionCreated,
        "did:exo:alice".into(),
        "tenant-1".into(),
        hlc,
    );
    let hlc2 = state.next_hlc();
    d1.advance(
        DecisionStatus::Deliberation,
        "did:exo:alice".into(),
        Some("Opening deliberation".into()),
        dummy_sig("did:exo:alice", hlc2),
        hlc2,
    )
    .unwrap();
    state.audit_log.append(
        id1,
        AuditEventType::DecisionAdvanced,
        "did:exo:alice".into(),
        "tenant-1".into(),
        hlc2,
    );
    state.decisions.push(d1);

    // Decision 2: in Voting with 2 votes
    let hlc = state.next_hlc();
    let id2 = hash_bytes(b"dec-002");
    let mut d2 = DecisionObject {
        id: id2,
        tenant_id: "tenant-1".into(),
        status: DecisionStatus::Created,
        title: "Adopt Remote Work Policy".into(),
        body: serde_cbor::to_vec(&"Enable full remote work for all employees").unwrap(),
        decision_class: DecisionClass::Strategic,
        constitution_hash: state.constitution.hash,
        constitution_version: SemVer::new(1, 0, 0),
        author: "did:exo:bob".into(),
        created_at: hlc,
        delegations_snapshot: vec![],
        evidence: vec![],
        conflicts_disclosed: vec![],
        votes: vec![],
        quorum_requirement: QuorumSpec {
            minimum_participants: 2,
            approval_threshold_pct: 51,
            eligible_voters: eligible.clone(),
        },
        parent_decisions: vec![],
        challenge_ids: vec![],
        signatures: vec![],
        transition_log: vec![],
        crosscheck_reports: vec![],
        clearance_certificates: vec![],
        anchor_receipts: vec![],
    };
    state.audit_log.append(
        id2,
        AuditEventType::DecisionCreated,
        "did:exo:bob".into(),
        "tenant-1".into(),
        hlc,
    );
    let h = state.next_hlc();
    d2.advance(
        DecisionStatus::Deliberation,
        "did:exo:bob".into(),
        None,
        dummy_sig("did:exo:bob", h),
        h,
    )
    .unwrap();
    let h = state.next_hlc();
    d2.advance(
        DecisionStatus::Voting,
        "did:exo:bob".into(),
        Some("Quorum verified, opening vote".into()),
        dummy_sig("did:exo:bob", h),
        h,
    )
    .unwrap();
    state.audit_log.append(
        id2,
        AuditEventType::DecisionAdvanced,
        "did:exo:bob".into(),
        "tenant-1".into(),
        h,
    );

    // Cast votes using the real governance engine
    let h = state.next_hlc();
    d2.cast_vote(Vote {
        voter: "did:exo:alice".into(),
        signer_type: SignerType::Human,
        choice: VoteChoice::Approve,
        rationale: Some("Supports work-life balance".into()),
        signature: dummy_sig("did:exo:alice", h),
        timestamp: h,
    })
    .unwrap();
    state.audit_log.append(
        id2,
        AuditEventType::VoteCast,
        "did:exo:alice".into(),
        "tenant-1".into(),
        h,
    );

    let h = state.next_hlc();
    d2.cast_vote(Vote {
        voter: "did:exo:carol".into(),
        signer_type: SignerType::Human,
        choice: VoteChoice::Approve,
        rationale: None,
        signature: dummy_sig("did:exo:carol", h),
        timestamp: h,
    })
    .unwrap();
    state.audit_log.append(
        id2,
        AuditEventType::VoteCast,
        "did:exo:carol".into(),
        "tenant-1".into(),
        h,
    );
    state.decisions.push(d2);

    // Decision 3: Approved (went through full lifecycle)
    let hlc = state.next_hlc();
    let id3 = hash_bytes(b"dec-003");
    let mut d3 = DecisionObject {
        id: id3,
        tenant_id: "tenant-1".into(),
        status: DecisionStatus::Created,
        title: "Annual Compliance Review".into(),
        body: serde_cbor::to_vec(&"Annual compliance assessment completed").unwrap(),
        decision_class: DecisionClass::Operational,
        constitution_hash: state.constitution.hash,
        constitution_version: SemVer::new(1, 0, 0),
        author: "did:exo:carol".into(),
        created_at: hlc,
        delegations_snapshot: vec![],
        evidence: vec![],
        conflicts_disclosed: vec![],
        votes: vec![],
        quorum_requirement: QuorumSpec {
            minimum_participants: 2,
            approval_threshold_pct: 51,
            eligible_voters: eligible.clone(),
        },
        parent_decisions: vec![],
        challenge_ids: vec![],
        signatures: vec![],
        transition_log: vec![],
        crosscheck_reports: vec![],
        clearance_certificates: vec![],
        anchor_receipts: vec![],
    };
    let h = state.next_hlc();
    d3.advance(
        DecisionStatus::Deliberation,
        "did:exo:carol".into(),
        None,
        dummy_sig("did:exo:carol", h),
        h,
    )
    .unwrap();
    let h = state.next_hlc();
    d3.advance(
        DecisionStatus::Voting,
        "did:exo:carol".into(),
        None,
        dummy_sig("did:exo:carol", h),
        h,
    )
    .unwrap();
    let h = state.next_hlc();
    d3.cast_vote(Vote {
        voter: "did:exo:alice".into(),
        signer_type: SignerType::Human,
        choice: VoteChoice::Approve,
        rationale: None,
        signature: dummy_sig("did:exo:alice", h),
        timestamp: h,
    })
    .unwrap();
    let h = state.next_hlc();
    d3.cast_vote(Vote {
        voter: "did:exo:bob".into(),
        signer_type: SignerType::Human,
        choice: VoteChoice::Approve,
        rationale: None,
        signature: dummy_sig("did:exo:bob", h),
        timestamp: h,
    })
    .unwrap();
    // Tally using real governance engine
    let outcome = d3.tally().unwrap();
    let h = state.next_hlc();
    d3.advance(
        outcome,
        "did:exo:carol".into(),
        Some("Vote tally: Approved".into()),
        dummy_sig("did:exo:carol", h),
        h,
    )
    .unwrap();
    state.audit_log.append(
        id3,
        AuditEventType::DecisionAdvanced,
        "did:exo:carol".into(),
        "tenant-1".into(),
        h,
    );
    state.decisions.push(d3);

    // Self-verify audit chain integrity
    state.audit_log.verify_integrity().unwrap();
    let h = state.next_hlc();
    state.audit_log.append(
        hash_bytes(b"self-verify"),
        AuditEventType::AuditSelfVerification,
        "system".into(),
        "tenant-1".into(),
        h,
    );
}

// ---------------------------------------------------------------------------
// JSON API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecisionJson {
    id: String,
    tenant_id: String,
    status: String,
    title: String,
    decision_class: String,
    author: String,
    created_at: u64,
    constitution_version: String,
    votes: Vec<VoteJson>,
    challenges: Vec<ChallengeJson>,
    transition_log: Vec<TransitionJson>,
    is_terminal: bool,
    valid_next_statuses: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VoteJson {
    voter: String,
    choice: String,
    rationale: Option<String>,
    signer_type: String,
    timestamp: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeJson {
    id: String,
    grounds: String,
    status: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransitionJson {
    from: String,
    to: String,
    actor: String,
    reason: Option<String>,
    timestamp: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegationJson {
    id: String,
    delegator: String,
    delegatee: String,
    scope: String,
    expires_at: u64,
    active: bool,
    sub_delegation_allowed: bool,
    constitution_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEntryJson {
    sequence: u64,
    event_type: String,
    actor: String,
    tenant_id: String,
    timestamp: u64,
    entry_hash: String,
    prev_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConstitutionJson {
    tenant_id: String,
    version: String,
    hash: String,
    document_count: usize,
    constraints: Vec<ConstraintJson>,
    human_gate_classes: Vec<String>,
    max_delegation_depth: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConstraintJson {
    id: String,
    description: String,
    failure_action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditIntegrityJson {
    chain_length: u64,
    verified: bool,
    head_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthJson {
    status: String,
    crates: Vec<String>,
    decisions: usize,
    delegations: usize,
    audit_entries: u64,
    audit_integrity: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDecisionReq {
    title: String,
    body: String,
    decision_class: String,
    author: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvanceReq {
    new_status: String,
    actor: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CastVoteReq {
    voter: String,
    choice: String,
    rationale: Option<String>,
}

#[derive(Deserialize)]
pub struct TallyReq {
    actor: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorJson {
    error: String,
}

// --- Auth request/response types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    display_name: String,
    email: String,
    password: String,
    tenant_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRes {
    did: String,
    display_name: String,
    email: String,
    pace_status: PaceStatus,
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginReq {
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRes {
    token: String,
    refresh_token: String,
    user: LoginUserJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginUserJson {
    did: String,
    display_name: String,
    roles: Vec<String>,
    pace_status: PaceStatus,
    identity_score: Option<IdentityScore>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReq {
    refresh_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshRes {
    token: String,
    refresh_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MeRes {
    did: String,
    display_name: String,
    email: String,
    roles: Vec<String>,
    tenant_id: String,
    pace_status: PaceStatus,
    identity_score: Option<IdentityScore>,
    mfa_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutRes {
    message: String,
}

// --- Agent request/response types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollAgentReq {
    agent_name: String,
    agent_type: String,
    owner_did: Option<String>,
    capabilities: Vec<String>,
    max_decision_class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollAgentRes {
    did: String,
    agent_name: String,
    trust_tier: TrustTier,
    trust_score: u32,
    pace_status: PaceStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentJson {
    did: String,
    agent_name: String,
    agent_type: String,
    owner_did: String,
    tenant_id: String,
    capabilities: Vec<String>,
    trust_tier: TrustTier,
    trust_score: u32,
    delegation_id: Option<String>,
    pace_status: PaceStatus,
    created_at: u64,
    status: AccountStatus,
    max_decision_class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancePaceReq {
    step: String,
}

// --- User list response type ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserListJson {
    did: String,
    display_name: String,
    email: String,
    roles: Vec<String>,
    pace_status: PaceStatus,
    trust_tier: TrustTier,
    trust_score: u32,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn format_hash(h: &Blake3Hash) -> String {
    hex::encode(&h.0[..8])
}

fn decision_class_to_string(c: &DecisionClass) -> String {
    match c {
        DecisionClass::Operational => "Operational".into(),
        DecisionClass::Strategic => "Strategic".into(),
        DecisionClass::Constitutional => "Constitutional".into(),
        DecisionClass::Financial { threshold_cents } => {
            format!("Financial(${:.2})", *threshold_cents as f64 / 100.0)
        }
        DecisionClass::Emergency => "Emergency".into(),
        DecisionClass::Custom(s) => format!("Custom({})", s),
    }
}

fn parse_decision_class(s: &str) -> DecisionClass {
    match s {
        "Operational" => DecisionClass::Operational,
        "Strategic" => DecisionClass::Strategic,
        "Constitutional" => DecisionClass::Constitutional,
        "Emergency" => DecisionClass::Emergency,
        s if s.starts_with("Financial") => DecisionClass::Financial {
            threshold_cents: 10_000_000,
        },
        other => DecisionClass::Custom(other.into()),
    }
}

fn status_to_string(s: &DecisionStatus) -> String {
    format!("{:?}", s)
}

fn parse_status(s: &str) -> Option<DecisionStatus> {
    match s {
        "Created" => Some(DecisionStatus::Created),
        "Deliberation" => Some(DecisionStatus::Deliberation),
        "Voting" => Some(DecisionStatus::Voting),
        "Approved" => Some(DecisionStatus::Approved),
        "Rejected" => Some(DecisionStatus::Rejected),
        "Void" => Some(DecisionStatus::Void),
        "Contested" => Some(DecisionStatus::Contested),
        "RatificationRequired" => Some(DecisionStatus::RatificationRequired),
        "RatificationExpired" => Some(DecisionStatus::RatificationExpired),
        "DegradedGovernance" => Some(DecisionStatus::DegradedGovernance),
        _ => None,
    }
}

fn signer_type_str(st: &SignerType) -> String {
    match st {
        SignerType::Human => "Human".into(),
        SignerType::AiAgent { .. } => "AiAgent".into(),
    }
}

fn decision_to_json(d: &DecisionObject) -> DecisionJson {
    DecisionJson {
        id: format_hash(&d.id),
        tenant_id: d.tenant_id.clone(),
        status: status_to_string(&d.status),
        title: d.title.clone(),
        decision_class: decision_class_to_string(&d.decision_class),
        author: d.author.clone(),
        created_at: d.created_at.physical_ms,
        constitution_version: d.constitution_version.to_string(),
        votes: d
            .votes
            .iter()
            .map(|v| VoteJson {
                voter: v.voter.clone(),
                choice: format!("{:?}", v.choice),
                rationale: v.rationale.clone(),
                signer_type: signer_type_str(&v.signer_type),
                timestamp: v.timestamp.physical_ms,
            })
            .collect(),
        challenges: vec![], // Simplified
        transition_log: d
            .transition_log
            .iter()
            .map(|t| TransitionJson {
                from: status_to_string(&t.from),
                to: status_to_string(&t.to),
                actor: t.actor.clone(),
                reason: t.reason.clone(),
                timestamp: t.timestamp.physical_ms,
            })
            .collect(),
        is_terminal: d.status.is_terminal(),
        valid_next_statuses: d
            .status
            .valid_transitions()
            .iter()
            .map(status_to_string)
            .collect(),
    }
}

fn agent_to_json(a: &AgentIdentity) -> AgentJson {
    AgentJson {
        did: a.did.clone(),
        agent_name: a.agent_name.clone(),
        agent_type: a.agent_type.clone(),
        owner_did: a.owner_did.clone(),
        tenant_id: a.tenant_id.clone(),
        capabilities: a.capabilities.clone(),
        trust_tier: a.trust_tier.clone(),
        trust_score: a.trust_score,
        delegation_id: a.delegation_id.clone(),
        pace_status: a.pace_status.clone(),
        created_at: a.created_at,
        status: a.status.clone(),
        max_decision_class: a.max_decision_class.clone(),
    }
}

// ---------------------------------------------------------------------------
// Helper: create AuthenticatedUser for JWT issuance
// ---------------------------------------------------------------------------

fn make_authenticated_user(user: &UserAccount) -> AuthenticatedUser {
    use chrono::Utc;
    AuthenticatedUser {
        user_id: user.did.clone(),
        tenant_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001")
            .unwrap_or_else(|_| uuid::Uuid::new_v4()),
        did: user.did.clone(),
        roles: user.roles.clone(),
        auth_provider: AuthProvider::Jwt,
        authenticated_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    }
}

// ---------------------------------------------------------------------------
// Handlers — existing governance endpoints
// ---------------------------------------------------------------------------

type SharedState = Arc<RwLock<AppState>>;

async fn health(State(state): State<SharedState>) -> Json<HealthJson> {
    let s = state.read().await;
    let integrity = s.audit_log.verify_integrity().is_ok();
    Json(HealthJson {
        status: "ok".into(),
        crates: vec![
            "exo-governance".into(),
            "exo-authority".into(),
            "exo-legal".into(),
            "exo-tenant".into(),
            "exo-proofs".into(),
            "exo-gateway".into(),
        ],
        decisions: s.decisions.len(),
        delegations: s.delegations.len(),
        audit_entries: s.audit_log.len(),
        audit_integrity: integrity,
    })
}

async fn list_decisions(State(state): State<SharedState>) -> Json<Vec<DecisionJson>> {
    let s = state.read().await;
    Json(s.decisions.iter().map(decision_to_json).collect())
}

async fn get_decision(
    Path(id): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<DecisionJson>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;
    s.decisions
        .iter()
        .find(|d| format_hash(&d.id) == id)
        .map(|d| Json(decision_to_json(d)))
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Decision {} not found", id),
            }),
        ))
}

async fn create_decision(
    State(state): State<SharedState>,
    Json(req): Json<CreateDecisionReq>,
) -> Result<(StatusCode, Json<DecisionJson>), (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;
    let hlc = s.next_hlc();
    let id = s.next_hash(req.title.as_bytes());
    let class = parse_decision_class(&req.decision_class);

    // Check constitutional constraints (TNC-04)
    if let Err(e) = s.constitution.check_blocking_constraints(
        &class,
        1,
        Some(3),
        None,
        None,
        true, // assume human for now
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorJson {
                error: format!("Constitutional violation: {}", e),
            }),
        ));
    }

    let decision = DecisionObject {
        id,
        tenant_id: "tenant-1".into(),
        status: DecisionStatus::Created,
        title: req.title,
        body: req.body.into_bytes(),
        decision_class: class,
        constitution_hash: s.constitution.hash,
        constitution_version: s.constitution.version.clone(),
        author: req.author.clone(),
        created_at: hlc,
        delegations_snapshot: vec![],
        evidence: vec![],
        conflicts_disclosed: vec![],
        votes: vec![],
        quorum_requirement: QuorumSpec {
            minimum_participants: 2,
            approval_threshold_pct: 51,
            eligible_voters: vec![
                "did:exo:alice".into(),
                "did:exo:bob".into(),
                "did:exo:carol".into(),
            ],
        },
        parent_decisions: vec![],
        challenge_ids: vec![],
        signatures: vec![],
        transition_log: vec![],
        crosscheck_reports: vec![],
        clearance_certificates: vec![],
        anchor_receipts: vec![],
    };
    s.audit_log.append(
        id,
        AuditEventType::DecisionCreated,
        req.author,
        "tenant-1".into(),
        hlc,
    );
    // Write-through to PostgreSQL
    if let Some(pool) = &s.pool {
        let payload = serde_json::to_value(&decision).unwrap_or_default();
        let id_hash = format_hash(&decision.id);
        let _ = crate::db::insert_decision(
            pool, &id_hash, &decision.tenant_id,
            &status_to_string(&decision.status), &decision.title,
            &decision_class_to_string(&decision.decision_class),
            &decision.author, decision.created_at.physical_ms as i64,
            &decision.constitution_version.to_string(), &payload,
        ).await;
        // Persist the audit entry
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }
    let json = decision_to_json(&decision);
    s.decisions.push(decision);
    Ok((StatusCode::CREATED, Json(json)))
}

async fn advance_decision(
    Path(id): Path<String>,
    State(state): State<SharedState>,
    Json(req): Json<AdvanceReq>,
) -> Result<Json<DecisionJson>, (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;
    let new_status = parse_status(&req.new_status).ok_or((
        StatusCode::BAD_REQUEST,
        Json(ErrorJson {
            error: format!("Invalid status: {}", req.new_status),
        }),
    ))?;

    let hlc = s.next_hlc();

    let idx = s
        .decisions
        .iter()
        .position(|d| format_hash(&d.id) == id)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Decision {} not found", id),
            }),
        ))?;

    s.decisions[idx]
        .advance(
            new_status,
            req.actor.clone(),
            req.reason,
            dummy_sig(&req.actor, hlc),
            hlc,
        )
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(ErrorJson {
                    error: format!("{}", e),
                }),
            )
        })?;

    let did = s.decisions[idx].id;
    s.audit_log.append(
        did,
        AuditEventType::DecisionAdvanced,
        req.actor,
        "tenant-1".into(),
        hlc,
    );
    // Write-through: update decision + persist audit entry
    if let Some(pool) = &s.pool {
        let payload = serde_json::to_value(&s.decisions[idx]).unwrap_or_default();
        let id_hash = format_hash(&s.decisions[idx].id);
        let _ = crate::db::upsert_decision(
            pool, &id_hash, &s.decisions[idx].tenant_id,
            &status_to_string(&s.decisions[idx].status), &s.decisions[idx].title,
            &decision_class_to_string(&s.decisions[idx].decision_class),
            &s.decisions[idx].author, s.decisions[idx].created_at.physical_ms as i64,
            &s.decisions[idx].constitution_version.to_string(), &payload,
        ).await;
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }

    let json = decision_to_json(&s.decisions[idx]);
    Ok(Json(json))
}

async fn cast_vote(
    Path(id): Path<String>,
    State(state): State<SharedState>,
    Json(req): Json<CastVoteReq>,
) -> Result<Json<DecisionJson>, (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;

    let hlc = s.next_hlc();

    let choice = match req.choice.as_str() {
        "Approve" => VoteChoice::Approve,
        "Reject" => VoteChoice::Reject,
        "Abstain" => VoteChoice::Abstain,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: "Invalid choice, must be Approve/Reject/Abstain".into(),
                }),
            ))
        }
    };

    let idx = s
        .decisions
        .iter()
        .position(|d| format_hash(&d.id) == id)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Decision {} not found", id),
            }),
        ))?;

    s.decisions[idx]
        .cast_vote(Vote {
            voter: req.voter.clone(),
            signer_type: SignerType::Human,
            choice,
            rationale: req.rationale,
            signature: dummy_sig(&req.voter, hlc),
            timestamp: hlc,
        })
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(ErrorJson {
                    error: format!("{}", e),
                }),
            )
        })?;

    let did = s.decisions[idx].id;
    s.audit_log.append(
        did,
        AuditEventType::VoteCast,
        req.voter,
        "tenant-1".into(),
        hlc,
    );
    // Write-through: update decision + persist audit entry
    if let Some(pool) = &s.pool {
        let payload = serde_json::to_value(&s.decisions[idx]).unwrap_or_default();
        let id_hash = format_hash(&s.decisions[idx].id);
        let _ = crate::db::upsert_decision(
            pool, &id_hash, &s.decisions[idx].tenant_id,
            &status_to_string(&s.decisions[idx].status), &s.decisions[idx].title,
            &decision_class_to_string(&s.decisions[idx].decision_class),
            &s.decisions[idx].author, s.decisions[idx].created_at.physical_ms as i64,
            &s.decisions[idx].constitution_version.to_string(), &payload,
        ).await;
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }

    let json = decision_to_json(&s.decisions[idx]);
    Ok(Json(json))
}

async fn tally_decision(
    Path(id): Path<String>,
    State(state): State<SharedState>,
    Json(req): Json<TallyReq>,
) -> Result<Json<DecisionJson>, (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;

    let hlc = s.next_hlc();

    let idx = s
        .decisions
        .iter()
        .position(|d| format_hash(&d.id) == id)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Decision {} not found", id),
            }),
        ))?;

    // Use real governance tally (enforces TNC-07 quorum)
    let outcome = s.decisions[idx].tally().map_err(|e| {
        (
            StatusCode::CONFLICT,
            Json(ErrorJson {
                error: format!("{}", e),
            }),
        )
    })?;

    let outcome_str = format!("Tally result: {:?}", outcome);
    s.decisions[idx]
        .advance(
            outcome,
            req.actor.clone(),
            Some(outcome_str),
            dummy_sig(&req.actor, hlc),
            hlc,
        )
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(ErrorJson {
                    error: format!("{}", e),
                }),
            )
        })?;

    let did = s.decisions[idx].id;
    s.audit_log.append(
        did,
        AuditEventType::DecisionAdvanced,
        req.actor,
        "tenant-1".into(),
        hlc,
    );
    // Write-through: update decision + persist audit entry
    if let Some(pool) = &s.pool {
        let payload = serde_json::to_value(&s.decisions[idx]).unwrap_or_default();
        let id_hash = format_hash(&s.decisions[idx].id);
        let _ = crate::db::upsert_decision(
            pool, &id_hash, &s.decisions[idx].tenant_id,
            &status_to_string(&s.decisions[idx].status), &s.decisions[idx].title,
            &decision_class_to_string(&s.decisions[idx].decision_class),
            &s.decisions[idx].author, s.decisions[idx].created_at.physical_ms as i64,
            &s.decisions[idx].constitution_version.to_string(), &payload,
        ).await;
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }

    let json = decision_to_json(&s.decisions[idx]);
    Ok(Json(json))
}

async fn list_delegations(State(state): State<SharedState>) -> Json<Vec<DelegationJson>> {
    let s = state.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    Json(
        s.delegations
            .iter()
            .map(|d| DelegationJson {
                id: format_hash(&d.id),
                delegator: d.delegator.clone(),
                delegatee: d.delegatee.clone(),
                scope: d
                    .scope
                    .decision_classes
                    .iter()
                    .map(decision_class_to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                expires_at: d.expires_at,
                active: d.is_active(now),
                sub_delegation_allowed: d.sub_delegation_allowed,
                constitution_version: d.constitution_version.to_string(),
            })
            .collect(),
    )
}

async fn get_audit_trail(State(state): State<SharedState>) -> Json<Vec<AuditEntryJson>> {
    let s = state.read().await;
    Json(
        s.audit_log
            .entries()
            .iter()
            .map(|e| AuditEntryJson {
                sequence: e.sequence,
                event_type: format!("{:?}", e.event_type),
                actor: e.actor.clone(),
                tenant_id: e.tenant_id.clone(),
                timestamp: e.timestamp.physical_ms,
                entry_hash: format_hash(&e.entry_hash),
                prev_hash: format_hash(&e.prev_hash),
            })
            .collect(),
    )
}

async fn verify_audit(State(state): State<SharedState>) -> Json<AuditIntegrityJson> {
    let s = state.read().await;
    let verified = s.audit_log.verify_integrity().is_ok();
    Json(AuditIntegrityJson {
        chain_length: s.audit_log.len(),
        verified,
        head_hash: format_hash(&s.audit_log.head_hash()),
    })
}

async fn get_constitution(State(state): State<SharedState>) -> Json<ConstitutionJson> {
    let s = state.read().await;
    let c = &s.constitution;
    Json(ConstitutionJson {
        tenant_id: c.tenant_id.clone(),
        version: c.version.to_string(),
        hash: format_hash(&c.hash),
        document_count: c.documents.len(),
        constraints: c
            .documents
            .iter()
            .flat_map(|d| &d.constraints)
            .map(|con| ConstraintJson {
                id: con.id.clone(),
                description: con.description.clone(),
                failure_action: format!("{:?}", con.failure_action),
            })
            .collect(),
        human_gate_classes: c
            .human_gate_classes
            .iter()
            .map(decision_class_to_string)
            .collect(),
        max_delegation_depth: c.max_delegation_depth,
    })
}

// ---------------------------------------------------------------------------
// Handlers — Authentication
// ---------------------------------------------------------------------------

async fn auth_register(
    State(state): State<SharedState>,
    Json(req): Json<RegisterReq>,
) -> Result<(StatusCode, Json<RegisterRes>), (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;

    // Check if email already exists
    if s.users.iter().any(|u| u.email == req.email) {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorJson {
                error: "Email already registered".into(),
            }),
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Generate salt and DID
    let salt_seed = format!("{}-{}", req.email, now);
    let salt = generate_salt(&salt_seed);
    let did_input = format!("{}{}", req.email, salt);
    let did_hash = hash_bytes(did_input.as_bytes());
    let did = format!("did:exo:{}", hex::encode(&did_hash.0[..8]));

    let password_hash = blake3_password_hash(&req.password, &salt);
    let tenant_id = req.tenant_id.unwrap_or_else(|| "tenant-1".into());

    let user = UserAccount {
        did: did.clone(),
        display_name: req.display_name.clone(),
        email: req.email.clone(),
        roles: vec!["voter".into()],
        tenant_id: tenant_id.clone(),
        created_at: now,
        status: AccountStatus::Active,
        pace_status: PaceStatus::Provable,
        password_hash,
        salt,
        mfa_enabled: false,
    };

    // Issue token
    let auth_user = make_authenticated_user(&user);
    let token_result = s.jwt_service.issue_token(&auth_user);

    // Create enrollment record for P step
    let hlc = s.next_hlc();
    let enrollment_hash = hash_bytes(format!("enroll-{}-P", did).as_bytes());
    s.enrollment_log.push(EnrollmentRecord {
        did: did.clone(),
        entity_type: "user".into(),
        step: "P".into(),
        timestamp: now,
        verified_by: "system".into(),
        audit_hash: hex::encode(&enrollment_hash.0[..16]),
    });

    // Log to audit trail
    s.audit_log.append(
        hash_bytes(format!("register-{}", did).as_bytes()),
        AuditEventType::DecisionCreated, // reuse event type for user registration
        did.clone(),
        tenant_id,
        hlc,
    );

    // Write-through: persist user + audit entry
    if let Some(pool) = &s.pool {
        let roles = serde_json::to_value(&user.roles).unwrap_or_default();
        let _ = crate::db::insert_user(
            pool, &user.did, &user.display_name, &user.email, &roles,
            &user.tenant_id, user.created_at as i64, &format!("{:?}", user.status),
            &format!("{:?}", user.pace_status), &user.password_hash, &user.salt, user.mfa_enabled,
        ).await;
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }

    s.users.push(user);

    Ok((
        StatusCode::CREATED,
        Json(RegisterRes {
            did,
            display_name: req.display_name,
            email: req.email,
            pace_status: PaceStatus::Provable,
            token: token_result.token,
        }),
    ))
}

async fn auth_login(
    State(state): State<SharedState>,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginRes>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;

    let user = s.users.iter().find(|u| u.email == req.email).ok_or((
        StatusCode::UNAUTHORIZED,
        Json(ErrorJson {
            error: "Invalid email or password".into(),
        }),
    ))?;

    // Verify password
    let computed_hash = blake3_password_hash(&req.password, &user.salt);
    if computed_hash != user.password_hash {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorJson {
                error: "Invalid email or password".into(),
            }),
        ));
    }

    // Check account status
    if user.status != AccountStatus::Active {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorJson {
                error: "Account is not active".into(),
            }),
        ));
    }

    // Issue token
    let auth_user = make_authenticated_user(user);
    let token_result = s.jwt_service.issue_token(&auth_user);

    let identity_score = s.identity_scores.get(&user.did).cloned();

    Ok(Json(LoginRes {
        token: token_result.token,
        refresh_token: token_result.refresh_token.unwrap_or_default(),
        user: LoginUserJson {
            did: user.did.clone(),
            display_name: user.display_name.clone(),
            roles: user.roles.clone(),
            pace_status: user.pace_status.clone(),
            identity_score,
        },
    }))
}

async fn auth_refresh(
    State(state): State<SharedState>,
    Json(req): Json<RefreshReq>,
) -> Result<Json<RefreshRes>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;

    // Validate refresh token
    let claims = s
        .jwt_service
        .validate_token(&req.refresh_token)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorJson {
                    error: format!("Invalid refresh token: {}", e),
                }),
            )
        })?;

    // Find user by DID
    let user = s
        .users
        .iter()
        .find(|u| u.did == claims.user_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: "User not found".into(),
            }),
        ))?;

    // Issue new tokens
    let auth_user = make_authenticated_user(user);
    let token_result = s.jwt_service.issue_token(&auth_user);

    Ok(Json(RefreshRes {
        token: token_result.token,
        refresh_token: token_result.refresh_token.unwrap_or_default(),
    }))
}

async fn auth_me(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MeRes>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;
    let claims = extract_auth(&s, &headers)?;

    let user = s
        .users
        .iter()
        .find(|u| u.did == claims.user_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: "User not found".into(),
            }),
        ))?;

    let identity_score = s.identity_scores.get(&user.did).cloned();

    Ok(Json(MeRes {
        did: user.did.clone(),
        display_name: user.display_name.clone(),
        email: user.email.clone(),
        roles: user.roles.clone(),
        tenant_id: user.tenant_id.clone(),
        pace_status: user.pace_status.clone(),
        identity_score,
        mfa_enabled: user.mfa_enabled,
    }))
}

async fn auth_logout() -> Json<LogoutRes> {
    Json(LogoutRes {
        message: "Logged out successfully".into(),
    })
}

// ---------------------------------------------------------------------------
// Handlers — Agent Enrollment
// ---------------------------------------------------------------------------

async fn enroll_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EnrollAgentReq>,
) -> Result<(StatusCode, Json<EnrollAgentRes>), (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;
    let claims = extract_auth(&s, &headers)?;

    // Derive owner_did from auth token if not provided
    let owner_did = req.owner_did.unwrap_or_else(|| claims.user_id.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Generate agent DID
    let did_input = format!("{}-{}-{}", req.agent_name, owner_did, now);
    let did_hash = hash_bytes(did_input.as_bytes());
    let agent_did = format!("did:exo:agent-{}", hex::encode(&did_hash.0[..8]));

    // Determine tenant from owner
    let tenant_id = s
        .users
        .iter()
        .find(|u| u.did == owner_did)
        .map(|u| u.tenant_id.clone())
        .unwrap_or_else(|| "tenant-1".into());

    // Create governance delegation from owner to agent (limited scope)
    let hlc = s.next_hlc();
    let del_class = parse_decision_class(&req.max_decision_class);
    let del_id = hash_bytes(format!("del-agent-{}", agent_did).as_bytes());
    let delegation = Delegation {
        id: del_id,
        tenant_id: tenant_id.clone(),
        delegator: owner_did.clone(),
        delegatee: agent_did.clone(),
        scope: DelegationScope {
            decision_classes: vec![del_class],
            monetary_cap: None,
            resource_ids: vec![],
            actions: vec![AuthorizedAction::CreateDecision],
        },
        sub_delegation_allowed: false,
        sub_delegation_scope_cap: None,
        created_at: hlc,
        expires_at: 9_999_999_999_000,
        revoked_at: None,
        constitution_version: SemVer::new(1, 0, 0),
        signature: dummy_sig(&owner_did, hlc),
        parent_delegation: None,
    };
    s.delegations.push(delegation);

    let agent = AgentIdentity {
        did: agent_did.clone(),
        agent_name: req.agent_name.clone(),
        agent_type: req.agent_type,
        owner_did: owner_did.clone(),
        tenant_id,
        capabilities: req.capabilities,
        trust_tier: TrustTier::Standard,
        trust_score: 500,
        delegation_id: Some(format_hash(&del_id)),
        pace_status: PaceStatus::Provable,
        created_at: now,
        status: AccountStatus::Active,
        max_decision_class: req.max_decision_class,
    };

    // Create enrollment record for P step
    let enrollment_hash = hash_bytes(format!("enroll-agent-{}-P", agent_did).as_bytes());
    s.enrollment_log.push(EnrollmentRecord {
        did: agent_did.clone(),
        entity_type: "agent".into(),
        step: "P".into(),
        timestamp: now,
        verified_by: owner_did,
        audit_hash: hex::encode(&enrollment_hash.0[..16]),
    });

    // Log to audit trail
    s.audit_log.append(
        hash_bytes(format!("agent-enroll-{}", agent_did).as_bytes()),
        AuditEventType::DecisionCreated,
        agent_did.clone(),
        agent.tenant_id.clone(),
        hlc,
    );

    // Write-through: persist agent, delegation, audit entry
    if let Some(pool) = &s.pool {
        let caps = serde_json::to_value(&agent.capabilities).unwrap_or_default();
        let del_id_str = agent.delegation_id.as_deref();
        let _ = crate::db::insert_agent(
            pool, &agent.did, &agent.agent_name, &agent.agent_type, &agent.owner_did,
            &agent.tenant_id, &caps, &format!("{:?}", agent.trust_tier), agent.trust_score as i32,
            del_id_str, &format!("{:?}", agent.pace_status), agent.created_at as i64,
            &format!("{:?}", agent.status), &agent.max_decision_class,
        ).await;
        if let Some(entry) = s.audit_log.entries().last() {
            let _ = crate::db::insert_audit_entry(
                pool, entry.sequence as i64, &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash), &format!("{:?}", entry.event_type),
                &entry.actor, &entry.tenant_id, entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32, &format_hash(&entry.entry_hash),
            ).await;
        }
    }

    let res = EnrollAgentRes {
        did: agent_did,
        agent_name: req.agent_name,
        trust_tier: TrustTier::Standard,
        trust_score: 500,
        pace_status: PaceStatus::Provable,
    };

    s.agents.push(agent);

    Ok((StatusCode::CREATED, Json(res)))
}

async fn list_agents(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<AgentJson>>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;

    // Try to get auth, but allow unauthenticated access for backwards compat
    let tenant_filter = if let Ok(claims) = extract_auth(&s, &headers) {
        s.users
            .iter()
            .find(|u| u.did == claims.user_id)
            .map(|u| u.tenant_id.clone())
    } else {
        None
    };

    let agents: Vec<AgentJson> = s
        .agents
        .iter()
        .filter(|a| {
            if let Some(ref tid) = tenant_filter {
                a.tenant_id == *tid
            } else {
                true
            }
        })
        .map(agent_to_json)
        .collect();

    Ok(Json(agents))
}

async fn get_agent(
    Path(did): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<AgentJson>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;
    s.agents
        .iter()
        .find(|a| a.did == did)
        .map(|a| Json(agent_to_json(a)))
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Agent {} not found", did),
            }),
        ))
}

async fn advance_agent_pace(
    Path(did): Path<String>,
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AdvancePaceReq>,
) -> Result<Json<AgentJson>, (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;
    let _claims = extract_auth(&s, &headers)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let agent_idx = s
        .agents
        .iter()
        .position(|a| a.did == did)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Agent {} not found", did),
            }),
        ))?;

    let step = req.step.as_str();

    match step {
        "A" => {
            if s.agents[agent_idx].pace_status != PaceStatus::Provable {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "Agent must be in Provable status to advance to Auditable".into(),
                    }),
                ));
            }
            // Prerequisite: agent has participated in at least 1 audit trail event
            let has_audit = s
                .audit_log
                .entries()
                .iter()
                .any(|e| e.actor == did);
            if !has_audit {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error: "Agent must have at least 1 audit trail event".into(),
                    }),
                ));
            }
            s.agents[agent_idx].pace_status = PaceStatus::Auditable;
        }
        "C" => {
            if s.agents[agent_idx].pace_status != PaceStatus::Auditable {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "Agent must be in Auditable status to advance to Compliant".into(),
                    }),
                ));
            }
            // Prerequisite: agent has a valid delegation with constitutional binding
            let has_delegation = s
                .delegations
                .iter()
                .any(|d| d.delegatee == did && d.revoked_at.is_none());
            if !has_delegation {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error: "Agent must have a valid delegation with constitutional binding"
                            .into(),
                    }),
                ));
            }
            s.agents[agent_idx].pace_status = PaceStatus::Compliant;
        }
        "E" => {
            if s.agents[agent_idx].pace_status != PaceStatus::Compliant {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "Agent must be in Compliant status to advance to Enforceable".into(),
                    }),
                ));
            }
            // Prerequisite: delegation with TNC enforcement + trust_score >= 500
            let has_delegation = s
                .delegations
                .iter()
                .any(|d| d.delegatee == did && d.revoked_at.is_none());
            if !has_delegation || s.agents[agent_idx].trust_score < 500 {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error:
                            "Agent must have TNC enforcement delegation and trust_score >= 500"
                                .into(),
                    }),
                ));
            }
            s.agents[agent_idx].pace_status = PaceStatus::Enforceable;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: format!("Invalid PACE step: {}. Must be A, C, or E", step),
                }),
            ));
        }
    }

    // Create enrollment record
    let enrollment_hash = hash_bytes(format!("enroll-agent-{}-{}", did, step).as_bytes());
    s.enrollment_log.push(EnrollmentRecord {
        did: did.clone(),
        entity_type: "agent".into(),
        step: step.to_string(),
        timestamp: now,
        verified_by: _claims.user_id,
        audit_hash: hex::encode(&enrollment_hash.0[..16]),
    });

    let json = agent_to_json(&s.agents[agent_idx]);
    Ok(Json(json))
}

// ---------------------------------------------------------------------------
// Handlers — Identity Score
// ---------------------------------------------------------------------------

async fn get_identity_score(
    Path(did): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<IdentityScore>, (StatusCode, Json<ErrorJson>)> {
    let s = state.read().await;

    // Check if DID exists
    let exists = s.users.iter().any(|u| u.did == did)
        || s.agents.iter().any(|a| a.did == did);
    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("Identity {} not found", did),
            }),
        ));
    }

    let score = compute_identity_score(&s, &did);
    Ok(Json(score))
}

// ---------------------------------------------------------------------------
// Handlers — User Management
// ---------------------------------------------------------------------------

async fn list_users(State(state): State<SharedState>) -> Json<Vec<UserListJson>> {
    let s = state.read().await;
    Json(
        s.users
            .iter()
            .map(|u| {
                let score_data = s.identity_scores.get(&u.did);
                let (trust_tier, trust_score) = match score_data {
                    Some(is) => (is.tier.clone(), is.score),
                    None => (TrustTier::Untrusted, 0),
                };
                UserListJson {
                    did: u.did.clone(),
                    display_name: u.display_name.clone(),
                    email: u.email.clone(),
                    roles: u.roles.clone(),
                    pace_status: u.pace_status.clone(),
                    trust_tier,
                    trust_score,
                }
            })
            .collect(),
    )
}

async fn advance_user_pace(
    Path(did): Path<String>,
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AdvancePaceReq>,
) -> Result<Json<UserListJson>, (StatusCode, Json<ErrorJson>)> {
    let mut s = state.write().await;
    let _claims = extract_auth(&s, &headers)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let user_idx = s
        .users
        .iter()
        .position(|u| u.did == did)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ErrorJson {
                error: format!("User {} not found", did),
            }),
        ))?;

    let step = req.step.as_str();

    match step {
        "A" => {
            if s.users[user_idx].pace_status != PaceStatus::Provable {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "User must be in Provable status to advance to Auditable".into(),
                    }),
                ));
            }
            // Prerequisite: user has appeared in audit trail
            let has_audit = s
                .audit_log
                .entries()
                .iter()
                .any(|e| e.actor == did);
            if !has_audit {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error: "User must have appeared in audit trail".into(),
                    }),
                ));
            }
            s.users[user_idx].pace_status = PaceStatus::Auditable;
        }
        "C" => {
            if s.users[user_idx].pace_status != PaceStatus::Auditable {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "User must be in Auditable status to advance to Compliant".into(),
                    }),
                ));
            }
            // Prerequisite: user has active delegation or is constitution signer
            let has_delegation = s
                .delegations
                .iter()
                .any(|d| (d.delegatee == did || d.delegator == did) && d.revoked_at.is_none());
            if !has_delegation {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error: "User must have active delegation or be constitution signer".into(),
                    }),
                ));
            }
            s.users[user_idx].pace_status = PaceStatus::Compliant;
        }
        "E" => {
            if s.users[user_idx].pace_status != PaceStatus::Compliant {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorJson {
                        error: "User must be in Compliant status to advance to Enforceable".into(),
                    }),
                ));
            }
            // Prerequisite: user has participated in a decision vote
            let has_voted = s
                .audit_log
                .entries()
                .iter()
                .any(|e| e.actor == did && matches!(e.event_type, AuditEventType::VoteCast));
            if !has_voted {
                return Err((
                    StatusCode::PRECONDITION_FAILED,
                    Json(ErrorJson {
                        error: "User must have participated in a decision vote".into(),
                    }),
                ));
            }
            s.users[user_idx].pace_status = PaceStatus::Enforceable;
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorJson {
                    error: format!("Invalid PACE step: {}. Must be A, C, or E", step),
                }),
            ));
        }
    }

    // Create enrollment record
    let enrollment_hash = hash_bytes(format!("enroll-user-{}-{}", did, step).as_bytes());
    s.enrollment_log.push(EnrollmentRecord {
        did: did.clone(),
        entity_type: "user".into(),
        step: step.to_string(),
        timestamp: now,
        verified_by: _claims.user_id,
        audit_hash: hex::encode(&enrollment_hash.0[..16]),
    });

    let user = &s.users[user_idx];
    let score_data = s.identity_scores.get(&user.did);
    let (trust_tier, trust_score) = match score_data {
        Some(is) => (is.tier.clone(), is.score),
        None => (TrustTier::Untrusted, 0),
    };

    Ok(Json(UserListJson {
        did: user.did.clone(),
        display_name: user.display_name.clone(),
        email: user.email.clone(),
        roles: user.roles.clone(),
        pace_status: user.pace_status.clone(),
        trust_tier,
        trust_score,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn create_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route(
            "/api/v1/decisions",
            get(list_decisions).post(create_decision),
        )
        .route("/api/v1/decisions/:id", get(get_decision))
        .route("/api/v1/decisions/:id/advance", post(advance_decision))
        .route("/api/v1/decisions/:id/vote", post(cast_vote))
        .route("/api/v1/decisions/:id/tally", post(tally_decision))
        .route("/api/v1/delegations", get(list_delegations))
        .route("/api/v1/audit", get(get_audit_trail))
        .route("/api/v1/audit/verify", get(verify_audit))
        .route("/api/v1/constitution", get(get_constitution))
        // Auth endpoints
        .route("/api/v1/auth/register", post(auth_register))
        .route("/api/v1/auth/login", post(auth_login))
        .route("/api/v1/auth/refresh", post(auth_refresh))
        .route("/api/v1/auth/me", get(auth_me))
        .route("/api/v1/auth/logout", post(auth_logout))
        // Agent endpoints
        .route("/api/v1/agents/enroll", post(enroll_agent))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/:did", get(get_agent))
        .route(
            "/api/v1/agents/:did/advance-pace",
            post(advance_agent_pace),
        )
        // Identity score endpoint
        .route("/api/v1/identity/:did/score", get(get_identity_score))
        // User management endpoints
        .route("/api/v1/users", get(list_users))
        .route(
            "/api/v1/users/:did/advance-pace",
            post(advance_user_pace),
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn run_server(port: u16) {
    let state = Arc::new(RwLock::new(AppState::new()));
    let app = create_router(state);
    start_server(port, app).await;
}

/// Run the server with PostgreSQL persistence.
/// Seeds the database on first run, then loads state from DB.
pub async fn run_server_with_db(port: u16, pool: sqlx::PgPool) {
    use crate::db;

    // Check if this is first run (empty users table)
    let user_count = db::count_users(&pool).await.unwrap_or(0);

    if user_count == 0 {
        println!("[DB] Empty database detected — seeding initial data");
        // Create in-memory state to generate seed data
        let seed_state = AppState::new();

        // Persist users
        for u in &seed_state.users {
            let roles = serde_json::to_value(&u.roles).unwrap_or_default();
            let _ = db::insert_user(
                &pool, &u.did, &u.display_name, &u.email, &roles,
                &u.tenant_id, u.created_at as i64, &format!("{:?}", u.status),
                &format!("{:?}", u.pace_status), &u.password_hash, &u.salt, u.mfa_enabled,
            ).await;
        }

        // Persist agents
        for a in &seed_state.agents {
            let caps = serde_json::to_value(&a.capabilities).unwrap_or_default();
            let del_id = a.delegation_id.as_deref();
            let _ = db::insert_agent(
                &pool, &a.did, &a.agent_name, &a.agent_type, &a.owner_did,
                &a.tenant_id, &caps, &format!("{:?}", a.trust_tier), a.trust_score as i32,
                del_id, &format!("{:?}", a.pace_status), a.created_at as i64,
                &format!("{:?}", a.status), &a.max_decision_class,
            ).await;
        }

        // Persist decisions
        for d in &seed_state.decisions {
            let payload = serde_json::to_value(d).unwrap_or_default();
            let id_hash = format_hash(&d.id);
            let _ = db::insert_decision(
                &pool, &id_hash, &d.tenant_id, &status_to_string(&d.status),
                &d.title, &decision_class_to_string(&d.decision_class),
                &d.author, d.created_at.physical_ms as i64,
                &d.constitution_version.to_string(), &payload,
            ).await;
        }

        // Persist delegations
        for d in &seed_state.delegations {
            let payload = serde_json::to_value(d).unwrap_or_default();
            let id_hash = format_hash(&d.id);
            let _ = db::insert_delegation(
                &pool, &id_hash, &d.tenant_id, &d.delegator, &d.delegatee,
                d.created_at.physical_ms as i64, d.expires_at as i64,
                &d.constitution_version.to_string(), &payload,
            ).await;
        }

        // Persist audit entries
        for entry in seed_state.audit_log.entries() {
            let _ = db::insert_audit_entry(
                &pool,
                entry.sequence as i64,
                &format_hash(&entry.prev_hash),
                &format_hash(&entry.event_hash),
                &format!("{:?}", entry.event_type),
                &entry.actor,
                &entry.tenant_id,
                entry.timestamp.physical_ms as i64,
                entry.timestamp.logical as i32,
                &format_hash(&entry.entry_hash),
            ).await;
        }

        // Persist identity scores
        for (did, score) in &seed_state.identity_scores {
            let factors = serde_json::to_value(&score.factors).unwrap_or_default();
            let _ = db::upsert_identity_score(
                &pool, did, score.score as i32, &format!("{:?}", score.tier),
                &factors, score.last_updated as i64,
            ).await;
        }

        // Persist enrollment records
        for e in &seed_state.enrollment_log {
            let _ = db::insert_enrollment(
                &pool, &e.did, &e.entity_type, &e.step,
                e.timestamp as i64, &e.verified_by, &e.audit_hash,
            ).await;
        }

        // Persist constitution
        let const_payload = serde_json::to_value(&seed_state.constitution).unwrap_or_default();
        let _ = db::upsert_constitution(
            &pool, &seed_state.constitution.tenant_id,
            &seed_state.constitution.version.to_string(),
            &const_payload,
        ).await;

        println!("[DB] Seed data persisted: {} users, {} agents, {} decisions, {} delegations, {} audit entries",
            seed_state.users.len(), seed_state.agents.len(),
            seed_state.decisions.len(), seed_state.delegations.len(),
            seed_state.audit_log.len());
    } else {
        println!("[DB] Found existing data ({} users) — skipping seed", user_count);
    }

    // Load state from database — this ensures all persisted data (including
    // data created after seeding) survives restarts.
    let mut state = load_state_from_db(&pool).await;
    state.pool = Some(pool);
    println!(
        "[DB] Loaded from PostgreSQL: {} users, {} agents, {} decisions, {} delegations, {} audit entries",
        state.users.len(), state.agents.len(), state.decisions.len(),
        state.delegations.len(), state.audit_log.len()
    );
    let state = Arc::new(RwLock::new(state));
    let app = create_router(state);
    start_server(port, app).await;
}

/// Load AppState from PostgreSQL database.
async fn load_state_from_db(pool: &sqlx::PgPool) -> AppState {
    use crate::db;

    let constitution = seed_constitution();
    let jwt_service = JwtService::new("decision.forum".into(), 3600);

    // Load users
    let user_rows = db::list_users_db(pool).await.unwrap_or_default();
    let users: Vec<UserAccount> = user_rows.into_iter().map(|r| {
        let roles: Vec<String> = serde_json::from_value(r.roles).unwrap_or_default();
        let status = match r.status.as_str() {
            "Active" => AccountStatus::Active,
            "Suspended" => AccountStatus::Suspended,
            "PendingVerification" => AccountStatus::PendingVerification,
            "Revoked" => AccountStatus::Revoked,
            _ => AccountStatus::Active,
        };
        let pace = match r.pace_status.as_str() {
            "Unenrolled" => PaceStatus::Unenrolled,
            "Provable" => PaceStatus::Provable,
            "Auditable" => PaceStatus::Auditable,
            "Compliant" => PaceStatus::Compliant,
            "Enforceable" => PaceStatus::Enforceable,
            _ => PaceStatus::Provable,
        };
        UserAccount {
            did: r.did, display_name: r.display_name, email: r.email,
            roles, tenant_id: r.tenant_id, created_at: r.created_at as u64,
            status, pace_status: pace, password_hash: r.password_hash,
            salt: r.salt, mfa_enabled: r.mfa_enabled,
        }
    }).collect();

    // Load agents
    let agent_rows = db::list_agents_db(pool, None).await.unwrap_or_default();
    let agents: Vec<AgentIdentity> = agent_rows.into_iter().map(|r| {
        let capabilities: Vec<String> = serde_json::from_value(r.capabilities).unwrap_or_default();
        let trust_tier = match r.trust_tier.as_str() {
            "Untrusted" => TrustTier::Untrusted,
            "Probationary" => TrustTier::Probationary,
            "Standard" => TrustTier::Standard,
            "Trusted" => TrustTier::Trusted,
            "Verified" => TrustTier::Verified,
            _ => TrustTier::Standard,
        };
        let status = match r.status.as_str() {
            "Active" => AccountStatus::Active,
            "Suspended" => AccountStatus::Suspended,
            _ => AccountStatus::Active,
        };
        let pace = match r.pace_status.as_str() {
            "Unenrolled" => PaceStatus::Unenrolled,
            "Provable" => PaceStatus::Provable,
            "Auditable" => PaceStatus::Auditable,
            "Compliant" => PaceStatus::Compliant,
            "Enforceable" => PaceStatus::Enforceable,
            _ => PaceStatus::Provable,
        };
        AgentIdentity {
            did: r.did, agent_name: r.agent_name, agent_type: r.agent_type,
            owner_did: r.owner_did, tenant_id: r.tenant_id, capabilities,
            trust_tier, trust_score: r.trust_score as u32,
            delegation_id: r.delegation_id, pace_status: pace,
            created_at: r.created_at as u64, status, max_decision_class: r.max_decision_class,
        }
    }).collect();

    // Load decisions from JSONB payload
    let decision_rows = db::list_decisions_db(pool).await.unwrap_or_default();
    let decisions: Vec<DecisionObject> = decision_rows.into_iter().filter_map(|r| {
        serde_json::from_value(r.payload).ok()
    }).collect();

    // Load delegations from JSONB payload
    let delegation_rows = db::list_delegations_db(pool).await.unwrap_or_default();
    let delegations: Vec<Delegation> = delegation_rows.into_iter().filter_map(|r| {
        serde_json::from_value(r.payload).ok()
    }).collect();

    // Load audit entries and reconstruct AuditLog
    let audit_rows = db::list_audit_entries(pool).await.unwrap_or_default();
    let mut audit_log = AuditLog::new();
    for row in &audit_rows {
        let event_type = match row.event_type.as_str() {
            "DecisionCreated" => AuditEventType::DecisionCreated,
            "DecisionAdvanced" => AuditEventType::DecisionAdvanced,
            "VoteCast" => AuditEventType::VoteCast,
            "DelegationGranted" => AuditEventType::DelegationGranted,
            "DelegationRevoked" => AuditEventType::DelegationRevoked,
            "ChallengeRaised" => AuditEventType::ChallengeRaised,
            "EmergencyActionTaken" => AuditEventType::EmergencyActionTaken,
            "ConstitutionAmended" => AuditEventType::ConstitutionAmended,
            "AuditSelfVerification" => AuditEventType::AuditSelfVerification,
            _ => AuditEventType::DecisionCreated,
        };
        let event_hash = hash_bytes(format!("{}-{}", row.event_type, row.actor).as_bytes());
        audit_log.append(
            event_hash,
            event_type,
            row.actor.clone(),
            row.tenant_id.clone(),
            HybridLogicalClock {
                physical_ms: row.timestamp_physical_ms as u64,
                logical: row.timestamp_logical as u32,
            },
        );
    }

    // Determine HLC counter from max timestamp in audit entries
    let max_hlc = audit_rows.iter().map(|r| r.timestamp_physical_ms).max().unwrap_or(1000);

    // Load identity scores
    let mut identity_scores = HashMap::new();
    for user in &users {
        if let Ok(Some(score_row)) = db::get_identity_score(pool, &user.did).await {
            let factors: ScoreFactors = serde_json::from_value(score_row.factors).unwrap_or(ScoreFactors {
                tenure_days: 0,
                decisions_participated: 0,
                votes_cast: 0,
                compliance_violations: 0,
                delegation_depth: 0,
                pace_complete: false,
            });
            let tier = match score_row.tier.as_str() {
                "Untrusted" => TrustTier::Untrusted,
                "Probationary" => TrustTier::Probationary,
                "Standard" => TrustTier::Standard,
                "Trusted" => TrustTier::Trusted,
                "Verified" => TrustTier::Verified,
                _ => TrustTier::Standard,
            };
            identity_scores.insert(user.did.clone(), IdentityScore {
                did: user.did.clone(),
                score: score_row.score as u32,
                tier,
                factors,
                last_updated: score_row.last_updated as u64,
            });
        }
    }

    AppState {
        decisions, delegations, audit_log, constitution,
        hlc_counter: max_hlc as u64 + 1,
        users, agents, identity_scores, jwt_service,
        enrollment_log: Vec::new(),
        pool: None,
    }
}

async fn start_server(port: u16, app: Router) {
    let addr = format!("0.0.0.0:{}", port);
    println!("decision.forum API server starting on http://{}", addr);
    println!("  GET  /api/v1/health");
    println!("  GET  /api/v1/decisions");
    println!("  POST /api/v1/decisions");
    println!("  GET  /api/v1/decisions/:id");
    println!("  POST /api/v1/decisions/:id/advance");
    println!("  POST /api/v1/decisions/:id/vote");
    println!("  POST /api/v1/decisions/:id/tally");
    println!("  GET  /api/v1/delegations");
    println!("  GET  /api/v1/audit");
    println!("  GET  /api/v1/audit/verify");
    println!("  GET  /api/v1/constitution");
    println!("  POST /api/v1/auth/register");
    println!("  POST /api/v1/auth/login");
    println!("  POST /api/v1/auth/refresh");
    println!("  GET  /api/v1/auth/me");
    println!("  POST /api/v1/auth/logout");
    println!("  POST /api/v1/agents/enroll");
    println!("  GET  /api/v1/agents");
    println!("  GET  /api/v1/agents/:did");
    println!("  POST /api/v1/agents/:did/advance-pace");
    println!("  GET  /api/v1/identity/:did/score");
    println!("  GET  /api/v1/users");
    println!("  POST /api/v1/users/:did/advance-pace");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
