//! PostgreSQL persistence layer for EXOCHAIN decision.forum.
//!
//! Replaces in-memory AppState Vecs/HashMaps with real database operations.
//! Complex governance objects (DecisionObject, Delegation) are stored as
//! JSONB payloads with indexed scalar columns for efficient queries.

use serde_json::Value as JsonValue;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

// ---------------------------------------------------------------------------
// Pool initialization
// ---------------------------------------------------------------------------

/// Create a connection pool and run migrations.
pub async fn init_pool(database_url: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    println!("[DB] Connected to PostgreSQL, migrations applied");
    pool
}

// ---------------------------------------------------------------------------
// HLC counter (atomic increment)
// ---------------------------------------------------------------------------

pub async fn next_hlc(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("UPDATE hlc_state SET counter = counter + 1 RETURNING counter")
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("counter"))
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_user(
    pool: &PgPool, did: &str, display_name: &str, email: &str, roles: &JsonValue,
    tenant_id: &str, created_at: i64, status: &str, pace_status: &str,
    password_hash: &str, salt: &str, mfa_enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (did) DO NOTHING"
    )
    .bind(did).bind(display_name).bind(email).bind(roles).bind(tenant_id)
    .bind(created_at).bind(status).bind(pace_status).bind(password_hash)
    .bind(salt).bind(mfa_enabled)
    .execute(pool).await?;
    Ok(())
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users WHERE email = $1"
    ).bind(email).fetch_optional(pool).await
}

pub async fn find_user_by_did(pool: &PgPool, did: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

pub async fn list_users_db(pool: &PgPool) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        "SELECT did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled FROM users ORDER BY created_at"
    ).fetch_all(pool).await
}

pub async fn update_user_pace(pool: &PgPool, did: &str, pace_status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET pace_status = $1 WHERE did = $2")
        .bind(pace_status).bind(did).execute(pool).await?;
    Ok(())
}

pub async fn user_exists_by_email(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM users WHERE email = $1").bind(email)
        .fetch_optional(pool).await?.is_some())
}

pub async fn count_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) as cnt FROM users").fetch_one(pool).await?
        .get::<i64, _>("cnt"))
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub did: String,
    pub display_name: String,
    pub email: String,
    pub roles: JsonValue,
    pub tenant_id: String,
    pub created_at: i64,
    pub status: String,
    pub pace_status: String,
    pub password_hash: String,
    pub salt: String,
    pub mfa_enabled: bool,
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_agent(
    pool: &PgPool, did: &str, agent_name: &str, agent_type: &str, owner_did: &str,
    tenant_id: &str, capabilities: &JsonValue, trust_tier: &str, trust_score: i32,
    delegation_id: Option<&str>, pace_status: &str, created_at: i64, status: &str,
    max_decision_class: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agents (did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (did) DO NOTHING"
    )
    .bind(did).bind(agent_name).bind(agent_type).bind(owner_did).bind(tenant_id)
    .bind(capabilities).bind(trust_tier).bind(trust_score).bind(delegation_id)
    .bind(pace_status).bind(created_at).bind(status).bind(max_decision_class)
    .execute(pool).await?;
    Ok(())
}

pub async fn find_agent_by_did(pool: &PgPool, did: &str) -> Result<Option<AgentRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentRow>(
        "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

pub async fn list_agents_db(pool: &PgPool, tenant_id: Option<&str>) -> Result<Vec<AgentRow>, sqlx::Error> {
    if let Some(tid) = tenant_id {
        sqlx::query_as::<_, AgentRow>(
            "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents WHERE tenant_id = $1 ORDER BY created_at"
        ).bind(tid).fetch_all(pool).await
    } else {
        sqlx::query_as::<_, AgentRow>(
            "SELECT did, agent_name, agent_type, owner_did, tenant_id, capabilities, trust_tier, trust_score, delegation_id, pace_status, created_at, status, max_decision_class FROM agents ORDER BY created_at"
        ).fetch_all(pool).await
    }
}

pub async fn update_agent_pace(pool: &PgPool, did: &str, pace_status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET pace_status = $1 WHERE did = $2")
        .bind(pace_status).bind(did).execute(pool).await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRow {
    pub did: String,
    pub agent_name: String,
    pub agent_type: String,
    pub owner_did: String,
    pub tenant_id: String,
    pub capabilities: JsonValue,
    pub trust_tier: String,
    pub trust_score: i32,
    pub delegation_id: Option<String>,
    pub pace_status: String,
    pub created_at: i64,
    pub status: String,
    pub max_decision_class: String,
}

// ---------------------------------------------------------------------------
// Decisions (JSONB payload)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_decision(
    pool: &PgPool, id_hash: &str, tenant_id: &str, status: &str, title: &str,
    decision_class: &str, author: &str, created_at_ms: i64,
    constitution_version: &str, payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO decisions (id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (id_hash) DO UPDATE SET status = $3, payload = $9"
    )
    .bind(id_hash).bind(tenant_id).bind(status).bind(title).bind(decision_class)
    .bind(author).bind(created_at_ms).bind(constitution_version).bind(payload)
    .execute(pool).await?;
    Ok(())
}

/// Alias for insert_decision — the INSERT already has ON CONFLICT DO UPDATE.
pub async fn upsert_decision(
    pool: &PgPool, id_hash: &str, tenant_id: &str, status: &str, title: &str,
    decision_class: &str, author: &str, created_at_ms: i64,
    constitution_version: &str, payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    insert_decision(pool, id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload).await
}

pub async fn find_decision(pool: &PgPool, id_hash: &str) -> Result<Option<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions WHERE id_hash = $1"
    ).bind(id_hash).fetch_optional(pool).await
}

pub async fn list_decisions_db(pool: &PgPool) -> Result<Vec<DecisionRow>, sqlx::Error> {
    sqlx::query_as::<_, DecisionRow>(
        "SELECT id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload FROM decisions ORDER BY created_at_ms"
    ).fetch_all(pool).await
}

pub async fn update_decision(pool: &PgPool, id_hash: &str, status: &str, payload: &JsonValue) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE decisions SET status = $1, payload = $2 WHERE id_hash = $3")
        .bind(status).bind(payload).bind(id_hash).execute(pool).await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DecisionRow {
    pub id_hash: String,
    pub tenant_id: String,
    pub status: String,
    pub title: String,
    pub decision_class: String,
    pub author: String,
    pub created_at_ms: i64,
    pub constitution_version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Delegations (JSONB payload)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_delegation(
    pool: &PgPool, id_hash: &str, tenant_id: &str, delegator: &str, delegatee: &str,
    created_at_ms: i64, expires_at: i64, constitution_version: &str, payload: &JsonValue,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO delegations (id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, constitution_version, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id_hash) DO NOTHING"
    )
    .bind(id_hash).bind(tenant_id).bind(delegator).bind(delegatee)
    .bind(created_at_ms).bind(expires_at).bind(constitution_version).bind(payload)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_delegations_db(pool: &PgPool) -> Result<Vec<DelegationRow>, sqlx::Error> {
    sqlx::query_as::<_, DelegationRow>(
        "SELECT id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, revoked_at, constitution_version, payload FROM delegations ORDER BY created_at_ms"
    ).fetch_all(pool).await
}

pub async fn has_active_delegation(pool: &PgPool, delegatee: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM delegations WHERE delegatee = $1 AND revoked_at IS NULL LIMIT 1")
        .bind(delegatee).fetch_optional(pool).await?.is_some())
}

pub async fn has_active_delegation_either(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM delegations WHERE (delegatee = $1 OR delegator = $1) AND revoked_at IS NULL LIMIT 1")
        .bind(did).fetch_optional(pool).await?.is_some())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegationRow {
    pub id_hash: String,
    pub tenant_id: String,
    pub delegator: String,
    pub delegatee: String,
    pub created_at_ms: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub constitution_version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Audit entries
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_entry(
    pool: &PgPool, sequence: i64, prev_hash: &str, event_hash: &str, event_type: &str,
    actor: &str, tenant_id: &str, timestamp_physical_ms: i64, timestamp_logical: i32, entry_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (sequence) DO NOTHING"
    )
    .bind(sequence).bind(prev_hash).bind(event_hash).bind(event_type)
    .bind(actor).bind(tenant_id).bind(timestamp_physical_ms).bind(timestamp_logical)
    .bind(entry_hash)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_audit_entries(pool: &PgPool) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence"
    ).fetch_all(pool).await
}

pub async fn get_last_audit_entry(pool: &PgPool) -> Result<Option<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
    ).fetch_optional(pool).await
}

pub async fn count_audit_entries(pool: &PgPool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) as cnt FROM audit_entries").fetch_one(pool).await?
        .get::<i64, _>("cnt"))
}

pub async fn check_actor_in_audit(pool: &PgPool, actor: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM audit_entries WHERE actor = $1 LIMIT 1")
        .bind(actor).fetch_optional(pool).await?.is_some())
}

pub async fn check_actor_voted(pool: &PgPool, actor: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM audit_entries WHERE actor = $1 AND event_type = 'VoteCast' LIMIT 1")
        .bind(actor).fetch_optional(pool).await?.is_some())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub sequence: i64,
    pub prev_hash: String,
    pub event_hash: String,
    pub event_type: String,
    pub actor: String,
    pub tenant_id: String,
    pub timestamp_physical_ms: i64,
    pub timestamp_logical: i32,
    pub entry_hash: String,
}

// ---------------------------------------------------------------------------
// Constitution
// ---------------------------------------------------------------------------

pub async fn upsert_constitution(pool: &PgPool, tenant_id: &str, version: &str, payload: &JsonValue) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO constitutions (tenant_id, version, payload) VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, version) DO UPDATE SET payload = $3"
    ).bind(tenant_id).bind(version).bind(payload).execute(pool).await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConstitutionRow {
    pub tenant_id: String,
    pub version: String,
    pub payload: JsonValue,
}

// ---------------------------------------------------------------------------
// Identity scores
// ---------------------------------------------------------------------------

pub async fn upsert_identity_score(pool: &PgPool, did: &str, score: i32, tier: &str, factors: &JsonValue, last_updated: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO identity_scores (did, score, tier, factors, last_updated) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (did) DO UPDATE SET score = $2, tier = $3, factors = $4, last_updated = $5"
    ).bind(did).bind(score).bind(tier).bind(factors).bind(last_updated)
    .execute(pool).await?;
    Ok(())
}

pub async fn get_identity_score(pool: &PgPool, did: &str) -> Result<Option<IdentityScoreRow>, sqlx::Error> {
    sqlx::query_as::<_, IdentityScoreRow>(
        "SELECT did, score, tier, factors, last_updated FROM identity_scores WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityScoreRow {
    pub did: String,
    pub score: i32,
    pub tier: String,
    pub factors: JsonValue,
    pub last_updated: i64,
}

// ---------------------------------------------------------------------------
// Enrollment log
// ---------------------------------------------------------------------------

pub async fn insert_enrollment(
    pool: &PgPool, did: &str, entity_type: &str, step: &str,
    timestamp: i64, verified_by: &str, audit_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO enrollment_log (did, entity_type, step, timestamp, verified_by, audit_hash) VALUES ($1, $2, $3, $4, $5, $6)"
    ).bind(did).bind(entity_type).bind(step).bind(timestamp).bind(verified_by).bind(audit_hash)
    .execute(pool).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LiveSafe tables
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_livesafe_identity(
    pool: &PgPool, did: &str, odentity_composite: f64, pace_status: &str,
    card_status: &str, created_at_ms: i64, exochain_anchor: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO livesafe_identities (did, odentity_composite, pace_status, card_status, created_at_ms, exochain_anchor)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (did) DO UPDATE SET odentity_composite = $2, pace_status = $3, card_status = $4, exochain_anchor = $6"
    ).bind(did).bind(odentity_composite).bind(pace_status).bind(card_status)
    .bind(created_at_ms).bind(exochain_anchor)
    .execute(pool).await?;
    Ok(())
}

pub async fn get_livesafe_identity(pool: &PgPool, did: &str) -> Result<Option<LiveSafeIdentityRow>, sqlx::Error> {
    sqlx::query_as::<_, LiveSafeIdentityRow>(
        "SELECT did, odentity_composite, pace_status, card_status, created_at_ms, exochain_anchor FROM livesafe_identities WHERE did = $1"
    ).bind(did).fetch_optional(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LiveSafeIdentityRow {
    pub did: String,
    pub odentity_composite: f64,
    pub pace_status: String,
    pub card_status: String,
    pub created_at_ms: i64,
    pub exochain_anchor: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_scan_receipt(
    pool: &PgPool, scan_id: &str, subscriber_did: &str, responder_did: &str,
    location: Option<&str>, scanned_at_ms: i64, consent_expires_at_ms: i64,
    audit_receipt_hash: &str, anchor_receipt: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO scan_receipts (scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    ).bind(scan_id).bind(subscriber_did).bind(responder_did).bind(location)
    .bind(scanned_at_ms).bind(consent_expires_at_ms).bind(audit_receipt_hash).bind(anchor_receipt)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_scan_receipts(pool: &PgPool, subscriber_did: &str) -> Result<Vec<ScanReceiptRow>, sqlx::Error> {
    sqlx::query_as::<_, ScanReceiptRow>(
        "SELECT scan_id, subscriber_did, responder_did, location, scanned_at_ms, consent_expires_at_ms, audit_receipt_hash, anchor_receipt FROM scan_receipts WHERE subscriber_did = $1 ORDER BY scanned_at_ms DESC"
    ).bind(subscriber_did).fetch_all(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScanReceiptRow {
    pub scan_id: String,
    pub subscriber_did: String,
    pub responder_did: String,
    pub location: Option<String>,
    pub scanned_at_ms: i64,
    pub consent_expires_at_ms: i64,
    pub audit_receipt_hash: String,
    pub anchor_receipt: Option<String>,
}

pub async fn insert_consent_anchor(
    pool: &PgPool, consent_id: &str, subscriber_did: &str, provider_did: &str,
    scope: &JsonValue, granted_at_ms: i64, expires_at_ms: Option<i64>, audit_receipt_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO consent_anchors (consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, audit_receipt_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    ).bind(consent_id).bind(subscriber_did).bind(provider_did).bind(scope)
    .bind(granted_at_ms).bind(expires_at_ms).bind(audit_receipt_hash)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_consent_anchors(pool: &PgPool, subscriber_did: &str) -> Result<Vec<ConsentAnchorRow>, sqlx::Error> {
    sqlx::query_as::<_, ConsentAnchorRow>(
        "SELECT consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, revoked_at_ms, audit_receipt_hash FROM consent_anchors WHERE subscriber_did = $1 ORDER BY granted_at_ms DESC"
    ).bind(subscriber_did).fetch_all(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentAnchorRow {
    pub consent_id: String,
    pub subscriber_did: String,
    pub provider_did: String,
    pub scope: JsonValue,
    pub granted_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub audit_receipt_hash: String,
}

pub async fn insert_trustee_shard(
    pool: &PgPool, subscriber_did: &str, trustee_did: &str, role: &str,
    shard_confirmed: bool, accepted_at_ms: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO trustee_shard_status (subscriber_did, trustee_did, role, shard_confirmed, accepted_at_ms) VALUES ($1, $2, $3, $4, $5)"
    ).bind(subscriber_did).bind(trustee_did).bind(role).bind(shard_confirmed).bind(accepted_at_ms)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_trustee_shards(pool: &PgPool, subscriber_did: &str) -> Result<Vec<TrusteeShardRow>, sqlx::Error> {
    sqlx::query_as::<_, TrusteeShardRow>(
        "SELECT subscriber_did, trustee_did, role, shard_confirmed, accepted_at_ms FROM trustee_shard_status WHERE subscriber_did = $1"
    ).bind(subscriber_did).fetch_all(pool).await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrusteeShardRow {
    pub subscriber_did: String,
    pub trustee_did: String,
    pub role: String,
    pub shard_confirmed: bool,
    pub accepted_at_ms: Option<i64>,
}
