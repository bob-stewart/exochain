-- ============================================================
-- EXOCHAIN decision.forum persistence layer
-- Core tables with seed data. Service-specific tables are
-- created by each service via ensureTable() on startup.
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users (identity-service reads, does not self-create)
CREATE TABLE IF NOT EXISTS users (
    did TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    roles JSONB NOT NULL DEFAULT '[]',
    tenant_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    pace_status TEXT NOT NULL DEFAULT 'Unenrolled',
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
    did TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]',
    trust_tier TEXT NOT NULL DEFAULT 'Untrusted',
    trust_score INTEGER NOT NULL DEFAULT 0,
    delegation_id TEXT,
    pace_status TEXT NOT NULL DEFAULT 'Unenrolled',
    created_at BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    max_decision_class TEXT NOT NULL
);

-- Delegations (used by authority chain verification)
CREATE TABLE IF NOT EXISTS delegations (
    id_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    delegator TEXT NOT NULL,
    delegatee TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    constitution_version TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delegations_delegator ON delegations(delegator);
CREATE INDEX IF NOT EXISTS idx_delegations_delegatee ON delegations(delegatee);

-- Constitution (versioned, single active per tenant)
CREATE TABLE IF NOT EXISTS constitutions (
    tenant_id TEXT NOT NULL,
    version TEXT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, version)
);

-- Identity scores
CREATE TABLE IF NOT EXISTS identity_scores (
    did TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    tier TEXT NOT NULL,
    factors JSONB NOT NULL,
    last_updated BIGINT NOT NULL
);

-- Enrollment log
CREATE TABLE IF NOT EXISTS enrollment_log (
    id BIGSERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    step TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    verified_by TEXT NOT NULL,
    audit_hash TEXT NOT NULL
);

-- HLC counter (singleton)
CREATE TABLE IF NOT EXISTS hlc_state (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    counter BIGINT NOT NULL DEFAULT 1000
);
INSERT INTO hlc_state (counter) VALUES (1000) ON CONFLICT DO NOTHING;

-- LiveSafe tables
CREATE TABLE IF NOT EXISTS livesafe_identities (
    did TEXT PRIMARY KEY,
    odentity_composite DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    pace_status TEXT NOT NULL DEFAULT 'Incomplete',
    card_status TEXT NOT NULL DEFAULT 'NotIssued',
    created_at_ms BIGINT NOT NULL,
    exochain_anchor TEXT
);

CREATE TABLE IF NOT EXISTS scan_receipts (
    scan_id TEXT PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    responder_did TEXT NOT NULL,
    location TEXT,
    scanned_at_ms BIGINT NOT NULL,
    consent_expires_at_ms BIGINT NOT NULL,
    audit_receipt_hash TEXT NOT NULL,
    anchor_receipt TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_subscriber ON scan_receipts(subscriber_did);

CREATE TABLE IF NOT EXISTS consent_anchors (
    consent_id TEXT PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    provider_did TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]',
    granted_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT,
    revoked_at_ms BIGINT,
    audit_receipt_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_consent_subscriber ON consent_anchors(subscriber_did);

CREATE TABLE IF NOT EXISTS trustee_shard_status (
    id BIGSERIAL PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    trustee_did TEXT NOT NULL,
    role TEXT NOT NULL,
    shard_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    accepted_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_shard_subscriber ON trustee_shard_status(subscriber_did);

-- ============================================================
-- Tables below are created by services via ensureTable().
-- We pre-create them here with the service-expected schema
-- so seed data can be inserted.
-- ============================================================

-- Executives / PACE enrollments (syntaxis-orchestrator)
CREATE TABLE IF NOT EXISTS executives (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    wallet_address TEXT,
    odentity_id TEXT,
    role TEXT NOT NULL,
    organization TEXT,
    pace_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    onboarded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attestations JSONB NOT NULL DEFAULT '[]',
    council_roles JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS pace_enrollments (
    pace_id TEXT PRIMARY KEY,
    executive_id TEXT NOT NULL REFERENCES executives(id),
    trustees JSONB NOT NULL DEFAULT '[]',
    threshold TEXT NOT NULL DEFAULT '3-of-4',
    recovery_policy TEXT NOT NULL DEFAULT 'timelocked_48h',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Thought blocks (syntaxis-orchestrator)
CREATE TABLE IF NOT EXISTS thought_blocks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'Proposal',
    author TEXT NOT NULL,
    module_id TEXT NOT NULL DEFAULT 'decision-forum',
    content TEXT,
    effects JSONB,
    combinators JSONB NOT NULL DEFAULT '[]',
    links JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Syntaxis workflows
CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'governance_decision',
    status TEXT NOT NULL DEFAULT 'running',
    steps JSONB NOT NULL DEFAULT '[]',
    decision JSONB,
    block JSONB,
    decision_id TEXT,
    block_id TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Decisions (superset schema for governance-engine + syntaxis-orchestrator)
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    -- governance-engine columns
    governance_case_id TEXT,
    decision TEXT,
    reasons JSONB DEFAULT '[]',
    checks JSONB DEFAULT '[]',
    policy_version TEXT,
    correlation_id TEXT,
    chain_verified BOOLEAN DEFAULT false,
    quorum_result JSONB,
    governance_hash TEXT,
    payload JSONB,
    -- syntaxis-orchestrator columns
    title TEXT,
    block_id TEXT,
    module_id TEXT,
    decision_class TEXT,
    status TEXT,
    author TEXT,
    quorum_required INTEGER,
    votes_for INTEGER DEFAULT 0,
    votes_against INTEGER DEFAULT 0,
    votes JSONB DEFAULT '[]',
    combinator_chain JSONB DEFAULT '[]',
    crosscheck_reports JSONB DEFAULT '[]',
    timeline JSONB DEFAULT '[]',
    wasm_decision JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit entries (superset schema for audit-api service)
CREATE TABLE IF NOT EXISTS audit_entries (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    correlation_id TEXT,
    event_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT '',
    prev_hash TEXT,
    record_hash TEXT,
    content_hash TEXT,
    data JSONB,
    recorded_at TIMESTAMPTZ DEFAULT NOW(),
    raw_record JSONB,
    -- original exochain schema columns
    sequence BIGINT,
    actor TEXT,
    tenant_id TEXT,
    timestamp_physical_ms BIGINT,
    timestamp_logical INTEGER DEFAULT 0
);

-- Provenance receipts (provenance-writer service)
CREATE TABLE IF NOT EXISTS provenance_receipts (
    id SERIAL PRIMARY KEY,
    receipt_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    correlation_id TEXT,
    payload_hash TEXT NOT NULL,
    record_hash TEXT,
    content_hash TEXT,
    prev_record_hash TEXT,
    immutable BOOLEAN DEFAULT TRUE,
    chain TEXT NOT NULL DEFAULT 'exochain-local',
    written_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_record JSONB
);
CREATE INDEX IF NOT EXISTS idx_receipts_correlation ON provenance_receipts(correlation_id);

-- Notifications (notification-service)
CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    channel TEXT NOT NULL DEFAULT 'system',
    message TEXT NOT NULL DEFAULT '',
    correlation_id TEXT,
    payload JSONB,
    delivered BOOLEAN NOT NULL DEFAULT TRUE,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CAIP Assessments (caip-engine creates its own schema)
-- Deliberately NOT pre-creating this table; caip-engine's
-- ensureTable() will create it with its own schema.
