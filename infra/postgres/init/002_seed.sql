-- ============================================================
-- ExoChain Foundation — Seed Data for Demo Environment
-- ============================================================

-- ── 3 Test Users (PACE Enrolled) ─────────────────────────────
INSERT INTO users (did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled)
VALUES
  ('did:exo:alice', 'Alice Chen', 'alice@exoeth.foundation',
   '["chair","ethics-officer"]', 'exoeth-foundation', 1710600000000, 'Active', 'Enrolled',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'salt_alice', TRUE),
  ('did:exo:bob', 'Bob Martinez', 'bob@exoeth.foundation',
   '["tech-lead","member"]', 'exoeth-foundation', 1710600000000, 'Active', 'Enrolled',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'salt_bob', TRUE),
  ('did:exo:carol', 'Carol Nguyen', 'carol@exoeth.foundation',
   '["general-counsel","member"]', 'exoeth-foundation', 1710600000000, 'Active', 'Enrolled',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'salt_carol', TRUE)
ON CONFLICT DO NOTHING;

-- ── Identity Scores ──────────────────────────────────────────
INSERT INTO identity_scores (did, score, tier, factors, last_updated)
VALUES
  ('did:exo:alice', 95, 'Platinum', '{"kyc":true,"org_binding":true,"pace_enrolled":true,"mfa":true,"attestation_count":4}', 1710600000000),
  ('did:exo:bob', 88, 'Gold', '{"kyc":true,"org_binding":true,"pace_enrolled":true,"mfa":true,"attestation_count":3}', 1710600000000),
  ('did:exo:carol', 91, 'Platinum', '{"kyc":true,"org_binding":true,"pace_enrolled":true,"mfa":true,"attestation_count":3}', 1710600000000)
ON CONFLICT DO NOTHING;

-- ── LiveSafe Identities ──────────────────────────────────────
INSERT INTO livesafe_identities (did, odentity_composite, pace_status, card_status, created_at_ms, exochain_anchor)
VALUES
  ('did:exo:alice', 0.95, 'Complete', 'Active', 1710600000000, 'anchor-genesis-alice'),
  ('did:exo:bob', 0.88, 'Complete', 'Active', 1710600000000, 'anchor-genesis-bob'),
  ('did:exo:carol', 0.91, 'Complete', 'Active', 1710600000000, 'anchor-genesis-carol')
ON CONFLICT DO NOTHING;

-- ── Constitution v1.0.0 ──────────────────────────────────────
INSERT INTO constitutions (tenant_id, version, payload)
VALUES ('exoeth-foundation', '1.0.0', '{
  "name": "ExoEth Foundation Constitution",
  "version": [1, 0, 0],
  "hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "tnc_controls": [
    "TNC-01: Human-in-the-loop for material decisions",
    "TNC-02: AI ceiling class enforcement",
    "TNC-03: Delegation depth limits",
    "TNC-04: Quorum requirements",
    "TNC-05: Authority chain verification",
    "TNC-06: Conflict of interest disclosure",
    "TNC-07: Audit trail integrity",
    "TNC-08: Consent verification",
    "TNC-09: Constitutional compliance",
    "TNC-10: Emergency override protocols"
  ],
  "decision_classes": ["Routine","Operational","Strategic","Constitutional"],
  "quorum_rules": {
    "Routine": {"minimum_participants": 1, "approval_threshold_pct": 51},
    "Operational": {"minimum_participants": 2, "approval_threshold_pct": 51},
    "Strategic": {"minimum_participants": 3, "approval_threshold_pct": 67},
    "Constitutional": {"minimum_participants": 3, "approval_threshold_pct": 75}
  }
}')
ON CONFLICT DO NOTHING;

-- ── Delegation (Alice→Bob for Operational) ───────────────────
INSERT INTO delegations (id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, constitution_version, payload)
VALUES (
  '0000000000000000000000000000000000000000000000000000000000000001',
  'exoeth-foundation', 'did:exo:alice', 'did:exo:bob',
  1710600000000, 1742136000000, '1.0.0',
  '{"allowed_classes":["Operational","Strategic"],"allowed_actions":["CreateDecision","CastVote"],"signer_is_human":true,"is_active":true}'
)
ON CONFLICT DO NOTHING;

-- Note: decisions table is created by governance-engine service on startup.
-- Sample decision will be seeded via the service API.

-- ── Consent Anchor (CyberMedica integration) ────────────────
INSERT INTO consent_anchors (consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, audit_receipt_hash)
VALUES (
  'consent-cybermedica-001', 'did:exo:alice', 'did:exo:cybermedica',
  '["governance_evaluation","regulated_ai_sdlc","clinical_decision_support"]',
  1710600000000, 1742136000000,
  'genesis-consent-receipt-hash'
)
ON CONFLICT DO NOTHING;

-- Note: audit_entries table is created by audit-api service on startup.
-- Genesis audit entry will be seeded via the service API.

-- ── Executives (for Syntaxis) ────────────────────────────────
INSERT INTO executives (id, name, email, wallet_address, odentity_id, role, organization, pace_id, status, attestations, council_roles)
VALUES
  ('exec-alice', 'Alice Chen', 'alice@exoeth.foundation', '0xAlice00000000000000000000000000000000', 'od-Alice0', 'ceo', 'ExoEth Foundation', 'pace-alice',
   'active', '["att-kyc-verified","att-org-binding","att-role-ceo"]',
   '[{"module":"decision-forum","role":"chair"},{"module":"ai-irb","role":"ethics-officer"}]'),
  ('exec-bob', 'Bob Martinez', 'bob@exoeth.foundation', '0xBob0000000000000000000000000000000000', 'od-Bob000', 'cto', 'ExoEth Foundation', 'pace-bob',
   'active', '["att-kyc-verified","att-org-binding","att-role-cto"]',
   '[{"module":"ai-sdlc","role":"tech-lead"},{"module":"decision-forum","role":"member"}]'),
  ('exec-carol', 'Carol Nguyen', 'carol@exoeth.foundation', '0xCarol000000000000000000000000000000', 'od-Carol0', 'gc', 'ExoEth Foundation', 'pace-carol',
   'active', '["att-kyc-verified","att-org-binding","att-role-gc"]',
   '[{"module":"legaldyne","role":"general-counsel"},{"module":"decision-forum","role":"member"}]')
ON CONFLICT DO NOTHING;

-- ── PACE Enrollments ─────────────────────────────────────────
INSERT INTO pace_enrollments (pace_id, executive_id, trustees, threshold, recovery_policy)
VALUES
  ('pace-alice', 'exec-alice',
   '[{"name":"Trustee A","shard":1,"status":"enrolled"},{"name":"Trustee B","shard":2,"status":"enrolled"},{"name":"Trustee C","shard":3,"status":"enrolled"},{"name":"Trustee D","shard":4,"status":"enrolled"}]',
   '3-of-4', 'timelocked_48h'),
  ('pace-bob', 'exec-bob',
   '[{"name":"Trustee A","shard":1,"status":"enrolled"},{"name":"Trustee B","shard":2,"status":"enrolled"},{"name":"Trustee C","shard":3,"status":"enrolled"},{"name":"Trustee D","shard":4,"status":"pending"}]',
   '3-of-4', 'timelocked_48h'),
  ('pace-carol', 'exec-carol',
   '[{"name":"Trustee A","shard":1,"status":"enrolled"},{"name":"Trustee B","shard":2,"status":"enrolled"},{"name":"Trustee C","shard":3,"status":"enrolled"},{"name":"Trustee D","shard":4,"status":"enrolled"}]',
   '3-of-4', 'timelocked_48h')
ON CONFLICT DO NOTHING;

-- ── Enrollment Log ───────────────────────────────────────────
INSERT INTO enrollment_log (did, entity_type, step, timestamp, verified_by, audit_hash)
VALUES
  ('did:exo:alice', 'Human', 'pace_complete', 1710600000000, 'system', 'enroll-alice-hash'),
  ('did:exo:bob', 'Human', 'pace_complete', 1710600000000, 'system', 'enroll-bob-hash'),
  ('did:exo:carol', 'Human', 'pace_complete', 1710600000000, 'system', 'enroll-carol-hash')
ON CONFLICT DO NOTHING;
