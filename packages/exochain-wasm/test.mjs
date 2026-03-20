import * as wasm from './wasm/exochain_wasm.js';

console.log('=== ExoChain WASM Test Suite ===\n');
let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}: ${e.message}`);
    failed++;
  }
}

// 1. Hash
test('wasm_hash_bytes', () => {
  const r = wasm.wasm_hash_bytes('01020304');
  const h = typeof r === 'string' ? r : r?.hash ?? JSON.stringify(r);
  if (!h || h.length < 32) throw new Error(`Unexpected hash: ${h}`);
  console.log(`     hash=${String(h).slice(0,16)}...`);
});

// 2. Keypair
test('wasm_generate_keypair', () => {
  const kp = wasm.wasm_generate_keypair();
  if (!kp.public_key) throw new Error('No public_key');
  console.log(`     pub=${kp.public_key.slice(0,16)}... secret_len=${kp.secret_key.length}`);
});

// 3. Sign + Verify
test('wasm_compute_signature + verify', () => {
  const kp = wasm.wasm_generate_keypair();
  const r = wasm.wasm_hash_bytes('deadbeef');
  const hash = typeof r === 'string' ? r : r?.hash;
  const sig = wasm.wasm_compute_signature(kp.secret_key, hash);
  const sigStr = typeof sig === 'string' ? sig : sig?.signature ?? JSON.stringify(sig);
  console.log(`     sig=${String(sigStr).slice(0,16)}...`);
  const valid = wasm.wasm_verify_signature(kp.public_key, hash, sigStr);
  const isValid = typeof valid === 'boolean' ? valid : valid?.valid;
  if (!isValid) throw new Error('Signature verification failed');
});

// 4. Combinator reduction
// WasmCombinatorTerm uses #[serde(tag = "kind")]
// WasmReductionContext has { bindings: {name: WasmTypedValue}, domains: {} }
// WasmTypedValue uses #[serde(tag = "type", content = "value")]
test('wasm_reduce_combinator', () => {
  // Build: App(App(And, Literal(true)), Literal(true)) => true
  const term = {
    kind: 'App',
    f: {
      kind: 'App',
      f: { kind: 'And' },
      x: { kind: 'Literal', value: { type: 'Bool', value: true } }
    },
    x: { kind: 'Literal', value: { type: 'Bool', value: true } }
  };
  const context = { bindings: {}, domains: {} };
  const r = wasm.wasm_reduce_combinator(
    JSON.stringify(term),
    JSON.stringify(context),
    'test-inv', 100
  );
  console.log(`     result=${JSON.stringify(r).slice(0,80)}...`);
});

// 5. Create decision
// CreateDecisionInput: { tenant_id, title, body?, decision_class, constitution_hash (hex 32 bytes),
//   constitution_version [u32;3], author, eligible_voters, minimum_participants, approval_threshold_pct }
test('wasm_create_decision', () => {
  const input = {
    tenant_id: 'exoeth-foundation',
    title: 'Approve AI Module',
    decision_class: 'Strategic',
    constitution_hash: '0000000000000000000000000000000000000000000000000000000000000000',
    constitution_version: [1, 0, 0],
    author: 'did:exo:alice',
    eligible_voters: ['did:exo:alice', 'did:exo:bob', 'did:exo:carol'],
    minimum_participants: 2,
    approval_threshold_pct: 51
  };
  const d = wasm.wasm_create_decision(JSON.stringify(input));
  console.log(`     decision=${JSON.stringify(d).slice(0,60)}...`);
});

// 6. Valid transitions
// wasm_valid_transitions takes a status string. Valid values: Created, Deliberation, Voting,
//   Approved, Rejected, Void, Contested, RatificationRequired, RatificationExpired, DegradedGovernance
test('wasm_valid_transitions', () => {
  const t = wasm.wasm_valid_transitions('Created');
  console.log(`     transitions=${JSON.stringify(t)}`);
});

// 7. Check quorum
// CheckQuorumInput: { eligible_voters, present_voters, minimum_participants }
test('wasm_check_quorum', () => {
  const input = {
    eligible_voters: ['did:exo:alice', 'did:exo:bob', 'did:exo:carol'],
    present_voters: ['did:exo:alice', 'did:exo:bob'],
    minimum_participants: 2
  };
  const m = wasm.wasm_check_quorum(JSON.stringify(input));
  console.log(`     quorum=${JSON.stringify(m)}`);
});

// 8. Enforce TNCs
// EnforceTncsInput: { decision: ForumDecisionObject }
// ForumDecisionObject fields: id, title, constitution_hash, authority_chain [{pubkey, signature}],
//   merkle_root, status (Draft|Pending|Approved|Rejected|Contested|Void),
//   created_at (ISO 8601), evidence [{hash, description}], decision_class (Routine|Operational|Strategic|Constitutional),
//   signer_type (Human or {AiAgent:{delegation_id,ceiling_class}}),
//   delegation_chain, conflicts_disclosed [{discloser, description}], votes [{voter_did, choice, signer_type}],
//   quorum_required, quorum_threshold_pct, audit_sequence, prev_audit_hash,
//   requires_ratification, ratification_deadline, constitution_version
test('wasm_enforce_tncs', () => {
  const decision = {
    id: 'test-decision-001',
    title: 'Test Decision',
    constitution_hash: 'genesis-constitution-hash',
    authority_chain: [{ pubkey: 'genesis-pubkey', signature: 'genesis-signature' }],
    merkle_root: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    status: 'Draft',
    created_at: new Date().toISOString(),
    evidence: [],
    decision_class: 'Routine',
    signer_type: 'Human',
    delegation_chain: [],
    conflicts_disclosed: [],
    votes: [],
    quorum_required: 0,
    quorum_threshold_pct: 0.0,
    audit_sequence: 1,
    prev_audit_hash: 'genesis-audit-hash',
    requires_ratification: false,
    ratification_deadline: null,
    constitution_version: '1.0.0'
  };
  const r = wasm.wasm_enforce_tncs(JSON.stringify({ decision }));
  console.log(`     tnc=${JSON.stringify(r).slice(0,60)}...`);
});

// 9. Genesis decision
test('wasm_create_genesis_decision', () => {
  const g = wasm.wasm_create_genesis_decision('Genesis Test');
  console.log(`     genesis=${JSON.stringify(g).slice(0,60)}...`);
});

// 10. Authenticated record
// CreateRecordInput: { record_type, tenant_id, content, custodian, prev_record_hash_hex? }
// record_type values: Decision, Vote, Delegation, ConstitutionalAmendment, AuditSegment, Evidence, Deliberation, or Custom:xxx
test('wasm_create_authenticated_record', () => {
  const r = wasm.wasm_create_authenticated_record(JSON.stringify({
    record_type: 'Decision',
    tenant_id: 'exoeth-foundation',
    content: 'Hello world record content',
    custodian: 'did:exo:alice'
  }));
  console.log(`     record=${JSON.stringify(r).slice(0,60)}...`);
});

// 11. Detect anomalies
// DetectAnomaliesInput: { events: [{ actor, anomaly_type, timestamp_ms }] }
// anomaly_type values: QuorumManipulation, DelegationCascade, AlignmentDrift, ConsentExpiry,
//   AuditGap, EquivocationAttempt, UnauthorizedAccess, SilentMutation, HumanOverrideAttempt,
//   KernelTamper, RapidEmergencyActions, TrustScoreAnomaly, or custom string
test('wasm_detect_anomalies', () => {
  const input = {
    events: [
      { actor: 'did:exo:alice', anomaly_type: 'QuorumManipulation', timestamp_ms: Date.now() },
      { actor: 'did:exo:bob', anomaly_type: 'UnauthorizedAccess', timestamp_ms: Date.now() }
    ]
  };
  const r = wasm.wasm_detect_anomalies(JSON.stringify(input));
  console.log(`     anomalies=${JSON.stringify(r).slice(0,60)}...`);
});

// 12. Consent evaluation
// EvaluatePolicyInput: { policies: [WasmPolicy], subject, resource, groups? }
// WasmPolicy: { id, description, effect ("Allow"|"Deny"), subjects (WasmAccessorSet), resources: [string], conditions?: [WasmCondition] }
// WasmAccessorSet: { type: "Any" } | { type: "Specific", dids: [...] } | { type: "Group", group_id: "..." }
// WasmCondition: { type: "...", value: "..." }
test('wasm_evaluate_policy', () => {
  const input = {
    policies: [{
      id: 'p1',
      description: 'Allow all access to governance evaluation',
      effect: 'Allow',
      subjects: { type: 'Any' },
      resources: ['governance_evaluation'],
      conditions: []
    }],
    subject: 'did:exo:alice',
    resource: 'governance_evaluation',
    groups: {}
  };
  const r = wasm.wasm_evaluate_policy(JSON.stringify(input));
  console.log(`     consent=${JSON.stringify(r).slice(0,60)}...`);
});

// 13. Authority chain verification
// VerifyChainInput: { actor, actor_is_ai, action, decision_class, chain: [WasmDelegationLink], max_depth, requires_human_gate }
// WasmDelegationLink: { id, delegator, delegatee, is_active, allowed_classes, allowed_actions, signer_is_human }
test('wasm_verify_chain', () => {
  const input = {
    actor: 'did:exo:bob',
    actor_is_ai: false,
    action: 'CreateDecision',
    decision_class: 'Operational',
    chain: [{
      id: '0000000000000000000000000000000000000000000000000000000000000001',
      delegator: 'did:exo:alice',
      delegatee: 'did:exo:bob',
      is_active: true,
      allowed_classes: ['Operational', 'Strategic'],
      allowed_actions: ['CreateDecision', 'CastVote'],
      signer_is_human: true
    }],
    max_depth: 5,
    requires_human_gate: false
  };
  const r = wasm.wasm_verify_chain(JSON.stringify(input));
  console.log(`     chain=${JSON.stringify(r).slice(0,60)}...`);
});

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
if (failed === 0) console.log('🎉 28K+ lines of Rust governance engine running in Node.js via WASM!');
process.exit(failed > 0 ? 1 : 0);
