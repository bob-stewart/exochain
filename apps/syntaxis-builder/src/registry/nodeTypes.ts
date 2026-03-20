import type { NodeTypeConfig } from '../types';

export const SERVICE_NODES: NodeTypeConfig[] = [
  {
    moduleRef: 'identity-service', category: 'service', icon: '🔐', name: '0dentity', description: 'PACE Identity Binding',
    color: '#58a6ff', glow: 'rgba(88,166,255,.25)', module: '0dentity', version: '1.0.0',
    exochainCrates: ['exo-identity', 'exo-consent'], gatewayPrefix: 'identity_',
    service: { name: '0dentity Identity Service', port: 3001, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [{ key: 'walletAddress', type: 'address', required: true, description: 'Ethereum wallet address (0x...)' }],
    outputs: ['odentityId', 'walletAddress', 'roles', 'organization', 'attestationRefs'],
    combinators: [
      { type: 'Gate', exochainTerm: 'Lookup(identityResolved)', description: 'Identity must resolve before execution' },
      { type: 'Threshold', exochainTerm: 'GreaterThanOrEqual(trustee_shards)', args: { percentage: 75 }, description: 'PACE trustee quorum' },
    ],
    councilRoles: [{ id: 'subscriber', name: 'Subscriber', vetoCapable: true }, { id: 'trustee', name: 'PACE Trustee', vetoCapable: false }],
    paceConfig: { threshold: '3-of-4', recoveryPolicy: 'timelocked_48h', shards: 4 },
  },
  {
    moduleRef: 'consent-service', category: 'service', icon: '🛡️', name: 'LiveSafe', description: 'Consent Verification',
    color: '#d29922', glow: 'rgba(210,153,34,.25)', module: 'livesafe', version: '1.0.0',
    exochainCrates: ['exo-consent', 'exo-identity'], gatewayPrefix: 'livesafe_',
    service: { name: 'LiveSafe Consent Service', port: 3002, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [{ key: 'assetId', type: 'address', required: true, description: 'Target asset or contract' }],
    outputs: ['consentId', 'assetId', 'owner', 'allowedUses', 'restrictions', 'effectiveAt', 'expiresAt'],
    combinators: [
      { type: 'Gate', exochainTerm: 'Lookup(consentVerified)', description: 'Consent must be verified' },
      { type: 'Veto', exochainTerm: 'Not(veto_exercised)', description: 'Subscriber can revoke consent' },
      { type: 'TimeLock', exochainTerm: 'GreaterThanOrEqual(elapsed_ms)', args: { duration: '365d' }, description: 'Consent expiry' },
    ],
    decisionClasses: ['Operational', 'Standard'],
  },
  {
    moduleRef: 'crosscheck-adapter', category: 'service', icon: '🔍', name: 'CrossChecked', description: '4-Signal Consensus',
    color: '#3fb950', glow: 'rgba(63,185,80,.25)', module: 'crosschecked', version: '1.0.0',
    exochainCrates: ['exo-governance', 'exo-gatekeeper'], gatewayPrefix: 'crosscheck_',
    service: { name: 'CrossChecked Adapter', port: 3005, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'proposal', type: 'object', required: true, description: 'Proposal to validate' },
      { key: 'identity', type: 'object', required: true, description: 'Resolved identity from 0dentity' },
    ],
    outputs: ['crosscheckId', 'consensus', 'conflictsDetected', 'riskScore', 'signals'],
    combinators: [
      { type: 'Reproducible', exochainTerm: 'GreaterThanOrEqual(trial_count)', args: { min_trials: 2 }, description: 'Multiple independent signals' },
      { type: 'Threshold', exochainTerm: 'GreaterThanOrEqual(approve_pct)', args: { percentage: 75 }, description: 'Signal consensus threshold' },
    ],
    signals: [
      { source: 'policy_engine', description: 'Checks against active policy version' },
      { source: 'identity_registry', description: 'Confirms identity is bound' },
      { source: 'risk_model', description: 'Evaluates composite risk' },
      { source: 'conflict_detector', description: 'Scans for conflicting proposals' },
    ],
  },
  {
    moduleRef: 'governance-engine', category: 'service', icon: '⚖️', name: 'Governance Engine', description: 'Gate Evaluation',
    color: '#a371f7', glow: 'rgba(163,113,247,.25)', module: 'decision-forum', version: '1.0.0',
    exochainCrates: ['exo-governance', 'exo-authority', 'exo-legal', 'exo-gatekeeper'], gatewayPrefix: 'governance_',
    service: { name: 'Governance Engine', port: 3003, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'proposal', type: 'object', required: true, description: 'Execution request' },
      { key: 'identity', type: 'object', required: true, description: 'Resolved identity' },
      { key: 'consent', type: 'object', required: true, description: 'Consent resolution' },
      { key: 'crosscheck', type: 'object', required: true, description: 'CrossChecked result' },
    ],
    outputs: ['governanceCaseId', 'decision', 'reasons', 'checks', 'policyVersion'],
    combinators: [
      { type: 'All', exochainTerm: 'ForAll', description: 'All gates must pass' },
      { type: 'Gate', exochainTerm: 'Lookup(condition)', description: 'Named predicate checks' },
      { type: 'Veto', exochainTerm: 'Not(veto_exercised)', description: 'Authority veto' },
      { type: 'Escalate', exochainTerm: 'TriageItem.priority.bump()', description: 'Escalation' },
    ],
    gates: ['identity_verified', 'consent_valid', 'crosscheck_consensus', 'wallet_present', 'target_present'],
    decisionClasses: ['Operational', 'Standard', 'Strategic', 'Constitutional'],
    councilRoles: [
      { id: 'chair', name: 'Council Chair', vetoCapable: true, decisionClasses: ['Constitutional', 'Strategic'] },
      { id: 'member', name: 'Council Member', vetoCapable: false, decisionClasses: ['Operational', 'Standard', 'Strategic', 'Constitutional'] },
    ],
  },
  {
    moduleRef: 'decision-forge', category: 'service', icon: '🔥', name: 'Decision Forge', description: 'Combinator Chain',
    color: '#f0883e', glow: 'rgba(240,136,62,.25)', module: 'decision-forum', version: '1.0.0',
    exochainCrates: ['exo-governance', 'exo-gatekeeper'], gatewayPrefix: 'governance_',
    service: { name: 'Decision Forge', port: 3004, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'proposalId', type: 'string', required: true, description: 'Source proposal / block ID' },
      { key: 'governanceDecision', type: 'object', required: true, description: 'Governance decision' },
    ],
    outputs: ['forgeId', 'forgedDecision', 'confidence', 'rationale', 'policyVersion'],
    combinators: [
      { type: 'Threshold', exochainTerm: 'GreaterThanOrEqual(approve_pct)', args: { percentage: 66 }, description: 'Vote threshold' },
      { type: 'TimeLock', exochainTerm: 'GreaterThanOrEqual(elapsed_ms)', args: { duration: '24h' }, description: 'Deliberation period' },
      { type: 'Gate', exochainTerm: 'Lookup(identityVerified)', description: 'Identity gate' },
    ],
  },
  {
    moduleRef: 'provenance-writer', category: 'service', icon: '⛓️', name: 'ExoChain', description: 'Provenance Receipt',
    color: '#39d2c0', glow: 'rgba(57,210,192,.25)', module: 'exochain', version: '1.0.0',
    exochainCrates: ['exo-ledger', 'exo-provenance', 'exo-hash'], gatewayPrefix: 'provenance_',
    service: { name: 'ExoChain Provenance Writer', port: 3006, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'eventType', type: 'string', required: true, description: 'Event type' },
      { key: 'correlationId', type: 'string', required: true, description: 'Correlation ID' },
      { key: 'payload', type: 'object', required: true, description: 'Payload to hash' },
    ],
    outputs: ['receiptId', 'payloadHash', 'immutable', 'chain', 'writtenAt'],
    combinators: [],
  },
  {
    moduleRef: 'audit-api', category: 'service', icon: '📜', name: 'Audit Ledger', description: 'Immutable Record',
    color: '#3fb950', glow: 'rgba(63,185,80,.25)', module: 'audit-api', version: '1.0.0',
    exochainCrates: ['exo-audit', 'exo-ledger'], gatewayPrefix: 'audit_',
    service: { name: 'Audit API', port: 3007, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'eventType', type: 'string', required: true, description: 'Audit event type' },
      { key: 'correlationId', type: 'string', required: true, description: 'Correlation ID' },
      { key: 'actor', type: 'string', required: false, description: '0dentity ID of acting entity' },
    ],
    outputs: ['recorded', 'entry'],
    combinators: [],
  },
  {
    moduleRef: 'policy-distribution', category: 'service', icon: '📋', name: 'LegalDyne Policy', description: 'Policy Distribution',
    color: '#a371f7', glow: 'rgba(163,113,247,.25)', module: 'legaldyne', version: '1.0.0',
    exochainCrates: ['exo-legal', 'exo-consent'], gatewayPrefix: 'legal_',
    service: { name: 'LegalDyne Policy Distribution', port: 3009, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [],
    outputs: ['version', 'name', 'rules', 'effectiveAt'],
    combinators: [
      { type: 'Gate', exochainTerm: 'Lookup(legalReview)', description: 'Legal review gate' },
      { type: 'TimeLock', exochainTerm: 'GreaterThanOrEqual(elapsed)', description: 'Public comment period' },
    ],
  },
  {
    moduleRef: 'notification-service', category: 'service', icon: '🔔', name: 'Notification', description: 'Alert Delivery',
    color: '#8b949e', glow: 'rgba(139,148,158,.25)', module: 'notification', version: '1.0.0',
    exochainCrates: [], gatewayPrefix: 'notify_',
    service: { name: 'Notification Service', port: 3008, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'channel', type: 'string', required: true, description: 'Notification channel' },
      { key: 'message', type: 'string', required: true, description: 'Message content' },
    ],
    outputs: ['delivered', 'sentAt'],
    combinators: [],
  },
  {
    moduleRef: 'caip-engine', category: 'service', icon: '🎯', name: 'CAIP Scoring', description: 'CTO Assessment (C1-C11)',
    color: '#f0883e', glow: 'rgba(240,136,62,.25)', module: 'caip-engine', version: '1.0.0',
    exochainCrates: ['exo-assessment', 'exo-identity'], gatewayPrefix: 'caip_',
    service: { name: 'CAIP Engine', port: 3011, protocol: 'HTTP/JSON', healthEndpoint: '/health' },
    parameters: [
      { key: 'cto_name', type: 'string', required: true, description: 'CTO name' },
      { key: 'company', type: 'object', required: true, description: 'Company profile' },
      { key: 'cto_profile', type: 'object', required: true, description: 'Role type, years' },
      { key: 'engagement_purpose', type: 'enum', required: true, description: 'Assessment use case', values: ['AVC_onboarding', 'fractional_engagement', 'diligence', 'self_dev'] },
    ],
    outputs: ['assessment_id', 'maturity_state', 'dimensions', 'composite'],
    combinators: [],
  },
];

export const COMBINATOR_NODES: NodeTypeConfig[] = [
  { moduleRef: 'Threshold', category: 'combinator', icon: '⊞', name: 'Threshold', description: 'Percentage-based approval', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [{ key: 'percentage', type: 'number', required: true, description: 'Approval threshold (0-100)', default: 66 }], outputs: ['passed'], combinators: [{ type: 'Threshold', exochainTerm: 'GreaterThanOrEqual(approve_pct)', description: 'Percentage approval' }] },
  { moduleRef: 'TimeLock', category: 'combinator', icon: '⏳', name: 'TimeLock', description: 'Enforced waiting period', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [{ key: 'duration', type: 'string', required: true, description: 'Duration (e.g., 24h, 7d)', default: '24h' }], outputs: ['passed'], combinators: [{ type: 'TimeLock', exochainTerm: 'GreaterThanOrEqual(elapsed_ms)', description: 'Enforced wait' }] },
  { moduleRef: 'Gate', category: 'combinator', icon: '🚧', name: 'Gate', description: 'Conditional predicate check', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [{ key: 'condition', type: 'string', required: true, description: 'Predicate name', default: 'identityVerified' }], outputs: ['passed'], combinators: [{ type: 'Gate', exochainTerm: 'Lookup(condition)', description: 'Conditional check' }] },
  { moduleRef: 'Veto', category: 'combinator', icon: '✋', name: 'Veto', description: 'Authority-based block', color: '#f85149', glow: 'rgba(248,81,73,.25)', version: '1.0.0', parameters: [{ key: 'role', type: 'string', required: true, description: 'Council role ID', default: 'chair' }], outputs: ['passed'], combinators: [{ type: 'Veto', exochainTerm: 'Not(veto_exercised)', description: 'Authority block' }] },
  { moduleRef: 'All', category: 'combinator', icon: '∀', name: 'All (ForAll)', description: 'Unanimous consent', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [], outputs: ['passed'], combinators: [{ type: 'All', exochainTerm: 'ForAll', description: 'All must pass' }] },
  { moduleRef: 'Any', category: 'combinator', icon: '∃', name: 'Any (Exists)', description: 'At least one path succeeds', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [], outputs: ['passed'], combinators: [{ type: 'Any', exochainTerm: 'Exists', description: 'One must pass' }] },
  { moduleRef: 'Escalate', category: 'combinator', icon: '⬆', name: 'Escalate', description: 'Escalation to higher authority', color: '#d29922', glow: 'rgba(210,153,34,.25)', version: '1.0.0', parameters: [{ key: 'target', type: 'string', required: true, description: 'Authority ID' }], outputs: ['escalated'], combinators: [{ type: 'Escalate', exochainTerm: 'TriageItem.priority.bump()', description: 'Escalate' }] },
  { moduleRef: 'Canary', category: 'combinator', icon: '🐤', name: 'Canary', description: 'Gradual rollout with safety net', color: '#d29922', glow: 'rgba(210,153,34,.25)', version: '1.0.0', parameters: [{ key: 'percent', type: 'number', required: true, description: 'Rollout %', default: 10 }, { key: 'rollback', type: 'string', required: true, description: 'Rollback condition' }], outputs: ['passed'], combinators: [{ type: 'Canary', exochainTerm: 'And(LessThan(rollout_pct), Not(rollback))', description: 'Gradual rollout' }] },
  { moduleRef: 'Reproducible', category: 'combinator', icon: '🔁', name: 'Reproducible', description: 'Multiple independent trials', color: '#a371f7', glow: 'rgba(163,113,247,.25)', version: '1.0.0', parameters: [{ key: 'min_trials', type: 'number', required: true, description: 'Min successful trials', default: 3 }], outputs: ['passed'], combinators: [{ type: 'Reproducible', exochainTerm: 'GreaterThanOrEqual(trial_count)', description: 'N trials required' }] },
];

export const CONTROL_NODES: NodeTypeConfig[] = [
  { moduleRef: 'input', category: 'control', icon: '▶', name: 'Input', description: 'Workflow entry point', color: '#58a6ff', glow: 'rgba(88,166,255,.25)', version: '1.0.0', parameters: [], outputs: ['data'] },
  { moduleRef: 'output', category: 'control', icon: '⏹', name: 'Output', description: 'Workflow result', color: '#3fb950', glow: 'rgba(63,185,80,.25)', version: '1.0.0', parameters: [], outputs: ['result'] },
  { moduleRef: 'branch', category: 'control', icon: '◇', name: 'Branch', description: 'Conditional routing', color: '#8b949e', glow: 'rgba(139,148,158,.25)', version: '1.0.0', parameters: [{ key: 'condition', type: 'string', required: true, description: 'Branch condition expression' }], outputs: ['true', 'false'] },
  { moduleRef: 'merge', category: 'control', icon: '◆', name: 'Merge', description: 'Join multiple paths', color: '#8b949e', glow: 'rgba(139,148,158,.25)', version: '1.0.0', parameters: [], outputs: ['merged'] },
];

export const ALL_NODE_TYPES = [...SERVICE_NODES, ...COMBINATOR_NODES, ...CONTROL_NODES];

export function getNodeType(moduleRef: string): NodeTypeConfig | undefined {
  return ALL_NODE_TYPES.find(n => n.moduleRef === moduleRef);
}
