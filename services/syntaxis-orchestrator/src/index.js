import http from "node:http";
import crypto from "node:crypto";
import * as wasm from '../../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth' });

const PORT = process.env.PORT || 3010;
const GATEWAY = process.env.GATEWAY_URL || "http://gateway-api:3000";
const IDENTITY = process.env.IDENTITY_URL || "http://identity-service:3001";
const CONSENT  = process.env.CONSENT_URL  || "http://consent-service:3002";
const CROSSCHECK = process.env.CROSSCHECK_URL || "http://crosscheck-adapter:3005";
const AUDIT    = process.env.AUDIT_URL    || "http://audit-api:3007";
const NOTIFY   = process.env.NOTIFICATION_URL || "http://notification-service:3008";

// ── Module Registry (mirrors Syntaxis) ───────────────────────────
const MODULES = [
  { id: "decision-forum", name: "decision.forum", icon: "\u2696\uFE0F", color: "#7C3AED", decisionClasses: ["Operational","Standard","Strategic","Constitutional"] },
  { id: "crosschecked", name: "crosschecked.ai", icon: "\uD83D\uDD0D", color: "#DC2626", decisionClasses: ["Standard","Strategic","Constitutional"] },
  { id: "livesafe", name: "LiveSafe.ai", icon: "\uD83C\uDFE5", color: "#059669", decisionClasses: ["Operational","Standard"] },
  { id: "legaldyne", name: "LegalDyne", icon: "\uD83D\uDCDC", color: "#4338CA", decisionClasses: ["Standard","Constitutional"] },
  { id: "ai-irb", name: "AI-IRB", icon: "\uD83E\uDDEA", color: "#D97706", decisionClasses: ["Strategic","Constitutional"] },
  { id: "ai-sdlc", name: "AI-SDLC", icon: "\uD83D\uDD04", color: "#2563EB", decisionClasses: ["Operational","Standard"] },
  { id: "cybermedica", name: "CyberMedica", icon: "\uD83D\uDC8A", color: "#0891B2", decisionClasses: ["Operational","Standard","Constitutional"] },
];

const COMBINATOR_BRIDGE = [
  { type: "All", exochainTerm: "ForAll", description: "Unanimous consent" },
  { type: "Any", exochainTerm: "Exists", description: "At least one path succeeds" },
  { type: "Threshold", exochainTerm: "GreaterThanOrEqual(approve_pct)", description: "Percentage-based approval" },
  { type: "Veto", exochainTerm: "Not(veto_exercised)", description: "Authority-based block" },
  { type: "TimeLock", exochainTerm: "GreaterThanOrEqual(elapsed_ms)", description: "Enforced waiting period" },
  { type: "Gate", exochainTerm: "Lookup(condition)", description: "Conditional check" },
  { type: "Escalate", exochainTerm: "TriageItem.priority.bump()", description: "Escalation to higher authority" },
  { type: "Canary", exochainTerm: "And(LessThan(rollout_pct), Not(rollback))", description: "Gradual rollout" },
  { type: "Reproducible", exochainTerm: "GreaterThanOrEqual(trial_count)", description: "Multiple independent trials" },
];

// ── HTTP helpers ─────────────────────────────────────────────────
function post(url, data) {
  const body = JSON.stringify(data);
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } }, (res) => {
      let d = ""; res.on("data", c => d += c); res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on("error", reject);
    req.write(body); req.end();
  });
}

function mapRoleToCouncilRoles(role) {
  const map = {
    "ceo": [{ module: "decision-forum", role: "chair" }, { module: "ai-irb", role: "ethics-officer" }],
    "cto": [{ module: "ai-sdlc", role: "tech-lead" }, { module: "decision-forum", role: "member" }],
    "coo": [{ module: "decision-forum", role: "member" }, { module: "livesafe", role: "provider" }],
    "gc": [{ module: "legaldyne", role: "general-counsel" }, { module: "decision-forum", role: "member" }],
    "cmo": [{ module: "cybermedica", role: "attending" }, { module: "decision-forum", role: "member" }],
    "board-member": [{ module: "decision-forum", role: "member" }],
  };
  return map[role] || [{ module: "decision-forum", role: "observer" }];
}

// ── DB helpers ───────────────────────────────────────────────────
async function dbQuery(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// ── PACE Executive Onboarding ────────────────────────────────────
async function onboardExecutive(data) {
  const { name, email, walletAddress, role, organization, trustees } = data;
  const odentityId = `od-${walletAddress.slice(2, 8)}`;
  const paceId = `pace-${crypto.randomUUID().slice(0, 8)}`;

  // Generate keypair via WASM
  const keypair = wasm.wasm_generate_keypair();

  const executive = {
    id: crypto.randomUUID().slice(0, 8),
    name, email, walletAddress, odentityId, role, organization,
    paceId,
    status: "active",
    onboardedAt: new Date().toISOString(),
    attestations: ["att-kyc-verified", "att-org-binding", `att-role-${role}`],
    councilRoles: mapRoleToCouncilRoles(role),
    publicKey: keypair.public_key,
  };

  const enrollment = {
    paceId,
    executiveId: executive.id,
    trustees: (trustees || [
      { name: "Trustee A", shard: 1, status: "enrolled" },
      { name: "Trustee B", shard: 2, status: "enrolled" },
      { name: "Trustee C", shard: 3, status: "enrolled" },
      { name: "Trustee D", shard: 4, status: "pending" },
    ]),
    threshold: "3-of-4",
    recoveryPolicy: "timelocked_48h",
    enrolledAt: new Date().toISOString(),
  };

  // Persist executive to DB
  await dbQuery(
    `INSERT INTO executives (id, name, email, wallet_address, odentity_id, role, organization, pace_id, status, onboarded_at, attestations, council_roles, public_key)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT (id) DO NOTHING`,
    [executive.id, name, email, walletAddress, odentityId, role, organization, paceId, "active", executive.onboardedAt, JSON.stringify(executive.attestations), JSON.stringify(executive.councilRoles), keypair.public_key]
  );

  // Persist PACE enrollment to DB
  await dbQuery(
    `INSERT INTO pace_enrollments (pace_id, executive_id, trustees, threshold, recovery_policy, enrolled_at)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (pace_id) DO NOTHING`,
    [paceId, executive.id, JSON.stringify(enrollment.trustees), enrollment.threshold, enrollment.recoveryPolicy, enrollment.enrolledAt]
  );

  console.log(`[Syntaxis] PACE onboarded: ${name} (${odentityId}) as ${role}`);
  return { executive, enrollment, modules: MODULES };
}

// ── Syntaxis Thought Block Composition ───────────────────────────
async function composeBlock(data) {
  const block = {
    id: `blk-${crypto.randomUUID().slice(0, 8)}`,
    title: data.title,
    type: data.type || "Proposal",
    author: data.author,
    moduleId: data.moduleId || "decision-forum",
    content: data.content,
    effects: data.effects || { risk: 0.3, fairness: 0.8, novelty: 0.5 },
    combinators: (data.combinators || []).map(c => ({
      id: `comb-${crypto.randomUUID().slice(0, 6)}`,
      type: c.type,
      args: c.args || {},
      exochainTerm: COMBINATOR_BRIDGE.find(b => b.type === c.type)?.exochainTerm || "Unknown",
    })),
    links: data.links || [],
    created: new Date().toISOString(),
  };

  // Persist to DB
  await dbQuery(
    `INSERT INTO thought_blocks (id, title, type, author, module_id, content, effects, combinators, links, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (id) DO NOTHING`,
    [block.id, block.title, block.type, block.author, block.moduleId, block.content, JSON.stringify(block.effects), JSON.stringify(block.combinators), JSON.stringify(block.links), block.created]
  );

  console.log(`[Syntaxis] Composed block: ${block.type} "${block.title}" with ${block.combinators.length} combinators`);
  return block;
}

// ── Decision Forum Workflow ──────────────────────────────────────
async function createDecision(data) {
  const { blockId, decisionClass, quorumRequired, moduleId } = data;

  // Load block from DB
  const blockRes = await dbQuery(`SELECT * FROM thought_blocks WHERE id = $1`, [blockId]);
  if (blockRes.rows.length === 0) return { error: "block_not_found" };
  const blockRow = blockRes.rows[0];
  const block = {
    id: blockRow.id,
    title: blockRow.title,
    type: blockRow.type,
    author: blockRow.author,
    moduleId: blockRow.module_id,
    content: blockRow.content,
    combinators: typeof blockRow.combinators === 'string' ? JSON.parse(blockRow.combinators) : blockRow.combinators,
  };

  // Use WASM to create a governance decision object
  let wasmDecision;
  try {
    wasmDecision = wasm.wasm_create_decision(JSON.stringify({
      tenant_id: "exoeth",
      title: block.title,
      body: block.content,
      decision_class: decisionClass || "Standard",
      constitution_hash: "0000000000000000000000000000000000000000000000000000000000000000",
      constitution_version: [1, 0, 0],
      author: block.author,
      eligible_voters: ["voter-1", "voter-2", "voter-3", "voter-4", "voter-5"],
      minimum_participants: quorumRequired || 3,
      approval_threshold_pct: 66,
    }));
  } catch (e) {
    console.log(`[Syntaxis] WASM create_decision fallback: ${e.message}`);
    wasmDecision = null;
  }

  const decision = {
    id: `dec-${crypto.randomUUID().slice(0, 8)}`,
    title: block.title,
    blockId,
    moduleId: moduleId || block.moduleId,
    decisionClass: decisionClass || "Standard",
    status: "Created",
    author: block.author,
    quorumRequired: quorumRequired || 3,
    votesFor: 0,
    votesAgainst: 0,
    votes: [],
    combinatorChain: block.combinators,
    crosscheckReports: [],
    timeline: [{ event: "decision_created", actor: block.author, timestamp: new Date().toISOString() }],
    createdAt: new Date().toISOString(),
    wasmDecisionId: wasmDecision?.id || null,
  };

  // Persist to DB
  await dbQuery(
    `INSERT INTO decisions (id, title, block_id, module_id, decision_class, status, author, quorum_required, votes_for, votes_against, votes, combinator_chain, crosscheck_reports, timeline, created_at, wasm_decision)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     ON CONFLICT (id) DO NOTHING`,
    [decision.id, decision.title, blockId, decision.moduleId, decision.decisionClass, decision.status, decision.author, decision.quorumRequired, 0, 0, JSON.stringify(decision.votes), JSON.stringify(decision.combinatorChain), JSON.stringify(decision.crosscheckReports), JSON.stringify(decision.timeline), decision.createdAt, wasmDecision ? JSON.stringify(wasmDecision) : null]
  );

  console.log(`[Syntaxis] Decision created: ${decision.id} (${decision.decisionClass})`);
  return decision;
}

// ── Decision Actions ─────────────────────────────────────────────
async function voteOnDecision(decisionId, vote, actor, rationale) {
  const res = await dbQuery(`SELECT * FROM decisions WHERE id = $1`, [decisionId]);
  if (res.rows.length === 0) return { error: "decision_not_found" };
  const row = res.rows[0];

  const votes = typeof row.votes === 'string' ? JSON.parse(row.votes) : (row.votes || []);
  const timeline = typeof row.timeline === 'string' ? JSON.parse(row.timeline) : (row.timeline || []);
  let votesFor = row.votes_for || 0;
  let votesAgainst = row.votes_against || 0;

  votes.push({ actor, vote, rationale, timestamp: new Date().toISOString() });
  if (vote === "approve") votesFor++;
  else votesAgainst++;
  timeline.push({ event: "vote_cast", actor, vote, timestamp: new Date().toISOString() });

  // WASM quorum check
  let quorumResult;
  try {
    const presentVoters = votes.map(v => v.actor);
    quorumResult = wasm.wasm_check_quorum(JSON.stringify({
      eligible_voters: ["voter-1", "voter-2", "voter-3", "voter-4", "voter-5"],
      present_voters: presentVoters,
      minimum_participants: row.quorum_required || 3,
    }));
    timeline.push({ event: "quorum_checked", result: quorumResult, timestamp: new Date().toISOString() });
  } catch (e) {
    console.log(`[Syntaxis] WASM quorum check fallback: ${e.message}`);
  }

  await dbQuery(
    `UPDATE decisions SET votes = $1, votes_for = $2, votes_against = $3, timeline = $4 WHERE id = $5`,
    [JSON.stringify(votes), votesFor, votesAgainst, JSON.stringify(timeline), decisionId]
  );

  return {
    id: decisionId, title: row.title, blockId: row.block_id, moduleId: row.module_id,
    decisionClass: row.decision_class, status: row.status, author: row.author,
    quorumRequired: row.quorum_required, votesFor, votesAgainst, votes, timeline,
    combinatorChain: typeof row.combinator_chain === 'string' ? JSON.parse(row.combinator_chain) : row.combinator_chain,
    crosscheckReports: typeof row.crosscheck_reports === 'string' ? JSON.parse(row.crosscheck_reports) : row.crosscheck_reports,
    createdAt: row.created_at, quorumCheck: quorumResult,
  };
}

async function advanceDecision(decisionId, newStatus, actor) {
  const res = await dbQuery(`SELECT * FROM decisions WHERE id = $1`, [decisionId]);
  if (res.rows.length === 0) return { error: "decision_not_found" };
  const row = res.rows[0];

  // WASM valid transitions check
  try {
    const transitions = wasm.wasm_valid_transitions(row.status);
    if (transitions.valid_transitions && !transitions.valid_transitions.includes(newStatus)) {
      return { error: "invalid_transition", currentStatus: row.status, validTransitions: transitions.valid_transitions, requestedStatus: newStatus };
    }
  } catch (e) {
    console.log(`[Syntaxis] WASM valid_transitions fallback: ${e.message}`);
  }

  const timeline = typeof row.timeline === 'string' ? JSON.parse(row.timeline) : (row.timeline || []);
  timeline.push({ event: "status_advanced", to: newStatus, actor, timestamp: new Date().toISOString() });

  await dbQuery(
    `UPDATE decisions SET status = $1, timeline = $2 WHERE id = $3`,
    [newStatus, JSON.stringify(timeline), decisionId]
  );

  return {
    id: decisionId, title: row.title, blockId: row.block_id, moduleId: row.module_id,
    decisionClass: row.decision_class, status: newStatus, author: row.author,
    quorumRequired: row.quorum_required, votesFor: row.votes_for, votesAgainst: row.votes_against,
    votes: typeof row.votes === 'string' ? JSON.parse(row.votes) : row.votes,
    timeline,
    combinatorChain: typeof row.combinator_chain === 'string' ? JSON.parse(row.combinator_chain) : row.combinator_chain,
    crosscheckReports: typeof row.crosscheck_reports === 'string' ? JSON.parse(row.crosscheck_reports) : row.crosscheck_reports,
    createdAt: row.created_at,
  };
}

// ── Full Orchestrated Workflow ────────────────────────────────────
async function executeWorkflow(data) {
  const wf = {
    id: `wf-${crypto.randomUUID().slice(0, 8)}`,
    type: data.type || "governance_decision",
    status: "running",
    steps: [],
    startedAt: new Date().toISOString(),
  };

  console.log(`\n${"=".repeat(70)}`);
  console.log(`[Syntaxis] ORCHESTRATED WORKFLOW: ${wf.id}`);
  console.log(`${"=".repeat(70)}`);

  // Step 1: PACE Identity Verification
  console.log(`\n[Step 1] PACE Identity Verification...`);
  let identity;
  try {
    identity = await post(`${IDENTITY}/resolve`, { walletAddress: data.walletAddress });
    wf.steps.push({ step: "pace_identity", service: "0dentity", status: "done", result: identity });
  } catch (e) {
    wf.steps.push({ step: "pace_identity", service: "0dentity", status: "failed", error: e.message });
  }

  // WASM: verify authority chain
  try {
    const chainResult = wasm.wasm_verify_chain(JSON.stringify({
      records: [{ content: data.walletAddress || "0x0", content_hash: "0000", record_hash: "0000" }],
    }));
    wf.steps.push({ step: "authority_chain_verify", service: "ExoChain WASM", status: "done", result: chainResult });
  } catch (e) {
    wf.steps.push({ step: "authority_chain_verify", service: "ExoChain WASM", status: "failed", error: e.message });
  }

  // Step 2: Compose Governance Block
  console.log(`[Step 2] Composing Syntaxis Thought Block...`);
  const block = await composeBlock({
    title: data.title || "Governance Proposal",
    type: data.blockType || "Proposal",
    author: identity?.odentityId || data.author || "unknown",
    moduleId: data.moduleId || "decision-forum",
    content: data.content || "Submitted via orchestrated workflow",
    combinators: data.combinators || [
      { type: "Threshold", args: { percentage: 66 } },
      { type: "TimeLock", args: { duration: "24h" } },
      { type: "Gate", args: { condition: "identityVerified" } },
    ],
  });
  wf.steps.push({ step: "compose_block", service: "Syntaxis", status: "done", result: block });

  // Step 3: Create Decision
  console.log(`[Step 3] Creating Decision Forum entry...`);
  const decision = await createDecision({
    blockId: block.id,
    decisionClass: data.decisionClass || "Standard",
    quorumRequired: data.quorumRequired || 3,
  });
  wf.steps.push({ step: "create_decision", service: "DecisionForum", status: "done", result: decision });

  // Step 4: CrossChecked Analysis
  console.log(`[Step 4] Running CrossChecked consensus...`);
  try {
    const xcheck = await post(`${CROSSCHECK}/check`, {
      proposal: { proposalId: block.id, walletAddress: data.walletAddress, target: data.target || "0x0", payload: data.content || "governance" },
      identity,
    });
    decision.crosscheckReports.push({
      id: `xr-${Date.now()}`,
      mode: "Crosscheck",
      verdict: xcheck.consensus ? "Pass" : "Fail",
      summary: `Consensus: ${xcheck.consensus}, Risk: ${xcheck.riskScore}, Signals: ${xcheck.signals?.length || 0}`,
      timestamp: new Date().toISOString(),
    });
    decision.timeline.push({ event: "crosscheck_complete", actor: "crosschecked.ai", result: xcheck.consensus ? "Pass" : "Fail", timestamp: new Date().toISOString() });
    wf.steps.push({ step: "crosscheck", service: "CrossChecked", status: "done", result: xcheck });
  } catch (e) {
    wf.steps.push({ step: "crosscheck", service: "CrossChecked", status: "failed", error: e.message });
  }

  // Step 5: Consent Verification (LiveSafe)
  console.log(`[Step 5] Verifying consent via LiveSafe...`);
  try {
    const consent = await post(`${CONSENT}/resolve`, { assetId: data.target || block.id });
    wf.steps.push({ step: "consent_verify", service: "LiveSafe", status: "done", result: consent });
  } catch (e) {
    wf.steps.push({ step: "consent_verify", service: "LiveSafe", status: "failed", error: e.message });
  }

  // Step 6: Advance to Deliberation
  console.log(`[Step 6] Advancing to Deliberation phase...`);
  decision.status = "Deliberation";
  decision.timeline.push({ event: "status_advanced", to: "Deliberation", actor: "syntaxis-orchestrator", timestamp: new Date().toISOString() });

  // Step 7: Simulate Votes
  console.log(`[Step 7] Simulating council votes...`);
  const voters = [
    { name: "Council Chair", role: "chair", vote: "approve", rationale: "Aligned with strategic goals" },
    { name: "Council Member A", role: "member", vote: "approve", rationale: "Evidence supports proposal" },
    { name: "Council Member B", role: "member", vote: "approve", rationale: "Risk assessment acceptable" },
  ];
  for (const v of voters) {
    decision.votes.push({ ...v, timestamp: new Date().toISOString() });
    if (v.vote === "approve") decision.votesFor++;
    else decision.votesAgainst++;
    decision.timeline.push({ event: "vote_cast", actor: v.name, vote: v.vote, timestamp: new Date().toISOString() });
  }
  decision.status = "Voting";

  // Step 8: Evaluate Combinators via WASM
  console.log(`[Step 8] Evaluating combinator chain...`);
  const combinatorResults = [];
  for (const c of block.combinators) {
    let passed = true;
    let wasmTrace = null;

    // Use WASM wasm_reduce_combinator for each combinator
    try {
      const termJson = JSON.stringify({ type: c.type, args: c.args });
      const contextJson = JSON.stringify({
        votes_for: decision.votesFor,
        votes_against: decision.votesAgainst,
        total_votes: decision.votesFor + decision.votesAgainst,
        identity_verified: !!identity?.odentityId,
        approve_pct: (decision.votesFor / (decision.votesFor + decision.votesAgainst)) * 100,
        elapsed_ms: 0,
        rollout_pct: 100,
        rollback: false,
        veto_exercised: false,
        trial_count: 1,
      });
      wasmTrace = wasm.wasm_reduce_combinator(termJson, contextJson, `combinator-${c.type}`, 100);
      passed = wasmTrace?.final_value !== false;
    } catch (e) {
      // Fallback to local evaluation
      if (c.type === "Threshold") passed = (decision.votesFor / (decision.votesFor + decision.votesAgainst)) * 100 >= (c.args.percentage || 66);
      if (c.type === "Gate") passed = !!identity?.odentityId;
    }

    combinatorResults.push({ combinator: c.type, exochainTerm: c.exochainTerm, passed, args: c.args, wasmTrace });
  }
  const allPassed = combinatorResults.every(r => r.passed);
  decision.status = allPassed ? "Approved" : "Rejected";
  decision.timeline.push({ event: "combinators_evaluated", results: combinatorResults, finalStatus: decision.status, timestamp: new Date().toISOString() });
  wf.steps.push({ step: "evaluate_combinators", service: "Syntaxis", status: "done", result: { combinatorResults, allPassed } });

  // WASM: hash the decision for integrity
  try {
    const hexData = Buffer.from(JSON.stringify(decision)).toString('hex');
    const hashResult = wasm.wasm_hash_bytes(hexData);
    decision.exochainHash = hashResult.hash;
  } catch (e) {
    console.log(`[Syntaxis] WASM hash fallback: ${e.message}`);
  }

  // Step 9: Execute via ExoEth Pipeline
  console.log(`[Step 9] Dispatching to ExoEth execution pipeline...`);
  if (allPassed) {
    try {
      const execution = await post(`${GATEWAY}/execute`, {
        proposalId: block.id,
        walletAddress: data.walletAddress,
        target: data.target || "0x0000000000000000000000000000000000000000",
        payload: data.content || "governance_execution",
        correlationId: wf.id,
      });
      decision.exochainHash = execution.steps?.find(s => s.step === "provenance_write")?.result?.payloadHash || decision.exochainHash;
      decision.timeline.push({ event: "exoeth_executed", decision: execution.governanceDecision, forged: execution.finalDecision, timestamp: new Date().toISOString() });
      wf.steps.push({ step: "exoeth_pipeline", service: "ExoEth Gateway", status: "done", result: { governanceDecision: execution.governanceDecision, finalDecision: execution.finalDecision, receiptId: execution.steps?.find(s => s.step === "provenance_write")?.result?.receiptId } });
    } catch (e) {
      wf.steps.push({ step: "exoeth_pipeline", service: "ExoEth Gateway", status: "failed", error: e.message });
    }
  } else {
    wf.steps.push({ step: "exoeth_pipeline", service: "ExoEth Gateway", status: "skipped", reason: "combinator_chain_failed" });
  }

  // Step 10: Audit Record
  console.log(`[Step 10] Recording audit trail...`);
  try {
    await post(`${AUDIT}/record`, {
      eventType: "syntaxis_workflow_complete",
      correlationId: wf.id,
      decisionId: decision.id,
      blockId: block.id,
      status: decision.status,
      actor: identity?.odentityId,
    });
    wf.steps.push({ step: "audit_record", service: "Audit API", status: "done" });
  } catch (e) {
    wf.steps.push({ step: "audit_record", service: "Audit API", status: "failed", error: e.message });
  }

  // Step 11: Notification
  try {
    await post(`${NOTIFY}/send`, {
      channel: "decision-forum",
      message: `Workflow ${wf.id}: Decision ${decision.id} -- ${decision.status} (${decision.decisionClass})`,
      correlationId: wf.id,
    });
  } catch {}

  wf.status = "complete";
  wf.completedAt = new Date().toISOString();
  wf.decision = decision;
  wf.block = block;

  // Persist decision updates back to DB
  await dbQuery(
    `UPDATE decisions SET status = $1, votes_for = $2, votes_against = $3, votes = $4, timeline = $5, crosscheck_reports = $6, wasm_decision = $7 WHERE id = $8`,
    [decision.status, decision.votesFor, decision.votesAgainst, JSON.stringify(decision.votes), JSON.stringify(decision.timeline), JSON.stringify(decision.crosscheckReports), decision.exochainHash ? JSON.stringify(decision.exochainHash) : null, decision.id]
  );

  // Persist workflow to DB
  await dbQuery(
    `INSERT INTO workflows (id, type, status, steps, decision_id, block_id, started_at, completed_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (id) DO NOTHING`,
    [wf.id, wf.type, wf.status, JSON.stringify(wf.steps), decision.id, block.id, wf.startedAt, wf.completedAt]
  );

  console.log(`\n[Syntaxis] WORKFLOW COMPLETE: ${decision.status}`);
  console.log(`${"=".repeat(70)}\n`);

  return wf;
}

// ── DB row to decision object ────────────────────────────────────
function rowToDecision(row) {
  return {
    id: row.id,
    title: row.title,
    blockId: row.block_id,
    moduleId: row.module_id,
    decisionClass: row.decision_class,
    status: row.status,
    author: row.author,
    quorumRequired: row.quorum_required,
    votesFor: row.votes_for,
    votesAgainst: row.votes_against,
    votes: typeof row.votes === 'string' ? JSON.parse(row.votes) : (row.votes || []),
    combinatorChain: typeof row.combinator_chain === 'string' ? JSON.parse(row.combinator_chain) : (row.combinator_chain || []),
    crosscheckReports: typeof row.crosscheck_reports === 'string' ? JSON.parse(row.crosscheck_reports) : (row.crosscheck_reports || []),
    timeline: typeof row.timeline === 'string' ? JSON.parse(row.timeline) : (row.timeline || []),
    createdAt: row.created_at,
  };
}

function rowToExecutive(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    walletAddress: row.wallet_address,
    odentityId: row.odentity_id,
    role: row.role,
    organization: row.organization,
    paceId: row.pace_id,
    status: row.status,
    onboardedAt: row.onboarded_at,
    attestations: typeof row.attestations === 'string' ? JSON.parse(row.attestations) : (row.attestations || []),
    councilRoles: typeof row.council_roles === 'string' ? JSON.parse(row.council_roles) : (row.council_roles || []),
  };
}

function rowToEnrollment(row) {
  return {
    paceId: row.pace_id,
    executiveId: row.executive_id,
    trustees: typeof row.trustees === 'string' ? JSON.parse(row.trustees) : (row.trustees || []),
    threshold: row.threshold,
    recoveryPolicy: row.recovery_policy,
    enrolledAt: row.enrolled_at,
  };
}

function rowToBlock(row) {
  return {
    id: row.id,
    title: row.title,
    type: row.type,
    author: row.author,
    moduleId: row.module_id,
    content: row.content,
    effects: typeof row.effects === 'string' ? JSON.parse(row.effects) : (row.effects || {}),
    combinators: typeof row.combinators === 'string' ? JSON.parse(row.combinators) : (row.combinators || []),
    links: typeof row.links === 'string' ? JSON.parse(row.links) : (row.links || []),
    created: row.created_at,
  };
}

function rowToWorkflow(row) {
  return {
    id: row.id,
    type: row.type,
    status: row.status,
    steps: typeof row.steps === 'string' ? JSON.parse(row.steps) : (row.steps || []),
    decisionId: row.decision_id,
    blockId: row.block_id,
    startedAt: row.started_at,
    completedAt: row.completed_at,
  };
}

// ── HTTP Server ──────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }

  try {
    if (req.method === "GET" && req.url === "/health") {
      const counts = await dbQuery(`SELECT
        (SELECT count(*) FROM executives) AS exec_count,
        (SELECT count(*) FROM thought_blocks) AS block_count,
        (SELECT count(*) FROM decisions) AS dec_count,
        (SELECT count(*) FROM workflows) AS wf_count`);
      const c = counts.rows[0];
      return res.end(JSON.stringify({ ok: true, service: "syntaxis-orchestrator", executives: parseInt(c.exec_count), blocks: parseInt(c.block_count), decisions: parseInt(c.dec_count), workflows: parseInt(c.wf_count) }));
    }

    // State queries — load from DB
    if (req.method === "GET" && req.url === "/modules") {
      return res.end(JSON.stringify({ modules: MODULES, combinators: COMBINATOR_BRIDGE }));
    }

    if (req.method === "GET" && req.url === "/executives") {
      const execRes = await dbQuery(`SELECT * FROM executives ORDER BY onboarded_at DESC`);
      const enrollRes = await dbQuery(`SELECT * FROM pace_enrollments ORDER BY enrolled_at DESC`);
      return res.end(JSON.stringify({
        executives: execRes.rows.map(rowToExecutive),
        paceEnrollments: enrollRes.rows.map(rowToEnrollment),
      }));
    }

    if (req.method === "GET" && req.url === "/blocks") {
      const blockRes = await dbQuery(`SELECT * FROM thought_blocks ORDER BY created_at DESC`);
      return res.end(JSON.stringify({ blocks: blockRes.rows.map(rowToBlock) }));
    }

    if (req.method === "GET" && req.url === "/decisions") {
      const decRes = await dbQuery(`SELECT * FROM decisions ORDER BY created_at DESC`);
      return res.end(JSON.stringify({ decisions: decRes.rows.map(rowToDecision) }));
    }

    if (req.method === "GET" && req.url === "/workflows") {
      const wfRes = await dbQuery(`SELECT * FROM workflows ORDER BY started_at DESC`);
      return res.end(JSON.stringify({ workflows: wfRes.rows.map(rowToWorkflow) }));
    }

    // Decision Forum situation room
    if (req.method === "GET" && req.url === "/situation-room") {
      const decRes = await dbQuery(`SELECT * FROM decisions ORDER BY created_at DESC`);
      const allDecisions = decRes.rows.map(rowToDecision);
      const execCount = (await dbQuery(`SELECT count(*) AS c FROM executives`)).rows[0].c;

      const pending = allDecisions.filter(d => ["Created","Deliberation","Voting"].includes(d.status));
      const contested = allDecisions.filter(d => d.status === "Contested");
      const resolved = allDecisions.filter(d => ["Approved","Rejected","Archived"].includes(d.status));
      return res.end(JSON.stringify({
        ambient: { pending: pending.length, contested: contested.length, resolved: resolved.length, chainIntegrity: true, totalExecutives: parseInt(execCount) },
        triage: pending.sort((a, b) => b.votesFor - a.votesFor),
        resolved,
        recentTimeline: allDecisions.flatMap(d => d.timeline).sort((a, b) => b.timestamp?.localeCompare(a.timestamp)).slice(0, 20),
      }));
    }

    // POST endpoints
    if (req.method === "POST") {
      let body = "";
      req.on("data", c => body += c);
      await new Promise(r => req.on("end", r));
      const data = JSON.parse(body);

      if (req.url === "/onboard") return res.end(JSON.stringify(await onboardExecutive(data)));
      if (req.url === "/compose") return res.end(JSON.stringify(await composeBlock(data)));
      if (req.url === "/decisions/create") return res.end(JSON.stringify(await createDecision(data)));
      if (req.url === "/decisions/vote") return res.end(JSON.stringify(await voteOnDecision(data.decisionId, data.vote, data.actor, data.rationale)));
      if (req.url === "/decisions/advance") return res.end(JSON.stringify(await advanceDecision(data.decisionId, data.status, data.actor)));
      if (req.url === "/workflow/execute") return res.end(JSON.stringify(await executeWorkflow(data)));
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error(`[Syntaxis] Error: ${err.message}`);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`  Syntaxis Governance Orchestrator`);
  console.log(`  Port: ${PORT} | WASM: ExoChain | DB: PostgreSQL`);
  console.log(`  Modules: ${MODULES.map(m => m.name).join(", ")}`);
  console.log(`${"=".repeat(70)}\n`);
});
