import http from "node:http";
import crypto from "node:crypto";
import * as wasm from '../../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth' });

// Ensure table exists
pool.query(`
  CREATE TABLE IF NOT EXISTS caip_assessments (
    id TEXT PRIMARY KEY,
    cto_name TEXT NOT NULL,
    company JSONB,
    cto_profile JSONB,
    engagement_purpose TEXT,
    maturity_state TEXT,
    dimensions JSONB,
    composite JSONB,
    governance_chain JSONB DEFAULT '[]',
    assessment_hash TEXT,
    authenticated_record JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`).catch(err => console.error('[CAIP] Table init error:', err.message));

const PORT = process.env.PORT || 3011;
const SYNTAXIS = process.env.SYNTAXIS_URL || "http://syntaxis-orchestrator:3010";
const PROVENANCE = process.env.PROVENANCE_URL || "http://provenance-writer:3006";
const AUDIT = process.env.AUDIT_URL || "http://audit-api:3007";

// ── Dimensions ───────────────────────────────────────────────────
const DIMENSIONS = {
  C1:  { name: "Technical Vision & Architecture", augmentable: "No", nonNegotiable: true },
  C2:  { name: "Engineering Execution & Reliability", augmentable: "Largely", nonNegotiable: false },
  C3:  { name: "Innovation & Technology Leadership", augmentable: "No", nonNegotiable: true },
  C4:  { name: "Security, Risk & Governance", augmentable: "Largely", nonNegotiable: false },
  C5:  { name: "Team Building & Talent Development", augmentable: "Partially", nonNegotiable: false },
  C6:  { name: "Organizational Design & Delegation", augmentable: "Partially", nonNegotiable: false },
  C7:  { name: "Engineering Culture & Psychological Safety", augmentable: "Partially", nonNegotiable: false },
  C8:  { name: "Strategic Business Alignment", augmentable: "No", nonNegotiable: true },
  C9:  { name: "Financial Acumen & Technology Economics", augmentable: "Largely", nonNegotiable: false },
  C10: { name: "Executive Presence & Stakeholder Comms", augmentable: "No (bridge only)", nonNegotiable: true },
  C11: { name: "External Presence & Thought Leadership", augmentable: "Partially", nonNegotiable: false },
};

const WEIGHT_TABLE = {
  Founding:  {C1:4,C2:4,C3:2,C4:1,C5:2,C6:1,C7:2,C8:2,C9:1,C10:1,C11:1},
  Validated: {C1:4,C2:4,C3:2,C4:2,C5:3,C6:1,C7:2,C8:3,C9:2,C10:3,C11:1},
  Complex:   {C1:4,C2:3,C3:3,C4:3,C5:4,C6:3,C7:3,C8:4,C9:3,C10:4,C11:2},
  Scaling:   {C1:4,C2:3,C3:4,C4:4,C5:4,C6:4,C7:3,C8:4,C9:4,C10:4,C11:3},
};

const LEVEL_MAP = { 5: "Distinctive", 4: "Proficient", 3: "Building", 2: "Emerging", 1: "Foundation" };
const RATER_WEIGHTS = { self: 0.25, reviewer: 0.45, ai: 0.30 };
const NON_NEGOTIABLE = ["C1","C3","C8","C10"];
const GAP_TYPES = ["Skill","Exposure","Wiring"];

// ── DB helpers ───────────────────────────────────────────────────
async function dbQuery(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// ── HTTP helpers ─────────────────────────────────────────────────
function postSvc(url, data) {
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

// ── Maturity Classification ──────────────────────────────────────
function classifyMaturity(company) {
  const { team_size, has_repeatable_sales, has_multiple_modules, has_formal_arch_function } = company;
  if (team_size >= 40 && has_formal_arch_function) return "Scaling";
  if (team_size >= 15 && has_multiple_modules) return "Complex";
  if (team_size >= 5 && has_repeatable_sales) return "Validated";
  return "Founding";
}

// ── Investor Overlay ─────────────────────────────────────────────
function applyInvestorOverlay(weights, maturity, investor_type, flags) {
  const w = { ...weights };
  if (investor_type === "PE" && ["Complex","Scaling"].includes(maturity)) { w.C2 = 4; w.C9 = 4; w.C4 = 4; }
  if (investor_type === "VC" && ["Complex","Scaling"].includes(maturity)) { w.C3 = 4; w.C11 = Math.max(w.C11, 3); }
  if (flags?.ai_native) w.C3 = 4;
  if (flags?.b2b_enterprise) w.C4 = Math.min(w.C4 + 1, 4);
  return w;
}

// ── Score Aggregation ────────────────────────────────────────────
function aggregateScore(self_score, reviewer_score, ai_score) {
  const scores = {};
  if (self_score != null) scores.self = self_score;
  if (reviewer_score != null) scores.reviewer = reviewer_score;
  scores.ai = ai_score;
  const totalWeight = Object.keys(scores).reduce((s, k) => s + RATER_WEIGHTS[k], 0);
  return +(Object.keys(scores).reduce((s, k) => s + scores[k] * RATER_WEIGHTS[k], 0) / totalWeight).toFixed(2);
}

// ── Deal Breaker Detection ───────────────────────────────────────
function detectDealBreakers(scores, maturity) {
  const flags = [];
  for (const [dim, score] of Object.entries(scores)) {
    if (NON_NEGOTIABLE.includes(dim) && score <= 2) {
      flags.push({ dimension: dim, score, reason: `${dim} is non-negotiable; score ${score} at ${maturity} requires explicit development plan` });
    }
    if (["Complex","Scaling"].includes(maturity) && dim === "C10" && score <= 2) {
      flags.push({ dimension: dim, score, reason: "C10 at Complex/Scaling is a board-level risk" });
    }
  }
  return flags;
}

// ── Cohort Fit Score ─────────────────────────────────────────────
function computeCohortFit(weightedAvg, dealBreakers, maturity) {
  const base = weightedAvg * 20;
  const deductions = dealBreakers.length * 8;
  const bonus = { Founding: 0, Validated: 5, Complex: 10, Scaling: 15 }[maturity] || 0;
  return Math.max(0, Math.min(100, Math.round(base - deductions + bonus)));
}

// ── Demo Score Generator ─────────────────────────────────────────
function generateDemoScores(profile, maturity) {
  const dims = {};
  for (const [id, meta] of Object.entries(DIMENSIONS)) {
    const base = profile.role_type === "founder_cto" ? 3 : profile.role_type === "hired_cto" ? 4 : 3.5;
    const variance = () => Math.round((Math.random() - 0.3) * 2);
    const selfScore = Math.max(1, Math.min(5, Math.round(base + variance() + (meta.nonNegotiable ? 0.5 : 0))));
    const aiScore = Math.max(1, Math.min(5, Math.round(selfScore + (Math.random() > 0.7 ? -1 : 0))));
    const reviewerScore = Math.max(1, Math.min(5, Math.round((selfScore + aiScore) / 2 + (Math.random() > 0.5 ? 0.5 : -0.5))));
    const composite = aggregateScore(selfScore, reviewerScore, aiScore);
    const divergence = Math.abs(selfScore - aiScore);
    const gapType = composite < 3 ? GAP_TYPES[Math.floor(Math.random() * 3)] : null;

    dims[id] = {
      name: meta.name,
      self_score: selfScore,
      reviewer_score: reviewerScore,
      ai_inferred_score: aiScore,
      ai_confidence: +(0.7 + Math.random() * 0.25).toFixed(2),
      composite_score: composite,
      level: LEVEL_MAP[Math.round(composite)] || "Building",
      gap_type: gapType,
      augmentable: meta.augmentable,
      divergence_flag: divergence >= 2,
      character_markers: divergence >= 2 ? ["self-awareness gap"] : composite >= 4 ? ["intellectual honesty","judgment under uncertainty"] : [],
    };
  }
  return dims;
}

// ── Run Assessment ───────────────────────────────────────────────
async function runAssessment(input) {
  const id = `caip-${crypto.randomUUID().slice(0, 8)}`;
  console.log(`\n${"=".repeat(70)}`);
  console.log(`[CAIP] Assessment ${id} -- ${input.cto_name}`);
  console.log(`${"=".repeat(70)}`);

  // Phase 1: Context
  const maturity = classifyMaturity(input.company);
  const baseWeights = WEIGHT_TABLE[maturity];
  const weights = applyInvestorOverlay(baseWeights, maturity, input.company.investor_type, { ai_native: input.company.ai_native, b2b_enterprise: input.company.b2b_enterprise });
  console.log(`[CAIP] Maturity: ${maturity} | Investor: ${input.company.investor_type}`);

  // Phase 2 & 3: Scoring
  const dimensions = generateDemoScores(input.cto_profile, maturity);

  // Apply weights
  let totalWeightedScore = 0, totalWeight = 0;
  for (const [dim, data] of Object.entries(dimensions)) {
    const w = weights[dim] || 2;
    data.weight = w;
    data.weight_label = w === 4 ? "Critical" : w === 3 ? "High" : w === 2 ? "Medium" : "Low";
    data.weighted_score = +(data.composite_score * w).toFixed(2);
    totalWeightedScore += data.weighted_score;
    totalWeight += w;
  }

  const compositeScores = Object.fromEntries(Object.entries(dimensions).map(([k, v]) => [k, v.composite_score]));
  const unweightedAvg = +(Object.values(compositeScores).reduce((s, v) => s + v, 0) / Object.keys(compositeScores).length).toFixed(2);
  const weightedAvg = +(totalWeightedScore / totalWeight).toFixed(2);
  const dealBreakers = detectDealBreakers(compositeScores, maturity);
  const cohortFit = computeCohortFit(weightedAvg, dealBreakers, maturity);

  // WASM: hash the assessment payload for integrity
  let assessmentHash = null;
  try {
    const hexData = Buffer.from(JSON.stringify({ id, cto_name: input.cto_name, dimensions, compositeScores, weightedAvg, cohortFit })).toString('hex');
    const hashResult = wasm.wasm_hash_bytes(hexData);
    assessmentHash = hashResult.hash;
  } catch (e) {
    console.log(`[CAIP] WASM hash fallback: ${e.message}`);
  }

  // WASM: create authenticated record for provenance
  let authenticatedRecord = null;
  try {
    authenticatedRecord = wasm.wasm_create_authenticated_record(JSON.stringify({
      record_type: "caip_assessment",
      tenant_id: "exoeth",
      content: JSON.stringify({ assessment_id: id, cto_name: input.cto_name, company: input.company.name, maturity, weightedAvg, cohortFit, dealBreakers: dealBreakers.length }),
      custodian: "caip-engine",
    }));
  } catch (e) {
    console.log(`[CAIP] WASM authenticated record fallback: ${e.message}`);
  }

  const assessment = {
    assessment_id: id,
    created_at: new Date().toISOString(),
    cto_name: input.cto_name,
    company: { ...input.company, maturity_state: maturity },
    cto_profile: input.cto_profile,
    engagement_purpose: input.engagement_purpose || "fractional_engagement",
    maturity_state: maturity,
    dimensions,
    composite: {
      unweighted_average: unweightedAvg,
      weighted_average: weightedAvg,
      deal_breakers: dealBreakers,
      cohort_fit_score: cohortFit,
      cohort_fit_band: cohortFit >= 80 ? "Ready" : cohortFit >= 60 ? "Conditional" : cohortFit >= 40 ? "Development Track" : "Not Yet",
    },
    governance_chain: [],
    assessment_hash: assessmentHash,
    authenticated_record: authenticatedRecord,
  };

  // Phase 4: ExoChain + Syntaxis integration
  console.log(`[CAIP] Composite: ${weightedAvg} | Cohort Fit: ${cohortFit} | Deal Breakers: ${dealBreakers.length}`);

  // Write to Syntaxis orchestrator
  try {
    const wf = await postSvc(`${SYNTAXIS}/workflow/execute`, {
      title: `CAIP Assessment: ${input.cto_name} (${input.company.name})`,
      walletAddress: input.walletAddress || "0xCAIP000000000000000000000000000000000000",
      decisionClass: dealBreakers.length > 0 ? "Strategic" : "Standard",
      moduleId: "decision-forum",
      content: `CTO Assessment -- ${input.cto_name} at ${input.company.name} (${maturity}). Weighted avg: ${weightedAvg}/5, Cohort fit: ${cohortFit}/100, Deal breakers: ${dealBreakers.length}`,
      blockType: "Proposal",
      target: "0xCAIP000000000000000000000000000000000001",
    });
    assessment.governance_chain.push({ step: "syntaxis_workflow", result: { workflowId: wf.id, decisionId: wf.decision?.id, decisionStatus: wf.decision?.status, exochainHash: wf.decision?.exochainHash } });
    console.log(`[CAIP] Governance workflow: ${wf.id} -> ${wf.decision?.status}`);
  } catch (e) {
    console.log(`[CAIP] Governance workflow failed: ${e.message}`);
  }

  // Direct provenance receipt
  try {
    const receipt = await postSvc(`${PROVENANCE}/write`, {
      eventType: "caip_assessment_complete",
      correlationId: id,
      payload: { assessment_id: id, cto_name: input.cto_name, company: input.company.name, maturity, weightedAvg, cohortFit, dealBreakers: dealBreakers.length },
    });
    assessment.governance_chain.push({ step: "exochain_provenance", result: receipt });
  } catch {}

  // Audit
  try {
    await postSvc(`${AUDIT}/record`, {
      eventType: "caip_assessment_complete",
      correlationId: id,
      assessmentId: id,
      cto: input.cto_name,
      company: input.company.name,
      maturity,
      weightedAvg,
      cohortFit,
      dealBreakers: dealBreakers.length,
      actor: "caip-engine",
    });
  } catch {}

  // Persist to DB
  await dbQuery(
    `INSERT INTO caip_assessments (id, cto_name, company, cto_profile, engagement_purpose, maturity_state, dimensions, composite, governance_chain, assessment_hash, authenticated_record, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     ON CONFLICT (id) DO NOTHING`,
    [id, input.cto_name, JSON.stringify(assessment.company), JSON.stringify(input.cto_profile), assessment.engagement_purpose, maturity, JSON.stringify(dimensions), JSON.stringify(assessment.composite), JSON.stringify(assessment.governance_chain), assessmentHash, authenticatedRecord ? JSON.stringify(authenticatedRecord) : null, assessment.created_at]
  );

  console.log(`[CAIP] Assessment complete: ${id}\n`);
  return assessment;
}

// ── DB row to assessment object ──────────────────────────────────
function rowToAssessment(row) {
  const company = typeof row.company === 'string' ? JSON.parse(row.company) : (row.company || {});
  const ctoProfile = typeof row.cto_profile === 'string' ? JSON.parse(row.cto_profile) : (row.cto_profile || {});
  const dimensions = typeof row.dimensions === 'string' ? JSON.parse(row.dimensions) : (row.dimensions || {});
  const composite = typeof row.composite === 'string' ? JSON.parse(row.composite) : (row.composite || {});
  const governanceChain = typeof row.governance_chain === 'string' ? JSON.parse(row.governance_chain) : (row.governance_chain || []);
  const authenticatedRecord = row.authenticated_record ? (typeof row.authenticated_record === 'string' ? JSON.parse(row.authenticated_record) : row.authenticated_record) : null;

  return {
    assessment_id: row.id,
    created_at: row.created_at,
    cto_name: row.cto_name,
    company,
    cto_profile: ctoProfile,
    engagement_purpose: row.engagement_purpose,
    maturity_state: row.maturity_state,
    dimensions,
    composite,
    governance_chain: governanceChain,
    assessment_hash: row.assessment_hash,
    authenticated_record: authenticatedRecord,
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
      const countRes = await dbQuery(`SELECT count(*) AS c FROM caip_assessments`);
      return res.end(JSON.stringify({ ok: true, service: "caip-engine", assessments: parseInt(countRes.rows[0].c) }));
    }

    if (req.method === "GET" && req.url === "/assessments") {
      const result = await dbQuery(`SELECT * FROM caip_assessments ORDER BY created_at DESC`);
      return res.end(JSON.stringify({ assessments: result.rows.map(rowToAssessment) }));
    }

    if (req.method === "GET" && req.url === "/dimensions") {
      return res.end(JSON.stringify({ dimensions: DIMENSIONS, weights: WEIGHT_TABLE, levels: LEVEL_MAP }));
    }

    if (req.method === "GET" && req.url?.startsWith("/assessment/")) {
      const id = req.url.split("/assessment/")[1];
      const result = await dbQuery(`SELECT * FROM caip_assessments WHERE id = $1`, [id]);
      if (result.rows.length === 0) return res.end(JSON.stringify({ error: "not_found" }));
      return res.end(JSON.stringify(rowToAssessment(result.rows[0])));
    }

    if (req.method === "POST" && req.url === "/assess") {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", async () => {
        try {
          const result = await runAssessment(JSON.parse(body));
          res.end(JSON.stringify(result, null, 2));
        } catch (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error(`[CAIP] Error: ${err.message}`);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`  CAIP -- CTO Assessment Intelligence Platform`);
  console.log(`  Wintonium Framework v3.8 + ExoChain WASM + PostgreSQL`);
  console.log(`  Port: ${PORT}`);
  console.log(`${"=".repeat(70)}\n`);
});
