import http from "node:http";
import crypto from "node:crypto";
import * as wasm from '../../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const PORT = process.env.PORT || 3004;
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth',
});

pool.on('error', (err) => console.error('[DecisionForge] Pool error:', err.message));

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS forge_results (
      id             TEXT PRIMARY KEY,
      proposal_id    TEXT NOT NULL,
      governance_case_id TEXT,
      input_decision TEXT,
      forged_decision TEXT NOT NULL,
      confidence     DOUBLE PRECISION,
      rationale      TEXT,
      policy_version TEXT,
      tnc_result     JSONB,
      combinator_trace JSONB,
      provenance_hash TEXT,
      payload        JSONB,
      forged_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

async function persistForgeResult(row) {
  await pool.query(
    `INSERT INTO forge_results (id, proposal_id, governance_case_id, input_decision, forged_decision, confidence, rationale, policy_version, tnc_result, combinator_trace, provenance_hash, payload, forged_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT (id) DO UPDATE SET forged_decision=$5, confidence=$6, provenance_hash=$11`,
    [
      row.forgeId,
      row.proposalId,
      row.governanceCaseId,
      row.inputDecision,
      row.forgedDecision,
      row.confidence,
      row.rationale,
      row.policyVersion,
      row.tncResult ? JSON.stringify(row.tncResult) : null,
      row.combinatorTrace ? JSON.stringify(row.combinatorTrace) : null,
      row.provenanceHash,
      row.payload ? JSON.stringify(row.payload) : null,
      row.forgedAt,
    ],
  );
}

// ---------------------------------------------------------------------------
// Original deliberation logic (preserved as fallback)
// ---------------------------------------------------------------------------

function deliberateFallback(proposalId, governanceDecision) {
  const confidence = governanceDecision.decision === "approved" ? 0.94 : 0.87;
  return {
    forgeId: `forge-${crypto.randomUUID().slice(0, 8)}`,
    proposalId,
    governanceCaseId: governanceDecision.governanceCaseId,
    inputDecision: governanceDecision.decision,
    forgedDecision: governanceDecision.decision === "approved" ? "execute" : "hold_for_review",
    confidence,
    rationale: governanceDecision.decision === "approved"
      ? "All governance gates passed. Identity verified, consent valid, crosscheck consensus reached. Recommended for execution."
      : `Governance returned ${governanceDecision.decision}. Reasons: ${governanceDecision.reasons.join(", ")}. Holding for human review.`,
    policyVersion: governanceDecision.policyVersion,
    forgedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// CORS helper
// ---------------------------------------------------------------------------

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// ---------------------------------------------------------------------------
// JSON body parser
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  setCors(res);

  // Preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  try {
    // ---- GET /health ----
    if (req.method === "GET" && req.url === "/health") {
      return res.end(JSON.stringify({ ok: true, service: "decision-forge" }));
    }

    // ---- POST /deliberate ----
    if (req.method === "POST" && req.url === "/deliberate") {
      const { proposalId, governanceDecision } = await readBody(req);

      // Start with backward-compatible fallback result
      const result = deliberateFallback(proposalId, governanceDecision);

      // --- WASM: enforce TNCs on the governance decision ---
      let tncResult = null;
      try {
        const tncInput = { decision: governanceDecision };
        tncResult = wasm.wasm_enforce_tncs(JSON.stringify(tncInput));
        result.tncResult = tncResult;
        if (tncResult?.valid === true) {
          result.rationale += " TNC enforcement: all controls passed.";
        } else {
          result.rationale += ` TNC enforcement: failed — ${tncResult?.error || "unknown violation"}.`;
          // If TNCs fail, downgrade to hold_for_review
          if (result.forgedDecision === "execute") {
            result.forgedDecision = "hold_for_review";
            result.confidence = Math.min(result.confidence, 0.6);
          }
        }
      } catch (err) {
        console.warn("[DecisionForge] wasm_enforce_tncs fallback:", err.message);
        result.tncResult = { skipped: true, error: err.message };
      }

      // --- WASM: reduce combinator for proposal logic ---
      let combinatorTrace = null;
      try {
        const termJson = JSON.stringify({
          tag: "App",
          func: { tag: "Var", name: "governance_gate" },
          arg: { tag: "Lit", value: governanceDecision.decision === "approved" },
        });
        const contextJson = JSON.stringify({
          bindings: {
            governance_gate: { tag: "Lam", param: "x", body: { tag: "Var", name: "x" } },
          },
        });
        combinatorTrace = wasm.wasm_reduce_combinator(termJson, contextJson, `proposal-${proposalId}`, 100);
        result.combinatorTrace = combinatorTrace;
      } catch (err) {
        console.warn("[DecisionForge] wasm_reduce_combinator fallback:", err.message);
        result.combinatorTrace = { skipped: true, error: err.message };
      }

      // --- WASM: provenance hash ---
      let provenanceHash = null;
      try {
        const payloadHex = Buffer.from(JSON.stringify({ proposalId, governanceDecision, forgeId: result.forgeId })).toString("hex");
        const hashResult = wasm.wasm_hash_bytes(payloadHex);
        provenanceHash = hashResult?.hash || null;
        result.provenanceHash = provenanceHash;
      } catch (err) {
        console.warn("[DecisionForge] wasm_hash_bytes fallback:", err.message);
      }

      // Persist
      try {
        await persistForgeResult({
          forgeId: result.forgeId,
          proposalId,
          governanceCaseId: result.governanceCaseId,
          inputDecision: result.inputDecision,
          forgedDecision: result.forgedDecision,
          confidence: result.confidence,
          rationale: result.rationale,
          policyVersion: result.policyVersion,
          tncResult,
          combinatorTrace,
          provenanceHash,
          payload: governanceDecision,
          forgedAt: result.forgedAt,
        });
      } catch (dbErr) {
        console.warn("[DecisionForge] DB persist failed (continuing):", dbErr.message);
      }

      console.log(`[DecisionForge] Forged decision for ${proposalId} → ${result.forgedDecision} (confidence: ${result.confidence})`);
      return res.end(JSON.stringify(result));
    }

    // ---- POST /enforce-tncs ----
    if (req.method === "POST" && req.url === "/enforce-tncs") {
      const body = await readBody(req);

      try {
        const tncResult = wasm.wasm_enforce_tncs(JSON.stringify(body));
        return res.end(JSON.stringify(tncResult));
      } catch (err) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "tnc_enforcement_failed", detail: err.message }));
      }
    }

    // 404
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error("[DecisionForge] Unhandled error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal_error", detail: err.message }));
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

ensureTable()
  .then(() => {
    server.listen(PORT, () => console.log(`[DecisionForge] Listening on :${PORT}`));
  })
  .catch((err) => {
    console.warn("[DecisionForge] Table creation failed (starting anyway):", err.message);
    server.listen(PORT, () => console.log(`[DecisionForge] Listening on :${PORT}`));
  });
