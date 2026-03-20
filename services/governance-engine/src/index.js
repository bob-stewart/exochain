import http from "node:http";
import crypto from "node:crypto";
import * as wasm from '../../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const PORT = process.env.PORT || 3003;
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth',
});

pool.on('error', (err) => console.error('[Governance] Pool error:', err.message));

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS decisions (
      id            TEXT PRIMARY KEY,
      governance_case_id TEXT NOT NULL,
      decision      TEXT NOT NULL,
      reasons       JSONB NOT NULL DEFAULT '[]',
      checks        JSONB NOT NULL DEFAULT '[]',
      policy_version TEXT,
      correlation_id TEXT,
      chain_verified BOOLEAN DEFAULT false,
      quorum_result  JSONB,
      governance_hash TEXT,
      payload       JSONB,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

async function persistDecision(row) {
  await pool.query(
    `INSERT INTO decisions (id, governance_case_id, decision, reasons, checks, policy_version, correlation_id, chain_verified, quorum_result, governance_hash, payload, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     ON CONFLICT (id) DO UPDATE SET decision=$3, reasons=$4, checks=$5, governance_hash=$10`,
    [
      row.id,
      row.governanceCaseId,
      row.decision,
      JSON.stringify(row.reasons),
      JSON.stringify(row.checks),
      row.policyVersion,
      row.correlationId,
      row.chainVerified ?? false,
      row.quorumResult ? JSON.stringify(row.quorumResult) : null,
      row.governanceHash ?? null,
      row.payload ? JSON.stringify(row.payload) : null,
      row.createdAt,
    ],
  );
}

// ---------------------------------------------------------------------------
// Core evaluation (original logic preserved as fallback)
// ---------------------------------------------------------------------------

function evaluateExecution(req, identity, consent, crosscheck) {
  const reasons = [];
  const checks = [];

  // Identity gate
  if (!identity?.odentityId) {
    reasons.push("identity_unresolved");
  } else {
    checks.push(`identity_verified:${identity.odentityId}`);
  }

  // Consent gate
  if (!consent?.allowedUses?.length) {
    reasons.push("consent_not_granted");
  } else {
    checks.push(`consent_valid:${consent.consentId}`);
  }

  // Crosscheck gate
  if (crosscheck?.conflictsDetected) {
    reasons.push("crosscheck_conflict_detected");
  } else if (crosscheck?.consensus) {
    checks.push(`crosscheck_consensus:risk_${crosscheck.riskScore}`);
  }

  // Payload validation
  if (!req.walletAddress) reasons.push("missing_wallet_address");
  if (!req.target) reasons.push("missing_target");
  if (!req.payload) reasons.push("missing_payload");

  const decision = reasons.length > 0 ? "denied" : "approved";

  return {
    governanceCaseId: `case-${req.proposalId}`,
    decision,
    reasons: decision === "denied" ? reasons : ["all_gates_passed"],
    checks,
    policyVersion: "v0",
    correlationId: req.correlationId,
    createdAt: new Date().toISOString(),
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
      return res.end(JSON.stringify({ ok: true, service: "governance-engine" }));
    }

    // ---- POST /evaluate ----
    if (req.method === "POST" && req.url === "/evaluate") {
      const { proposal, identity, consent, crosscheck } = await readBody(req);

      // Start with the original computed result
      const result = evaluateExecution(proposal, identity, consent, crosscheck);

      // --- WASM: verify authority chain ---
      let chainVerified = false;
      try {
        const chainInput = {
          chain: identity?.authorityChain || [],
          actor: identity?.odentityId || "unknown",
          actor_is_ai: identity?.isAi ?? false,
          action: proposal?.action || "Execute",
          decision_class: proposal?.decisionClass || "Operational",
          max_depth: 10,
          requires_human_gate: proposal?.requiresHumanGate ?? false,
        };
        const chainResult = wasm.wasm_verify_chain(JSON.stringify(chainInput));
        chainVerified = chainResult?.valid === true;
        if (chainVerified) {
          result.checks.push("wasm_chain_verified");
        } else {
          result.checks.push(`wasm_chain_failed:${chainResult?.error || "unknown"}`);
        }
      } catch (err) {
        console.warn("[Governance] wasm_verify_chain fallback:", err.message);
        result.checks.push("wasm_chain_skipped");
      }

      // --- WASM: quorum check ---
      let quorumResult = null;
      try {
        const quorumInput = {
          eligible_voters: crosscheck?.eligibleVoters || [],
          present_voters: crosscheck?.presentVoters || [],
          minimum_participants: crosscheck?.minimumParticipants ?? 1,
        };
        quorumResult = wasm.wasm_check_quorum(JSON.stringify(quorumInput));
        if (quorumResult?.is_met) {
          result.checks.push("wasm_quorum_met");
        } else {
          result.checks.push("wasm_quorum_not_met");
        }
      } catch (err) {
        console.warn("[Governance] wasm_check_quorum fallback:", err.message);
        result.checks.push("wasm_quorum_skipped");
      }

      // --- WASM: hash the governance case ---
      let governanceHash = null;
      try {
        const caseHex = Buffer.from(JSON.stringify({ proposal, identity, consent, crosscheck })).toString("hex");
        const hashResult = wasm.wasm_hash_bytes(caseHex);
        governanceHash = hashResult?.hash || null;
        if (governanceHash) {
          result.checks.push(`governance_hash:${governanceHash.slice(0, 16)}`);
        }
      } catch (err) {
        console.warn("[Governance] wasm_hash_bytes fallback:", err.message);
      }

      // Enrich result
      result.chainVerified = chainVerified;
      result.quorumResult = quorumResult;
      result.governanceHash = governanceHash;

      // Persist
      const decisionId = `dec-${crypto.randomUUID().slice(0, 12)}`;
      try {
        await persistDecision({
          id: decisionId,
          governanceCaseId: result.governanceCaseId,
          decision: result.decision,
          reasons: result.reasons,
          checks: result.checks,
          policyVersion: result.policyVersion,
          correlationId: result.correlationId,
          chainVerified,
          quorumResult,
          governanceHash,
          payload: proposal,
          createdAt: result.createdAt,
        });
      } catch (dbErr) {
        console.warn("[Governance] DB persist failed (continuing):", dbErr.message);
      }

      result.decisionId = decisionId;
      console.log(`[Governance] Evaluated proposal ${proposal.proposalId} → ${result.decision}`);
      return res.end(JSON.stringify(result));
    }

    // ---- POST /create-decision ----
    if (req.method === "POST" && req.url === "/create-decision") {
      const body = await readBody(req);
      const {
        tenant_id, title, body: decisionBody, decision_class,
        constitution_hash, constitution_version, author,
        eligible_voters, minimum_participants, approval_threshold_pct,
      } = body;

      const input = {
        tenant_id: tenant_id || "default",
        title: title || "Untitled Decision",
        body: decisionBody || "",
        decision_class: decision_class || "Operational",
        constitution_hash: constitution_hash || "0000000000000000000000000000000000000000000000000000000000000000",
        constitution_version: constitution_version || [0, 1, 0],
        author: author || "system",
        eligible_voters: eligible_voters || [],
        minimum_participants: minimum_participants ?? 1,
        approval_threshold_pct: approval_threshold_pct ?? 51,
      };

      let decisionObj;
      try {
        decisionObj = wasm.wasm_create_decision(JSON.stringify(input));
      } catch (err) {
        console.error("[Governance] wasm_create_decision error:", err.message);
        res.statusCode = 500;
        return res.end(JSON.stringify({ error: "wasm_create_decision_failed", detail: err.message }));
      }

      // Persist the decision object
      const decisionId = decisionObj?.id || `dec-${crypto.randomUUID().slice(0, 12)}`;
      try {
        await persistDecision({
          id: decisionId,
          governanceCaseId: decisionObj?.governance_case_id || `case-${decisionId}`,
          decision: decisionObj?.status || "Created",
          reasons: ["wasm_created"],
          checks: ["wasm_create_decision"],
          policyVersion: "v0",
          correlationId: body.correlation_id || null,
          chainVerified: false,
          quorumResult: null,
          governanceHash: null,
          payload: decisionObj,
          createdAt: decisionObj?.created_at || new Date().toISOString(),
        });
      } catch (dbErr) {
        console.warn("[Governance] DB persist failed (continuing):", dbErr.message);
      }

      console.log(`[Governance] Created decision ${decisionId}`);
      return res.end(JSON.stringify(decisionObj));
    }

    // ---- GET /decisions ----
    if (req.method === "GET" && req.url === "/decisions") {
      try {
        const { rows } = await pool.query(
          `SELECT id, governance_case_id, decision, reasons, checks, policy_version, correlation_id, chain_verified, quorum_result, governance_hash, payload, created_at
           FROM decisions ORDER BY created_at DESC LIMIT 100`,
        );
        return res.end(JSON.stringify({ decisions: rows }));
      } catch (dbErr) {
        console.warn("[Governance] DB query failed:", dbErr.message);
        return res.end(JSON.stringify({ decisions: [], error: dbErr.message }));
      }
    }

    // ---- GET /transitions/:status ----
    if (req.method === "GET" && req.url?.startsWith("/transitions/")) {
      const status = decodeURIComponent(req.url.split("/transitions/")[1]);
      try {
        const result = wasm.wasm_valid_transitions(status);
        return res.end(JSON.stringify(result));
      } catch (err) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "invalid_status", detail: err.message }));
      }
    }

    // 404
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error("[Governance] Unhandled error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal_error", detail: err.message }));
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

ensureTable()
  .then(() => {
    server.listen(PORT, () => console.log(`[Governance] Engine listening on :${PORT}`));
  })
  .catch((err) => {
    console.warn("[Governance] Table creation failed (starting anyway):", err.message);
    server.listen(PORT, () => console.log(`[Governance] Engine listening on :${PORT}`));
  });
