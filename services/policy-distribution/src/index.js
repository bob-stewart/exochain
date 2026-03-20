import http from "node:http";
import crypto from "node:crypto";
import * as wasm from '../../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const PORT = process.env.PORT || 3009;
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth',
});

pool.on('error', (err) => console.error('[PolicyDist] Pool error:', err.message));

// ---------------------------------------------------------------------------
// Hardcoded fallback (original behavior preserved)
// ---------------------------------------------------------------------------

const fallbackPolicy = {
  version: "v0",
  name: "ExoEth Foundation Policy Pack",
  rules: [
    "identity_required_before_execution",
    "consent_required_before_computation",
    "governance_required_before_deployment",
    "provenance_required_after_execution",
    "human_override_for_material_decisions",
  ],
  effectiveAt: "2026-01-01T00:00:00Z",
  distributedAt: new Date().toISOString(),
};

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS constitutions (
      id          TEXT PRIMARY KEY,
      tenant_id   TEXT NOT NULL DEFAULT 'default',
      version     TEXT NOT NULL,
      name        TEXT,
      rules       JSONB NOT NULL DEFAULT '[]',
      content     JSONB,
      policy_hash TEXT,
      effective_at TIMESTAMPTZ,
      published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      is_current  BOOLEAN NOT NULL DEFAULT false
    );
  `);
  // Create index for fast tenant+current lookup
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_constitutions_tenant_current
    ON constitutions (tenant_id, is_current) WHERE is_current = true;
  `).catch(() => {});
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
// URL helpers
// ---------------------------------------------------------------------------

function parseTenant(req) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  return url.searchParams.get("tenant") || "default";
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
    if (req.method === "GET" && req.url?.split("?")[0] === "/health") {
      return res.end(JSON.stringify({ ok: true, service: "legaldyne-policy-distribution", currentVersion: "v0" }));
    }

    // ---- GET /current ----
    if (req.method === "GET" && req.url?.split("?")[0] === "/current") {
      const tenantId = parseTenant(req);

      // Try DB first
      try {
        const { rows } = await pool.query(
          `SELECT id, tenant_id, version, name, rules, content, policy_hash, effective_at, published_at
           FROM constitutions
           WHERE tenant_id = $1 AND is_current = true
           LIMIT 1`,
          [tenantId],
        );

        if (rows.length > 0) {
          const row = rows[0];
          const policy = {
            version: row.version,
            name: row.name,
            rules: row.rules,
            content: row.content,
            policyHash: row.policy_hash,
            effectiveAt: row.effective_at,
            distributedAt: row.published_at,
          };

          // WASM: validate policy is well-formed
          try {
            const evalInput = {
              policies: (row.rules || []).map((rule, i) => ({
                id: `rule-${i}`,
                description: rule,
                subject_pattern: "*",
                resource_pattern: "*",
                decision: "Allow",
              })),
              subject: "system",
              resource: "policy-validation",
            };
            const evalResult = wasm.wasm_evaluate_policy(JSON.stringify(evalInput));
            policy.validation = evalResult;
          } catch (err) {
            console.warn("[PolicyDist] wasm_evaluate_policy skipped:", err.message);
            policy.validation = { skipped: true };
          }

          return res.end(JSON.stringify(policy));
        }
      } catch (dbErr) {
        console.warn("[PolicyDist] DB query failed, using fallback:", dbErr.message);
      }

      // Fallback to hardcoded
      return res.end(JSON.stringify(fallbackPolicy));
    }

    // ---- GET /version/:version ----
    if (req.method === "GET" && req.url?.split("?")[0]?.startsWith("/version/")) {
      const version = decodeURIComponent(req.url.split("/version/")[1]?.split("?")[0]);
      const tenantId = parseTenant(req);

      // Try DB
      try {
        const { rows } = await pool.query(
          `SELECT id, tenant_id, version, name, rules, content, policy_hash, effective_at, published_at
           FROM constitutions
           WHERE tenant_id = $1 AND version = $2
           LIMIT 1`,
          [tenantId, version],
        );

        if (rows.length > 0) {
          const row = rows[0];
          return res.end(JSON.stringify({
            version: row.version,
            name: row.name,
            rules: row.rules,
            content: row.content,
            policyHash: row.policy_hash,
            effectiveAt: row.effective_at,
            distributedAt: row.published_at,
          }));
        }
      } catch (dbErr) {
        console.warn("[PolicyDist] DB query failed, using fallback:", dbErr.message);
      }

      // Fallback to hardcoded map
      if (version === "v0") {
        return res.end(JSON.stringify(fallbackPolicy));
      }

      res.statusCode = 404;
      return res.end(JSON.stringify({ error: "policy_version_not_found" }));
    }

    // ---- POST /publish ----
    if (req.method === "POST" && req.url?.split("?")[0] === "/publish") {
      const body = await readBody(req);
      const {
        tenant_id = "default",
        version,
        name,
        rules = [],
        content,
        effective_at,
      } = body;

      if (!version) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "version_required" }));
      }

      // WASM: hash the policy content
      let policyHash = null;
      try {
        const contentHex = Buffer.from(JSON.stringify({ version, name, rules, content })).toString("hex");
        const hashResult = wasm.wasm_hash_bytes(contentHex);
        policyHash = hashResult?.hash || null;
      } catch (err) {
        console.warn("[PolicyDist] wasm_hash_bytes fallback:", err.message);
        // Use crypto fallback
        policyHash = crypto.createHash("sha256").update(JSON.stringify({ version, name, rules, content })).digest("hex");
      }

      const id = `const-${crypto.randomUUID().slice(0, 12)}`;

      try {
        // Unset previous current for this tenant
        await pool.query(
          `UPDATE constitutions SET is_current = false WHERE tenant_id = $1 AND is_current = true`,
          [tenant_id],
        );

        // Insert new version
        await pool.query(
          `INSERT INTO constitutions (id, tenant_id, version, name, rules, content, policy_hash, effective_at, is_current)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)`,
          [
            id,
            tenant_id,
            version,
            name || `Policy ${version}`,
            JSON.stringify(rules),
            content ? JSON.stringify(content) : null,
            policyHash,
            effective_at || new Date().toISOString(),
          ],
        );
      } catch (dbErr) {
        console.error("[PolicyDist] DB insert failed:", dbErr.message);
        res.statusCode = 500;
        return res.end(JSON.stringify({ error: "publish_failed", detail: dbErr.message }));
      }

      const result = {
        id,
        tenant_id,
        version,
        name: name || `Policy ${version}`,
        rules,
        policyHash,
        effectiveAt: effective_at || new Date().toISOString(),
        publishedAt: new Date().toISOString(),
        isCurrent: true,
      };

      console.log(`[PolicyDist] Published constitution ${version} for tenant ${tenant_id} (hash: ${policyHash?.slice(0, 16)})`);
      return res.end(JSON.stringify(result));
    }

    // 404
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error("[PolicyDist] Unhandled error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal_error", detail: err.message }));
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

ensureTable()
  .then(() => {
    server.listen(PORT, () => console.log(`[LegalDyne] Policy distribution listening on :${PORT}`));
  })
  .catch((err) => {
    console.warn("[PolicyDist] Table creation failed (starting anyway):", err.message);
    server.listen(PORT, () => console.log(`[LegalDyne] Policy distribution listening on :${PORT}`));
  });
