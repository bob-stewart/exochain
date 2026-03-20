import http from "node:http";
import { createRequire } from "node:module";
import pg from "pg";

const require = createRequire(import.meta.url);
const wasm = require("../../../packages/exochain-wasm/wasm/exochain_wasm.js");

const PORT = process.env.PORT || 3002;
const pool = new pg.Pool({
  connectionString:
    process.env.DATABASE_URL ||
    "postgresql://exoeth:exoeth_dev@localhost:5432/exoeth",
});

// ---------------------------------------------------------------------------
// CORS helper
// ---------------------------------------------------------------------------
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function toHex(str) {
  return Buffer.from(str, "utf-8").toString("hex");
}

function fallbackConsent(assetId) {
  return {
    consentId: `consent-${assetId}`,
    assetId,
    owner: "CyberMedica",
    allowedUses: [
      "governance_evaluation",
      "regulated_ai_sdlc",
      "clinical_decision_support",
    ],
    restrictions: ["no_reidentification", "audit_required"],
    effectiveAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
    resolvedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Body parser
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Route: POST /resolve
// ---------------------------------------------------------------------------
async function handleResolve(req, res) {
  const { assetId, subject, requestedUse } = await readBody(req);

  try {
    // Look up consent_anchors by asset
    const anchorRes = await pool.query(
      "SELECT * FROM consent_anchors WHERE asset_id = $1 ORDER BY created_at DESC LIMIT 1",
      [assetId]
    );

    if (anchorRes.rows.length > 0) {
      const anchor = anchorRes.rows[0];

      // Use WASM policy evaluation to check consent validity
      let policyResult = null;
      try {
        const policyInput = JSON.stringify({
          policies: [
            {
              id: anchor.consent_id || `consent-${assetId}`,
              description: anchor.description || "consent anchor policy",
              subject_pattern: anchor.subject_pattern || "*",
              resource_pattern: anchor.resource_pattern || assetId,
              decision: "Allow",
              accessor_set: anchor.accessor_set || [],
            },
          ],
          subject: subject || "anonymous",
          resource: assetId,
          groups: {},
        });
        policyResult = wasm.wasm_evaluate_policy(policyInput);
        if (typeof policyResult === "string")
          policyResult = JSON.parse(policyResult);
      } catch (err) {
        console.warn("[LiveSafe] WASM policy eval failed:", err.message);
      }

      const consent = {
        consentId: anchor.consent_id || `consent-${assetId}`,
        assetId: anchor.asset_id,
        owner: anchor.owner || "CyberMedica",
        allowedUses: anchor.allowed_uses || [
          "governance_evaluation",
          "regulated_ai_sdlc",
          "clinical_decision_support",
        ],
        restrictions: anchor.restrictions || [
          "no_reidentification",
          "audit_required",
        ],
        effectiveAt: anchor.effective_at || "2026-01-01T00:00:00Z",
        expiresAt: anchor.expires_at || "2027-01-01T00:00:00Z",
        resolvedAt: new Date().toISOString(),
        ...(policyResult && { policyEvaluation: policyResult }),
      };

      console.log(
        `[LiveSafe] Consent resolved (DB) for asset ${assetId} → ${consent.consentId}`
      );
      return res.end(JSON.stringify(consent));
    }
  } catch (err) {
    console.warn("[LiveSafe] DB lookup failed, falling back:", err.message);
  }

  // Fallback: compute consent without DB
  const consent = fallbackConsent(assetId);
  console.log(
    `[LiveSafe] Consent resolved (computed) for asset ${assetId} → ${consent.consentId}`
  );
  res.end(JSON.stringify(consent));
}

// ---------------------------------------------------------------------------
// Route: GET /anchors
// ---------------------------------------------------------------------------
async function handleListAnchors(res) {
  try {
    const result = await pool.query(
      "SELECT * FROM consent_anchors ORDER BY created_at DESC LIMIT 100"
    );
    res.end(JSON.stringify({ anchors: result.rows, total: result.rows.length }));
  } catch (err) {
    console.error("[LiveSafe] List anchors error:", err.message);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "db_error", detail: err.message }));
  }
}

// ---------------------------------------------------------------------------
// Route: POST /grant
// ---------------------------------------------------------------------------
async function handleGrant(req, res) {
  const {
    assetId,
    owner,
    allowedUses,
    restrictions,
    effectiveAt,
    expiresAt,
    subject,
  } = await readBody(req);

  // Generate audit receipt hash via WASM
  let auditReceiptHash = null;
  try {
    const receiptPayload = JSON.stringify({
      assetId,
      owner,
      allowedUses,
      grantedAt: new Date().toISOString(),
    });
    const hashResult = wasm.wasm_hash_bytes(toHex(receiptPayload));
    const parsed =
      typeof hashResult === "string" ? JSON.parse(hashResult) : hashResult;
    auditReceiptHash = parsed.hash;
  } catch (err) {
    console.warn("[LiveSafe] WASM hash failed for audit receipt:", err.message);
  }

  const consentId = `consent-${assetId}-${Date.now()}`;

  try {
    await pool.query(
      `INSERT INTO consent_anchors
        (consent_id, asset_id, owner, allowed_uses, restrictions,
         effective_at, expires_at, audit_receipt_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [
        consentId,
        assetId,
        owner || "CyberMedica",
        JSON.stringify(
          allowedUses || [
            "governance_evaluation",
            "regulated_ai_sdlc",
            "clinical_decision_support",
          ]
        ),
        JSON.stringify(
          restrictions || ["no_reidentification", "audit_required"]
        ),
        effectiveAt || "2026-01-01T00:00:00Z",
        expiresAt || "2027-01-01T00:00:00Z",
        auditReceiptHash,
      ]
    );

    const result = {
      consentId,
      assetId,
      owner: owner || "CyberMedica",
      allowedUses: allowedUses || [
        "governance_evaluation",
        "regulated_ai_sdlc",
        "clinical_decision_support",
      ],
      restrictions: restrictions || [
        "no_reidentification",
        "audit_required",
      ],
      effectiveAt: effectiveAt || "2026-01-01T00:00:00Z",
      expiresAt: expiresAt || "2027-01-01T00:00:00Z",
      auditReceiptHash,
      grantedAt: new Date().toISOString(),
    };

    console.log(`[LiveSafe] Consent granted for asset ${assetId} → ${consentId}`);
    res.end(JSON.stringify(result));
  } catch (err) {
    console.error("[LiveSafe] Grant error:", err.message);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "grant_failed", detail: err.message }));
  }
}

// ---------------------------------------------------------------------------
// Route: GET /health
// ---------------------------------------------------------------------------
async function handleHealth(res) {
  let anchorCount = null;
  try {
    const r = await pool.query(
      "SELECT COUNT(*)::int AS count FROM consent_anchors"
    );
    anchorCount = r.rows[0].count;
  } catch (_) {
    /* DB may be unreachable */
  }

  res.end(
    JSON.stringify({
      ok: true,
      service: "livesafe-consent-service",
      ...(anchorCount !== null && { anchorCount }),
    })
  );
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  setCors(res);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  try {
    if (req.method === "GET" && req.url === "/health") {
      return await handleHealth(res);
    }

    if (req.method === "POST" && req.url === "/resolve") {
      return await handleResolve(req, res);
    }

    if (req.method === "GET" && req.url === "/anchors") {
      return await handleListAnchors(res);
    }

    if (req.method === "POST" && req.url === "/grant") {
      return await handleGrant(req, res);
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error("[LiveSafe] Unhandled error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal_error", detail: err.message }));
  }
});

server.listen(PORT, () =>
  console.log(`[LiveSafe] Consent service listening on :${PORT}`)
);
