import http from "node:http";
import { createRequire } from "node:module";
import pg from "pg";

const require = createRequire(import.meta.url);
const wasm = require("../../../packages/exochain-wasm/wasm/exochain_wasm.js");

const PORT = process.env.PORT || 3001;
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

function computeOdentityId(walletAddress) {
  try {
    const result = wasm.wasm_hash_bytes(toHex(walletAddress));
    const hash = typeof result === "string" ? JSON.parse(result) : result;
    return `od-${hash.hash.slice(0, 12)}`;
  } catch (err) {
    console.error("[0dentity] WASM hash failed, falling back:", err.message);
    return `od-${walletAddress.slice(2, 8)}`;
  }
}

function fallbackIdentity(walletAddress) {
  return {
    odentityId: computeOdentityId(walletAddress),
    walletAddress,
    roles: ["operator"],
    organization: "CyberMedica",
    attestationRefs: ["att-kyc-2026-01", "att-org-binding-cm"],
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
  const { walletAddress } = await readBody(req);

  try {
    // Try DB lookup: users + identity_scores + livesafe_identities
    const userRes = await pool.query(
      "SELECT * FROM users WHERE wallet_address = $1 LIMIT 1",
      [walletAddress]
    );

    if (userRes.rows.length > 0) {
      const user = userRes.rows[0];

      // identity_scores
      let score = null;
      try {
        const scoreRes = await pool.query(
          "SELECT * FROM identity_scores WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
          [user.id]
        );
        if (scoreRes.rows.length > 0) score = scoreRes.rows[0];
      } catch (_) {
        /* table may not exist */
      }

      // livesafe_identities
      let livesafe = null;
      try {
        const lsRes = await pool.query(
          "SELECT * FROM livesafe_identities WHERE user_id = $1 LIMIT 1",
          [user.id]
        );
        if (lsRes.rows.length > 0) livesafe = lsRes.rows[0];
      } catch (_) {
        /* table may not exist */
      }

      const odentityId = computeOdentityId(walletAddress);

      const identity = {
        odentityId,
        walletAddress: user.wallet_address,
        roles: user.roles || ["operator"],
        organization: user.organization || "CyberMedica",
        attestationRefs: user.attestation_refs || [
          "att-kyc-2026-01",
          "att-org-binding-cm",
        ],
        resolvedAt: new Date().toISOString(),
        ...(score && { identityScore: score }),
        ...(livesafe && { livesafeIdentity: livesafe }),
      };

      console.log(
        `[0dentity] Resolved identity (DB) for ${walletAddress} → ${identity.odentityId}`
      );
      return res.end(JSON.stringify(identity));
    }
  } catch (err) {
    console.warn("[0dentity] DB lookup failed, falling back:", err.message);
  }

  // Fallback: compute identity without DB
  const identity = fallbackIdentity(walletAddress);
  console.log(
    `[0dentity] Resolved identity (computed) for ${walletAddress} → ${identity.odentityId}`
  );
  res.end(JSON.stringify(identity));
}

// ---------------------------------------------------------------------------
// Route: GET /identity/:did
// ---------------------------------------------------------------------------
async function handleGetByDid(did, res) {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE did = $1 LIMIT 1",
      [did]
    );
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const identity = {
        odentityId: computeOdentityId(user.wallet_address || did),
        walletAddress: user.wallet_address,
        did: user.did,
        roles: user.roles || ["operator"],
        organization: user.organization || "CyberMedica",
        attestationRefs: user.attestation_refs || [],
        resolvedAt: new Date().toISOString(),
      };
      return res.end(JSON.stringify(identity));
    }

    res.statusCode = 404;
    return res.end(JSON.stringify({ error: "identity_not_found", did }));
  } catch (err) {
    console.error("[0dentity] DID lookup error:", err.message);
    res.statusCode = 500;
    return res.end(JSON.stringify({ error: "db_error", detail: err.message }));
  }
}

// ---------------------------------------------------------------------------
// Route: POST /enroll  (PACE enrollment)
// ---------------------------------------------------------------------------
async function handleEnroll(req, res) {
  const { walletAddress, did, organization, roles } = await readBody(req);

  try {
    // Insert enrollment log
    await pool.query(
      `INSERT INTO enrollment_log (wallet_address, did, organization, enrolled_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT DO NOTHING`,
      [walletAddress, did || null, organization || "CyberMedica"]
    );

    // Update users pace_status
    await pool.query(
      `UPDATE users SET pace_status = 'enrolled', updated_at = NOW()
       WHERE wallet_address = $1`,
      [walletAddress]
    );

    const odentityId = computeOdentityId(walletAddress);

    const result = {
      enrolled: true,
      odentityId,
      walletAddress,
      paceStatus: "enrolled",
      enrolledAt: new Date().toISOString(),
    };

    console.log(`[0dentity] PACE enrollment for ${walletAddress}`);
    res.end(JSON.stringify(result));
  } catch (err) {
    console.error("[0dentity] Enrollment error:", err.message);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "enrollment_failed", detail: err.message }));
  }
}

// ---------------------------------------------------------------------------
// Route: GET /health
// ---------------------------------------------------------------------------
async function handleHealth(res) {
  let userCount = null;
  try {
    const r = await pool.query("SELECT COUNT(*)::int AS count FROM users");
    userCount = r.rows[0].count;
  } catch (_) {
    /* DB may be unreachable */
  }

  res.end(
    JSON.stringify({
      ok: true,
      service: "0dentity-identity-service",
      ...(userCount !== null && { userCount }),
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

    // GET /identity/:did
    const didMatch = req.url?.match(/^\/identity\/(.+)$/);
    if (req.method === "GET" && didMatch) {
      return await handleGetByDid(decodeURIComponent(didMatch[1]), res);
    }

    if (req.method === "POST" && req.url === "/enroll") {
      return await handleEnroll(req, res);
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error("[0dentity] Unhandled error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "internal_error", detail: err.message }));
  }
});

server.listen(PORT, () =>
  console.log(`[0dentity] Identity service listening on :${PORT}`)
);
