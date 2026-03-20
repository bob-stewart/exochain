import http from "node:http";
import * as wasm from '../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const PORT = process.env.PORT || 3007;
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth' });

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_entries (
      id SERIAL PRIMARY KEY,
      event_type TEXT NOT NULL,
      correlation_id TEXT,
      event_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL,
      prev_hash TEXT,
      record_hash TEXT,
      content_hash TEXT,
      data JSONB,
      recorded_at TIMESTAMPTZ DEFAULT NOW(),
      raw_record JSONB
    )
  `);
}

ensureTable().catch(err => console.error('[Audit] Table init error:', err.message));

function toHex(str) {
  return Buffer.from(str, 'utf-8').toString('hex');
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  cors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  try {
    if (req.method === "GET" && req.url === "/health") {
      const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM audit_entries');
      return res.end(JSON.stringify({ ok: true, service: "audit-api", entries: rows[0].count }));
    }

    if (req.method === "GET" && req.url?.startsWith("/trace/")) {
      const correlationId = decodeURIComponent(req.url.split("/trace/")[1]);
      const { rows } = await pool.query(
        'SELECT * FROM audit_entries WHERE correlation_id = $1 ORDER BY recorded_at ASC',
        [correlationId]
      );
      const entries = rows.map(r => ({
        eventType: r.event_type,
        correlationId: r.correlation_id,
        eventHash: r.event_hash,
        entryHash: r.entry_hash,
        prevHash: r.prev_hash,
        data: r.data,
        recordedAt: r.recorded_at,
      }));
      return res.end(JSON.stringify({ correlationId, entries }));
    }

    if (req.method === "GET" && req.url === "/log") {
      const { rows } = await pool.query('SELECT * FROM audit_entries ORDER BY recorded_at DESC LIMIT 100');
      const entries = rows.map(r => ({
        eventType: r.event_type,
        correlationId: r.correlation_id,
        eventHash: r.event_hash,
        entryHash: r.entry_hash,
        prevHash: r.prev_hash,
        data: r.data,
        recordedAt: r.recorded_at,
      }));
      return res.end(JSON.stringify({ entries }));
    }

    if (req.method === "GET" && req.url === "/verify") {
      const { rows } = await pool.query('SELECT * FROM audit_entries ORDER BY id ASC');
      if (rows.length === 0) {
        return res.end(JSON.stringify({ valid: true, entry_count: 0 }));
      }

      let allValid = true;
      const errors = [];

      for (let i = 0; i < rows.length; i++) {
        const entry = rows[i];

        // Verify event_hash: Blake3 of the event data
        const eventDataHex = toHex(JSON.stringify(entry.data || {}));
        const expectedEventHash = wasm.wasm_hash_bytes(eventDataHex);
        if (expectedEventHash.hash !== entry.event_hash) {
          allValid = false;
          errors.push(`Entry ${entry.id}: event_hash mismatch`);
        }

        // Verify chain linkage: entry_hash = Blake3(prev_hash + event_hash)
        const chainInput = (entry.prev_hash || '') + entry.event_hash;
        const expectedEntryHash = wasm.wasm_hash_bytes(toHex(chainInput));
        if (expectedEntryHash.hash !== entry.entry_hash) {
          allValid = false;
          errors.push(`Entry ${entry.id}: entry_hash chain mismatch`);
        }

        // Verify prev_hash matches previous entry's entry_hash
        if (i > 0 && entry.prev_hash !== rows[i - 1].entry_hash) {
          allValid = false;
          errors.push(`Entry ${entry.id}: prev_hash does not match prior entry_hash`);
        }
      }

      return res.end(JSON.stringify({ valid: allValid, entry_count: rows.length, errors }));
    }

    if (req.method === "POST" && req.url === "/record") {
      const body = await readBody(req);
      const parsed = JSON.parse(body);
      const { eventType, correlationId, ...rest } = parsed;
      const data = rest.data || rest;

      // Compute event_hash via WASM Blake3
      const eventDataHex = toHex(JSON.stringify(data));
      const eventHashResult = wasm.wasm_hash_bytes(eventDataHex);
      const eventHash = eventHashResult.hash;

      // Get previous entry hash for chain linkage
      const prevResult = await pool.query('SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1');
      const prevHash = prevResult.rows.length > 0 ? prevResult.rows[0].entry_hash : null;

      // Compute entry_hash = Blake3(prev_hash + event_hash) for chain integrity
      const chainInput = (prevHash || '') + eventHash;
      const entryHashResult = wasm.wasm_hash_bytes(toHex(chainInput));
      const entryHash = entryHashResult.hash;

      // Create authenticated record via WASM
      const recordInput = {
        record_type: eventType || 'audit',
        tenant_id: 'exoeth',
        content: JSON.stringify({ eventType, correlationId, data, eventHash, entryHash, prevHash }),
        custodian: 'audit-api',
      };
      if (prevHash) {
        recordInput.prev_record_hash_hex = prevHash;
      }
      const record = wasm.wasm_create_authenticated_record(JSON.stringify(recordInput));

      const recordedAt = new Date().toISOString();

      await pool.query(
        `INSERT INTO audit_entries (event_type, correlation_id, event_hash, entry_hash, prev_hash, record_hash, content_hash, data, recorded_at, raw_record)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [eventType, correlationId, eventHash, entryHash, prevHash, record.record_hash, record.content_hash, data, recordedAt, record]
      );

      const entry = {
        eventType,
        correlationId,
        eventHash,
        entryHash,
        prevHash,
        data,
        recordedAt,
      };

      console.log(`[Audit] Recorded: ${eventType} for ${correlationId}`);
      return res.end(JSON.stringify({ recorded: true, entry }));
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error('[Audit] Error:', err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => console.log(`[Audit] API listening on :${PORT}`));
