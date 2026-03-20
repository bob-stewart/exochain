import http from "node:http";
import * as wasm from '../../packages/exochain-wasm/wasm/exochain_wasm.js';
import pg from 'pg';

const PORT = process.env.PORT || 3006;
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth' });

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS provenance_receipts (
      id SERIAL PRIMARY KEY,
      receipt_id TEXT UNIQUE NOT NULL,
      event_type TEXT NOT NULL,
      correlation_id TEXT,
      payload_hash TEXT NOT NULL,
      record_hash TEXT,
      content_hash TEXT,
      prev_record_hash TEXT,
      immutable BOOLEAN DEFAULT TRUE,
      chain TEXT DEFAULT 'exochain-local',
      written_at TIMESTAMPTZ DEFAULT NOW(),
      raw_record JSONB
    )
  `);
}

ensureTable().catch(err => console.error('[ExoChain] Table init error:', err.message));

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
      const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM provenance_receipts');
      return res.end(JSON.stringify({ ok: true, service: "exochain-provenance-writer", receipts: rows[0].count }));
    }

    if (req.method === "GET" && req.url === "/receipts") {
      const { rows } = await pool.query('SELECT * FROM provenance_receipts ORDER BY written_at DESC LIMIT 100');
      const receipts = rows.map(r => ({
        receiptId: r.receipt_id,
        eventType: r.event_type,
        correlationId: r.correlation_id,
        payloadHash: r.payload_hash,
        recordHash: r.record_hash,
        contentHash: r.content_hash,
        immutable: r.immutable,
        chain: r.chain,
        writtenAt: r.written_at,
      }));
      return res.end(JSON.stringify({ receipts }));
    }

    if (req.method === "GET" && req.url?.startsWith("/receipt/")) {
      const id = decodeURIComponent(req.url.split("/receipt/")[1]);
      const { rows } = await pool.query('SELECT * FROM provenance_receipts WHERE receipt_id = $1', [id]);
      if (rows.length === 0) {
        res.statusCode = 404;
        return res.end(JSON.stringify({ error: "receipt_not_found" }));
      }
      const r = rows[0];
      return res.end(JSON.stringify({
        receiptId: r.receipt_id,
        eventType: r.event_type,
        correlationId: r.correlation_id,
        payloadHash: r.payload_hash,
        recordHash: r.record_hash,
        contentHash: r.content_hash,
        immutable: r.immutable,
        chain: r.chain,
        writtenAt: r.written_at,
        rawRecord: r.raw_record,
      }));
    }

    if (req.method === "GET" && req.url === "/verify") {
      const { rows } = await pool.query('SELECT * FROM provenance_receipts ORDER BY id ASC');
      if (rows.length === 0) {
        return res.end(JSON.stringify({ valid: true, record_count: 0 }));
      }
      // Verify each receipt's payload hash using WASM Blake3
      let allValid = true;
      const errors = [];
      for (const r of rows) {
        if (r.raw_record && r.raw_record.content) {
          const contentHex = toHex(JSON.stringify(r.raw_record.content));
          const hashResult = wasm.wasm_hash_bytes(contentHex);
          if (hashResult.hash !== r.content_hash) {
            allValid = false;
            errors.push(`Receipt ${r.receipt_id}: content_hash mismatch`);
          }
        }
      }
      return res.end(JSON.stringify({ valid: allValid, record_count: rows.length, errors }));
    }

    if (req.method === "POST" && req.url === "/write") {
      const body = await readBody(req);
      const { eventType, correlationId, payload } = JSON.parse(body);

      // Compute Blake3 hash of payload via WASM
      const payloadHex = toHex(JSON.stringify(payload));
      const hashResult = wasm.wasm_hash_bytes(payloadHex);
      const payloadHash = hashResult.hash;

      // Get previous record hash for chain linkage
      const prevResult = await pool.query('SELECT record_hash FROM provenance_receipts ORDER BY id DESC LIMIT 1');
      const prevRecordHash = prevResult.rows.length > 0 ? prevResult.rows[0].record_hash : undefined;

      // Create authenticated record via WASM
      const recordInput = {
        record_type: eventType || 'provenance',
        tenant_id: 'exoeth',
        content: JSON.stringify({ eventType, correlationId, payload, payloadHash }),
        custodian: 'provenance-writer',
      };
      if (prevRecordHash) {
        recordInput.prev_record_hash_hex = prevRecordHash;
      }
      const record = wasm.wasm_create_authenticated_record(JSON.stringify(recordInput));

      const receiptId = `rcpt-${(record.id || crypto.randomUUID()).slice(0, 8)}`;

      await pool.query(
        `INSERT INTO provenance_receipts (receipt_id, event_type, correlation_id, payload_hash, record_hash, content_hash, prev_record_hash, raw_record)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [receiptId, eventType, correlationId, payloadHash, record.record_hash, record.content_hash, prevRecordHash || null, record]
      );

      const receipt = {
        receiptId,
        eventType,
        correlationId,
        payloadHash,
        recordHash: record.record_hash,
        contentHash: record.content_hash,
        immutable: true,
        chain: "exochain-local",
        writtenAt: new Date().toISOString(),
      };

      console.log(`[ExoChain] Provenance receipt written: ${receiptId} (${eventType}) hash=${payloadHash.slice(0, 16)}...`);
      return res.end(JSON.stringify(receipt));
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error('[ExoChain] Error:', err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => console.log(`[ExoChain] Provenance writer listening on :${PORT}`));
