// @exoeth/exochain-wasm/db — PostgreSQL helper using pg package
// Usage: import { query, getPool } from '@exoeth/exochain-wasm/db.js';

import pg from 'pg';
const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth';

let pool = null;

export function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      max: 5,
      idleTimeoutMillis: 30000,
    });
    pool.on('error', (err) => {
      console.error('[DB] Pool error:', err.message);
    });
  }
  return pool;
}

export async function query(sql, params) {
  const p = getPool();
  return p.query(sql, params);
}

export async function withClient(fn) {
  const p = getPool();
  const client = await p.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export default { getPool, query, withClient };
