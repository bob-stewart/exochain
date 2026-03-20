import http from "node:http";
import pg from 'pg';

const PORT = process.env.PORT || 3008;
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://exoeth:exoeth_dev@localhost:5432/exoeth' });

async function ensureTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      channel TEXT,
      message TEXT,
      recipient TEXT,
      data JSONB,
      delivered BOOLEAN DEFAULT TRUE,
      sent_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

ensureTable().catch(err => console.error('[Notify] Table init error:', err.message));

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
      const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM notifications');
      return res.end(JSON.stringify({ ok: true, service: "notification-service", pending: rows[0].count }));
    }

    if (req.method === "GET" && req.url === "/notifications") {
      const { rows } = await pool.query('SELECT * FROM notifications ORDER BY sent_at DESC LIMIT 100');
      const notifications = rows.map(r => ({
        id: r.id,
        channel: r.channel,
        message: r.message,
        recipient: r.recipient,
        data: r.data,
        delivered: r.delivered,
        sentAt: r.sent_at,
      }));
      return res.end(JSON.stringify({ notifications }));
    }

    if (req.method === "POST" && req.url === "/send") {
      const body = await readBody(req);
      const parsed = JSON.parse(body);
      const { channel, message, recipient, ...rest } = parsed;
      const data = Object.keys(rest).length > 0 ? rest : null;
      const sentAt = new Date().toISOString();

      const { rows } = await pool.query(
        `INSERT INTO notifications (channel, message, recipient, data, delivered, sent_at)
         VALUES ($1, $2, $3, $4, TRUE, $5)
         RETURNING id`,
        [channel || 'system', message, recipient || null, data, sentAt]
      );

      const notification = {
        id: rows[0].id,
        channel: channel || 'system',
        message,
        recipient: recipient || null,
        data,
        delivered: true,
        sentAt,
      };

      console.log(`[Notify] ${notification.channel}: ${notification.message}`);
      return res.end(JSON.stringify(notification));
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    console.error('[Notify] Error:', err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => console.log(`[Notify] Service listening on :${PORT}`));
