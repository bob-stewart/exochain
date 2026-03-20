import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;
const GATEWAY = process.env.GATEWAY_URL || "http://gateway-api:3000";
const SYNTAXIS = process.env.SYNTAXIS_URL || "http://syntaxis-orchestrator:3010";
const CAIP = process.env.CAIP_URL || "http://caip-engine:3011";

function proxy(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: { "Content-Type": "application/json" } };
    if (body) opts.headers["Content-Length"] = Buffer.byteLength(body);
    const req = http.request(opts, (res) => {
      let d = "";
      res.on("data", (c) => (d += c));
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  // Syntaxis API proxy
  if (req.url.startsWith("/syntaxis/")) {
    const target = req.url.replace("/syntaxis", "");
    try {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (c) => (body += c));
        await new Promise((r) => req.on("end", r));
        const result = await proxy("POST", `${SYNTAXIS}${target}`, body);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      } else {
        const result = await proxy("GET", `${SYNTAXIS}${target}`);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      }
    } catch (err) {
      res.statusCode = 502;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // CAIP API proxy
  if (req.url.startsWith("/caip/")) {
    const target = req.url.replace("/caip", "");
    try {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (c) => (body += c));
        await new Promise((r) => req.on("end", r));
        const result = await proxy("POST", `${CAIP}${target}`, body);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      } else {
        const result = await proxy("GET", `${CAIP}${target}`);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      }
    } catch (err) {
      res.statusCode = 502;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // Gateway API proxy
  if (req.url.startsWith("/api/")) {
    const target = req.url.replace("/api", "");
    try {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (c) => (body += c));
        await new Promise((r) => req.on("end", r));
        const result = await proxy("POST", `${GATEWAY}${target}`, body);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      } else {
        let url = GATEWAY;
        if (target.startsWith("/receipts")) url = (process.env.PROVENANCE_URL || "http://provenance-writer:3006");
        else if (target.startsWith("/log") || target.startsWith("/trace")) url = (process.env.AUDIT_URL || "http://audit-api:3007");
        else if (target.startsWith("/notifications")) url = (process.env.NOTIFICATION_URL || "http://notification-service:3008");
        else if (target.startsWith("/current") || target.startsWith("/version")) url = (process.env.POLICY_URL || "http://policy-distribution:3009");
        const result = await proxy("GET", `${url}${target}`);
        res.setHeader("Content-Type", "application/json");
        return res.end(JSON.stringify(result));
      }
    } catch (err) {
      res.statusCode = 502;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // Redirect root to /cto
  if (req.url === "/") {
    res.writeHead(302, { Location: "/cto" });
    return res.end();
  }

  // Serve HTML for all UI routes
  res.setHeader("Content-Type", "text/html");
  res.end(fs.readFileSync(path.join(__dirname, "index.html"), "utf8"));
});

server.listen(PORT, () => console.log(`[Dashboard] ExoEth + Syntaxis UI listening on :${PORT}`));
