import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8081;
const DIST = path.join(__dirname, "dist");

const MIME = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2" };

const server = http.createServer((req, res) => {
  let filePath = path.join(DIST, req.url === "/" ? "index.html" : req.url);

  // SPA fallback — serve index.html for non-asset routes
  if (!fs.existsSync(filePath)) filePath = path.join(DIST, "index.html");

  const ext = path.extname(filePath);
  res.setHeader("Content-Type", MIME[ext] || "application/octet-stream");
  res.end(fs.readFileSync(filePath));
});

server.listen(PORT, () => console.log(`[Syntaxis Builder] Serving on :${PORT}`));
