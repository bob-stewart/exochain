// ─── EXO Gateway HTTP Server ─────────────────────────────────────────
// Serves the EXO commercial API on port 4000 (configurable).
// Routes: BCTS lifecycle, MCP enforcement, metering/admin, health.
//
// Zero external dependencies — uses Node.js built-in http module.

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import {
  createBCTS, transitionBCTS, canTransition, getValidTransitions,
  isTerminal, isFailure, executeCauseAction,
  validateForSubmission, validateIdentityResolution,
  validateConsentResolution, validateGovernance, validatePACE,
} from "./bcts-engine.js";
import {
  buildMCPContext, enforceMCP, createMCPResponse, createMCPAuditEntry,
} from "./mcp-middleware.js";
import { MeterStore, TIER_LIMITS } from "./metering.js";
import { ExochainClient, exochain } from "./exochain-client.js";
import type { BCTS, BCTSState, MCPRequest } from "../../../packages/shared-schemas/src/index.js";
import type { CreateBCTSInput } from "./bcts-engine.js";

const PORT = parseInt(process.env.EXO_PORT ?? "4000", 10);
const ALLOWED_ORIGINS = (process.env.EXO_CORS_ORIGINS ?? "http://localhost:3000,http://localhost:5173").split(",");

// ─── In-Memory State (replace with persistent store in production) ───

const transactionSets: Map<string, BCTS> = new Map();
const meterStore = new MeterStore();

// ─── HTTP Helpers ────────────────────────────────────────────────────

function setCors(res: ServerResponse, origin?: string): void {
  const allowed = origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  res.setHeader("Access-Control-Allow-Origin", allowed);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-Id");
  res.setHeader("Access-Control-Max-Age", "86400");
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function error(res: ServerResponse, status: number, message: string): void {
  json(res, status, { error: message });
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

async function parseJsonBody<T>(req: IncomingMessage): Promise<T> {
  const raw = await readBody(req);
  if (!raw) throw new Error("Empty request body");
  return JSON.parse(raw) as T;
}

function extractTenantId(req: IncomingMessage): string {
  return (req.headers["x-tenant-id"] as string) ?? "default";
}

// ─── Route Matching ──────────────────────────────────────────────────

interface Route {
  method: string;
  pattern: RegExp;
  handler: (req: IncomingMessage, res: ServerResponse, params: Record<string, string>) => Promise<void>;
}

function matchRoute(method: string, url: string, routes: Route[]): { route: Route; params: Record<string, string> } | null {
  for (const route of routes) {
    if (route.method !== method) continue;
    const match = url.match(route.pattern);
    if (match) {
      const params: Record<string, string> = {};
      const groups = match.groups;
      if (groups) Object.assign(params, groups);
      return { route, params };
    }
  }
  return null;
}

// ─── Route Handlers ──────────────────────────────────────────────────

const routes: Route[] = [
  // ── Health ──
  {
    method: "GET",
    pattern: /^\/health$/,
    handler: async (_req, res) => {
      json(res, 200, {
        ok: true,
        service: "exo-gateway",
        version: "1.0.0",
        transactionSets: transactionSets.size,
        tenants: meterStore.listTenants().length,
      });
    },
  },

  // ── BCTS Lifecycle ──

  // Create transaction set
  {
    method: "POST",
    pattern: /^\/transaction-set$/,
    handler: async (req, res) => {
      const tenantId = extractTenantId(req);
      const body = await parseJsonBody<CreateBCTSInput & { actor?: string }>(req);
      const actor = body.actor ?? body.parties?.principal ?? "system";

      // Meter the creation
      const limitCheck = meterStore.checkLimit(tenantId, "bcts_created");
      if (!limitCheck.allowed) {
        error(res, 429, `Rate limit exceeded: ${limitCheck.reason}`);
        return;
      }

      const bcts = createBCTS(body, actor);
      transactionSets.set(bcts.transactionSetId, bcts);
      meterStore.record("bcts_created", tenantId, actor, bcts.correlationId);

      json(res, 201, {
        transactionSetId: bcts.transactionSetId,
        state: bcts.state,
        version: bcts.version,
        correlationId: bcts.correlationId,
        stateLog: bcts.stateLog,
      });
    },
  },

  // Get transaction set
  {
    method: "GET",
    pattern: /^\/transaction-set\/(?<id>[^/]+)$/,
    handler: async (_req, res, params) => {
      const bcts = transactionSets.get(params.id);
      if (!bcts) { error(res, 404, `Transaction set ${params.id} not found`); return; }
      json(res, 200, bcts);
    },
  },

  // Advance transaction set state
  {
    method: "POST",
    pattern: /^\/transaction-set\/(?<id>[^/]+)\/advance$/,
    handler: async (req, res, params) => {
      const bcts = transactionSets.get(params.id);
      if (!bcts) { error(res, 404, `Transaction set ${params.id} not found`); return; }

      const body = await parseJsonBody<{ targetState: BCTSState; actor: string; reason: string }>(req);
      const tenantId = extractTenantId(req);

      // Run validation gates based on target state
      const validationGates: Record<string, (b: BCTS) => { valid: boolean; issues: string[] }> = {
        SUBMITTED: validateForSubmission,
        IDENTITY_RESOLVED: validateIdentityResolution,
        CONSENT_VALIDATED: validateConsentResolution,
        GOVERNED: validateGovernance,
      };

      const gate = validationGates[body.targetState];
      if (gate) {
        const validation = gate(bcts);
        if (!validation.valid) {
          error(res, 422, `Validation failed: ${validation.errors.join(", ")}`);
          return;
        }
      }

      // PACE continuity validation for execution states
      if (body.targetState === "EXECUTED" || body.targetState === "APPROVED") {
        const paceCheck = validatePACE(bcts);
        if (!paceCheck.valid) {
          error(res, 422, `PACE validation failed: ${paceCheck.errors.join(", ")}`);
          return;
        }
      }

      const result = transitionBCTS(bcts, body.targetState, body.actor, body.reason);
      if (!result.success) {
        error(res, 422, result.error ?? "Transition failed");
        return;
      }

      transactionSets.set(params.id, result.bcts);
      meterStore.record("bcts_state_transition", tenantId, body.actor, result.bcts.correlationId);

      json(res, 200, {
        transactionSetId: result.bcts.transactionSetId,
        state: result.bcts.state,
        version: result.bcts.version,
        correlationId: result.bcts.correlationId,
        stateLog: result.bcts.stateLog,
        receiptHash: result.receiptHash,
      });
    },
  },

  // Trigger cause-action
  {
    method: "POST",
    pattern: /^\/transaction-set\/(?<id>[^/]+)\/cause$/,
    handler: async (req, res, params) => {
      const bcts = transactionSets.get(params.id);
      if (!bcts) { error(res, 404, `Transaction set ${params.id} not found`); return; }

      const body = await parseJsonBody<{ cause: string; actor: string }>(req);
      const result = executeCauseAction(bcts, body.cause, body.actor);
      if (!result.success) {
        error(res, 422, result.error ?? "Cause action failed");
        return;
      }

      transactionSets.set(params.id, result.bcts);

      json(res, 200, {
        transactionSetId: result.bcts.transactionSetId,
        state: result.bcts.state,
        version: result.bcts.version,
        correlationId: result.bcts.correlationId,
        stateLog: result.bcts.stateLog,
        causeTriggered: body.cause,
      });
    },
  },

  // List transaction sets
  {
    method: "GET",
    pattern: /^\/transaction-set$/,
    handler: async (req, res) => {
      const tenantId = extractTenantId(req);
      const all = Array.from(transactionSets.values());
      json(res, 200, { transactionSets: all, total: all.length });
    },
  },

  // ── MCP Enforcement ──

  {
    method: "POST",
    pattern: /^\/mcp\/check$/,
    handler: async (req, res) => {
      const body = await parseJsonBody<{ transactionSetId: string; task: string; actor: string }>(req);
      const tenantId = extractTenantId(req);

      const bcts = transactionSets.get(body.transactionSetId);
      if (!bcts) { error(res, 404, `Transaction set ${body.transactionSetId} not found`); return; }

      // Build MCP context from BCTS state
      const context = buildMCPContext(bcts, body.actor);

      // Build MCP request
      const mcpRequest: MCPRequest = {
        task: body.task,
        exoContext: context,
      };

      // Enforce MCP rules
      const enforcement = enforceMCP(mcpRequest);

      // Build response
      const response = createMCPResponse(
        enforcement.allowed ? body.task : "blocked",
        enforcement.allowed
          ? `Task "${body.task}" permitted under MCP governance`
          : `Task "${body.task}" blocked: ${enforcement.violations.join("; ")}`,
        enforcement.allowed ? 0.9 : 0.0,
        !enforcement.allowed,
        bcts.correlationId,
        enforcement.violations,
      );

      // Create audit entry
      const audit = createMCPAuditEntry(mcpRequest, response, enforcement);
      meterStore.record("mcp_request", tenantId, body.actor, bcts.correlationId);

      json(res, 200, {
        allowed: enforcement.allowed,
        violations: enforcement.violations,
        response,
        audit: { receiptHash: audit.receiptHash, timestamp: audit.timestamp },
      });
    },
  },

  // ── Metering / Admin ──

  // Get tenant usage
  {
    method: "GET",
    pattern: /^\/admin\/usage\/(?<tenantId>[^/]+)$/,
    handler: async (_req, res, params) => {
      const usage = meterStore.getUsage(params.tenantId);
      json(res, 200, usage);
    },
  },

  // Create or update tenant
  {
    method: "POST",
    pattern: /^\/admin\/tenants$/,
    handler: async (req, res) => {
      const body = await parseJsonBody<{ tenantId: string; name: string; tier?: string }>(req);
      const existing = meterStore.getTenant(body.tenantId);
      if (existing) {
        if (body.tier) {
          meterStore.updateTenantTier(body.tenantId, body.tier as any);
        }
        json(res, 200, meterStore.getTenant(body.tenantId));
      } else {
        const tenant = meterStore.createTenant(
          body.tenantId,
          body.name,
          (body.tier as any) ?? "free",
        );
        json(res, 201, tenant);
      }
    },
  },

  // List tenants
  {
    method: "GET",
    pattern: /^\/admin\/tenants$/,
    handler: async (_req, res) => {
      json(res, 200, { tenants: meterStore.listTenants() });
    },
  },

  // Get tier limits
  {
    method: "GET",
    pattern: /^\/admin\/tiers$/,
    handler: async (_req, res) => {
      json(res, 200, TIER_LIMITS);
    },
  },

  // System-wide usage
  {
    method: "GET",
    pattern: /^\/admin\/usage$/,
    handler: async (_req, res) => {
      json(res, 200, meterStore.getSystemUsage());
    },
  },

  // ── EXOCHAIN Proxy ──

  // Proxy governance decisions to EXOCHAIN
  {
    method: "GET",
    pattern: /^\/exochain\/health$/,
    handler: async (_req, res) => {
      const health = await exochain.health();
      if (health) {
        json(res, 200, health);
      } else {
        json(res, 503, { error: "EXOCHAIN unavailable" });
      }
    },
  },

  {
    method: "GET",
    pattern: /^\/exochain\/decisions$/,
    handler: async (_req, res) => {
      const decisions = await exochain.listDecisions();
      json(res, 200, { decisions });
    },
  },

  {
    method: "POST",
    pattern: /^\/exochain\/combinators\/reduce$/,
    handler: async (req, res) => {
      const body = await parseJsonBody<{ term: unknown; context?: unknown; maxReductions?: number }>(req);
      const result = await exochain.reduceCombinator(body.term, body.context, body.maxReductions);
      if (result) {
        json(res, 200, result);
      } else {
        json(res, 502, { error: "EXOCHAIN combinator reduction failed" });
      }
    },
  },
];

// ─── Server ──────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const origin = req.headers.origin;
  setCors(res, origin as string | undefined);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const pathname = url.pathname;

  try {
    const match = matchRoute(req.method ?? "GET", pathname, routes);
    if (match) {
      await match.route.handler(req, res, match.params);
    } else {
      error(res, 404, `Route not found: ${req.method} ${pathname}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("Empty request body") || message.includes("JSON")) {
      error(res, 400, `Bad request: ${message}`);
    } else {
      console.error(`[EXO] Error handling ${req.method} ${pathname}:`, message);
      error(res, 500, `Internal server error: ${message}`);
    }
  }
});

// ─── Start ───────────────────────────────────────────────────────────

if (process.argv[1] && (process.argv[1].endsWith("server.ts") || process.argv[1].endsWith("server.js"))) {
  // Create a default tenant for development
  meterStore.createTenant("default", "Development", "professional");

  server.listen(PORT, () => {
    console.log(`[EXO] Gateway API listening on http://localhost:${PORT}`);
    console.log(`[EXO] CORS allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
    console.log(`[EXO] EXOCHAIN upstream: ${process.env.EXOCHAIN_GATEWAY_URL || "http://localhost:8080"}`);
    console.log(`[EXO] Routes:`);
    console.log(`  GET  /health`);
    console.log(`  POST /transaction-set`);
    console.log(`  GET  /transaction-set`);
    console.log(`  GET  /transaction-set/:id`);
    console.log(`  POST /transaction-set/:id/advance`);
    console.log(`  POST /transaction-set/:id/cause`);
    console.log(`  POST /mcp/check`);
    console.log(`  GET  /admin/usage/:tenantId`);
    console.log(`  POST /admin/tenants`);
    console.log(`  GET  /admin/tenants`);
    console.log(`  GET  /admin/tiers`);
    console.log(`  GET  /admin/usage`);
    console.log(`  GET  /exochain/health`);
    console.log(`  GET  /exochain/decisions`);
    console.log(`  POST /exochain/combinators/reduce`);
  });
}

export { server, transactionSets, meterStore };
