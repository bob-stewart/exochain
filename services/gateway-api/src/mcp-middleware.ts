// ─── MCP (Model Context Protocol) Middleware ─────────────────────────
// Enforces governance constraints on every AI interaction.
// Every request/response through EXO passes through this layer.

import type {
  MCPContext, MCPRequest, MCPResponse, BCTS,
  GovernanceDecisionStatus,
} from "../../../packages/shared-schemas/src/index.js";
import { createHash, randomUUID } from "crypto";

// ─── MCP Context Builder ────────────────────────────────────────────

export function buildMCPContext(bcts: BCTS, actorDid: string): MCPContext {
  const role = resolveRole(bcts, actorDid);
  const binding = bcts.identityBindings.find(b => b.did === actorDid);

  return {
    transactionSetId: bcts.transactionSetId,
    actor: binding?.odentityId ?? actorDid,
    role,
    allowedActions: bcts.authorities.allowedActions,
    restrictedActions: bcts.authorities.restrictedActions,
    governanceStatus: mapBCTSStateToGovernance(bcts.state),
    riskLevel: assessRisk(bcts),
    consentStatus: bcts.state === "CONSENT_VALIDATED" ||
      stateIndex(bcts.state) > stateIndex("CONSENT_VALIDATED")
      ? "valid"
      : "pending",
    policyPack: bcts.governance.policyPack,
    executionScope: bcts.intent,
  };
}

// ─── MCP Enforcement ─────────────────────────────────────────────────

export interface MCPEnforcementResult {
  allowed: boolean;
  response?: MCPResponse;
  violations: string[];
}

export function enforceMCP(request: MCPRequest): MCPEnforcementResult {
  const violations: string[] = [];
  const ctx = request.exoContext;

  // Rule 1: Cannot execute outside BCTS scope
  if (!ctx.transactionSetId) {
    violations.push("MCP_001: No transaction set context — action outside BCTS scope");
  }

  // Rule 2: Cannot perform restricted actions
  if (ctx.restrictedActions.includes(request.task)) {
    violations.push(`MCP_002: Action "${request.task}" is explicitly restricted`);
  }

  // Rule 3: Must have allowed action (if allowedActions is non-empty)
  if (ctx.allowedActions.length > 0 && !ctx.allowedActions.includes(request.task)) {
    violations.push(`MCP_003: Action "${request.task}" is not in allowed actions list`);
  }

  // Rule 4: Cannot bypass governance
  if (ctx.governanceStatus === "denied") {
    violations.push("MCP_004: Governance has denied this transaction set");
  }

  // Rule 5: Consent must be valid for data operations
  if (ctx.consentStatus === "invalid") {
    violations.push("MCP_005: Consent is invalid — cannot proceed");
  }

  // Rule 6: High-risk actions require review
  if (ctx.riskLevel === "critical" || ctx.riskLevel === "high") {
    violations.push(`MCP_006: Risk level "${ctx.riskLevel}" — requires human review`);
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      response: {
        action: "BLOCKED",
        justification: violations.join("; "),
        confidence: 1.0,
        requiresReview: true,
        correlationId: randomUUID(),
        violations,
      },
      violations,
    };
  }

  return { allowed: true, violations: [] };
}

// ─── MCP Response Builder ────────────────────────────────────────────

export function createMCPResponse(
  action: string,
  justification: string,
  confidence: number,
  requiresReview: boolean,
  correlationId?: string,
): MCPResponse {
  return {
    action,
    justification,
    confidence: Math.max(0, Math.min(1, confidence)),
    requiresReview,
    correlationId: correlationId ?? randomUUID(),
  };
}

// ─── MCP Audit Trail ─────────────────────────────────────────────────

export interface MCPAuditEntry {
  entryId: string;
  timestamp: string;
  request: MCPRequest;
  enforcement: MCPEnforcementResult;
  response?: MCPResponse;
  receiptHash: string;
}

export function createMCPAuditEntry(
  request: MCPRequest,
  enforcement: MCPEnforcementResult,
  response?: MCPResponse,
): MCPAuditEntry {
  const timestamp = new Date().toISOString();
  const entryId = randomUUID();
  const hashInput = `${entryId}|${request.task}|${request.exoContext.actor}|${timestamp}|${enforcement.allowed}`;
  const receiptHash = createHash("sha256").update(hashInput).digest("hex");

  return {
    entryId,
    timestamp,
    request,
    enforcement,
    response,
    receiptHash,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────

function resolveRole(bcts: BCTS, actorDid: string): string {
  if (bcts.parties.principal === actorDid) return "principal";
  if (bcts.parties.bailor === actorDid) return "bailor";
  if (bcts.parties.custodian === actorDid) return "custodian";
  if (bcts.parties.delegates.includes(actorDid)) return "delegate";
  if (bcts.parties.beneficiaries.includes(actorDid)) return "beneficiary";
  return "unknown";
}

function mapBCTSStateToGovernance(state: string): GovernanceDecisionStatus {
  switch (state) {
    case "APPROVED":
    case "EXECUTED":
    case "RECORDED":
    case "CLOSED":
      return "approved";
    case "DENIED":
      return "denied";
    case "GOVERNED":
    case "VERIFIED":
      return "voting";
    default:
      return "pending_review";
  }
}

const STATE_ORDER: string[] = [
  "DRAFT", "SUBMITTED", "IDENTITY_RESOLVED", "CONSENT_VALIDATED",
  "DELIBERATED", "VERIFIED", "GOVERNED", "APPROVED",
  "EXECUTED", "RECORDED", "CLOSED",
];

function stateIndex(state: string): number {
  const idx = STATE_ORDER.indexOf(state);
  return idx >= 0 ? idx : -1;
}

function assessRisk(bcts: BCTS): "low" | "moderate" | "high" | "critical" {
  if (bcts.governance.riskThreshold <= 0.2) return "critical";
  if (bcts.governance.riskThreshold <= 0.4) return "high";
  if (bcts.governance.riskThreshold <= 0.6) return "moderate";
  return "low";
}
