// ─── EXO Gateway API ─────────────────────────────────────────────────
// The commercial product surface for the EXO transaction fabric.
// Routes: BCTS lifecycle, MCP enforcement, metering, admin.
//
// This is the "operating system" layer that monetizes EXOCHAIN.

export { createBCTS, transitionBCTS, canTransition, getValidTransitions,
  isTerminal, isFailure, executeCauseAction, validateForSubmission,
  validateIdentityResolution, validateConsentResolution, validateGovernance,
  validatePACE, VALID_TRANSITIONS } from "./bcts-engine.js";

export { buildMCPContext, enforceMCP, createMCPResponse,
  createMCPAuditEntry } from "./mcp-middleware.js";

export { MeterStore, TIER_LIMITS } from "./metering.js";

export { ExochainClient, exochain } from "./exochain-client.js";

export type { CreateBCTSInput, TransitionResult, ValidationResult } from "./bcts-engine.js";
export type { MCPEnforcementResult, MCPAuditEntry } from "./mcp-middleware.js";
export type { LimitCheckResult, UsageReport } from "./metering.js";
export type { ExochainHealth, ExochainDecision, CombinatorReduceResult } from "./exochain-client.js";

export { server } from "./server.js";
