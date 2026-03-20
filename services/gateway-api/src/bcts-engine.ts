// ─── BCTS Execution Engine ───────────────────────────────────────────
// Implements the 11-state execution machine for Bailment-Conditioned
// Transaction Sets. This is the core product logic of EXO.

import type {
  BCTS, BCTSState, BCTSTransition, BCTSParties, BCTSGovernance,
  BCTSAsset, BailmentTerms, ActionForCause, PACEContinuity,
  BCTSTrigger, IdentityBinding,
} from "../../../packages/shared-schemas/src/index.js";
import { createHash, randomUUID } from "crypto";

// ─── Valid State Transitions ─────────────────────────────────────────

const VALID_TRANSITIONS: Record<BCTSState, BCTSState[]> = {
  DRAFT:              ["SUBMITTED", "DENIED"],
  SUBMITTED:          ["IDENTITY_RESOLVED", "DENIED", "ESCALATED"],
  IDENTITY_RESOLVED:  ["CONSENT_VALIDATED", "DENIED", "ESCALATED"],
  CONSENT_VALIDATED:  ["DELIBERATED", "DENIED", "ESCALATED"],
  DELIBERATED:        ["VERIFIED", "DENIED", "ESCALATED"],
  VERIFIED:           ["GOVERNED", "DENIED", "ESCALATED"],
  GOVERNED:           ["APPROVED", "DENIED", "ESCALATED"],
  APPROVED:           ["EXECUTED", "DENIED", "ESCALATED"],
  EXECUTED:           ["RECORDED", "ESCALATED"],
  RECORDED:           ["CLOSED"],
  CLOSED:             [],
  // Failure paths
  DENIED:             ["ESCALATED", "REMEDIATED"],
  ESCALATED:          ["REMEDIATED", "DENIED"],
  REMEDIATED:         ["SUBMITTED"],  // retry from SUBMITTED
};

// ─── BCTS Factory ────────────────────────────────────────────────────

export interface CreateBCTSInput {
  intent: string;
  parties: BCTSParties;
  assets?: BCTSAsset[];
  bailment?: BailmentTerms;
  governance?: Partial<BCTSGovernance>;
  triggers?: BCTSTrigger[];
  actionsForCause?: ActionForCause[];
  pace?: Partial<PACEContinuity>;
  identityBindings?: IdentityBinding[];
}

export function createBCTS(input: CreateBCTSInput, actor: string): BCTS {
  const now = new Date().toISOString();
  const id = randomUUID();
  const correlationId = randomUUID();

  return {
    transactionSetId: id,
    version: 1,
    intent: input.intent,
    state: "DRAFT",
    parties: {
      principal: input.parties.principal,
      bailor: input.parties.bailor,
      custodian: input.parties.custodian,
      delegates: input.parties.delegates || [],
      beneficiaries: input.parties.beneficiaries || [],
    },
    identityBindings: input.identityBindings || [],
    assets: input.assets || [],
    authorities: {
      allowedActions: [],
      restrictedActions: [],
    },
    bailment: input.bailment,
    governance: {
      requiresAIIRB: input.governance?.requiresAIIRB ?? false,
      requiresCrossCheck: input.governance?.requiresCrossCheck ?? true,
      policyPack: input.governance?.policyPack ?? "default",
      riskThreshold: input.governance?.riskThreshold ?? 0.5,
    },
    triggers: input.triggers || [],
    actionsForCause: input.actionsForCause || defaultActionsForCause(),
    pace: {
      primary: input.pace?.primary ?? input.parties.principal,
      alternate: input.pace?.alternate ?? "",
      contingency: input.pace?.contingency ?? "",
      emergency: input.pace?.emergency ?? "",
    },
    stateLog: [{
      from: "DRAFT" as BCTSState,
      to: "DRAFT" as BCTSState,
      actor,
      reason: "Transaction set created",
      timestamp: now,
    }],
    createdAt: now,
    updatedAt: now,
    correlationId,
  };
}

// ─── State Machine ───────────────────────────────────────────────────

export interface TransitionResult {
  success: boolean;
  bcts: BCTS;
  transition?: BCTSTransition;
  error?: string;
  receiptHash?: string;
}

export function canTransition(from: BCTSState, to: BCTSState): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

export function getValidTransitions(state: BCTSState): BCTSState[] {
  return VALID_TRANSITIONS[state] || [];
}

export function isTerminal(state: BCTSState): boolean {
  return state === "CLOSED";
}

export function isFailure(state: BCTSState): boolean {
  return state === "DENIED" || state === "ESCALATED";
}

export function transitionBCTS(
  bcts: BCTS,
  to: BCTSState,
  actor: string,
  reason: string,
): TransitionResult {
  if (!canTransition(bcts.state, to)) {
    return {
      success: false,
      bcts,
      error: `Invalid transition: ${bcts.state} → ${to}. Valid: [${getValidTransitions(bcts.state).join(", ")}]`,
    };
  }

  const now = new Date().toISOString();
  const transition: BCTSTransition = {
    from: bcts.state,
    to,
    actor,
    reason,
    timestamp: now,
    receiptHash: hashTransition(bcts.transactionSetId, bcts.state, to, actor, now),
  };

  const updated: BCTS = {
    ...bcts,
    state: to,
    version: bcts.version + 1,
    stateLog: [...bcts.stateLog, transition],
    updatedAt: now,
  };

  return {
    success: true,
    bcts: updated,
    transition,
    receiptHash: transition.receiptHash,
  };
}

// ─── Validation Gates ────────────────────────────────────────────────
// Each state transition has preconditions. These are the gate checks.

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function validateForSubmission(bcts: BCTS): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!bcts.intent) errors.push("Intent is required");
  if (!bcts.parties.principal) errors.push("Principal DID is required");
  if (bcts.assets.length === 0) warnings.push("No assets declared");
  if (!bcts.bailment) warnings.push("No bailment terms defined");
  if (bcts.actionsForCause.length === 0) warnings.push("No actions-for-cause defined");

  return { valid: errors.length === 0, errors, warnings };
}

export function validateIdentityResolution(bcts: BCTS): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (bcts.identityBindings.length === 0) {
    errors.push("At least one identity binding is required");
  }

  const principalBound = bcts.identityBindings.some(
    b => b.did === bcts.parties.principal
  );
  if (!principalBound) {
    errors.push("Principal must have an identity binding");
  }

  return { valid: errors.length === 0, errors, warnings };
}

export function validateConsentResolution(bcts: BCTS): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  for (const asset of bcts.assets) {
    if (!asset.consentId) {
      errors.push(`Asset ${asset.assetId} has no consent record`);
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

export function validateGovernance(bcts: BCTS): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (bcts.governance.requiresAIIRB) {
    warnings.push("AI-IRB evaluation required before approval");
  }
  if (bcts.governance.requiresCrossCheck) {
    warnings.push("CrossCheck verification required before approval");
  }

  return { valid: errors.length === 0, errors, warnings };
}

export function validatePACE(bcts: BCTS): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!bcts.pace.primary) errors.push("PACE primary is required");
  if (!bcts.pace.alternate) warnings.push("No PACE alternate defined");
  if (!bcts.pace.contingency) warnings.push("No PACE contingency defined");
  if (!bcts.pace.emergency) warnings.push("No PACE emergency defined");

  return { valid: errors.length === 0, errors, warnings };
}

// ─── Actions for Cause ───────────────────────────────────────────────

export function defaultActionsForCause(): ActionForCause[] {
  return [
    { cause: "unauthorized_use",    action: "freeze",               severity: "critical" },
    { cause: "policy_breach",       action: "revoke_authority",     severity: "high" },
    { cause: "high_risk",           action: "escalate",             severity: "high" },
    { cause: "adverse_event",       action: "pace_escalate",        severity: "critical" },
    { cause: "custodian_failure",   action: "transfer_custody",     severity: "critical" },
    { cause: "consent_violation",   action: "halt_execution",       severity: "critical" },
    { cause: "model_anomaly",       action: "require_revalidation", severity: "moderate" },
    { cause: "governance_conflict", action: "human_review",         severity: "moderate" },
    { cause: "data_corruption",     action: "quarantine",           severity: "high" },
    { cause: "execution_failure",   action: "rollback",             severity: "high" },
  ];
}

export function findActionForCause(bcts: BCTS, cause: string): ActionForCause | undefined {
  return bcts.actionsForCause.find(a => a.cause === cause);
}

export function executeCauseAction(
  bcts: BCTS,
  cause: string,
  actor: string,
): TransitionResult {
  const actionDef = findActionForCause(bcts, cause);
  if (!actionDef) {
    return {
      success: false,
      bcts,
      error: `No action defined for cause: ${cause}`,
    };
  }

  // Map cause actions to state transitions
  const targetState: BCTSState =
    actionDef.action === "freeze" || actionDef.action === "halt_execution"
      ? "DENIED"
      : actionDef.action === "escalate" || actionDef.action === "pace_escalate"
        || actionDef.action === "human_review"
        ? "ESCALATED"
        : actionDef.action === "rollback"
          ? "DENIED"
          : "ESCALATED"; // default to escalation

  return transitionBCTS(
    bcts,
    targetState,
    actor,
    `Action-for-cause: ${cause} → ${actionDef.action} (severity: ${actionDef.severity})`,
  );
}

// ─── Receipt Hashing ─────────────────────────────────────────────────

function hashTransition(
  txSetId: string,
  from: BCTSState,
  to: BCTSState,
  actor: string,
  timestamp: string,
): string {
  const input = `${txSetId}|${from}|${to}|${actor}|${timestamp}`;
  return createHash("sha256").update(input).digest("hex");
}

// ─── Export valid transitions for testing ─────────────────────────────

export { VALID_TRANSITIONS };
