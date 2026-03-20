// ─── Metering & Admin Surface ────────────────────────────────────────
// Tracks every billable event in the EXO fabric.
// Admin API surfaces usage, limits, and tenant configuration.

import type {
  MeterEvent, MeterableEvent, TenantConfig,
} from "../../../packages/shared-schemas/src/index.js";
import { randomUUID } from "crypto";

// ─── Tier Limits ─────────────────────────────────────────────────────

const TIER_LIMITS: Record<string, TenantConfig["limits"]> = {
  free: {
    maxBCTSPerMonth: 10,
    maxGovernanceCasesPerMonth: 25,
    maxCombinatorReductions: 100,
    maxMCPRequests: 500,
    legalArtifactsEnabled: false,
    crosscheckEnabled: false,
    paceEnabled: false,
  },
  starter: {
    maxBCTSPerMonth: 100,
    maxGovernanceCasesPerMonth: 500,
    maxCombinatorReductions: 5000,
    maxMCPRequests: 10000,
    legalArtifactsEnabled: false,
    crosscheckEnabled: true,
    paceEnabled: true,
  },
  professional: {
    maxBCTSPerMonth: 1000,
    maxGovernanceCasesPerMonth: 5000,
    maxCombinatorReductions: 50000,
    maxMCPRequests: 100000,
    legalArtifactsEnabled: true,
    crosscheckEnabled: true,
    paceEnabled: true,
  },
  enterprise: {
    maxBCTSPerMonth: -1,  // unlimited
    maxGovernanceCasesPerMonth: -1,
    maxCombinatorReductions: -1,
    maxMCPRequests: -1,
    legalArtifactsEnabled: true,
    crosscheckEnabled: true,
    paceEnabled: true,
  },
};

// ─── In-Memory Meter Store ───────────────────────────────────────────
// Production: replace with PostgreSQL or time-series DB

export class MeterStore {
  private events: MeterEvent[] = [];
  private tenants: Map<string, TenantConfig> = new Map();

  // ─── Tenant Management ─────────────────────────────────────────

  createTenant(tenantId: string, name: string, tier: TenantConfig["tier"] = "free"): TenantConfig {
    const config: TenantConfig = {
      tenantId,
      name,
      tier,
      limits: { ...TIER_LIMITS[tier] },
      billing: {
        plan: tier,
        overage: tier === "enterprise" ? "allow_and_bill" : "block",
      },
    };
    this.tenants.set(tenantId, config);
    return config;
  }

  getTenant(tenantId: string): TenantConfig | undefined {
    return this.tenants.get(tenantId);
  }

  updateTenantTier(tenantId: string, tier: TenantConfig["tier"]): TenantConfig | undefined {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) return undefined;
    tenant.tier = tier;
    tenant.limits = { ...TIER_LIMITS[tier] };
    tenant.billing.plan = tier;
    tenant.billing.overage = tier === "enterprise" ? "allow_and_bill" : "block";
    return tenant;
  }

  listTenants(): TenantConfig[] {
    return Array.from(this.tenants.values());
  }

  // ─── Event Recording ───────────────────────────────────────────

  record(
    eventType: MeterableEvent,
    tenantId: string,
    actor: string,
    correlationId: string,
    metadata?: Record<string, unknown>,
  ): MeterEvent {
    const event: MeterEvent = {
      eventId: randomUUID(),
      eventType,
      tenantId,
      correlationId,
      actor,
      timestamp: new Date().toISOString(),
      metadata,
    };
    this.events.push(event);
    return event;
  }

  // ─── Limit Checking ────────────────────────────────────────────

  checkLimit(tenantId: string, eventType: MeterableEvent): LimitCheckResult {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) {
      return { allowed: false, reason: "Tenant not found", current: 0, limit: 0 };
    }

    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const monthStartStr = monthStart.toISOString();

    const count = this.events.filter(
      e => e.tenantId === tenantId
        && e.eventType === eventType
        && e.timestamp >= monthStartStr
    ).length;

    const limit = this.getLimitForEvent(tenant, eventType);

    if (limit === -1) {
      return { allowed: true, current: count, limit: -1 };
    }

    if (count >= limit) {
      if (tenant.billing.overage === "allow_and_bill") {
        return { allowed: true, current: count, limit, overage: true };
      }
      return { allowed: false, reason: `Limit reached: ${count}/${limit}`, current: count, limit };
    }

    return { allowed: true, current: count, limit };
  }

  // ─── Usage Reports ─────────────────────────────────────────────

  getUsage(tenantId: string, since?: string): UsageReport {
    const sinceDate = since ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const filtered = this.events.filter(
      e => e.tenantId === tenantId && e.timestamp >= sinceDate
    );

    const breakdown: Record<string, number> = {};
    for (const e of filtered) {
      breakdown[e.eventType] = (breakdown[e.eventType] || 0) + 1;
    }

    return {
      tenantId,
      since: sinceDate,
      totalEvents: filtered.length,
      breakdown,
    };
  }

  getSystemUsage(since?: string): UsageReport {
    const sinceDate = since ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const filtered = this.events.filter(e => e.timestamp >= sinceDate);

    const breakdown: Record<string, number> = {};
    for (const e of filtered) {
      breakdown[e.eventType] = (breakdown[e.eventType] || 0) + 1;
    }

    return {
      tenantId: "*",
      since: sinceDate,
      totalEvents: filtered.length,
      breakdown,
    };
  }

  // ─── Admin: Raw Event Access ───────────────────────────────────

  getEvents(tenantId?: string, limit = 100, offset = 0): MeterEvent[] {
    let filtered = tenantId
      ? this.events.filter(e => e.tenantId === tenantId)
      : this.events;
    return filtered.slice(offset, offset + limit);
  }

  getEventCount(): number {
    return this.events.length;
  }

  // ─── Private Helpers ───────────────────────────────────────────

  private getLimitForEvent(tenant: TenantConfig, eventType: MeterableEvent): number {
    switch (eventType) {
      case "bcts_created":
        return tenant.limits.maxBCTSPerMonth;
      case "bcts_state_transition":
        return tenant.limits.maxBCTSPerMonth * 11; // avg 11 transitions per BCTS
      case "governance_evaluation":
      case "governance_decision":
        return tenant.limits.maxGovernanceCasesPerMonth;
      case "combinator_reduction":
        return tenant.limits.maxCombinatorReductions;
      case "mcp_request":
        return tenant.limits.maxMCPRequests;
      case "legal_artifact":
        return tenant.limits.legalArtifactsEnabled ? -1 : 0;
      case "crosscheck_evaluation":
        return tenant.limits.crosscheckEnabled ? -1 : 0;
      default:
        return -1; // unlimited by default
    }
  }
}

// ─── Types ───────────────────────────────────────────────────────────

export interface LimitCheckResult {
  allowed: boolean;
  reason?: string;
  current: number;
  limit: number;
  overage?: boolean;
}

export interface UsageReport {
  tenantId: string;
  since: string;
  totalEvents: number;
  breakdown: Record<string, number>;
}

// ─── Default TIER_LIMITS export for testing ──────────────────────────

export { TIER_LIMITS };
