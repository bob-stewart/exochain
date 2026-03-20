// ─── EXOCHAIN Gateway Client ─────────────────────────────────────────
// Connects EXO product layer to EXOCHAIN protocol primitives.
// All governance, identity, audit, and combinator operations route
// through this client to the EXOCHAIN REST API.

const EXOCHAIN_URL = process.env.EXOCHAIN_GATEWAY_URL || "http://localhost:8080";

export interface ExochainHealth {
  status: string;
  decisions: number;
  delegations: number;
  auditEntries: number;
  auditIntegrity: boolean;
}

export interface ExochainDecision {
  id: string;
  title: string;
  status: string;
  author: string;
  tenant_id: string;
  decision_class: string;
  votes: number;
  created_at: number;
}

export interface CombinatorReduceResult {
  valid: boolean;
  finalValue: unknown;
  totalReductions: number;
  invariantId: string;
  steps: unknown[];
}

export class ExochainClient {
  private baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl ?? EXOCHAIN_URL;
  }

  // ─── Health ──────────────────────────────────────────────────────

  async health(): Promise<ExochainHealth | null> {
    return this.get<ExochainHealth>("/api/v1/health");
  }

  // ─── Decisions (Governance) ──────────────────────────────────────

  async listDecisions(): Promise<ExochainDecision[]> {
    return (await this.get<ExochainDecision[]>("/api/v1/decisions")) ?? [];
  }

  async getDecision(id: string): Promise<ExochainDecision | null> {
    return this.get<ExochainDecision>(`/api/v1/decisions/${id}`);
  }

  async createDecision(input: {
    title: string;
    body: string;
    author_did: string;
    tenant_id: string;
    decision_class?: string;
  }): Promise<ExochainDecision | null> {
    return this.post<ExochainDecision>("/api/v1/decisions", input);
  }

  async advanceDecision(id: string, newStatus: string, actor: string): Promise<unknown> {
    return this.post(`/api/v1/decisions/${id}/advance`, {
      new_status: newStatus,
      actor,
    });
  }

  async castVote(decisionId: string, vote: {
    voter: string;
    choice: "Approve" | "Reject" | "Abstain";
    rationale?: string;
  }): Promise<unknown> {
    return this.post(`/api/v1/decisions/${decisionId}/vote`, vote);
  }

  // ─── Audit ───────────────────────────────────────────────────────

  async getAuditLog(): Promise<unknown[]> {
    return (await this.get<unknown[]>("/api/v1/audit")) ?? [];
  }

  async verifyAuditIntegrity(): Promise<{ intact: boolean }> {
    return (await this.get<{ intact: boolean }>("/api/v1/audit/verify")) ?? { intact: false };
  }

  // ─── Combinators ─────────────────────────────────────────────────

  async reduceCombinator(term: unknown, context?: unknown, maxReductions?: number): Promise<CombinatorReduceResult | null> {
    return this.post<CombinatorReduceResult>("/api/v1/combinators/reduce", {
      term,
      context,
      maxReductions,
    });
  }

  // ─── Identity ────────────────────────────────────────────────────

  async listUsers(): Promise<unknown[]> {
    return (await this.get<unknown[]>("/api/v1/users")) ?? [];
  }

  async getIdentityScore(did: string): Promise<unknown> {
    return this.get(`/api/v1/identity/${did}/score`);
  }

  // ─── LiveSafe Integration ────────────────────────────────────────

  async livesafeQuery(query: unknown): Promise<unknown> {
    return this.post("/api/v1/livesafe/query", query);
  }

  async livesafeMutation(mutation: unknown): Promise<unknown> {
    return this.post("/api/v1/livesafe/mutation", mutation);
  }

  // ─── HTTP Primitives ─────────────────────────────────────────────

  private async get<T>(path: string): Promise<T | null> {
    try {
      const res = await fetch(`${this.baseUrl}${path}`);
      if (!res.ok) {
        console.warn(`[EXOCHAIN] GET ${path} → ${res.status}`);
        return null;
      }
      return (await res.json()) as T;
    } catch (err) {
      console.warn(`[EXOCHAIN] GET ${path} failed:`, (err as Error).message);
      return null;
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T | null> {
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        console.warn(`[EXOCHAIN] POST ${path} → ${res.status}`);
        return null;
      }
      return (await res.json()) as T;
    } catch (err) {
      console.warn(`[EXOCHAIN] POST ${path} failed:`, (err as Error).message);
      return null;
    }
  }
}

// Singleton
export const exochain = new ExochainClient();
