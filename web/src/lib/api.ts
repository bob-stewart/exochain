/** API client for decision.forum gateway — connects to real Rust backend. */

import type {
  Decision, Delegation, AuditEntry, AuditIntegrity, ConstitutionInfo,
  LoginResponse, RegisterResponse, UserProfile, AgentIdentity, IdentityScore,
} from './types'

const API_BASE = '/api/v1'

function getToken(): string | null {
  return localStorage.getItem('df_token')
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers,
    ...init,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json()
}

export const api = {
  health: () =>
    fetchJson<{
      status: string
      decisions: number
      delegations: number
      auditEntries: number
      auditIntegrity: boolean
    }>('/health'),

  decisions: {
    list: () => fetchJson<Decision[]>('/decisions'),
    get: (id: string) => fetchJson<Decision>(`/decisions/${id}`),
    create: (data: { title: string; body: string; decisionClass: string; author: string }) =>
      fetchJson<Decision>('/decisions', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    advance: (id: string, newStatus: string, actor: string, reason?: string) =>
      fetchJson<Decision>(`/decisions/${id}/advance`, {
        method: 'POST',
        body: JSON.stringify({ newStatus, actor, reason }),
      }),
    vote: (id: string, voter: string, choice: string, rationale?: string) =>
      fetchJson<Decision>(`/decisions/${id}/vote`, {
        method: 'POST',
        body: JSON.stringify({ voter, choice, rationale }),
      }),
    tally: (id: string, actor: string) =>
      fetchJson<Decision>(`/decisions/${id}/tally`, {
        method: 'POST',
        body: JSON.stringify({ actor }),
      }),
  },

  delegations: {
    list: () => fetchJson<Delegation[]>('/delegations'),
  },

  audit: {
    trail: () => fetchJson<AuditEntry[]>('/audit'),
    verify: () => fetchJson<AuditIntegrity>('/audit/verify'),
  },

  constitution: {
    get: () => fetchJson<ConstitutionInfo>('/constitution'),
  },

  auth: {
    register: (data: { displayName: string; email: string; password: string }) =>
      fetchJson<RegisterResponse>('/auth/register', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    login: (data: { email: string; password: string }) =>
      fetchJson<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    refresh: (refreshToken: string) =>
      fetchJson<{ token: string; refreshToken: string }>('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      }),
    me: () => fetchJson<UserProfile>('/auth/me'),
    logout: () =>
      fetchJson<void>('/auth/logout', { method: 'POST' }),
  },

  agents: {
    list: () => fetchJson<AgentIdentity[]>('/agents'),
    get: (did: string) => fetchJson<AgentIdentity>(`/agents/${did}`),
    enroll: (data: {
      agentName: string
      agentType: string
      capabilities: string[]
      maxDecisionClass: string
    }) =>
      fetchJson<AgentIdentity>('/agents', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    advancePace: (did: string, step: string) =>
      fetchJson<AgentIdentity>(`/agents/${did}/pace`, {
        method: 'POST',
        body: JSON.stringify({ step }),
      }),
  },

  users: {
    list: () => fetchJson<UserProfile[]>('/users'),
    advancePace: (did: string, step: string) =>
      fetchJson<UserProfile>(`/users/${did}/pace`, {
        method: 'POST',
        body: JSON.stringify({ step }),
      }),
  },

  identity: {
    score: (did: string) => fetchJson<IdentityScore>(`/identity/${did}/score`),
  },
}
