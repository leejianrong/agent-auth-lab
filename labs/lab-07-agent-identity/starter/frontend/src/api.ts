export const API_BASE = "http://localhost:8000";

export interface User {
  id: number;
  username: string;
  role: string;
}

export interface AdminUserRow {
  id: number;
  username: string;
  role: string;
}

export interface SessionInfo {
  session_id_prefix: string;
  user_id: number;
  created_at: number;
  expires_at: number;
  seconds_remaining: number;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface VerifyResult {
  valid: boolean;
  signature_valid: boolean;
  expired: boolean;
  claims: Record<string, unknown> | null;
  reason: string | null;
}

interface ErrorBody {
  detail?: string;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = (await res.json().catch(() => null)) as T | ErrorBody | null;
  if (!res.ok) {
    const detail = (body as ErrorBody | null)?.detail ?? res.statusText;
    throw new Error(detail);
  }
  return body as T;
}

export const signup = (username: string, password: string): Promise<{ username: string }> =>
  request("/signup", { method: "POST", body: JSON.stringify({ username, password }) });

export const login = (username: string, password: string): Promise<{ username: string }> =>
  request("/login", { method: "POST", body: JSON.stringify({ username, password }) });

export const logout = (): Promise<{ ok: boolean }> => request("/logout", { method: "POST" });

export const me = (): Promise<User> => request("/me");

export const sessionsMine = (): Promise<SessionInfo> => request("/sessions/mine");

export const issueToken = (): Promise<TokenResponse> => request("/token", { method: "POST" });

export const verifyToken = (token: string): Promise<VerifyResult> =>
  request("/verify", { method: "POST", body: JSON.stringify({ token }) });

export const listUsers = (): Promise<AdminUserRow[]> => request("/admin/users");

// --- lab 03: ABAC/ReBAC notes + policy-decision trace ----------------------

export interface Note {
  id: number;
  owner_id: number;
  owner_username: string;
  title: string;
  body: string;
  created_at: number;
}

export interface NoteDecision {
  allowed: boolean;
  rule_id: string;
  rule_description: string;
  note: Note | null;
}

export const createNote = (title: string, body: string): Promise<Note> =>
  request("/notes", { method: "POST", body: JSON.stringify({ title, body }) });

export const listMyNotes = (): Promise<Note[]> => request("/notes/mine");

// The read/update endpoints return a `NoteDecision` on both allow (200) and
// deny (403) — the policy-decision trace viewer needs the matched rule
// either way, not just on success. FastAPI wraps a raised HTTPException's
// `detail` under a top-level "detail" key, so a 403 body looks like
// `{ detail: { allowed, rule_id, ... } }` while a 200 body is the
// NoteDecision itself; unwrap so callers get one consistent shape.
async function noteDecisionRequest(path: string, options: RequestInit): Promise<NoteDecision> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await res.json().catch(() => null);
  if (res.ok) return body as NoteDecision;
  const detail = body && typeof body === "object" ? (body as { detail?: unknown }).detail : null;
  if (detail && typeof detail === "object") {
    return detail as NoteDecision;
  }
  // A plain-string detail (e.g. "note not found" on a 404) isn't a policy
  // decision at all — surface it as a normal error instead of pretending
  // it's a trace result.
  throw new Error(typeof detail === "string" ? detail : res.statusText);
}

export const attemptReadNote = (noteId: number): Promise<NoteDecision> =>
  noteDecisionRequest(`/notes/${noteId}`, { method: "GET" });

export const attemptUpdateNote = (noteId: number, title: string, body: string): Promise<NoteDecision> =>
  noteDecisionRequest(`/notes/${noteId}`, { method: "PUT", body: JSON.stringify({ title, body }) });

// --- lab 04: Sign in with the Lab IdP + the live OIDC trace ----------------

// The browser leaves for the IdP from here. This is a full-page navigation,
// not a fetch: the login happens on the IdP's own pages, so this app never
// sees the user's password.
export const oidcLoginUrl = `${API_BASE}/auth/oidc/login`;

export interface OidcTraceEvent {
  id: string;
  ts: number;
  source: "client" | "idp";
  actor_type: string;
  actor_id: string;
  action: string;
  resource: string | null;
  decision: "allow" | "deny";
  reason: string | null;
}

export interface OidcTrace {
  trace_id: string;
  outcome: "success" | "failed" | null;
  failure_reason: string | null;
  id_token_claims: Record<string, unknown> | null;
  idp_reachable: boolean;
  events: OidcTraceEvent[];
}

export const fetchOidcTrace = (traceId: string): Promise<OidcTrace> =>
  request(`/oidc/trace/${encodeURIComponent(traceId)}`);

// --- lab 05: what the IdP says about this session's access token -----------

export interface TokenInfo {
  federated: boolean;
  active?: boolean;
  scopes?: string[];
  expires_at?: number;
  jti_prefix?: string;
}

export const tokenMine = (): Promise<TokenInfo> => request("/oidc/token/mine");

export const revokeMyToken = (): Promise<{ revoked: boolean }> =>
  request("/oidc/token/revoke", { method: "POST" });

// --- lab 06: service-to-service calls, from both sides ---------------------

export interface ServiceCall {
  id: string;
  ts: number;
  source: "app" | "idp";
  actor_id: string;
  action: string;
  resource: string | null;
  decision: "allow" | "deny";
  reason: string | null;
  trace_id: string | null;
}

export const serviceCalls = (): Promise<ServiceCall[]> => request("/service-calls");

// --- lab 07: the agent activity dashboard ----------------------------------

export interface AgentRow {
  client_id: string;
  name: string;
  sponsor_sub: string | null;
  first_seen: number;
  last_seen: number;
}

export interface AgentEvent {
  id: string;
  ts: number;
  actor_type: string;
  actor_id: string;
  action: string;
  resource: string | null;
  decision: "allow" | "deny";
  reason: string | null;
  metadata: { sponsor?: string | null; name?: string | null };
}

export interface AgentReport {
  id: number;
  agent_id: string;
  title: string;
  body: string;
  created_at: number;
}

export const agentActivity = (): Promise<{ agents: AgentRow[]; events: AgentEvent[] }> => request("/agent-activity");

export const agentReports = (): Promise<AgentReport[]> => request("/agent/reports");
