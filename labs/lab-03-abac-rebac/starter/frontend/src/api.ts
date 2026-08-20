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
