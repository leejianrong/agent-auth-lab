export const API_BASE = "http://localhost:8000";

export interface User {
  id: number;
  username: string;
}

export interface SessionInfo {
  session_id_prefix: string;
  user_id: number;
  created_at: number;
  expires_at: number;
  seconds_remaining: number;
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
