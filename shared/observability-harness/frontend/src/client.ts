export interface AuditEvent {
  id: string;
  ts: number;
  trace_id: string | null;
  span_id: string | null;
  actor_type: string;
  actor_id: string;
  action: string;
  resource: string | null;
  decision: "allow" | "deny";
  reason: string | null;
  metadata: Record<string, unknown>;
}

export async function fetchEvents(baseUrl: string, { limit = 100 } = {}): Promise<AuditEvent[]> {
  const res = await fetch(`${baseUrl}/observability/events?limit=${limit}`, {
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`observability harness: fetching events failed (${res.status})`);
  }
  return res.json();
}

export async function fetchTrace(baseUrl: string, traceId: string): Promise<AuditEvent[]> {
  const res = await fetch(`${baseUrl}/observability/traces/${traceId}`, {
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(`observability harness: fetching trace failed (${res.status})`);
  }
  return res.json();
}
