<script lang="ts">
  import { fetchEvents, type AuditEvent } from "./client";

  interface Props {
    apiBase?: string;
    pollMs?: number;
    limit?: number;
  }

  let { apiBase = "", pollMs = 1500, limit = 100 }: Props = $props();

  let events = $state<AuditEvent[]>([]);
  let error = $state<string | null>(null);

  async function poll() {
    try {
      events = await fetchEvents(apiBase, { limit });
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    poll();
    const id = setInterval(poll, pollMs);
    return () => clearInterval(id);
  });

  function fmtTime(ts: number) {
    return new Date(ts * 1000).toLocaleTimeString();
  }
</script>

<div class="audit-dashboard">
  <h3>Audit log</h3>
  {#if error}
    <p class="error">{error}</p>
  {/if}
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Actor</th>
        <th>Action</th>
        <th>Resource</th>
        <th>Decision</th>
        <th>Reason</th>
        <th>Trace</th>
      </tr>
    </thead>
    <tbody>
      {#each events as ev (ev.id)}
        <tr class={ev.decision === "deny" ? "deny" : "allow"}>
          <td>{fmtTime(ev.ts)}</td>
          <td>{ev.actor_type}:{ev.actor_id}</td>
          <td>{ev.action}</td>
          <td>{ev.resource ?? "—"}</td>
          <td class="decision">{ev.decision}</td>
          <td>{ev.reason ?? "—"}</td>
          <td class="trace" title={ev.trace_id}>{(ev.trace_id ?? "").slice(0, 8)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .audit-dashboard {
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 0.25rem 0.5rem;
    border-bottom: 1px solid #ddd;
  }
  tr.deny .decision {
    color: #b3261e;
    font-weight: 600;
  }
  tr.allow .decision {
    color: #146c2e;
    font-weight: 600;
  }
  .error {
    color: #b3261e;
  }
  .trace {
    opacity: 0.6;
  }
</style>
