<script lang="ts">
  import AuditDashboard from "@harness/AuditDashboard.svelte";
  import * as api from "./api";
  import type {
    AdminUserRow, AgentEvent, ApprovalRow, ApprovalTrace, AgentReport, AgentRow, DelegationTrace, Note, NoteDecision, OidcTrace, ServiceCall, SessionInfo, TokenInfo,
    User, VerifyResult,
  } from "./api";

  let mode = $state<"login" | "signup">("login");
  let username = $state("");
  let password = $state("");
  let error = $state<string | null>(null);

  let currentUser = $state<User | null>(null);
  let sessionInfo = $state<SessionInfo | null>(null);

  let jwtInput = $state("");
  let decodedHeader = $state<Record<string, unknown> | null>(null);
  let decodedPayload = $state<Record<string, unknown> | null>(null);
  let decodeError = $state<string | null>(null);
  let verifyResult = $state<VerifyResult | null>(null);
  let verifyError = $state<string | null>(null);

  let allUsers = $state<AdminUserRow[] | null>(null);
  let allUsersError = $state<string | null>(null);

  let myNotes = $state<Note[] | null>(null);
  let newNoteTitle = $state("");
  let newNoteBody = $state("");
  let createNoteError = $state<string | null>(null);

  let targetNoteId = $state("");
  let targetAction = $state<"read" | "write">("read");
  let writeTitle = $state("");
  let writeBody = $state("");
  let traceResult = $state<NoteDecision | null>(null);
  let traceError = $state<string | null>(null);

  // Lab 05: sessions that came from the IdP are only as alive as their
  // access token. When the IdP says it's gone, the server ends the session
  // and tells us why; show that instead of silently dropping to the login form.
  let tokenInfo = $state<TokenInfo | null>(null);
  let sessionEndedReason = $state<string | null>(null);
  let revokeMessage = $state<string | null>(null);

  async function refreshTokenInfo() {
    try {
      tokenInfo = await api.tokenMine();
    } catch {
      tokenInfo = null;
    }
  }

  async function refreshSession() {
    try {
      currentUser = await api.me();
      sessionInfo = await api.sessionsMine();
      sessionEndedReason = null;
      await refreshTokenInfo();
      await refreshMyNotes();
    } catch (e) {
      const hadSession = currentUser !== null;
      currentUser = null;
      sessionInfo = null;
      tokenInfo = null;
      const msg = e instanceof Error ? e.message : "";
      if (hadSession && msg.startsWith("session ended")) sessionEndedReason = msg;
    }
  }

  // Lab 06: admins can watch service-to-service calls land, from both the
  // IdP's side (token requests) and the app's side (the endpoint decision).
  let serviceRows = $state<ServiceCall[] | null>(null);
  let serviceError = $state<string | null>(null);
  let watchingServices = $state(false);

  async function loadServiceCalls() {
    try {
      serviceRows = await api.serviceCalls();
      serviceError = null;
    } catch (e) {
      serviceError = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    if (!watchingServices) return;
    loadServiceCalls();
    const id = setInterval(loadServiceCalls, 1500);
    return () => clearInterval(id);
  });

  // Lab 07: the agent activity dashboard. Agents are identities in their own
  // right, so the admin can see who they are, who answers for them, and what
  // each one has tried to do.
  let agentRows = $state<AgentRow[] | null>(null);
  let agentEvents = $state<AgentEvent[]>([]);
  let agentReports = $state<AgentReport[]>([]);
  let agentError = $state<string | null>(null);
  let watchingAgents = $state(false);

  async function loadAgentActivity() {
    try {
      const data = await api.agentActivity();
      agentRows = data.agents;
      agentEvents = data.events;
      agentReports = await api.agentReports();
      agentError = null;
    } catch (e) {
      agentError = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    if (!watchingAgents) return;
    loadAgentActivity();
    const id = setInterval(loadAgentActivity, 1500);
    return () => clearInterval(id);
  });

  // Lab 09: ask the agent to act for you, then read the chain back.
  let delegationTraceId = $state<string | null>(null);
  let delegation = $state<DelegationTrace | null>(null);
  let delegationError = $state<string | null>(null);

  async function askTheAgent(kind: "summarise_notes" | "archive_notes" = "summarise_notes") {
    try {
      const ticket = await api.askAgent(kind);
      delegationTraceId = ticket.trace_id;
      delegation = null;
      delegationError = null;
    } catch (e) {
      delegationError = e instanceof Error ? e.message : String(e);
    }
  }

  async function loadDelegation() {
    if (!delegationTraceId) return;
    try {
      delegation = await api.delegationTrace(delegationTraceId);
      delegationError = null;
    } catch (e) {
      delegationError = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    if (!delegationTraceId || delegation?.status === "done") return;
    loadDelegation();
    const id = setInterval(loadDelegation, 1500);
    return () => clearInterval(id);
  });

  // Lab 10: the pending-approval queue. An elevated call from an agent waits
  // here until a person who is allowed to decide it says yes or no.
  let approvalRows = $state<ApprovalRow[]>([]);
  let approvalError = $state<string | null>(null);
  let approvalTrace = $state<ApprovalTrace | null>(null);

  async function loadApprovals() {
    try {
      approvalRows = await api.approvalQueue();
      approvalError = null;
    } catch (e) {
      approvalError = e instanceof Error ? e.message : String(e);
    }
  }

  async function decide(id: number, decision: "approve" | "deny") {
    try {
      await api.decideApproval(id, decision);
      approvalError = null;
      if (approvalTrace) await showApprovalTrace(id);
    } catch (e) {
      approvalError = e instanceof Error ? e.message : String(e);
    }
    await loadApprovals();
  }

  async function showApprovalTrace(id: number) {
    try {
      approvalTrace = await api.approvalTrace(id);
    } catch (e) {
      approvalError = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    if (!currentUser) return;
    loadApprovals();
    const id = setInterval(loadApprovals, 2000);
    return () => clearInterval(id);
  });

  async function revokeToken() {
    revokeMessage = null;
    try {
      await api.revokeMyToken();
      revokeMessage = "Revoked at the IdP. This page hasn't noticed yet: make any request and see what happens.";
    } catch (e) {
      revokeMessage = e instanceof Error ? e.message : String(e);
    }
  }

  async function poke() {
    // Any authenticated request does: the server checks the token with the IdP each time.
    await refreshSession();
  }

  async function submit() {
    error = null;
    try {
      if (mode === "signup") {
        await api.signup(username, password);
      }
      await api.login(username, password);
      password = "";
      await refreshSession();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function doLogout() {
    await api.logout();
    currentUser = null;
    sessionInfo = null;
    allUsers = null;
    allUsersError = null;
    myNotes = null;
    traceResult = null;
    traceError = null;
  }

  async function loadUsers() {
    allUsersError = null;
    allUsers = null;
    try {
      allUsers = await api.listUsers();
    } catch (e) {
      allUsersError = e instanceof Error ? e.message : String(e);
    }
  }

  async function refreshMyNotes() {
    try {
      myNotes = await api.listMyNotes();
    } catch {
      myNotes = null;
    }
  }

  async function submitNewNote() {
    createNoteError = null;
    try {
      await api.createNote(newNoteTitle, newNoteBody);
      newNoteTitle = "";
      newNoteBody = "";
      await refreshMyNotes();
    } catch (e) {
      createNoteError = e instanceof Error ? e.message : String(e);
    }
  }

  async function attemptAccess() {
    traceError = null;
    traceResult = null;
    const noteId = Number(targetNoteId);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      traceError = "enter a valid note id";
      return;
    }
    try {
      traceResult =
        targetAction === "read"
          ? await api.attemptReadNote(noteId)
          : await api.attemptUpdateNote(noteId, writeTitle, writeBody);
      await refreshMyNotes();
    } catch (e) {
      traceError = e instanceof Error ? e.message : String(e);
    }
  }

  function base64UrlDecode(segment: string): string {
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const percentEncoded = Array.from(binary)
      .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
      .join("");
    return decodeURIComponent(percentEncoded);
  }

  function decodeLocally() {
    decodeError = null;
    decodedHeader = null;
    decodedPayload = null;
    verifyResult = null;
    verifyError = null;
    const token = jwtInput.trim();
    if (!token) return;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("a JWT has three dot-separated parts (header.payload.signature)");
      }
      decodedHeader = JSON.parse(base64UrlDecode(parts[0]));
      decodedPayload = JSON.parse(base64UrlDecode(parts[1]));
    } catch (e) {
      decodeError = e instanceof Error ? e.message : String(e);
    }
  }

  async function getFreshToken() {
    verifyError = null;
    try {
      const issued = await api.issueToken();
      jwtInput = issued.access_token;
      decodeLocally();
    } catch (e) {
      verifyError = e instanceof Error ? e.message : String(e);
    }
  }

  async function verifyWithServer() {
    verifyError = null;
    verifyResult = null;
    try {
      verifyResult = await api.verifyToken(jwtInput.trim());
    } catch (e) {
      verifyError = e instanceof Error ? e.message : String(e);
    }
  }

  // Lab 04: after the IdP round trip the app redirects back here with
  // ?oidc_trace=<id> (and ?oidc_error=... when the login failed). Fetch the
  // trace so the learner can see what happened, then tidy the address bar.
  let oidcTrace = $state<OidcTrace | null>(null);
  let oidcTraceError = $state<string | null>(null);

  async function loadOidcTraceFromUrl() {
    const traceId = new URLSearchParams(location.search).get("oidc_trace");
    if (!traceId) return;
    history.replaceState(null, "", location.pathname);
    try {
      oidcTrace = await api.fetchOidcTrace(traceId);
    } catch (e) {
      oidcTraceError = e instanceof Error ? e.message : String(e);
    }
  }

  function msSinceStart(ts: number): number {
    const first = oidcTrace?.events[0]?.ts ?? ts;
    return Math.round((ts - first) * 1000);
  }

  refreshSession();
  loadOidcTraceFromUrl();
</script>

<main>
  <h1>Lab 11 — The confused deputy</h1>

  {#if sessionEndedReason}
    <section class="panel trace-bad">
      <h2>Your session ended</h2>
      <p class="decision-deny">{sessionEndedReason}</p>
      <p class="hint">The audit log below has the matching deny row.</p>
    </section>
  {/if}

  {#if oidcTraceError}
    <section class="panel"><p class="error">Couldn't load the login trace: {oidcTraceError}</p></section>
  {/if}
  {#if oidcTrace}
    <section class="panel" class:trace-ok={oidcTrace.outcome === "success"} class:trace-bad={oidcTrace.outcome !== "success"}>
      <h2>Sign in with Lab IdP: live trace</h2>
      {#if oidcTrace.outcome === "success"}
        <p class="decision-allow">Login succeeded. Every step below was recorded as it happened.</p>
      {:else}
        <p class="decision-deny">Login failed: {oidcTrace.failure_reason ?? "unknown reason"}</p>
      {/if}
      {#if !oidcTrace.idp_reachable}
        <p class="hint">The IdP's own events couldn't be fetched, so only this app's side is shown.</p>
      {/if}
      <table class="trace">
        <thead>
          <tr><th>+ms</th><th>Who</th><th>Step</th><th>Decision</th><th>Why</th></tr>
        </thead>
        <tbody>
          {#each oidcTrace.events as ev (ev.id)}
            <tr class={ev.decision === "deny" ? "deny-row" : ""}>
              <td class="mono">{msSinceStart(ev.ts)}</td>
              <td><span class="who who-{ev.source}">{ev.source === "idp" ? "Lab IdP" : "This app"}</span></td>
              <td class="mono">{ev.action}</td>
              <td class="decision-{ev.decision}">{ev.decision}</td>
              <td>{ev.reason ?? "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if oidcTrace.id_token_claims}
        <h3>ID token claims (after validation)</h3>
        <pre class="mono">{JSON.stringify(oidcTrace.id_token_claims, null, 2)}</pre>
      {/if}
      <p class="hint">Trace id <code>{oidcTrace.trace_id}</code></p>
      <button onclick={() => (oidcTrace = null)}>Dismiss</button>
    </section>
  {/if}

  {#if currentUser}
    <section class="panel">
      <h2>Signed in as {currentUser.username} <span class="role-badge">{currentUser.role}</span></h2>
      <button onclick={doLogout}>Log out</button>
    </section>

    {#if tokenInfo?.federated}
      <section class="panel">
        <h2>Access token and grants</h2>
        <p class="hint">
          You signed in through the Lab IdP, so this session is backed by an access token. The server
          asks the IdP whether it's still good on every request.
        </p>
        <p>
          Scopes you shared:
          {#each tokenInfo.scopes ?? [] as scope (scope)}
            <span class="scope">{scope}</span>
          {/each}
        </p>
        <p class="hint">
          Token <code>{tokenInfo.jti_prefix}</code>, {tokenInfo.active ? "active" : "not active"}, expires
          {tokenInfo.expires_at ? new Date(tokenInfo.expires_at * 1000).toLocaleTimeString() : "unknown"}.
          If a scope is missing, you unticked it on the consent screen: try creating a note.
        </p>
        <div class="row">
          <button onclick={refreshTokenInfo}>Introspect now</button>
          <button onclick={revokeToken}>Revoke this token</button>
          <button onclick={poke}>Make a request</button>
        </div>
        {#if revokeMessage}
          <p class="hint">{revokeMessage}</p>
        {/if}
      </section>
    {/if}

    {#if tokenInfo?.federated}
      <section class="panel">
        <h2>Ask the agent to act for you</h2>
        <p class="hint">
          The agent will read your notes and write a short report. It never sees your password. It is handed
          your access token for this one task, and trades it at the IdP for a token that names you both. Then
          run <code>python -m agent_runner --tasks</code> in a terminal. To have it pass the filing to a second agent,
          ask the agents to archive your notes, then run <code>--hand-off</code> and <code>--archive</code>.
        </p>
        <div class="row">
          <button onclick={() => askTheAgent("summarise_notes")}>Ask the agent to summarise my notes</button>
          <button onclick={() => askTheAgent("archive_notes")}>Ask the agents to archive my notes</button>
          <button onclick={loadDelegation} disabled={!delegationTraceId}>Refresh trace</button>
        </div>
        {#if delegationError}
          <p class="error">{delegationError}</p>
        {/if}
        {#if delegationTraceId && !delegation}
          <p class="hint">Task queued under trace <code>{delegationTraceId}</code>. Waiting for the agent.</p>
        {/if}
        {#if delegation}
          <h3>Who acted, in order</h3>
          <p class="chain">
            {#each delegation.chain as hop, i (hop.role + hop.id)}
              {#if i > 0}<span class="arrow">→</span>{/if}
              <span class="hop hop-{hop.role}"><small>{hop.role}</small> {hop.id}</span>
            {:else}
              <span class="hint">Nothing has happened yet.</span>
            {/each}
          </p>
          <table class="trace">
            <thead><tr><th>Where</th><th>Who</th><th>On behalf of</th><th>Action</th><th>Decision</th><th>Why</th></tr></thead>
            <tbody>
              {#each delegation.events as ev (ev.id)}
                <tr class={ev.decision === "deny" ? "deny-row" : ""}>
                  <td class="mono">{ev.source}</td>
                  <td class="mono">
                    {ev.actor_type}:{ev.actor_id}
                    {#if ev.metadata.via?.length}<br /><span class="hint">via {ev.metadata.via.join(" → ")}</span>{/if}
                  </td>
                  <td class="mono">{ev.metadata.on_behalf_of ?? "—"}</td>
                  <td class="mono">{ev.action}</td>
                  <td class="decision-{ev.decision}">{ev.decision}</td>
                  <td>
                    {#if ev.metadata.violation}<strong class="decision-deny">scope violation</strong>{" "}{/if}{ev.reason ?? "—"}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          <p class="hint">Trace <code>{delegation.trace_id}</code>, task {delegation.status}.</p>
        {/if}
      </section>
    {/if}

    <section class="panel">
      <h2>Admin panel — all users</h2>
      <p class="hint">
        Only the <code>admin</code> role can load this. You're signed in as
        <strong>{currentUser.username}</strong>, role <strong>{currentUser.role}</strong> —
        try it and see what happens.
      </p>
      <button onclick={loadUsers}>Load all users</button>
      {#if allUsersError}
        <p class="error">
          Denied: {allUsersError}. Check the audit log below for the exact reason.
        </p>
      {/if}
      {#if allUsers}
        <table>
          <thead>
            <tr><th>Id</th><th>Username</th><th>Role</th></tr>
          </thead>
          <tbody>
            {#each allUsers as row (row.id)}
              <tr><td>{row.id}</td><td>{row.username}</td><td>{row.role}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section class="panel">
      <h2>Service-to-service calls</h2>
      <p class="hint">
        Run the digest job from a terminal (<code>python -m digest_service</code>) and watch it land here.
        Admin only: other roles get a 403 and a deny row in the audit log.
      </p>
      <div class="row">
        <button onclick={loadServiceCalls}>Load once</button>
        <button onclick={() => (watchingServices = !watchingServices)}>
          {watchingServices ? "Stop watching" : "Watch live"}
        </button>
      </div>
      {#if serviceError}
        <p class="error">Denied: {serviceError}</p>
      {/if}
      {#if serviceRows}
        <table class="trace">
          <thead>
            <tr><th>Time</th><th>Side</th><th>Who</th><th>Step</th><th>Decision</th><th>Why</th></tr>
          </thead>
          <tbody>
            {#each serviceRows as row (row.id)}
              <tr class={row.decision === "deny" ? "deny-row" : ""}>
                <td class="mono">{new Date(row.ts * 1000).toLocaleTimeString()}</td>
                <td><span class="who who-{row.source === 'idp' ? 'idp' : 'client'}">{row.source === "idp" ? "Lab IdP" : "This app"}</span></td>
                <td>{row.actor_id}</td>
                <td class="mono">{row.action}</td>
                <td class="decision-{row.decision}">{row.decision}</td>
                <td>{row.reason ?? "—"}</td>
              </tr>
            {:else}
              <tr><td colspan="6">No service calls yet.</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section class="panel" id="approvals">
      <h2>Pending approvals</h2>
      <p class="hint">
        When an agent asks for something elevated, it waits here. Run
        <code>python -m agent_runner --elevated</code> in a terminal and the request appears within a second or
        two. You see the requests you are allowed to decide: admins see all of them, a sponsor sees their own
        agent's.
      </p>
      {#if approvalError}
        <p class="error">{approvalError}</p>
      {/if}
      <table>
        <thead><tr><th>Agent</th><th>Asking to</th><th>Status</th><th>Time left</th><th></th></tr></thead>
        <tbody>
          {#each approvalRows as a (a.id)}
            <tr class={a.status === "denied" || a.status === "expired" ? "deny-row" : ""}>
              <td>
                <span class="who who-client">agent:{a.agent_id}</span>
                <span class="hint">for {a.sponsor ?? "nobody"}</span>
              </td>
              <td class="mono">{a.tool}({Object.entries(a.args).map(([k, v]) => `${k}=${v}`).join(", ")})</td>
              <td class="status-{a.status}">
                {a.status}{#if a.decided_by}{" "}<span class="hint">by {a.decided_by}</span>{/if}
              </td>
              <td class="mono">{a.seconds_left !== null ? `${Math.ceil(a.seconds_left)}s` : "—"}</td>
              <td class="row">
                {#if a.status === "pending"}
                  <button onclick={() => decide(a.id, "approve")}>Approve</button>
                  <button class="link" onclick={() => decide(a.id, "deny")}>Deny</button>
                {/if}
                <button class="link" onclick={() => showApprovalTrace(a.id)}>Trace</button>
              </td>
            </tr>
          {:else}
            <tr><td colspan="5">Nothing is waiting for you.</td></tr>
          {/each}
        </tbody>
      </table>
      {#if approvalTrace}
        <h3>One request, one trace</h3>
        <table class="trace">
          <thead><tr><th>Who</th><th>Action</th><th>Decision</th><th>Why</th></tr></thead>
          <tbody>
            {#each approvalTrace.events as ev (ev.id)}
              <tr class={ev.decision === "deny" ? "deny-row" : ""}>
                <td class="mono">{ev.actor_type}:{ev.actor_id}</td>
                <td class="mono">{ev.action}</td>
                <td class="decision-{ev.decision}">{ev.decision}</td>
                <td>{ev.reason ?? "—"}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="hint">Trace <code>{approvalTrace.trace_id}</code></p>
      {/if}
    </section>

    <section class="panel">
      <h2>Agent activity</h2>
      <p class="hint">
        Run the agent from a terminal (<code>python -m agent_runner --ticks 3 --interval 5</code>) and watch it
        appear here, under its own name and its sponsor's. Then run it with <code>--probe</code> to watch the
        policy engine refuse it, and read which policy did. Admin only.
      </p>
      <div class="row">
        <button onclick={loadAgentActivity}>Load once</button>
        <button onclick={() => (watchingAgents = !watchingAgents)}>
          {watchingAgents ? "Stop watching" : "Watch live"}
        </button>
      </div>
      {#if agentError}
        <p class="error">Denied: {agentError}</p>
      {/if}
      {#if agentRows}
        <h3>Agents the app has seen</h3>
        <table>
          <thead><tr><th>Agent</th><th>Name</th><th>Sponsor</th><th>Last seen</th></tr></thead>
          <tbody>
            {#each agentRows as a (a.client_id)}
              <tr>
                <td class="mono">{a.client_id}</td>
                <td>{a.name}</td>
                <td class="mono">{a.sponsor_sub ?? "none recorded"}</td>
                <td>{new Date(a.last_seen * 1000).toLocaleTimeString()}</td>
              </tr>
            {:else}
              <tr><td colspan="4">No agent has called the app yet.</td></tr>
            {/each}
          </tbody>
        </table>
        <h3>What they did</h3>
        <table class="trace">
          <thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Decision</th><th>Policy</th><th>Why</th></tr></thead>
          <tbody>
            {#each agentEvents as ev (ev.id)}
              <tr class={ev.decision === "deny" ? "deny-row" : ""}>
                <td class="mono">{new Date(ev.ts * 1000).toLocaleTimeString()}</td>
                <td>
                  <span class="who who-client">agent:{ev.actor_id}</span>
                  {#if ev.metadata.sponsor}<span class="hint">for {ev.metadata.sponsor}</span>{/if}
                </td>
                <td class="mono">{ev.action}</td>
                <td class="decision-{ev.decision}">{ev.decision}</td>
                <td class="mono">{ev.metadata.policies?.join(", ") ?? "—"}</td>
                <td>{ev.reason ?? "—"}</td>
              </tr>
            {:else}
              <tr><td colspan="6">Nothing yet.</td></tr>
            {/each}
          </tbody>
        </table>
        {#if agentReports.length}
          <h3>Reports they left</h3>
          {#each agentReports.slice(0, 3) as r (r.id)}
            <p><strong>{r.title}</strong> <span class="hint">by {r.agent_id}</span><br />{r.body}</p>
          {/each}
        {/if}
      {/if}
    </section>

    <section class="panel">
      <h2>Cookie / session inspector</h2>
      <p>
        <code>document.cookie</code> as seen by this page's JavaScript:
        <code class="mono">{document.cookie || "(empty)"}</code>
      </p>
      <p class="hint">
        The session cookie doesn't show up there — it's set
        <code>HttpOnly</code>, so JavaScript on this page can never read it,
        only the browser and the server can. What the server actually holds
        for your session:
      </p>
      {#if sessionInfo}
        <table>
          <tbody>
            <tr><th>Session id (prefix)</th><td>{sessionInfo.session_id_prefix}</td></tr>
            <tr><th>User id</th><td>{sessionInfo.user_id}</td></tr>
            <tr><th>Created at</th><td>{new Date(sessionInfo.created_at * 1000).toLocaleString()}</td></tr>
            <tr><th>Expires at</th><td>{new Date(sessionInfo.expires_at * 1000).toLocaleString()}</td></tr>
            <tr><th>Seconds remaining</th><td>{Math.round(sessionInfo.seconds_remaining)}</td></tr>
          </tbody>
        </table>
      {/if}
    </section>

    <section class="panel">
      <h2>Notes and the policy-decision trace</h2>
      <p class="hint">
        A note has one owner. Reading or updating one is an ABAC decision:
        it depends on the relationship between you and that specific note
        (are you its owner?), not just your role — RBAC's admin panel above
        can't express that. Every attempt below runs through the policy
        evaluator and reports back exactly which rule decided the outcome.
      </p>

      <h3>Create a note</h3>
      <form onsubmit={(e) => { e.preventDefault(); submitNewNote(); }}>
        <label>
          Title
          <input bind:value={newNoteTitle} required />
        </label>
        <label>
          Body
          <input bind:value={newNoteBody} required />
        </label>
        <button type="submit">Create note (owned by you)</button>
      </form>
      {#if createNoteError}
        <p class="error">{createNoteError}</p>
      {/if}

      <h3>Your notes</h3>
      {#if myNotes && myNotes.length}
        <table>
          <thead>
            <tr><th>Id</th><th>Title</th><th>Owner</th></tr>
          </thead>
          <tbody>
            {#each myNotes as note (note.id)}
              <tr><td>{note.id}</td><td>{note.title}</td><td>{note.owner_username}</td></tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="hint">No notes yet — create one above, or ask another signed-up user for one of their note ids to try below.</p>
      {/if}

      <h3>Try reading or updating any note by id</h3>
      <p class="hint">
        Enter any note id, yours or someone else's, and see whether the
        policy evaluator lets you through — and which rule made that call.
      </p>
      <form onsubmit={(e) => { e.preventDefault(); attemptAccess(); }}>
        <label>
          Note id
          <input bind:value={targetNoteId} inputmode="numeric" required />
        </label>
        <label>
          Action
          <select bind:value={targetAction}>
            <option value="read">read</option>
            <option value="write">write (update)</option>
          </select>
        </label>
        {#if targetAction === "write"}
          <label>
            New title
            <input bind:value={writeTitle} required />
          </label>
          <label>
            New body
            <input bind:value={writeBody} required />
          </label>
        {/if}
        <button type="submit">Attempt {targetAction}</button>
      </form>

      {#if traceError}
        <p class="error">{traceError}</p>
      {/if}

      {#if traceResult}
        <h4>Policy-decision trace</h4>
        <table>
          <tbody>
            <tr>
              <th>Outcome</th>
              <td class={traceResult.allowed ? "decision-allow" : "decision-deny"}>
                {traceResult.allowed ? "ALLOW" : "DENY"}
              </td>
            </tr>
            <tr><th>Rule fired</th><td class="mono">{traceResult.rule_id}</td></tr>
            <tr><th>Rule description</th><td>{traceResult.rule_description}</td></tr>
          </tbody>
        </table>
        {#if traceResult.allowed && traceResult.note}
          <p class="hint">Note content ({targetAction === "write" ? "after update" : "current"}):</p>
          <pre class="mono">title: {traceResult.note.title}
body:  {traceResult.note.body}
owner: {traceResult.note.owner_username} (id {traceResult.note.owner_id})</pre>
        {/if}
      {/if}
    </section>
  {:else}
    <section class="panel">
      <h2>{mode === "login" ? "Log in" : "Sign up"}</h2>
      <form onsubmit={(e) => { e.preventDefault(); submit(); }}>
        <label>
          Username
          <input bind:value={username} autocomplete="username" required />
        </label>
        <label>
          Password
          <input type="password" bind:value={password} autocomplete="current-password" required />
        </label>
        <button type="submit">{mode === "login" ? "Log in" : "Sign up"}</button>
      </form>
      <button class="link" onclick={() => (mode = mode === "login" ? "signup" : "login")}>
        {mode === "login" ? "Need an account? Sign up" : "Have an account? Log in"}
      </button>
      {#if error}
        <p class="error">{error}</p>
      {/if}
      <hr />
      <a class="idp-button" href={api.oidcLoginUrl}>Sign in with Lab IdP</a>
      <p class="hint">
        You'll leave this app for the IdP's own page. Lab accounts there:
        <code>alice</code>, <code>bob</code>, <code>carol</code> (password <code>&lt;name&gt;-lab-pass</code>).
      </p>
    </section>
  {/if}

  <section class="panel">
    <h2>Live JWT decoder</h2>
    <p class="hint">
      Paste any JWT below, or fetch a fresh one for your current session.
      The header and payload decode instantly, client-side, with no network
      call and no secret needed — a JWT's claims are base64url, not
      encrypted, so anyone holding the token can already read them. Whether
      the <em>signature</em> is genuine, and whether the token has expired,
      is something only the server can tell you, because only the server
      holds the key that signed it.
    </p>
    <textarea
      rows="3"
      bind:value={jwtInput}
      oninput={decodeLocally}
      placeholder="paste a JWT here, or fetch one below"
    ></textarea>
    <div class="row">
      <button onclick={getFreshToken} disabled={!currentUser}>
        Get a fresh token for my session
      </button>
      <button onclick={verifyWithServer} disabled={!jwtInput.trim()}>
        Verify signature &amp; expiry with server
      </button>
    </div>
    {#if !currentUser}
      <p class="hint">Log in to fetch a token — decoding a pasted token works either way.</p>
    {/if}

    {#if decodeError}
      <p class="error">{decodeError}</p>
    {/if}

    {#if decodedHeader || decodedPayload}
      <h3>Claims — decoded locally, readable by anyone, prove nothing on their own</h3>
      <pre class="mono">header:  {JSON.stringify(decodedHeader, null, 2)}
payload: {JSON.stringify(decodedPayload, null, 2)}</pre>
    {/if}

    {#if verifyError}
      <p class="error">{verifyError}</p>
    {/if}

    {#if verifyResult}
      <h3>Server verification — requires the signing key</h3>
      <table>
        <tbody>
          <tr><th>Signature valid</th><td>{verifyResult.signature_valid ? "yes" : "no"}</td></tr>
          <tr><th>Expired</th><td>{verifyResult.expired ? "yes" : "no"}</td></tr>
          <tr><th>Overall valid</th><td>{verifyResult.valid ? "yes" : "no"}</td></tr>
          {#if verifyResult.reason}
            <tr><th>Reason</th><td>{verifyResult.reason}</td></tr>
          {/if}
        </tbody>
      </table>
    {/if}
  </section>

  <section class="panel">
    <AuditDashboard apiBase={api.API_BASE} />
  </section>
</main>

<style>
  main {
    max-width: 920px;
    margin: 2rem auto;
    font-family: system-ui, sans-serif;
    padding: 0 1rem;
  }
  .panel {
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 1.5rem;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-width: 320px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.9rem;
  }
  input, textarea, select {
    padding: 0.4rem;
    font-size: 1rem;
    font-family: inherit;
    width: 100%;
    box-sizing: border-box;
  }
  textarea {
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
    resize: vertical;
  }
  .row {
    display: flex;
    gap: 0.5rem;
    margin: 0.5rem 0;
    flex-wrap: wrap;
  }
  button {
    padding: 0.5rem 1rem;
    cursor: pointer;
  }
  button:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  button.link {
    background: none;
    border: none;
    color: #2563eb;
    text-decoration: underline;
    padding: 0.5rem 0;
  }
  .error {
    color: #b3261e;
  }
  .decision-allow {
    color: #146c2e;
    font-weight: 600;
  }
  .decision-deny {
    color: #b3261e;
    font-weight: 600;
  }
  .role-badge {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    background: rgba(37, 99, 235, 0.12);
    color: #2563eb;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    vertical-align: middle;
  }
  .hint {
    font-size: 0.85rem;
    opacity: 0.8;
  }
  .mono {
    font-family: ui-monospace, monospace;
  }
  pre.mono {
    white-space: pre-wrap;
    word-break: break-word;
    background: rgba(127, 127, 127, 0.08);
    padding: 0.75rem;
    border-radius: 6px;
    font-size: 0.8rem;
  }
  .idp-button {
    display: inline-block;
    padding: 0.5rem 1rem;
    background: #2563eb;
    color: white;
    border-radius: 6px;
    text-decoration: none;
  }
  .scope {
    display: inline-block;
    font-family: ui-monospace, monospace;
    font-size: 0.8rem;
    background: rgba(37, 99, 235, 0.12);
    color: #1d4ed8;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    margin-right: 0.3rem;
  }
  .trace-ok { border-color: #146c2e; }
  .trace-bad { border-color: #b3261e; }
  .status-pending { color: #b45309; font-weight: 600; }
  .status-approved, .status-used { color: #15803d; font-weight: 600; }
  .status-denied, .status-expired { color: #b91c1c; font-weight: 600; }
  .chain { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; }
  .hop { border: 1px solid #888; border-radius: 6px; padding: 0.25rem 0.6rem; font-family: ui-monospace, monospace; }
  .hop small { text-transform: uppercase; opacity: 0.65; margin-right: 0.3rem; }
  .hop-human { background: rgba(32, 96, 200, 0.12); }
  .hop-agent { background: rgba(20, 108, 46, 0.12); }
  .hop-api { background: rgba(120, 80, 160, 0.12); }
  .arrow { opacity: 0.6; }
  .trace .deny-row td { background: rgba(179, 38, 30, 0.07); }
  .who {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    white-space: nowrap;
  }
  .who-client { background: rgba(37, 99, 235, 0.12); color: #2563eb; }
  .who-idp { background: rgba(146, 64, 14, 0.14); color: #92400e; }
  table {
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 0.2rem 0.6rem;
  }
</style>
