<script lang="ts">
  import AuditDashboard from "@harness/AuditDashboard.svelte";
  import * as api from "./api";
  import type { AdminUserRow, Note, NoteDecision, SessionInfo, User, VerifyResult } from "./api";

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

  async function refreshSession() {
    try {
      currentUser = await api.me();
      sessionInfo = await api.sessionsMine();
      await refreshMyNotes();
    } catch {
      currentUser = null;
      sessionInfo = null;
    }
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

  refreshSession();
</script>

<main>
  <h1>Lab 03 — ABAC/ReBAC</h1>

  {#if currentUser}
    <section class="panel">
      <h2>Signed in as {currentUser.username} <span class="role-badge">{currentUser.role}</span></h2>
      <button onclick={doLogout}>Log out</button>
    </section>

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
    max-width: 720px;
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
  table {
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 0.2rem 0.6rem;
  }
</style>
