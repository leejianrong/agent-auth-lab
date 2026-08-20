<script lang="ts">
  import AuditDashboard from "@harness/AuditDashboard.svelte";
  import * as api from "./api";
  import type { SessionInfo, User, VerifyResult } from "./api";

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

  async function refreshSession() {
    try {
      currentUser = await api.me();
      sessionInfo = await api.sessionsMine();
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
  <h1>Lab 01 — JWTs</h1>

  {#if currentUser}
    <section class="panel">
      <h2>Signed in as {currentUser.username}</h2>
      <button onclick={doLogout}>Log out</button>
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
  input, textarea {
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
