<script lang="ts">
  import AuditDashboard from "@harness/AuditDashboard.svelte";
  import * as api from "./api";
  import type { SessionInfo, User } from "./api";

  let mode = $state<"login" | "signup">("login");
  let username = $state("");
  let password = $state("");
  let error = $state<string | null>(null);

  let currentUser = $state<User | null>(null);
  let sessionInfo = $state<SessionInfo | null>(null);

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

  refreshSession();
</script>

<main>
  <h1>Lab 00 — Sessions &amp; Cookies</h1>

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
  input {
    padding: 0.4rem;
    font-size: 1rem;
  }
  button {
    padding: 0.5rem 1rem;
    cursor: pointer;
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
  table {
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 0.2rem 0.6rem;
  }
</style>
