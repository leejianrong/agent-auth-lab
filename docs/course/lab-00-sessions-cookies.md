---
icon: lucide/key-round
---

# Lab 00: sessions and cookies

You'll build a login system from scratch: a signup and login endpoint, a
server-side session store, and a cookie that ties a browser to that session.
Then you'll find two real bugs in it (plaintext passwords and a session
fixation hole) and fix both yourself.

This is the only lab in the course with no agents anywhere in it. Everything
here is the foundation the rest of the course builds on, so it's worth taking
slowly.

## What you'll learn

- What a session actually is on the server side, and what the cookie in the
  browser does and doesn't contain
- Why passwords must never be stored as-is, and what a password hash buys you
- What session fixation is, how an attacker exploits it, and the one-line fix
  that closes it
- How to read a structured audit log to see an authorization decision (allow
  or deny) as it happens, not just guess at it from a status code

## What a session is

A cookie is just a string the browser sends back on every request to the
domain that set it. On its own it proves nothing. The security comes from
what's on the server: a session record that says "this opaque string
corresponds to user 42, created at this time, expiring at that time." The
cookie is a claim; the session record is the source of truth. The session
inspector you'll meet in task 3 puts the two side by side.


??? note "Background: why hash passwords, and what session fixation is"

    ### Why hash passwords

    If your database is ever read by someone who shouldn't read it (a backup
    that leaks, a misconfigured bucket, a SQL injection bug somewhere else
    entirely), a plaintext password column hands them every user's real password
    immediately. A password hash is a one-way function: easy to compute forward,
    practically impossible to reverse. You check a login attempt by hashing the
    submitted password and comparing hashes, never by storing or comparing the
    original.

    This lab uses [Argon2](https://en.wikipedia.org/wiki/Argon2), the winner of
    the Password Hashing Competition and the current recommendation from OWASP.
    Older systems you'll encounter in the wild often use bcrypt or PBKDF2
    instead; the principle is identical even if the algorithm differs.

    ### Session fixation

    Suppose login "elevates" whatever session the browser already presents,
    rather than issuing a fresh one. The attacker was never near the victim's
    password. They just needed their chosen session id to survive the victim's
    login. Task 2 walks through the attack one message at a time. The fix is one
    rule: **login always issues a brand-new session id**, and never reuses
    whatever the client happened to send beforehand.

## Prerequisites

- Python 3.12
- Node.js (any recent version; the course was built and tested on Node 24)
- `uv` or plain `pip` for installing Python dependencies

## Setup

```sh
cd labs/lab-00-sessions-cookies/starter/backend
uv venv .venv --python 3.12
uv pip install -r requirements.txt --python .venv/bin/python
```

```sh
cd labs/lab-00-sessions-cookies/starter/frontend
npm install
```

## Your tasks

Open `starter/backend/app/security.py`. You'll find three functions marked
with a `TODO(lab-00)` comment.

### 1. Hash passwords properly

Right now, `hash_password` and `verify_password` look like this:

```python title="starter/backend/app/security.py"
def hash_password(password: str) -> str:
    # TODO(lab-00): this stores the password as-is. Anyone who reads the
    # database (a backup, a leaked file, an SQL-injection bug elsewhere)
    # gets every user's real password. Hash it instead — see the "Password
    # Hashing" section of the lab 00 handout, and the `argon2` package
    # that's already a dependency.
    return password


def verify_password(password: str, password_hash: str) -> bool:
    # TODO(lab-00): this only works because hash_password() above doesn't
    # actually hash anything yet. Once you fix hash_password(), this needs
    # to verify against the hash, not compare raw strings.
    return password == password_hash
```

Fix both using the `argon2` package, which is already a dependency and
already imported at the top of the file. `PasswordHasher` (from
`argon2`) has a `.hash(password)` method for writes and a `.verify(hash,
password)` method for reads; the latter raises `VerifyMismatchError`
(already imported for you) on a mismatch rather than returning `False`
directly, so `verify_password` needs to catch that.

### 2. Stop session fixation

Here is the attack you're about to close. Step through it first: the attacker
never learns the victim's password, and the whole thing turns on one decision
the server makes in step 4.

<!-- stepper: flows/session-fixation.flow -->
<div class="stepper" markdown>

<figure class="stepper-diagram">
<svg class="flow" viewBox="0 0 700 420" role="img" aria-label="Sequence diagram: Attacker, Victim, Server">
<g class="actor"><rect x="45" y="8" width="110" height="34" rx="6"/><text x="100" y="30" text-anchor="middle">Attacker</text></g>
<g class="actor"><rect x="295" y="8" width="110" height="34" rx="6"/><text x="350" y="30" text-anchor="middle">Victim</text></g>
<g class="actor"><rect x="545" y="8" width="110" height="34" rx="6"/><text x="600" y="30" text-anchor="middle">Server</text></g>
<line class="life" x1="100" y1="42" x2="100" y2="410"/>
<line class="life" x1="350" y1="42" x2="350" y2="410"/>
<line class="life" x1="600" y1="42" x2="600" y2="410"/>
<g class="msg" id="m1"><line x1="100" y1="100" x2="591" y2="100"/><polygon points="600,100 591,95 591,105"/><text x="350" y="93" text-anchor="middle">1 GET / (no login)</text></g>
<g class="msg" id="m2"><line x1="100" y1="158" x2="341" y2="158"/><polygon points="350,158 341,153 341,163"/><text x="225" y="151" text-anchor="middle">2 link that sets FIXED123</text></g>
<g class="msg" id="m3"><line x1="350" y1="216" x2="591" y2="216"/><polygon points="600,216 591,211 591,221"/><text x="475" y="209" text-anchor="middle">3 POST /login + FIXED123</text></g>
<g class="secret" id="s4_1"><rect x="404" y="280" width="186" height="22"/><text x="497" y="295" text-anchor="middle">FIXED123 is now the victim&#x27;s</text></g>
<g class="msg" id="m5"><line x1="100" y1="332" x2="591" y2="332"/><polygon points="600,332 591,327 591,337"/><text x="350" y="325" text-anchor="middle">5 GET /me + FIXED123</text></g>
</svg>
</figure>

<div class="step" data-title="The attacker gets a session id of their own" data-hl="m1" markdown>
The attacker visits the site without logging in and is handed a
session id, `FIXED123`. Nothing about it is valuable yet, because nobody is
logged in behind it.
</div>

<div class="step" data-title="The attacker plants that id in the victim&#x27;s browser" data-hl="m2" markdown>
A crafted link, a cookie set from a sibling subdomain, or a hostile
network can all do this. The attacker never touches the victim's password.
</div>

<div class="step" data-title="The victim logs in carrying the planted cookie" data-hl="m3" markdown>
The victim types the right password. The server accepts it, and now has
to decide which session id the login should be attached to.
</div>

<div class="step" data-title="A vulnerable server keeps the id it was given" data-hl="s4_1" markdown>
This is the bug in the lab 00 starter. The server reuses the id the
request came with, so the session the attacker already knows about turns
into a logged-in one.
</div>

<div class="step" data-title="The attacker uses the id they already had" data-hl="m5" markdown>
The server sees a valid, authenticated session and answers as the
victim. The only thing that would have stopped this is a login that never
reuses an id supplied from outside.
</div>

</div>
<!-- /stepper -->

??? question "The victim logs in with the right password, and the request carries the cookie `FIXED123`. Which session id does the starter's login hand back?"
    `FIXED123`, the same one. The starter only mints a new id when the request
    arrives with no cookie at all, so a cookie that was planted before login
    survives it and becomes a logged-in session. That is why the attacker's last
    request in the diagram works.

Further down the same file, `resolve_login_session_id` looks like this:

```python title="starter/backend/app/security.py"
def resolve_login_session_id(cookie_session_id: str | None) -> str:
    """What session id does a successful login issue?"""
    # TODO(lab-00): reusing whatever session id the client already sent (or
    # minting one only if none was sent) opens session fixation — an
    # attacker can set a victim's cookie *before* they log in, then reuse
    # that same session id afterward, now authenticated as the victim.
    # Always issue a fresh session id here instead. See "Session Fixation"
    # in the lab 00 handout.
    return cookie_session_id or new_session_id()
```

Fix it so a successful login always mints a fresh session id, ignoring
`cookie_session_id` entirely. `new_session_id()` is already defined a few
lines above and does exactly what its name says.

!!! warning "Don't just delete the parameter"
    It's tempting to simplify the function signature once you stop using
    `cookie_session_id`. Leave it as-is for this lab: a later lab reuses this
    same shape when a request needs to compare an incoming credential against
    a freshly-issued one.

### 3. Run it and watch it work

Before you start the app, step through a login once. The last two steps are
exactly what the session inspector shows you.

<!-- stepper: flows/login-session.flow -->
<div class="stepper" markdown>

<figure class="stepper-diagram">
<svg class="flow" viewBox="0 0 700 478" role="img" aria-label="Sequence diagram: Browser, Server, sessions table">
<g class="actor"><rect x="45" y="8" width="110" height="34" rx="6"/><text x="100" y="30" text-anchor="middle">Browser</text></g>
<g class="actor"><rect x="295" y="8" width="110" height="34" rx="6"/><text x="350" y="30" text-anchor="middle">Server</text></g>
<g class="actor"><rect x="545" y="8" width="110" height="34" rx="6"/><text x="600" y="30" text-anchor="middle">sessions table</text></g>
<line class="life" x1="100" y1="42" x2="100" y2="468"/>
<line class="life" x1="350" y1="42" x2="350" y2="468"/>
<line class="life" x1="600" y1="42" x2="600" y2="468"/>
<g class="msg" id="m1"><line x1="100" y1="100" x2="341" y2="100"/><polygon points="350,100 341,95 341,105"/><text x="225" y="93" text-anchor="middle">1 POST /login</text></g>
<g class="secret" id="s2_1"><rect x="360" y="164" width="120" height="22"/><text x="420" y="179" text-anchor="middle">verify_password()</text></g>
<g class="msg" id="m3"><line x1="350" y1="216" x2="591" y2="216"/><polygon points="600,216 591,211 591,221"/><text x="475" y="209" text-anchor="middle">3 INSERT id, user, expiry</text></g>
<g class="msg" id="m4"><line x1="350" y1="274" x2="109" y2="274"/><polygon points="100,274 109,269 109,279"/><text x="225" y="267" text-anchor="middle">4 Set-Cookie: session_id</text></g>
<g class="msg" id="m5"><line x1="100" y1="332" x2="341" y2="332"/><polygon points="350,332 341,327 341,337"/><text x="225" y="325" text-anchor="middle">5 GET /sessions/mine + cookie</text></g>
<g class="msg" id="m6"><line x1="350" y1="390" x2="591" y2="390"/><polygon points="600,390 591,385 591,395"/><text x="475" y="383" text-anchor="middle">6 SELECT by id</text></g>
</svg>
</figure>

<div class="step" data-title="You send a username and password" data-hl="m1" markdown>
The only time the password travels. Everything after this step rides on
the cookie instead.
</div>

<div class="step" data-title="The server checks the password against its hash" data-hl="s2_1" markdown>
The server never compares the password you typed with a stored copy. It
hashes your attempt and compares the two hashes. This is the function you
fix in task 1.
</div>

<div class="step" data-title="The server writes a session row" data-hl="m3" markdown>
The row is the real session. It says which user the id belongs to and
when it stops being valid. The id comes from `resolve_login_session_id`,
the function you fix in task 2.
</div>

<div class="step" data-title="The browser gets a cookie holding only the id" data-hl="m4" markdown>
The cookie is `HttpOnly`, so JavaScript on the page can't read it. It
holds an opaque id and nothing else. No name, no role, no expiry you could
trust.
</div>

<div class="step" data-title="The browser sends it back by itself" data-hl="m5" markdown>
From now on the browser attaches the cookie to every request to this
site. You don't write any code for that. It is also why the cookie is
worth stealing: whoever presents it is treated as you.
</div>

<div class="step" data-title="The server trusts the row, not the cookie" data-hl="m6" markdown>
A cookie that matches no row, or a row that has expired, gets a 401. The
session inspector in the app shows both sides of this step at once: an
empty `document.cookie` next to what the server holds.
</div>

</div>
<!-- /stepper -->


Start the backend and frontend in two terminals:

```sh
cd labs/lab-00-sessions-cookies/starter/backend
.venv/bin/uvicorn app.main:app --reload
```

```sh
cd labs/lab-00-sessions-cookies/starter/frontend
npm run dev
```

Open the frontend (Vite will print the local URL, normally
`http://localhost:5173`).

??? question "After you log in, the session inspector shows two things side by side. What do you expect `document.cookie` to contain, and what do you expect the server to report?"
    `document.cookie` is empty, because the session cookie is `HttpOnly` and the
    page's JavaScript can't see it. The server side shows the first eight
    characters of the session id, the creation time, the expiry and a
    countdown, because it is the one holding the real session row. The cookie
    is only a pointer to it.

Sign up, log in, and look at the session inspector
panel: it shows you `document.cookie` as your own JavaScript sees it next to
what the server actually holds for your session, matching the last two steps of the
diagram above. Below that, the audit log panel updates live every time you log in,
log out, or get denied.

## You're done when

Run the self-check suite from `starter/backend`:

```sh
.venv/bin/pytest tests/ -v
```

- [ ] `test_password_hashing_round_trips` passes: a password hashes to
      something other than itself, and only the right password verifies
      against it
- [ ] `test_password_stored_hashed_not_plaintext` passes: the database
      column never contains the raw password
- [ ] `test_session_id_rotates_on_login_session_fixation` passes: a
      pre-existing cookie is never reused as the post-login session id
- [ ] Every other test in the suite still passes (they should, untouched,
      from the start; if one of them broke, you changed something you
      didn't mean to)
- [ ] In the browser, the session inspector shows a session id, a creation
      time, and a countdown, and the audit log shows an `allow` entry for
      your login

## Going further

These don't have a self-check. Try them, then decide for yourself whether
your answer holds up. Lab 01's handout opens with a discussion of these.

1. This lab hashes session tokens nowhere: the raw session id sits in the
   `sessions` table exactly as it's sent in the cookie. What's the actual
   risk if someone reads that table directly, and what would you change to
   reduce it?
2. The session TTL is a flat 30 minutes from creation, with no concept of
   "still active, extend it" versus "abandoned, let it die." Design a sliding
   expiration and explain what new failure mode it introduces.
3. Right now, logging out deletes exactly one session row: the one tied to
   the cookie you're holding. If a user is logged in on three devices and
   suspects one of them is compromised, they have no way to revoke just that
   one, or all of them at once. Sketch the data model change that would let
   them do either.
4. `SESSION_TTL_SECONDS` is a constant. What would break if two different
   parts of the system needed different session lifetimes (say, a
   short-lived admin session next to a long-lived regular one)?

## Further reading

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Production systems rarely hand-roll session and password logic the way
  this lab does. [Keycloak](https://www.keycloak.org/) is the tool you'd
  reach for instead, and you'll meet it (by name, not by installing it) in
  Lab 04.
