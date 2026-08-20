---
icon: lucide/scan-line
---

# Lab 01: JWTs

You'll add a second way to prove identity to the system you built in lab 00:
a signed, self-contained token instead of a server-side session. By the end,
your backend issues JWTs, verifies them properly (signature and expiry, not
just the base64), and your frontend has a live decoder that shows exactly
what a JWT does and doesn't protect.

## What you'll learn

- What actually makes a JWT trustworthy, and why decoding one is not the
  same as verifying one
- How to reject a tampered signature, an expired token, and a token missing
  a required claim, each for a distinct reason
- Why a session cookie and a JWT solve the same problem (proving who you
  are on a later request) with opposite trade-offs

## Closing the loop on lab 00

### The password hashing fix

Lab 00 started you off with `hash_password` and `verify_password` storing
and comparing passwords as-is. The fix swaps in Argon2:

```python title="solution/backend/app/security.py"
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
```

`PasswordHasher.hash()` produces a string that encodes the algorithm,
its parameters, a random salt, and the derived hash, all together, so two
users with the same password never end up with the same stored value.
`verify()` takes the stored hash and a plaintext guess and redoes the same
derivation, comparing the result in constant time. It raises
`VerifyMismatchError` on a mismatch instead of returning `False`, which is
why `verify_password` needs the `try`/`except` rather than a plain
`==` check.

```mermaid
flowchart LR
    A[POST /signup] --> B[hash_password]
    B --> C[(users.password_hash)]
    D[POST /login] --> E[verify_password]
    C -.->|read stored hash| E
    E -->|VerifyMismatchError| F[401, audit: deny]
    E -->|hash matches| G[mint new session id]
```

### The session fixation fix

`resolve_login_session_id` used to reuse whatever session id the client
already presented, which is what let an attacker plant a cookie in a
victim's browser before they logged in and inherit their session
afterward. The fix ignores that entirely:

```python title="solution/backend/app/security.py"
def resolve_login_session_id(cookie_session_id: str | None) -> str:
    """What session id does a successful login issue?"""
    return new_session_id()
```

The parameter is still there even though the function no longer looks at
it. That's a side effect of how the starter is generated, not a design
choice about this function specifically: `scripts/generate_starter.py`
swaps the function *body* between the `LAB:SOLUTION` and `LAB:STARTER`
blocks, but the `def` line itself is written once and shared by both. The
starter's buggy body still reads `cookie_session_id`, so the signature has
to keep accepting it, whether or not the fixed body above uses it.

```mermaid
sequenceDiagram
    participant A as Attacker
    participant V as Victim
    participant S as Server (fixed)

    A->>S: visit site, no login
    S-->>A: Set-Cookie: session_id=FIXED123
    A->>V: trick victim into using session_id=FIXED123
    V->>S: POST /login (cookie: FIXED123)
    Note over S: resolve_login_session_id ignores FIXED123,<br/>mints a brand-new id instead
    S-->>V: Set-Cookie: session_id=NEW456
    A->>S: GET /me (cookie: FIXED123)
    S-->>A: 401 — FIXED123 was never bound to a login
```

### Discussing lab 00's going further questions

These aren't graded, and what follows is one take, not the only correct
one.

**Hashing the session token at rest.** Right now, anyone who reads the
`sessions` table directly gets a live, valid session id they can drop
straight into a cookie: it's exactly as sensitive as a plaintext password
would be, for the same reason. Store a hash of the session id (a fast one,
like SHA-256, is fine here, since the id already has 256 bits of entropy
and doesn't need Argon2's slow, salted design) and look sessions up by
hashing the incoming cookie value and matching against the stored hash. The
cookie itself is unaffected; only what a backup or an SQL injection bug
would leak changes.

**Sliding expiration.** Extending the TTL on every authenticated request
solves the "still active, don't log me out" problem, but it opens a new
one: a stolen session, used regularly by the attacker, never expires
either. Any sliding-expiration design needs a second, absolute ceiling
(say, 12 hours from creation, no matter how active the session stays) that
sliding renewal can't push past, otherwise "still active" and "compromised
and being actively abused" look identical from the server's side.

**Per-device revocation.** The current schema has no concept of "device" at
all, just a session row per login. Add a label (say, a hash of the
`User-Agent` header plus a rough client fingerprint, captured at login) to
each session row, list sessions grouped by that label in a "your devices"
panel, and offer both a delete-one-row and a delete-all-rows-for-this-user
endpoint. The interesting design question isn't the schema, it's how much
you trust a `User-Agent` string as a device identity given how easy it is
to spoof.

**Per-context TTLs.** `SESSION_TTL_SECONDS` being a module constant means
every session gets the same lifetime regardless of what it's for. The
straightforward fix is moving the TTL from the constant into a column on
the session row, decided by whatever calls `session_expiry()` at creation
time rather than by the function itself. The harder question it raises:
once TTL is a per-session decision, something has to decide it, which
means introducing the concept of "what kind of session is this" before
you've built anything that would tell you.

## Background

### Signed, not encrypted

A JWT looks like three base64url-encoded chunks joined with dots: a
header, a payload, and a signature. The header and payload are just JSON.
Nothing about them is encrypted, so anyone holding the token, your
frontend, a browser extension, a proxy in the middle, can decode and read
every claim without knowing any secret at all. That's not a bug. It's the
whole design: a JWT is meant to be self-describing.

What the secret actually buys you is the third chunk. The signature is
computed over the header and payload using a key only the issuing server
holds, and it's the only part that isn't attacker-editable without
detection. Read the claims, and you know what the token *claims*. Check
the signature, and you know whether to believe it.

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server

    Note over B,S: Session cookie (lab 00) — stateful
    B->>S: GET /me (Cookie: session_id=...)
    S->>S: look up session_id in the sessions table
    S-->>B: 200, or 401 if not found/expired

    Note over B,S: JWT (lab 01) — stateless
    B->>S: POST /token (Cookie: session_id=...)
    S-->>B: { access_token: header.payload.signature }
    Note over B: decode header + payload locally,<br/>no request needed
    B->>S: POST /verify { token }
    S->>S: check signature against JWT_SECRET,<br/>check exp, check required claims
    S-->>B: { valid, signature_valid, expired, reason }
```

Notice what changed between the two halves of that diagram. The session
flow needs the database on every request, because the cookie is only an
opaque reference. The JWT flow needs the database for nothing (it's
already stateless), but it needs the one thing the browser never has: the
key that made the signature genuine in the first place.

### What "verify" actually has to check

A JWT verification function that only decodes the payload and calls it
done is the trap this lab exists to catch you in. A real verify has at
least three independent ways to fail, and conflating them (or skipping any
of them) is how "JWT auth" ends up meaning "anyone can forge a token by
hand."

```mermaid
flowchart TD
    A[Receive token] --> B[Decode header + payload<br/>without checking the signature]
    B --> C{well-formed base64url + JSON?}
    C -->|no| D[reject: not well-formed]
    C -->|yes| E[Check signature against JWT_SECRET]
    E -->|invalid| F[reject: invalid signature]
    E -->|valid| L{exp present but not a number?}
    L -->|yes| M[reject: malformed exp claim]
    L -->|no| G{exp already in the past?}
    G -->|yes| H[reject: token expired]
    G -->|no| I{sub and exp both present?}
    I -->|no| J[reject: missing required claim]
    I -->|yes| K[accept: valid]
```

The order matters. A signature check has to run before you trust anything
else about the token, including whether it's expired, because a forged
token can claim any `exp` it likes. This lab's self-check suite exercises
each rejection path separately and expects a distinct reason string for
each: `"invalid signature"`, `"malformed exp claim"`, `"token expired"`,
and `"missing required claim: <name>"`. A verify function that collapses
these into one generic "invalid token" makes debugging (and this handout's
audit-log tests) much harder than it needs to be.

Watch out for a subtler trap in that ordering: a token can be genuinely
signed with the real secret and still carry an `exp` that isn't a number
at all (a hand-edited payload with `"exp": "soon"`, say). PyJWT's own
built-in expiry check tries to convert `exp` to an integer during
verification, and it raises an error if it can't, one that looks exactly
like a signature failure to code that isn't careful about it. A malformed
`exp` is a real problem, but it isn't a signature problem, and reporting
it as `"invalid signature"` would blame the wrong thing.

## Prerequisites

- Python 3.12
- Node.js (any recent version; the course was built and tested on Node 24)
- `uv` or plain `pip` for installing Python dependencies
- Lab 00 completed, since this lab's starter is lab 00's finished solution
  plus one new gap

## Setup

```sh
cd labs/lab-01-jwt/starter/backend
uv venv .venv --python 3.12
uv pip install -r requirements.txt --python .venv/bin/python
```

```sh
cd labs/lab-01-jwt/starter/frontend
npm install
```

## Your tasks

Open `starter/backend/app/security.py` and find `verify_token`. The top of
the function already handles a token that isn't even shaped like a JWT
(decode failure on `jwt.decode(token, options={"verify_signature": False})`
gets reported as `"token is not well-formed"`), and it already works out
whether `exp` is present and whether it's actually a number. Keep scrolling
past that and you'll find the part marked with a `TODO(lab-01)` comment:

```python title="starter/backend/app/security.py"
    # TODO(lab-01): this trusts the token completely once it's decodable —
    # signature_valid is hardcoded True below, so nothing here actually
    # checks whether the signature is genuine. A token whose payload was
    # hand-edited and re-signed with a wrong key (or not signed at all)
    # sails through as long as its claims otherwise look fine. Verify the
    # signature for real instead: call
    # `jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` and let
    # PyJWT do the cryptographic check, then translate a failure into
    # `signature_valid=False` with reason "invalid signature".
    #
    # One thing to watch for on the way there: that verifying call also
    # runs PyJWT's own expiry check by default, and a malformed
    # (non-numeric) exp claim can make it raise too — indistinguishable, if
    # you're not careful, from an actually-forged signature. Tell
    # `jwt.decode` not to do its own expiry validation here (there's an
    # `options` argument for that) and keep relying on `exp_present` /
    # `exp_well_formed` / `expired` above, computed from the unverified
    # claims, to decide the rest. See "Signed, not encrypted" in the lab 01
    # handout.
    signature_valid = True
```

That single hardcoded line is the whole gap. Everything below it (the
`if not signature_valid`, the malformed-`exp` check, the expiry check, the
missing-claim check) is already correct and already reads from the claims
this function decoded at the top without checking anything against a
secret, which is exactly why `signature_valid=True` never being earned is
a problem: a token whose payload was hand-edited and re-signed with a
wrong key (or not signed at all) sails through every one of those checks
unless it also happens to be expired or missing a claim.

Fix it by actually verifying the signature: call
`jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` and let PyJWT
do the cryptographic check, instead of assigning `signature_valid = True`
outright. That call raises `jwt.InvalidTokenError` (or one of its
subclasses) when the signature doesn't check out, so you'll need to catch
it and set `signature_valid` from whether the call succeeded.

The comment above already flags the one trap in this: the verifying call
runs PyJWT's own built-in expiry check by default, so it can raise for a
malformed `exp` claim too, not only a forged signature. Tell `jwt.decode`
not to do its own expiry validation on this call (there's an `options`
argument for that) and let the `exp_present` / `exp_well_formed` /
`expired` values computed further up the function keep deciding the rest,
the same way they already do once you know the signature genuinely
checked out.

!!! warning "Peeking at claims and verifying them are different operations"
    The unverified read at the top of the function (the one that produces
    `unverified_claims`) is always possible without the secret. Don't let
    it stand in for the real signature check you're adding below it.

### Run it and watch it work

Start the backend and frontend in two terminals:

```sh
cd labs/lab-01-jwt/starter/backend
.venv/bin/uvicorn app.main:app --reload
```

```sh
cd labs/lab-01-jwt/starter/frontend
npm run dev
```

Sign up (or log in, if you already have an account from an earlier run),
then scroll to the "Live JWT decoder" panel. Click "Get a fresh
token for my session": the claims decode instantly, client-side, no
network call involved. Click "Verify signature & expiry with server," and
you'll see a second, separate result that only the backend could produce.
Then try pasting a token with a character changed in the signature part
(the third dot-separated chunk) and verify it again: the local decode
still works fine (that's the point), but the server verification now comes
back invalid.

## You're done when

Run the self-check suite from `starter/backend`:

```sh
.venv/bin/pytest tests/ -v
```

- [ ] `test_verify_rejects_tampered_signature` passes: a token with an
      edited signature is rejected with reason `"invalid signature"`
- [ ] `test_verify_rejects_expired_token` passes: a token whose `exp` is in
      the past is rejected with reason `"token expired"`
- [ ] `test_verify_rejects_missing_required_claim` passes: a token missing
      `sub` is rejected with reason naming the missing claim
- [ ] `test_verify_reports_malformed_exp_as_its_own_reason_not_bad_signature`
      passes: a genuinely-signed token with a non-numeric `exp` is reported
      as `signature_valid=True` with reason `"malformed exp claim"`, not
      blamed on the signature
- [ ] `test_verify_denials_produce_distinct_audit_reasons` passes: all
      three denial reasons show up as separate audit log entries
- [ ] `test_verify_unit_level_distinct_errors` passes: calling
      `verify_token()` directly produces the same three distinct outcomes
- [ ] Every other test in the suite still passes, including everything
      carried over from lab 00
- [ ] In the browser, the JWT decoder panel shows decoded header/payload
      claims immediately after fetching a token, and shows a separate
      "signature valid" / "expired" result only after you click verify
- [ ] Tampering with a pasted token's signature still decodes locally but
      fails server verification, and that denial appears in the audit log
      panel with a reason of `"invalid signature"`

## Going further

No self-check for these. Lab 02's handout opens with a discussion of them.

1. This lab's JWT has no refresh flow: once `exp` passes, the only way to
   get a new one is to still hold a valid session cookie and hit `/token`
   again. What happens to a caller that only ever received the JWT (say, a
   mobile client that never sees the cookie) once it expires, and what
   would you need to add to let it recover without asking the user to log
   in again?
2. Lab 00's session table gives the server a lever it can pull instantly:
   delete the row, and the session is dead on the next request. A JWT has
   no equivalent until `exp` arrives on its own. Sketch what a revocation
   mechanism for JWTs would need to look like, and be honest about what it
   costs you in exchange for statelessness.
3. `JWT_SECRET` is one fixed symmetric key, known to whoever issues tokens
   and whoever verifies them, which in this lab is the same process. What
   breaks the moment a second, separate service needs to verify tokens it
   didn't issue, and how does switching to an asymmetric algorithm change
   who needs to hold what?
4. `verify_token` only requires `sub` and `exp`. If a future lab wants to
   gate access by role, where would that claim naturally live, and what
   happens to a token that was minted before that claim existed?

## Further reading

- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [jwt.io debugger](https://jwt.io/), the same decode-without-a-secret
  trick this lab's UI panel does, from the library that popularized it
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [PyJWT documentation](https://pyjwt.readthedocs.io/)
