---
icon: lucide/shield-check
---

# Agent Auth Lab

Most developers learn authentication and authorization the same way: copy a JWT
snippet from Stack Overflow, wire up an OAuth library without reading what it
does, and move on. That works until something breaks, or until you're asked to
design the auth story for a system where half the callers aren't humans at all.

This course takes the slower route on purpose. You'll build a session-based
login system by hand, break it, fix it, then keep building on the same
codebase through JWTs, RBAC, OIDC, and eventually a system with multiple
autonomous agents acting on their own credentials and on behalf of the humans
who deployed them. By the end you'll have built the thing you'd otherwise
just be configuring.

## Who this is for

You're comfortable writing code and reading a stack trace, but authentication
and authorization still feel like something that happens in a library you
don't fully trust. You don't need prior security background. You do need
Python and a willingness to run things, break them, and read the error.

## How the course is structured

Fourteen labs, numbered 00 through 13, split into three arcs:

**Sessions, tokens, and access control (labs 00-03).** No agents yet. Just the
mechanics everyone should know: password hashing, session cookies, JWTs, and
the difference between "who are you" (authentication) and "what are you
allowed to do" (authorization).

**Federated and delegated identity (labs 04-06).** You build your own minimal
OAuth2/OIDC identity provider, add consent and revocation, and handle the
case where the caller is another service with no human behind it at all.

**Agents (labs 07-13).** Autonomous callers with their own identity, scoped
tool permissions, delegated "on behalf of" authority, human approval gates,
multi-agent authorization, and a unified audit trail across every identity
type in the system. Lab 13 is open-ended: extend the whole thing yourself.

There's one important thing to understand before you start: this isn't
fourteen separate exercises. Your lab 00 solution becomes your lab 01 starting
point, and so on all the way to lab 13. You're building one system that grows
a new capability every lab, not restarting from scratch each time.

## How each lab works

Every lab ships two folders:

- `starter/` is where you work. It's a working system with one deliberate gap
  or vulnerability, marked with a `TODO(lab-NN)` comment and explained in the
  handout.
- `solution/` is the reference answer. Don't open it until you've had a real
  attempt, but don't feel bad about checking it either. That's what it's for.

Each lab also ships a pytest self-check suite that runs against your own
implementation. When every test passes, you're done with the required part of
the lab. The open-ended questions at the end of each handout go further than
the self-check does, and there's no answer key for those.

## Before you start

You'll need Python 3.12, Node.js, and a terminal you're not afraid of. Every
lab's backend is FastAPI, every frontend is Svelte with TypeScript, and every
lab uses SQLite so you can open the database file yourself and see exactly
what your code just did.

Start with [Lab 00](lab-00-sessions-cookies.md).
