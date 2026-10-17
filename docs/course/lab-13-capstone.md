---
icon: lucide/flag
---

# Lab 13: the capstone

There is nothing to fix in this lab. The starter is the finished platform from lab
12, and the task is to make it yours: pick some of the six challenges below, build
them on top, prove each one with tests you write, and say in a page what your system
now guarantees and what it doesn't.

That is a different kind of lab from the last twelve, so it is worth saying what it
is for. Every earlier lab handed you the shape of the answer and asked you to fill
a gap. Real authorization work doesn't come with a gap marked `TODO`. It comes as
"managers should be able to see their team's notes, but not through an agent unless
they said so", and you have to decide where that lives, what could go wrong, and how
you would know. This lab is that, with the training wheels off and the safety net of
a full test suite underneath.

## What you'll do

- Run the whole platform and watch one job use every part of it
- Choose at least three challenges, one of them from the first three
- Build each with its own tests, keeping the baseline suite green
- Write a one-page threat note for what you added

??? note "Closing the loop on lab 12 (skip this if you finished it)"

    ### The three fixes

    **A cut-off that follows the chain.** The starter only asked whether the token's
    own client was cut off, so a token made for the second agent by the first kept
    working after the first was cut off. The fix asks of every token three
    questions:

    ```python title="solution/idp/lab_idp/oauth.py"
    def token_cut_off(claims: dict, cut_off: set[str]) -> str | None:
        """Has this token been cut off because of who it belongs to, or who it came
        through? Returns the reason, or None when it is fine. `claims` is the decoded
        token, `cut_off` the set of client ids that have been revoked.

        A token is only as trustworthy as every agent in its history. A delegated
        token made for the archive agent by the tidy agent carries `acting_as.via`,
        and cutting the tidy agent off has to cut off what it handed on."""
        if claims.get("client_id") in cut_off:
            return f"{claims['client_id']} has been cut off"
        acting = claims.get("acting_as") or {}
        if acting.get("sub") in cut_off:
            return f"{acting['sub']} has been cut off"
        for upstream in acting.get("via", []):
            if upstream in cut_off:
                return f"{upstream}, an agent this authority passed through, has been cut off"
        return None
    ```

    The `via` list from lab 11 is what makes the third question possible. Without
    it the IdP would have no record of where a token came from.

    **One timeline from two services.** The starter glued the two logs together as
    they came. The fix is a filter and a sort, tagging each row with where it came
    from:

    ```python title="solution/backend/app/traces.py"
    def correlate(trace_id: str, app_events: list[dict], idp_events: list[dict]) -> list[dict]:
        """One timeline for `trace_id`. `app_events` and `idp_events` are audit rows
        as dicts, each with a `trace_id`, a timestamp `ts` and an `action`. Tag each
        row with where it came from (`source`: "app" or "idp"), keep only rows of this
        trace, drop the introspection calls (they happen on every hop and say nothing
        about who acted), and put the rest in the order they happened."""
        tagged = [{**e, "source": "app"} for e in app_events] + [{**e, "source": "idp"} for e in idp_events]
        mine = [e for e in tagged if e.get("trace_id") == trace_id and e["action"] != "oidc_introspect"]
        return sorted(mine, key=lambda e: e["ts"])
    ```

    Two lines of work, and the whole of "unified audit" depends on them. The filter
    is why every service has to write the trace id, and the sort is why they all
    have to write a timestamp somebody can compare.

    **Ending what a dead agent left behind.** The starter stopped the tokens and left
    the pending work. The fix ends all three kinds, reusing the approval state
    machine from lab 10 to say what a request that dies this way becomes:

    ```python title="solution/backend/app/approvals.py"
    def cut_off_pending_work(conn: sqlite3.Connection, agent_id: str, now: float) -> int:
        """Lab 12: an agent has been cut off. Whatever it had waiting has to die with
        it, or a person could still approve a request from an agent that no longer
        exists, and a token minted for it would sit in a table. End every approval
        request of this agent that is still pending or approved (the state machine's
        `expire` event gives the final state, and the token is wiped), cancel hand-
        offs it gave or was given that are not finished (wipe their tokens), and
        cancel tasks it claimed but did not complete (wipe the person's token).
        Returns how many rows were ended, across all three tables."""
        ended = 0
        for row in conn.execute(
            "SELECT id, status FROM approvals WHERE agent_id = ? AND status IN (?, ?)", (agent_id, PENDING, APPROVED)
        ).fetchall():
            conn.execute(
                "UPDATE approvals SET status = ?, approval_token = NULL, decided_by = 'kill-switch', decided_at = ?, "
                "decision_note = 'the agent was cut off' WHERE id = ?",
                (transition(row["status"], "expire"), now, row["id"]),
            )
            ended += 1
        ended += conn.execute(
            "UPDATE agent_handoffs SET status = 'cancelled', token = NULL "
            "WHERE (from_agent = ? OR to_agent = ?) AND status IN ('pending', 'claimed')", (agent_id, agent_id),
        ).rowcount
        ended += conn.execute(
            "UPDATE agent_tasks SET status = 'cancelled', subject_token = NULL WHERE claimed_by = ? AND status = 'claimed'",
            (agent_id,),
        ).rowcount
        conn.commit()
        return ended
    ```

    Enforcement without hygiene still works, since no token passes, but it leaves
    requests a person could approve and tokens sitting in tables.

    ### Discussing lab 12's going further questions

    One perspective, not a graded answer key.

    **What to cache.** A positive answer ("this token is active") is the dangerous one,
    because the switch exists to change it. If you cache it at all, the cache's lifetime
    is the delay before a cut-off bites, and you should pick that number on purpose.
    A negative answer is different: a token that is expired, or revoked by its `jti`,
    never comes back, so that can be remembered for good. The better answer at scale
    is to flip caches by pushing the news, which is what shared-signals standards are
    for, instead of making every request ask.

    **Cutting off the second agent too.** Not by reflex. Its token died with the
    first agent's, which is what stops the damage. Cutting off its identity says
    something stronger, that it is itself untrustworthy, and you'd want to know
    first what it did under that token, who sponsors it, and whether it takes
    input from anyone else. Look at its trace and tell its sponsor before deciding.

    **A button that can be pressed by mistake.** Make it reversible (a cut-off is a
    row, and restoring is a separate permission), visible (it lands in the trace it
    interrupted and should page someone) and bounded (cutting off one agent is easy,
    cutting off everything wants a second person). Making the reason mandatory is
    cheap and worth doing.

    **A service that drops the trace id.** The story splits. The next hop starts a
    fresh trace at the edge, so the work after the gap looks like a different job
    with an agent in it and no person behind it. You'd notice by looking for exactly
    that: traces whose first row is an agent, or IdP rows with no matching app row.

## One day on the platform, one message at a time

This is the whole system at once. Step through it, and notice that each message is
something you built in an earlier lab, and which lab.

<!-- stepper: flows/capstone-day.flow -->
<div class="stepper" markdown>

<figure class="stepper-diagram">
<svg class="flow" viewBox="0 0 700 652" role="img" aria-label="Sequence diagram: Alice, Agents, Platform, Operator">
<g class="actor"><rect x="45" y="8" width="110" height="34" rx="6"/><text x="100" y="30" text-anchor="middle">Alice</text></g>
<g class="actor"><rect x="212" y="8" width="110" height="34" rx="6"/><text x="267" y="30" text-anchor="middle">Agents</text></g>
<g class="actor"><rect x="378" y="8" width="110" height="34" rx="6"/><text x="433" y="30" text-anchor="middle">Platform</text></g>
<g class="actor"><rect x="545" y="8" width="110" height="34" rx="6"/><text x="600" y="30" text-anchor="middle">Operator</text></g>
<line class="life" x1="100" y1="42" x2="100" y2="642"/>
<line class="life" x1="267" y1="42" x2="267" y2="642"/>
<line class="life" x1="433" y1="42" x2="433" y2="642"/>
<line class="life" x1="600" y1="42" x2="600" y2="642"/>
<g class="msg" id="m1"><line x1="100" y1="100" x2="424" y2="100"/><polygon points="433,100 424,95 424,105"/><text x="266" y="93" text-anchor="middle">1 archive my notes</text></g>
<g class="secret" id="s1_1"><rect x="443" y="106" width="108" height="22"/><text x="497" y="121" text-anchor="middle">task + trace id</text></g>
<g class="msg" id="m2"><line x1="267" y1="158" x2="424" y2="158"/><polygon points="433,158 424,153 424,163"/><text x="350" y="151" text-anchor="middle">2 claim + exchange</text></g>
<g class="secret" id="s2_1"><rect x="443" y="164" width="156" height="22"/><text x="521" y="179" text-anchor="middle">delegated, read + write</text></g>
<g class="msg" id="m3"><line x1="267" y1="216" x2="424" y2="216"/><polygon points="433,216 424,211 424,221"/><text x="350" y="209" text-anchor="middle">3 hand off, read only</text></g>
<g class="secret" id="s3_1"><rect x="443" y="222" width="120" height="22"/><text x="503" y="237" text-anchor="middle">new token per hop</text></g>
<g class="msg" id="m4"><line x1="267" y1="274" x2="424" y2="274"/><polygon points="433,274 424,269 424,279"/><text x="350" y="267" text-anchor="middle">4 read notes</text></g>
<g class="secret" id="s4_1"><rect x="443" y="280" width="126" height="22"/><text x="506" y="295" text-anchor="middle">delete not allowed</text></g>
<g class="msg" id="m5"><line x1="267" y1="332" x2="424" y2="332"/><polygon points="433,332 424,327 424,337"/><text x="350" y="325" text-anchor="middle">5 purge old reports</text></g>
<g class="secret" id="s5_1"><rect x="443" y="338" width="150" height="22"/><text x="518" y="353" text-anchor="middle">policy: needs approval</text></g>
<g class="msg" id="m6"><line x1="100" y1="390" x2="424" y2="390"/><polygon points="433,390 424,385 424,395"/><text x="266" y="383" text-anchor="middle">6 approve</text></g>
<g class="secret" id="s6_1"><rect x="443" y="396" width="114" height="22"/><text x="500" y="411" text-anchor="middle">one-minute token</text></g>
<g class="msg" id="m7"><line x1="433" y1="448" x2="276" y2="448"/><polygon points="267,448 276,443 276,453"/><text x="350" y="441" text-anchor="middle">7 token, then done</text></g>
<g class="msg" id="m8"><line x1="600" y1="506" x2="442" y2="506"/><polygon points="433,506 442,501 442,511"/><text x="516" y="499" text-anchor="middle">8 open the trace</text></g>
<g class="secret" id="s8_1"><rect x="443" y="512" width="132" height="22"/><text x="509" y="527" text-anchor="middle">app + IdP, in order</text></g>
<g class="msg" id="m9"><line x1="600" y1="564" x2="442" y2="564"/><polygon points="433,564 442,559 442,569"/><text x="516" y="557" text-anchor="middle">9 cut off tidy-agent</text></g>
<g class="secret" id="s9_1"><rect x="443" y="570" width="168" height="22"/><text x="527" y="585" text-anchor="middle">its tokens and chain dead</text></g>
</svg>
</figure>

<div class="step" data-title="Alice asks the agents to archive her notes" data-hl="m1 s1_1" markdown>
She is signed in through the IdP, so her session has an access token, and the
request gets a trace id that will follow the whole job (labs 04, 05 and 09).
</div>

<div class="step" data-title="The first agent claims the job and trades her token" data-hl="m2 s2_1" markdown>
It authenticates as itself with client credentials (lab 06), and gets a token
that names Alice and the agent, narrowed to what both may hold (lab 09).
</div>

<div class="step" data-title="It hands the filing to a second agent" data-hl="m3 s3_1" markdown>
The second agent has its own identity and sponsor. It receives a token of its
own with only the scope that was passed on, and the route it came by (lab 11).
</div>

<div class="step" data-title="The second agent reads the notes and ignores an order hidden in one" data-hl="m4 s4_1" markdown>
A note's title tells it to delete another note. It tries, and the API refuses
because the token never held the scope. The refusal is flagged in the log.
</div>

<div class="step" data-title="The first agent asks to do something irreversible" data-hl="m5 s5_1" markdown>
Policy allows the tool and also says a person has to agree (labs 08 and 10).
The call is held as a request and the agent waits.
</div>

<div class="step" data-title="A person decides" data-hl="m6 s6_1" markdown>
Alice is the agent's sponsor, so she may decide. The approval is tied to this
agent, this tool and these arguments, and it works once.
</div>

<div class="step" data-title="The agent repeats the call and it runs" data-hl="m7" markdown>
The token is spent and the reports are deleted. Everything so far is in the
audit log under one trace id.
</div>

<div class="step" data-title="The operator reads the whole day as one timeline" data-hl="m8 s8_1" markdown>
A human, a service, two agents, the IdP and the approval gate appear in one
list, sorted by time, with who acted for whom (lab 12).
</div>

<div class="step" data-title="The operator decides that is enough, and cuts the first agent off" data-hl="m9 s9_1" markdown>
The IdP stops honouring every token the agent holds or passed on, and its
unfinished work is ended. Its next request, to anything, is refused.
</div>

</div>
<!-- /stepper -->

## Run it and watch it work

Check that ports 5173, 8000, 8181 and 9000 are free, then start the four processes
from `labs/lab-13-capstone/starter`:

```sh
cd labs/lab-13-capstone/starter/idp
uv venv .venv --python 3.12
uv pip install -r requirements.txt --python .venv/bin/python
.venv/bin/uvicorn lab_idp.main:app --port 9000
```

```sh
cd labs/lab-13-capstone/starter
opa run --server --addr 127.0.0.1:8181 policy
```

```sh
cd labs/lab-13-capstone/starter/backend
uv venv .venv --python 3.12
uv pip install -r requirements.txt --python .venv/bin/python
.venv/bin/uvicorn app.main:app --reload
```

```sh
cd labs/lab-13-capstone/starter/frontend
npm install
npm run dev
```

(Or `docker compose up --build` from `labs/lab-13-capstone/starter`.) Before you build
anything, run the baseline from `starter/backend` (OPA on your `PATH`, or `OPA_BIN`):

```sh
.venv/bin/pytest tests/test_capstone_baseline.py -v
```

??? question "That one test walks a person, a service account and two agents through a working day. Before you run it, what do you expect it to prove that the 300-odd tests before it don't?"
    That the pieces work *together*. Every other test exercises one part with the
    rest held still: the exchange without the hand-off, the gate without the trace,
    the switch without a job in flight. The baseline runs one job through all of them
    and checks that they agree, that the chain a human started is the chain the
    operator reads, and that a switch pulled at the end stops the thing that began in
    the morning. A change that is correct locally and wrong in combination is the kind
    this test exists to catch.

Then do the same thing by hand, in two browser windows (one private). Sign in as
`alice` through the IdP in the first and as `admin` in the second, ask the agents to
archive Alice's notes, and run the agents from `starter/agent` as in labs 11 and 12. Open
the admin window's trace panel and read the job top to bottom.

![One job as a single timeline across the app and the IdP](assets/lab-12-audit-killswitch/unified-trace-solution.png)

## The brief

You are the engineer who owns this platform for a small company that keeps its
notes in it. People sign in as themselves. A nightly job reads statistics. Agents file
and tidy notes on people's behalf. Someone has just asked "could we let managers see
their team's notes?" and someone else "could an agent do my expenses?", and you can
tell neither is as simple as it sounds.

What you've inherited:

| Part | Where it lives | Built in |
|------|----------------|----------|
| Passwords, sessions, JWTs | `backend/app/security.py` | labs 00, 01 |
| Roles, then rules and relationships | `backend/app/main.py`, `policy.py` | labs 02, 03 |
| A teaching IdP: PKCE, consent, introspection, revocation | `idp/` | labs 04, 05 |
| A service account with client credentials | `digest/`, `idp/lab_idp/oauth.py` | lab 06 |
| Agents as identities, with sponsors | `agent/`, `idp/` | lab 07 |
| Scoped tools decided by OPA | `policy/agent_tools.rego` | lab 08 |
| Acting on behalf of a person | `idp/lab_idp/oauth.py` | lab 09 |
| An approval gate | `backend/app/approvals.py` | lab 10 |
| Hand-offs between agents | `idp/`, `backend/app/main.py` | lab 11 |
| One trace, one kill-switch | `backend/app/traces.py` | lab 12 |

What is expected of you:

1. Pick **at least three** of the challenges below, **at least one** from A to C.
2. For each, write tests in a new file under `backend/tests/` that fail before your
   change and pass after it. A challenge without a test hasn't been done.
3. Keep `test_capstone_baseline.py` and the rest of the suite green throughout.
4. Write the threat note (below) and keep it in the lab's folder as `THREAT-NOTE.md`.

## The challenges

Each one says what to build and what "done" has to look like. How you build it is
yours to decide, and some of the interesting choices are in where it lives: the IdP,
the policy, the app, or the agent.

### A. Managers and their teams

Add a `manager` role and a notion of who reports to whom. A manager may read the notes
of the people who report to them, and nobody else's. Then the hard part: an agent
acting for a manager gets that reach only if the manager agreed to it at consent.

*Done when:* a manager reads a report's note directly, an agent acting for the same
manager cannot read it until the manager has consented to team access, and a manager
cannot read a note of someone outside their team by either route. Every denial names
the rule that produced it, in the audit log.

*Where you'll be tempted to cut a corner:* putting the team check in the frontend, or
in the agent's tool list. Both are courtesies, as lab 08 told you.

### B. A third agent, and a longer chain

Add a third agent with a different job (a report writer, say) with its own identity,
sponsor, capabilities and delegable scopes. Let the archive agent hand it work, which
makes a chain of three, and raise `MAX_HAND_OFFS` to allow it.

*Done when:* the third agent's token carries only what both hops explicitly passed on,
the trace shows all three agents in order with the right sponsor against each, and
cutting off the *first* agent stops the third agent's next request.

*Worth thinking about:* what the third agent's registration should say it may be
handed, and by whom. The answer isn't "anything the archive agent holds".

### C. A better approval gate

Lab 10's gate shows a person the agent's arguments. Make it show what the arguments
will *do*. Compute a summary in the app, not from anything the agent wrote ("delete 3
of 5 reports, keeping the newest 2"), show it in the queue and record it in the audit
row. Then handle the sponsor who is on leave: a request that nobody has answered after
a set time goes to a second approver instead of lapsing.

*Done when:* the summary comes from the app and cannot be influenced by the agent's own
text, and an unanswered request escalates once and only once, to someone who is
allowed to decide it, with both steps in the trace.

### D. Consent with an expiry

Alice can already narrow what an app may do on her behalf. Let her say "let the agent
read my notes for an hour". Store the expiry with her consent and check it at the
moment of delegation.

*Done when:* an exchange inside the hour succeeds, one after it is refused for exactly
that reason, a delegated token issued inside the hour does not outlive it, and the
consent screen says the grant is temporary.

### E. Tokens bound to their holder

Lab 11's closing note said sender-constrained tokens are the next step. Build a small
version: each agent registers a public key, hop tokens carry its fingerprint, and the
API only accepts a token when the caller proves it holds the key (a signature over the
request, say). You are building a cut-down DPoP, so read RFC 9449 first and say in the
threat note what you left out.

*Done when:* a hop token replayed by a different agent is refused even though it is
otherwise valid, and the audit log says it was refused for the key and not for the
scope.

### F. Operator tooling

An operator has one switch today, and it cuts off a whole agent. Add the finer ones:
cancel a single job (one trace) without touching the agent, an export of a trace as a
file, and a simple alert that fires when scope violations from one agent pass a
threshold in a minute.

*Done when:* cancelling a job stops that job's tokens and leaves the agent's other work
alone, the export contains the same timeline the panel shows, and the alert fires in a
test that provokes it and stays quiet in one that doesn't.

!!! note "Stretch: a real model in the loop"
    Point the archive agent at a real model through any OpenAI-compatible endpoint,
    as in lab 07 (`python -m agent_runner --llm`), and run lab 11's note-title attack
    against it. A model is less predictable than the scripted agent and just as
    steerable, so this is the honest test of whether your scopes, your gate and your
    switch hold when the thing choosing the actions isn't you. It is optional,
    costs real money and never touches a self-check.

## The threat note

For each capability you add, one row: who can do what, how they are stopped when they
shouldn't be, and where it is logged. Add a final section called "What I didn't do",
because every system has one and the useful ones say so.

| Capability | Who may use it | What stops everyone else | Where you'd see it |
|------------|----------------|--------------------------|--------------------|
| (yours) | | | |

If you can't fill in the third column for something, you have found the next thing to
build.

## You're done when

- [ ] `pytest tests/` passes in full, including `test_capstone_baseline.py`
- [ ] At least three challenges are built, one from A to C, each with tests that
      failed before the change
- [ ] `THREAT-NOTE.md` has a row for everything you added and a "What I didn't do"
      section
- [ ] In the browser, one job you ran after your changes appears as a single trace
      with every identity in it, and the kill-switch still stops it

## Going further

No self-check for these, and nothing here is a lab. They are the adjacent questions
this course didn't build.

1. **Who should still have this access?** Everything in the platform answers "may this
   request go ahead right now". Nothing answers "should this person, service or agent
   still be able to do that at all". Identity governance (access reviews, recertification,
   joiner-mover-leaver processes) is the discipline for that, and it is where long-lived
   agents with sponsors will end up, since the sponsor can leave the company. What would a
   quarterly review of `SERVICE_CLIENTS` need to show a reviewer?
2. **Passkeys.** The course stopped at passwords. Where would a passkey change the shape
   of lab 00's login, and which later labs wouldn't notice at all?
3. **Replacing the teaching IdP.** If you swapped the Lab IdP for a production one,
   which parts of this platform would carry over unchanged and which assumed things only
   your IdP does (a `via` claim, a cut-off list, `hand_off`)?
4. **Workload identity.** Agents here authenticate with a fixed secret. In production
   you'd probably give them a platform-issued identity instead. What does that remove,
   and what does it leave exactly as hard?

## Further reading

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700), the checklist this course's IdP is a toy version of
- [RFC 9449: DPoP](https://datatracker.ietf.org/doc/html/rfc9449), for challenge E
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [SPIFFE](https://spiffe.io/), workload identity without long-lived secrets
- [NIST SP 800-53, control AC-2 (account management)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), the formal home of the access-review question
