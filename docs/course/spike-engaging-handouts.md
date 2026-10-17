---
icon: lucide/sparkles
---

# Spike: engaging handouts (draft)

This page is a prototype for the AAL-11 spike. It is not a lab. It shows
three components that every handout now uses: a clickthrough
that animates a diagram, an embedded widget you can break on purpose, and a
predict-then-reveal check. The write-up with the reasoning lives in
`docs/research/handout-engagement.md`.

## A clickthrough: the authorization code flow with PKCE

Use the arrow keys or the buttons. Each step lights up one message in the
diagram and says what to notice.

<!-- stepper: flows/pkce.flow -->
<div class="stepper" markdown>

<figure class="stepper-diagram">
<svg class="flow" viewBox="0 0 700 536" role="img" aria-label="Sequence diagram: Browser, Client app, Lab IdP">
<g class="actor"><rect x="45" y="8" width="110" height="34" rx="6"/><text x="100" y="30" text-anchor="middle">Browser</text></g>
<g class="actor"><rect x="295" y="8" width="110" height="34" rx="6"/><text x="350" y="30" text-anchor="middle">Client app</text></g>
<g class="actor"><rect x="545" y="8" width="110" height="34" rx="6"/><text x="600" y="30" text-anchor="middle">Lab IdP</text></g>
<line class="life" x1="100" y1="42" x2="100" y2="526"/>
<line class="life" x1="350" y1="42" x2="350" y2="526"/>
<line class="life" x1="600" y1="42" x2="600" y2="526"/>
<g class="msg" id="m1"><line x1="100" y1="100" x2="341" y2="100"/><polygon points="350,100 341,95 341,105"/><text x="225" y="93" text-anchor="middle">1 click &quot;Log in&quot;</text></g>
<g class="msg" id="m2"><line x1="350" y1="158" x2="109" y2="158"/><polygon points="100,158 109,153 109,163"/><text x="225" y="151" text-anchor="middle">2 redirect + code_challenge</text></g>
<g class="secret" id="s2_1"><rect x="360" y="164" width="174" height="22"/><text x="447" y="179" text-anchor="middle">keeps code_verifier secret</text></g>
<g class="msg" id="m3"><line x1="100" y1="216" x2="591" y2="216"/><polygon points="600,216 591,211 591,221"/><text x="350" y="209" text-anchor="middle">3 GET /authorize?code_challenge=...</text></g>
<g class="secret" id="s3_1"><rect x="446" y="222" width="144" height="22"/><text x="518" y="237" text-anchor="middle">stores code_challenge</text></g>
<g class="msg" id="m4"><line x1="600" y1="274" x2="109" y2="274"/><polygon points="100,274 109,269 109,279"/><text x="350" y="267" text-anchor="middle">4 login + consent, redirect with ?code=</text></g>
<g class="msg" id="m5"><line x1="100" y1="332" x2="341" y2="332"/><polygon points="350,332 341,327 341,337"/><text x="225" y="325" text-anchor="middle">5 GET /callback?code=...</text></g>
<g class="msg" id="m6"><line x1="350" y1="390" x2="591" y2="390"/><polygon points="600,390 591,385 591,395"/><text x="475" y="383" text-anchor="middle">6 POST /token (code + verifier)</text></g>
<g class="msg" id="m7"><line x1="600" y1="448" x2="359" y2="448"/><polygon points="350,448 359,443 359,453"/><text x="475" y="441" text-anchor="middle">7 ID token + access token</text></g>
</svg>
</figure>

<div class="step" data-title="The user asks to log in" data-hl="m1" markdown>
The user clicks "Log in" on the client app. At this point the app knows
nothing about them, and it never will see their password.
</div>

<div class="step" data-title="The app invents a secret and shows only its fingerprint" data-hl="m2 s2_1" markdown>
The app generates a random `code_verifier`, hashes it into a
`code_challenge`, and redirects the browser to the IdP carrying only the
challenge. The verifier stays on the app's side.

Notice that someone who intercepts this redirect learns the hash, not the
secret.
</div>

<div class="step" data-title="The browser carries the request to the IdP" data-hl="m3 s3_1" markdown>
The IdP stores the challenge next to the pending request. It will compare
it against whatever shows up at the token endpoint later.
</div>

<div class="step" data-title="The user authenticates at the IdP, not the app" data-hl="m4" markdown>
Login and consent happen on the IdP's own pages. The IdP then redirects
back with a short-lived, single-use `code`. A code on its own is useless;
that is the point of the next two steps.
</div>

<div class="step" data-title="The code lands on the app&#x27;s callback" data-hl="m5" markdown>
The code travelled through the browser, so treat it as exposed. If an
attacker grabbed it here, what would stop them from redeeming it?
</div>

<div class="step" data-title="The app proves it started the flow" data-hl="m6" markdown>
The app posts the code together with the original `code_verifier`. The IdP
hashes the verifier and compares it with the stored challenge. A thief with
only the code fails this check, which is exactly the lab's PKCE-mismatch
rejection.
</div>

<div class="step" data-title="Tokens come back over the direct channel" data-hl="m7" markdown>
Tokens only ever travel on the app-to-IdP request, never through the
browser's address bar. Open the trace panel and find these seven messages
in the live trace.
</div>

</div>
<!-- /stepper -->

## A widget you can break

The signature is the whole trick. Try the two attacker buttons and read the
verdict before moving on.

<iframe class="widget-frame" src="../widgets/jwt-tamper.html" title="Interactive: tamper with a JWT" height="560" loading="lazy"></iframe>

## Predict, then reveal

??? question "Checkpoint: you change `role` to `admin` in the payload and leave the signature alone. What does the server do?"
    It rejects the token. It recomputes the signature over the header and
    the new payload with its secret, gets a different value, and the
    comparison fails. You would need the secret to produce a matching one.
