"""The hand-rolled ABAC/ReBAC policy evaluator (ADR-0007).

RBAC (lab 02) answers "does this role get in the door at all" for an entire
route. That's the wrong shape of question for something like "can this
specific caller read this specific note" — the answer there depends on the
*relationship* between the caller and the resource (are they its owner?),
not just which role they hold. This module answers that finer-grained
question.

The rules below are a flat, ordered list of data, not a pile of nested
`if`/`elif` — the whole point (per ADR-0007) is that a decision can point at
the specific rule that produced it, by ID, rather than just "the code path
that happened to run." `evaluate()` walks the list in order and returns the
first rule whose condition matches, alongside the allow/deny outcome that
rule specifies. `default-deny` matches unconditionally, at the end, so a
resource with no owner-shaped rule that applies always denies rather than
falling through with no answer at all.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Subject:
    """The caller attempting the action — the attributes a rule might need
    about *who* is asking, not *what* they're asking to do."""

    id: int
    role: str


@dataclass(frozen=True)
class ResourceAttrs:
    """The attributes of the resource being acted on — here, just the note's
    owner, which is all any current rule needs to know about it."""

    owner_id: int


@dataclass(frozen=True)
class PolicyDecision:
    """The evaluator's answer: not just allow/deny, but which rule produced
    it and a human-readable description of that rule — the pair the
    policy-decision trace viewer renders for a request."""

    allow: bool
    rule_id: str
    rule_description: str


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    effect: str  # "allow" or "deny"
    condition: Callable[[Subject, ResourceAttrs, str], bool]


def _is_admin(subject: Subject, resource: ResourceAttrs, action: str) -> bool:
    return subject.role == "admin"


def _is_owner(subject: Subject, resource: ResourceAttrs, action: str) -> bool:
    """Is `subject` the resource's owner? The one attribute-vs-relationship
    check this whole lab exists to teach: it has to compare the *caller* to
    the resource, not the resource to itself."""
    # TODO(lab-03): this compares the resource's owner_id to itself, which
    # is trivially always True, instead of comparing it to the caller's
    # subject.id. Since `admin-full-access` below only catches actual
    # admins, every OTHER authenticated caller falls through to this rule
    # next — and with this comparison, this rule matches for all of them,
    # owner or not. Any logged-in user ends up able to read and overwrite
    # anyone else's note, not just their own. Compare the two ids for real.
    return resource.owner_id == resource.owner_id


RULES: list[Rule] = [
    Rule(
        id="admin-full-access",
        description="Admins can read or write any resource",
        effect="allow",
        condition=_is_admin,
    ),
    Rule(
        id="owner-full-access",
        description="The resource's owner can read or write it",
        effect="allow",
        condition=_is_owner,
    ),
    Rule(
        id="default-deny",
        description="No rule granted access; deny by default",
        effect="deny",
        condition=lambda subject, resource, action: True,
    ),
]


def evaluate(subject: Subject, resource: ResourceAttrs, action: str) -> PolicyDecision:
    """Walk `RULES` in order and return the first match, allow or deny,
    naming the rule that decided it. `default-deny` always matches, so this
    always returns something — there's no code path where a caller reaches
    the end of the rule list with no answer."""
    for rule in RULES:
        if rule.condition(subject, resource, action):
            return PolicyDecision(
                allow=(rule.effect == "allow"),
                rule_id=rule.id,
                rule_description=rule.description,
            )
    raise AssertionError("no rule matched — default-deny should always match")
