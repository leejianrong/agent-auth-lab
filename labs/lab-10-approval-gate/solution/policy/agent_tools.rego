# Which tool calls may an agent make? (ADR-0007: the policy engine arrives.)
#
# The app asks OPA one question per tool call, sending a document like:
#
#   {
#     "agent":        {"id": "tidy-agent", "sponsor": "idp-alice"},
#     "capabilities": [{"tool": "get_stats"}, {"tool": "write_report", "max_body_chars": 200}],
#     "tool":         {"name": "write_report", "args": {"title": "...", "body": "..."}}
#   }
#
# `capabilities` comes from the agent's introspected token, never from the
# request. OPA answers with `decision`: allow or deny, plus the name of every
# policy that said no, so the audit trail can say which rule stopped the call.
package agentauth.tools

import rego.v1

# The capabilities on the token that are about the tool being called.
grants contains grant if {
	some grant in input.capabilities
	grant.tool == input.tool.name
}

# Every `deny` entry is one named policy that objects to this call.
# Deny wins: a single entry blocks the call, whatever else allows it.

deny contains {
	"policy": "no-sponsor",
	"reason": "the agent has no human sponsor, so nobody answers for it",
} if {
	not input.agent.sponsor
}

deny contains {
	"policy": "tool-not-granted",
	"reason": sprintf("the token carries no capability for '%s'", [input.tool.name]),
} if {
	count(grants) == 0
}

deny contains {
	"policy": "report-too-long",
	"reason": sprintf("the report body is %d characters; this capability allows %d", [count(input.tool.args.body), grant.max_body_chars]),
} if {
	input.tool.name == "write_report"
	some grant in grants
	count(input.tool.args.body) > grant.max_body_chars
}

# Lab 10: some capabilities are marked `"approval": "required"`. The policy says
# so in its answer, and the app holds the call until a person has decided.
requires_approval := true if {
	some grant in grants
	grant.approval == "required"
} else := false

decision := {
	"allow": true,
	"policies": ["capability-granted"],
	"reasons": [sprintf("a capability on the token covers '%s'", [input.tool.name])],
	"requires_approval": requires_approval,
} if {
	count(deny) == 0
}

decision := {
	"allow": false,
	"policies": sort({d.policy | some d in deny}),
	"reasons": sort([d.reason | some d in deny]),
	"requires_approval": false,
} if {
	count(deny) > 0
}
