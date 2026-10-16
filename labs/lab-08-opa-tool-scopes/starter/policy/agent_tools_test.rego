# Run with:  opa test policy/ -v
package agentauth.tools_test

import data.agentauth.tools
import rego.v1

caps := [
	{"tool": "get_stats"},
	{"tool": "write_report", "max_body_chars": 200},
]

xs(n) := concat("", [x | some _ in numbers.range(1, n); x := "x"])

call_as(agent, capabilities, name, args) := {
	"agent": agent,
	"capabilities": capabilities,
	"tool": {"name": name, "args": args},
}

call(name, args) := call_as({"id": "tidy-agent", "sponsor": "idp-alice"}, caps, name, args)

test_a_granted_tool_is_allowed if {
	d := tools.decision with input as call("get_stats", {})
	d.allow
	d.policies == ["capability-granted"]
}

test_a_short_report_is_allowed if {
	d := tools.decision with input as call("write_report", {"title": "t", "body": "short"})
	d.allow
}

test_a_tool_with_no_capability_is_denied if {
	d := tools.decision with input as call("list_users", {})
	not d.allow
	d.policies == ["tool-not-granted"]
}

test_a_report_over_the_limit_is_denied if {
	d := tools.decision with input as call("write_report", {"title": "t", "body": xs(201)})
	not d.allow
	d.policies == ["report-too-long"]
}

test_a_report_exactly_at_the_limit_is_allowed if {
	d := tools.decision with input as call("write_report", {"title": "t", "body": xs(200)})
	d.allow
}

test_an_agent_without_a_sponsor_is_denied_even_for_a_granted_tool if {
	d := tools.decision with input as call_as({"id": "tidy-agent"}, caps, "get_stats", {})
	not d.allow
	d.policies == ["no-sponsor"]
}

test_every_objecting_policy_is_named if {
	bad := call_as({"id": "tidy-agent"}, caps, "list_users", {})
	d := tools.decision with input as bad
	d.policies == ["no-sponsor", "tool-not-granted"]
}

test_a_token_with_no_capabilities_is_denied if {
	d := tools.decision with input as call_as({"id": "tidy-agent", "sponsor": "idp-alice"}, [], "get_stats", {})
	not d.allow
}
