# Reports every problem an Xshield check of the plan raised, with the check's own message. Only a failed check
# carries problems. HCP Terraform passes the plan as input.plan; `opa eval` takes the plan JSON as the input itself.
package terraform.policies.xshield_checks

plan := object.get(input, "plan", input)

warn contains message if {
	some check in object.get(plan, "checks", [])
	check.address.kind == "check"
	startswith(check.address.name, "xshield_")
	some instance in check.instances
	some problem in object.get(instance, "problems", [])
	message := sprintf("%s: %s", [check.address.to_display, problem.message])
}
