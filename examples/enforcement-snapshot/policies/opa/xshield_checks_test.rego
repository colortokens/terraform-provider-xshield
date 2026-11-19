package terraform.policies.xshield_checks_test

import data.terraform.policies.xshield_checks

check_result(name, status, problems) := {
	"address": {"kind": "check", "name": name, "to_display": sprintf("check.%s", [name])},
	"status": status,
	"instances": [object.union({"address": {"to_display": sprintf("check.%s", [name])}, "status": status}, problems)],
}

failed_check(name, message) := check_result(name, "fail", {"problems": [{"message": message}]})

test_a_failed_xshield_check_is_reported_with_its_message if {
	warnings := xshield_checks.warn with input as {"checks": [
		failed_check("xshield_drift_high", "Xshield sees high-severity drift in 123456789012/us-east-1:"),
		check_result("xshield_never_applied", "pass", {}),
	]}
	warnings == {"check.xshield_drift_high: Xshield sees high-severity drift in 123456789012/us-east-1:"}
}

test_checks_that_pass_report_nothing if {
	count(xshield_checks.warn) == 0 with input as {"checks": [check_result("xshield_drift_high", "pass", {}), check_result("xshield_never_applied", "unknown", {})]}
}

test_a_failed_check_that_is_not_xshields_is_left_alone if {
	count(xshield_checks.warn) == 0 with input as {"checks": [failed_check("certificate_expiry", "the certificate expires in 3 days")]}
}

test_a_failed_precondition_named_like_a_check_is_left_alone if {
	count(xshield_checks.warn) == 0 with input as {"checks": [object.union(
		failed_check("xshield_drift_high", "x"),
		{"address": {"kind": "output_value", "name": "xshield_drift_high", "to_display": "output.xshield_drift_high"}},
	)]}
}

test_a_plan_with_no_checks_reports_nothing if {
	count(xshield_checks.warn) == 0 with input as {"resource_changes": []}
}

test_failed_checks_in_the_hcp_terraform_input_shape if {
	count(xshield_checks.warn) == 1 with input as {"plan": {"checks": [failed_check("xshield_apply_overdue", "waited")]}}
}

test_a_check_the_plan_did_not_evaluate_reports_nothing if {
	count(xshield_checks.warn) == 0 with input as {"checks": [
		{"address": {"kind": "check", "name": "xshield_drift_high", "to_display": "check.xshield_drift_high"}, "status": "unknown"},
		{"address": {"kind": "check", "name": "xshield_never_applied", "to_display": "check.xshield_never_applied"}, "status": "unknown", "instances": null},
	]}
}
