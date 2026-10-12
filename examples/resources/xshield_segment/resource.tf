# A segment selects assets by their tags and attaches policy to them.

# Check the criteria before creating the segment: this reports how many assets it
# selects today, and fails the plan if the expression is invalid.
data "xshield_criteria" "payroll_db" {
  criteria = "application = 'payroll' AND role = 'db'"
}

resource "xshield_segment" "payroll_db" {
  tag_based_policy_name = "payroll-db"
  description           = "Payroll database servers"
  criteria              = data.xshield_criteria.payroll_db.criteria

  # A segment criteria takes a strict subset of the search grammar: only =, !=,
  # IN, NOT IN, AND and parentheses, over core tag fields. The backend also
  # appends a managedby clause, which the provider applies during plan so the
  # stored value matches.

  target_breach_impact_score = 40
  timeline                   = 90

  # Attach policy. Either id or name works; a name is resolved during apply.
  templates = [
    { template_name = "payroll-web" },
  ]
  namednetworks = [
    { named_network_name = "corp-networks" },
  ]

  # The floor every member asset is held to.
  lowest_inbound_segment_asset_policy_status = "zerotrust"

  # Auto-sync deploys new rules on a schedule. The modes are test, enforce and
  # disable; the API reads them back as under-test and enforced, which the
  # provider maps for you.
  inbound_auto_sync_deployment_mode     = "test"
  inbound_auto_sync_interval_minutes    = 60
  inbound_auto_sync_include_violations  = true
  inbound_auto_sync_violation_threshold = 10
}
