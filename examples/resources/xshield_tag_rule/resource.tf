# A tag rule applies core tags to the assets its criteria matches. Those tags are
# what segment criteria then select on, so tag rules run first in practice.

# Confirm the values you are matching on actually exist in the tenant.
data "xshield_field_values" "os" {
  field = "osname"
}

resource "xshield_tag_rule" "payroll_db" {
  rule_name        = "tag-payroll-databases"
  rule_description = "Tag the payroll database servers so the segment can select them"
  rule_enabled     = true

  # Unlike a segment criteria, a rule criteria is stored exactly as written.
  rule_criteria = "assetname like 'payroll-db-%'"

  on_match = {
    application = "payroll"
    role        = "db"
  }
}
