data "xshield_tag_rules" "all" {}

# A segment that matches too few assets usually means a disabled tag rule.
output "disabled_rules" {
  value = [
    for r in data.xshield_tag_rules.all.tag_rules : r.rule_name
    if !r.rule_enabled
  ]
}
