# What values the environment tag actually takes, and how many assets carry each.
data "xshield_field_values" "environments" {
  field = "environment"
}

# Narrow the population first to see the values within one application.
data "xshield_field_values" "payroll_roles" {
  field    = "role"
  criteria = "application = 'payroll'"
}
