# Who actually connects to the payroll database, before writing template paths.
data "xshield_paths" "into_payroll_db" {
  criteria = "application = 'payroll' AND role = 'db'"
}

output "peers" {
  value = toset([
    for p in data.xshield_paths.into_payroll_db.paths : p.source_asset_name
    if p.direction == "inbound" && p.source_asset_name != null
  ])
}
