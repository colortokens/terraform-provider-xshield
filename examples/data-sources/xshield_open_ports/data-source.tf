# Which inbound ports a payroll template would have to cover.
data "xshield_open_ports" "payroll" {
  criteria = "application = 'payroll' AND environment = 'prod'"
}

# Ports carrying no decision yet, which a deployment would leave in test.
output "unreviewed" {
  value = [
    for p in data.xshield_open_ports.payroll.ports :
    "${p.asset_name} ${p.listen_port_protocol}/${p.listen_port}"
    if p.listen_port_reviewed == "unreviewed"
  ]
}
