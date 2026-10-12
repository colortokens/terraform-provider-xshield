# A named network is a reusable set of addresses that policy rules can refer to.

resource "xshield_named_network" "corp" {
  named_network_name        = "corp-networks"
  named_network_description = "Corporate address space"

  ip_ranges = [
    { ip_range = "10.0.0.0/8" },
    { ip_range = "192.168.0.0/16" },
  ]

  # Whether traffic to these addresses counts as intranet rather than internet,
  # which decides how an allow-intranet port rule treats it.
  program_as_intranet = true
}
