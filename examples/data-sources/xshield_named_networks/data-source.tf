data "xshield_named_networks" "all" {}

output "ranges" {
  value = {
    for n in data.xshield_named_networks.all.named_networks :
    n.named_network_name => [for r in n.ip_ranges : r.ip_range]
  }
}
