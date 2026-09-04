# A template is a set of rules. Attaching it to a segment applies those rules to
# every asset in the segment.

# See what the assets actually listen on before deciding what to allow.
data "xshield_open_ports" "payroll_db" {
  criteria = "application = 'payroll' AND role = 'db'"
}

resource "xshield_template" "payroll_db" {
  template_name        = "payroll-db"
  template_description = "Inbound access to the payroll databases"
  template_type        = "application-template"
  template_category    = "Applications"

  # A port rule decides how traffic to a listening port is treated.
  #   denied          block it
  #   allow-intranet  allow from the intranet only
  #   allow-any       allow from anywhere, including the internet
  #   path-restricted allow only from the peers named in template_paths below
  template_ports = [
    {
      listen_port          = "5432"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "path-restricted"
      listen_process_names = ["postgres"]
    },
    {
      listen_port          = "22"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "allow-intranet"
    },
  ]

  # A path rule names one peer. An inbound path sets exactly one source, and an
  # outbound path exactly one destination.
  template_paths = [
    {
      direction = "inbound"
      port      = "5432"
      protocol  = "TCP"
      source_tag_based_policy = {
        tag_based_policy_name = "payroll-app"
      }
    },
    {
      direction = "inbound"
      port      = "5432"
      protocol  = "TCP"
      source_named_network = {
        named_network_name = "corp-networks"
      }
    },
  ]
}
