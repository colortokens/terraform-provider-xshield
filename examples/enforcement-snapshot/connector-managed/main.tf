resource "xshield_named_network" "saas_billing" {
  named_network_name        = "SaaS Billing"
  named_network_description = "Third-party billing provider ranges"

  ip_ranges = [
    { ip_range = "198.51.100.0/24" },
    { ip_range = "203.0.113.0/24" },
  ]
}

# A path-restricted port permits only the paths the template declares for it.
resource "xshield_template" "postgres_from_app" {
  template_name        = "postgres-from-app"
  template_description = "Allow Postgres only from the PCI application tier"
  template_type        = "application-template"
  template_category    = "custom"

  template_ports = [
    {
      listen_port          = "5432"
      listen_port_name     = "postgres"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "path-restricted"
    },
  ]

  template_paths = [
    {
      direction = "inbound"
      port      = "5432"
      protocol  = "TCP"

      source_tag_based_policy = {
        tag_based_policy_id = xshield_segment.pci_app.id
      }
    },
  ]
}

resource "xshield_template" "billing_egress" {
  template_name        = "billing-egress"
  template_description = "Allow outbound HTTPS to the billing provider only"
  template_type        = "application-template"
  template_category    = "custom"

  template_ports = [
    {
      listen_port          = "443"
      listen_port_name     = "https"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "path-restricted"
    },
  ]

  template_paths = [
    {
      direction = "outbound"
      port      = "443"
      protocol  = "TCP"

      destination_named_network = {
        named_network_id = xshield_named_network.saas_billing.id
      }
    },
  ]
}

resource "xshield_template" "node_exporter" {
  template_name        = "node-exporter"
  template_description = "Allow metrics scraping from anywhere on the intranet"
  template_type        = "application-template"
  template_category    = "custom"

  template_ports = [
    {
      listen_port          = "9100"
      listen_port_name     = "node-exporter"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "allow-intranet"
    },
  ]
}

# A blocked port stays closed whatever another segment allows.
resource "xshield_template" "block_legacy_ssh" {
  template_name        = "block-legacy-ssh"
  template_description = "Deny legacy SSH estate-wide"
  template_type        = "block-template"
  template_category    = "custom"

  template_ports = [
    {
      listen_port          = "22"
      listen_port_name     = "ssh"
      listen_port_protocol = "TCP"
      listen_port_reviewed = "denied"
    },
  ]
}

resource "xshield_segment" "all_prod" {
  tag_based_policy_name = "All Production"
  description           = "Every production workload"
  criteria              = "environment IN ('prod')"

  templates = [
    { template_id = xshield_template.block_legacy_ssh.id },
    { template_id = xshield_template.node_exporter.id },
    { template_id = xshield_template.billing_egress.id },
  ]

  namednetworks = [
    { named_network_id = xshield_named_network.saas_billing.id },
  ]
}

resource "xshield_segment" "pci_app" {
  tag_based_policy_name = "PCI App Tier"
  description           = "PCI application tier"
  criteria              = "environment IN ('prod') AND application IN ('pci') AND tier IN ('app')"
}

resource "xshield_segment" "pci_db" {
  tag_based_policy_name = "PCI Database"
  description           = "PCI data tier"
  criteria              = "environment IN ('prod') AND application IN ('pci') AND tier IN ('db')"

  templates = [
    { template_id = xshield_template.postgres_from_app.id },
  ]
}

resource "xshield_tag_rule" "pci_db_classification" {
  rule_name        = "pci-db-classification"
  rule_description = "Classify AWS workloads carrying the org standard tags into the PCI data tier"
  rule_enabled     = true

  rule_criteria = "cloudprovider IN ('aws') AND cct1 IN ('pci') AND cct2 IN ('db')"

  on_match = {
    application = "pci"
    environment = "prod"
    tier        = "db"
  }
}
