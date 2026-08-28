# =============================================================================
# CONNECTOR-MANAGED ENFORCEMENT - policy-as-code + deployment trigger
#
# A deliberately different shape from Pipeline-Rendered Enforcement: here your
# Terraform authors the POLICY in Xshield and triggers deployment, and the
# Xshield cloud connector performs the cloud writes.
#
#   Pipeline-Rendered:  Xshield compiles -> your Terraform renders native
#                       security groups (vendor holds NO cloud credentials)
#   Connector-Managed:  your Terraform authors policy + triggers deploy
#                       (connector writes the security groups, as it does today)
#
# Connector-Managed is available with today's provider for the authoring half,
# works on any Terraform runner (no Sentinel dependency), and covers every cloud
# and resource type the connector already supports. Its trade-off is explicit:
# the connector keeps write access to the cloud account, and the concrete
# security group changes do not appear in the plan diff.
#
# Both approaches are supported. See ../APPROACHES.md for the comparison.
# =============================================================================

# ---- 1. Named networks: off-cloud peers, as code -----------------------------
resource "xshield_named_network" "saas_billing" {
  named_network_name        = "SaaS Billing"
  named_network_description = "Third-party billing provider ranges"

  ip_ranges = [
    { ip_range = "52.10.0.0/16" },
    { ip_range = "52.20.0.0/16" },
  ]
}

# ---- 2. Templates: reusable allow/block policy, as code ----------------------
#
# A template declares PORTS (what may listen) and, where the port is restricted,
# PATHS (who specifically may reach it).
#
# `listen_port_reviewed` is the decision for the port, and takes one of four
# values:
#
#   allow-any        listening open to any source
#   allow-intranet   listening open to intranet sources
#   path-restricted  listening permitted ONLY via the paths declared below
#   denied           port closed
#
# Ports and paths are the two halves of an allow: a port set to
# `path-restricted` with no matching path permits nothing.

# --- Allow, restricted to a specific source segment --------------------------
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

  # The path is what turns a restricted port into a usable allow. Here the
  # source is another SEGMENT, so the rule follows membership rather than
  # addresses - new instances in pci-app are covered automatically.
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

# --- Allow, restricted to a named network (off-cloud peer) -------------------
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

# --- Allow, open to intranet (no path restriction needed) --------------------
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

# --- Block: highest precedence in policy resolution --------------------------
# A blocked port stays closed regardless of any allow inherited from another
# segment - this is the construct that makes "most restrictive wins" hold.
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

# ---- 3. Segments: tag-based membership + attached policy, as code ------------
#
# Segments are hierarchical: a workload in pci-db is also in all-prod and
# inherits its policy. Where inherited policies conflict, blocks win and the
# most restrictive outcome prevails.

resource "xshield_segment" "all_prod" {
  tag_based_policy_name = "All Production"
  description           = "Every production workload"
  criteria              = "environment IN ('prod')"

  # Inherited by every segment below: the block, plus intranet metrics scraping.
  templates = [
    { template_id = xshield_template.block_legacy_ssh.id },
    { template_id = xshield_template.node_exporter.id },
    { template_id = xshield_template.billing_egress.id },
  ]

  namednetworks = [
    { named_network_id = xshield_named_network.saas_billing.id },
  ]
}

# The source segment referenced by the postgres path above. Declaring it as a
# segment (rather than naming addresses) is what keeps the resulting policy
# stable as the application tier scales.
resource "xshield_segment" "pci_app" {
  tag_based_policy_name = "PCI App Tier"
  description           = "PCI application tier"
  criteria              = "environment IN ('prod') AND application IN ('pci') AND tier IN ('app')"
}

resource "xshield_segment" "pci_db" {
  tag_based_policy_name = "PCI Database"
  description           = "PCI data tier"
  criteria              = "environment IN ('prod') AND application IN ('pci') AND tier IN ('db')"

  # Effective policy for a pci-db workload is this template composed with
  # everything inherited from all-prod, with the SSH block suppressing any
  # allow on 22.
  templates = [
    { template_id = xshield_template.postgres_from_app.id },
  ]
}

# ---- 4. Tag rules: keep membership deterministic -----------------------------
resource "xshield_tag_rule" "pci_db_classification" {
  rule_name        = "pci-db-classification"
  rule_description = "Classify AWS workloads carrying the org standard tags into the PCI data tier"
  rule_enabled     = true

  # Matches on discovered cloud tags; keeping this in code means the tag ->
  # segment join is reviewed in a pull request rather than configured ad hoc.
  rule_criteria = "cloudprovider IN ('aws') AND cct1 IN ('pci') AND cct2 IN ('db')"

  # Fields set on every matching asset - these are what segment criteria match.
  on_match = {
    application = "pci"
    environment = "prod"
    role        = "database"
  }
}
