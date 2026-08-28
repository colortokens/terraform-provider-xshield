# =============================================================================
# PORTABILITY - the same enforcement snapshot rendered to Azure.
#
# This workspace consumes the identical `xshield_enforcement_snapshot` data
# source as the AWS example. Nothing in the snapshot contract is AWS-specific;
# only the rendering differs, mapping onto each platform's native primitives:
#
#   enforcement group  -> azurerm_application_security_group   (ASG)
#   marker             -> azurerm_application_security_group   (rule-less ASG)
#   composed rule      -> azurerm_network_security_rule
#   peer = group       -> ASG reference on the opposite side of the rule
#   peer = marker      -> ASG reference on the opposite side of the rule
#   peer = prefix list -> address prefixes (NSG rules take prefixes directly;
#                         Azure IP Groups are an Azure Firewall construct)
#   peer = cidr        -> address prefix
#   workload directory -> azurerm_app_configuration_key
#
# Two Azure characteristics the rendering uses:
#
#  1. ASGs are membership tokens in their own right, so enforcement groups and
#     markers use the same primitive.
#  2. NSG rules are priority-ordered and support explicit deny, so the
#     default-deny floor is an explicit, auditable rule.
#
# As on AWS, no member address is ever emitted into a rule: peers resolve to ASG
# references or to stable ranges, so rules are invariant under scaling.
# =============================================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    xshield = { source = "colortokens/xshield" }
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "xshield" {
  server_url       = var.xshield_server_url
  tenancy_id       = var.xshield_tenancy_id
  user_id          = var.xshield_user_id
  fingerprint      = var.xshield_fingerprint
  private_key_path = var.xshield_private_key_path
}

data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.cloud_region
}

locals {
  snap         = data.xshield_enforcement_snapshot.this
  groups       = { for g in local.snap.enforcement_groups : g.slug => g }
  markers      = { for m in local.snap.markers : m.slug => m }
  prefix_lists = { for p in local.snap.prefix_lists : p.slug => p }

  rules_by_key = { for r in local.snap.rules : r.key => r }

  # Deterministic priorities from sorted rule keys: the same snapshot always
  # yields the same priorities. Allows occupy 1000+, the deny floor sits at 4000.
  ordered_rule_keys = sort(keys(local.rules_by_key))
  rule_priority     = { for idx, k in local.ordered_rule_keys : k => 1000 + idx }

  protocol_map   = { tcp = "Tcp", udp = "Udp", icmp = "Icmp" }
  asg_peer_types = ["group", "marker"]
}

resource "azurerm_resource_group" "ct" {
  name     = var.resource_group_name
  location = var.location
}

# ---- 1. enforcement group -> Application Security Group ---------------------
# Membership is ASG association on the NIC, so rules never change when instances
# scale - the property security group references provide on AWS.
resource "azurerm_application_security_group" "group" {
  for_each            = local.groups
  name                = "ct-seg-${each.value.slug}"
  location            = azurerm_resource_group.ct.location
  resource_group_name = azurerm_resource_group.ct.name

  tags = {
    colortokens_managed      = "true"
    colortokens_group        = each.value.slug
    colortokens_display_name = each.value.display_name
  }
}

# ---- 2. marker -> rule-less Application Security Group ----------------------
resource "azurerm_application_security_group" "marker" {
  for_each            = local.markers
  name                = "ct-ref-${each.key}"
  location            = azurerm_resource_group.ct.location
  resource_group_name = azurerm_resource_group.ct.name

  tags = {
    colortokens_managed = "true"
    colortokens_marker  = each.key
  }
}

# ---- 3. one NSG carrying the composed rules ---------------------------------
resource "azurerm_network_security_group" "ct" {
  name                = var.network_security_group_name
  location            = azurerm_resource_group.ct.location
  resource_group_name = azurerm_resource_group.ct.name

  tags = {
    colortokens_managed          = "true"
    colortokens_snapshot_version = local.snap.version
    colortokens_snapshot_hash    = local.snap.content_hash
  }
}

# ---- 4. composed rules ------------------------------------------------------
# Each rule places its OWN group on the side matching its direction, and its
# PEER on the opposite side. Both sides are always populated.
resource "azurerm_network_security_rule" "rule" {
  for_each = local.rules_by_key

  name                        = substr(replace(replace(each.value.key, "|", "_"), ":", "-"), 0, 80)
  resource_group_name         = azurerm_resource_group.ct.name
  network_security_group_name = azurerm_network_security_group.ct.name

  priority    = local.rule_priority[each.value.key]
  direction   = each.value.direction == "ingress" ? "Inbound" : "Outbound"
  access      = "Allow"
  protocol    = lookup(local.protocol_map, each.value.protocol, "*")
  description = "ct:${each.value.provenance_template}"

  source_port_range = "*"
  destination_port_range = (
    contains(["tcp", "udp"], each.value.protocol)
    ? (each.value.from_port == each.value.to_port
      ? tostring(each.value.from_port)
    : "${each.value.from_port}-${each.value.to_port}")
    : "*"
  )

  # --- SOURCE ---------------------------------------------------------------
  # inbound: the peer. outbound: the rule's own group.
  source_application_security_group_ids = (
    each.value.direction == "ingress"
    ? (contains(local.asg_peer_types, each.value.peer_type)
      ? [each.value.peer_type == "group"
        ? azurerm_application_security_group.group[each.value.peer_ref].id
      : azurerm_application_security_group.marker[each.value.peer_ref].id]
    : null)
    : [azurerm_application_security_group.group[each.value.group].id]
  )
  source_address_prefix = (
    each.value.direction == "ingress" && each.value.peer_type == "cidr"
    ? each.value.peer_ref : null
  )
  source_address_prefixes = (
    each.value.direction == "ingress" && each.value.peer_type == "prefixList"
    ? local.prefix_lists[each.value.peer_ref].entries : null
  )

  # --- DESTINATION ----------------------------------------------------------
  # inbound: the rule's own group. outbound: the peer.
  destination_application_security_group_ids = (
    each.value.direction == "ingress"
    ? [azurerm_application_security_group.group[each.value.group].id]
    : (contains(local.asg_peer_types, each.value.peer_type)
      ? [each.value.peer_type == "group"
        ? azurerm_application_security_group.group[each.value.peer_ref].id
      : azurerm_application_security_group.marker[each.value.peer_ref].id]
    : null)
  )
  destination_address_prefix = (
    each.value.direction == "egress" && each.value.peer_type == "cidr"
    ? each.value.peer_ref : null
  )
  destination_address_prefixes = (
    each.value.direction == "egress" && each.value.peer_type == "prefixList"
    ? local.prefix_lists[each.value.peer_ref].entries : null
  )

  lifecycle {
    precondition {
      condition     = contains(["group", "marker", "prefixList", "cidr"], each.value.peer_type)
      error_message = "Rule ${each.value.key} has an unrenderable peer type '${each.value.peer_type}'."
    }
  }
}

# ---- 5. explicit default-deny floor -----------------------------------------
resource "azurerm_network_security_rule" "deny_all_inbound" {
  name                        = "ct-deny-all-inbound"
  resource_group_name         = azurerm_resource_group.ct.name
  network_security_group_name = azurerm_network_security_group.ct.name
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
}

# ---- 6. workload directory -> App Configuration -----------------------------
# Same contract as SSM Parameter Store on AWS: application teams resolve their
# groups from their own tags.
resource "azurerm_app_configuration" "ct" {
  name                = var.app_configuration_name
  resource_group_name = azurerm_resource_group.ct.name
  location            = azurerm_resource_group.ct.location
  sku                 = "standard"
}

resource "azurerm_app_configuration_key" "directory" {
  for_each               = { for e in local.snap.directory : e.path => e }
  configuration_store_id = azurerm_app_configuration.ct.id
  key                    = "/colortokens/v1/${each.value.path}"

  value = jsonencode({
    group    = each.value.group
    asg_ids  = [azurerm_application_security_group.group[each.value.group].id]
    snapshot = local.snap.version
  })
}

output "rendering_summary" {
  description = "Same snapshot, Azure-native rendering."
  value = {
    snapshot_version = local.snap.version
    groups           = { for k, a in azurerm_application_security_group.group : k => a.name }
    markers          = { for k, a in azurerm_application_security_group.marker : k => a.name }
    rules_rendered   = length(local.rules_by_key)
  }
}
