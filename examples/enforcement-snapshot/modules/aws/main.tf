# Applies the AWS resources Xshield rendered for one account and region, and
# tells Xshield what was applied. Every decision is in the snapshot: this module
# only creates what it lists, keyed as it lists it.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = coalesce(var.cloud_account_id, data.aws_caller_identity.current.account_id)
  region     = coalesce(var.region, data.aws_region.current.region)
  workspace  = coalesce(var.workspace, "xshield-enforcement-${local.account_id}-${local.region}")
  snap       = data.xshield_enforcement_snapshot.this
}

data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = local.account_id
  region           = local.region
  version          = var.snapshot_version

  lifecycle {
    postcondition {
      condition     = self.cloud_account_id == data.aws_caller_identity.current.account_id && self.region == data.aws_region.current.region
      error_message = "This snapshot is for ${self.cloud_account_id}/${self.region}, but the AWS provider is configured for ${data.aws_caller_identity.current.account_id}/${data.aws_region.current.region}. Point the AWS provider at the account and region the snapshot is for."
    }
  }
}

# Xshield never unpublishes an account: it withdraws by publishing an empty
# version. So with nothing published, groups it rendered for a pipeline mean the
# provider is reading another tenant or endpoint, and applying would remove them.
data "aws_security_groups" "rendered" {
  count = local.snap.published ? 0 : 1

  filter {
    name   = "tag:ManagedBy"
    values = ["ColorTokens"]
  }
  filter {
    name   = "tag:ct:delivery"
    values = ["pipeline"]
  }

  lifecycle {
    postcondition {
      condition     = length(self.ids) == 0
      error_message = "Xshield has published nothing for ${local.account_id}/${local.region}, yet the account holds security groups Xshield rendered for a pipeline (${join(", ", self.ids)}), and applying would remove them. Check that the xshield provider's endpoint and API key are for the tenant that published them. To remove Xshield's groups on purpose, remove this module from the configuration."
    }
  }
}

resource "aws_security_group" "this" {
  for_each = local.snap.security_groups

  name        = each.value.name
  description = each.value.description
  vpc_id      = each.value.vpc_id
  tags        = merge(var.tags, each.value.tags)

  # Xshield drops a group only once no network interface holds it. If one still does, such as an
  # interface AWS has not yet released, fail within minutes rather than hold the pipeline.
  timeouts {
    delete = "5m"
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.snap.ingress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  description                  = each.value.description
  referenced_security_group_id = each.value.referenced_security_group_id
  tags                         = merge(var.tags, each.value.tags)
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.snap.egress_rules

  security_group_id            = aws_security_group.this[each.value.security_group].id
  ip_protocol                  = each.value.ip_protocol
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  description                  = each.value.description
  referenced_security_group_id = each.value.referenced_security_group_id
  tags                         = merge(var.tags, each.value.tags)
}

# Adds the group to the interface and leaves the interface's other groups in
# place, as the cloud connector does.
resource "aws_network_interface_sg_attachment" "this" {
  for_each = local.snap.interface_attachments

  security_group_id    = aws_security_group.this[each.value.security_group].id
  network_interface_id = each.value.network_interface_id
}

# One parameter per database, function or service its own workspace attaches;
# the group-lookup module reads it by handle.
resource "aws_ssm_parameter" "directory" {
  for_each = local.snap.directory

  name = each.value.parameter_name
  type = "String"
  insecure_value = jsonencode({
    handle             = each.value.handle
    security_group_ids = [for key in each.value.security_groups : aws_security_group.this[key].id]
  })
  tags = merge(var.tags, each.value.tags)
}

# Nothing published means nothing to confirm, so no receipt is created or sent.
resource "xshield_enforcement_receipt" "this" {
  count = local.snap.published ? 1 : 0

  cloud_account_id = local.snap.cloud_account_id
  region           = local.snap.region
  workspace        = local.workspace
  snapshot_version = local.snap.version

  security_groups = { for key, group in aws_security_group.this : key => group.id }
  rules = merge(
    { for key, rule in aws_vpc_security_group_ingress_rule.this : key => rule.security_group_rule_id },
    { for key, rule in aws_vpc_security_group_egress_rule.this : key => rule.security_group_rule_id },
  )
  # Recorded as the attachment's import ID, so a lost state can be rebuilt from the receipt.
  attachments = { for key, attachment in aws_network_interface_sg_attachment.this : key => "${attachment.network_interface_id}_${attachment.security_group_id}" }

  depends_on = [aws_ssm_parameter.directory]
}
