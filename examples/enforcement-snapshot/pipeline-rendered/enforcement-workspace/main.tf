# =============================================================================
# Account ENFORCEMENT workspace (one per account x region; SecOps-owned).
#
# This is the ONLY place ColorTokens resources are created. It:
#   1. resolves the account's expected enforcement snapshot (no version pin)
#   2. renders one composed security group per enforcement group
#   3. renders marker groups (membership tokens) and managed prefix lists
#   4. renders one rule per composed rule, keyed by a STABLE content-derived key
#   5. publishes the tag -> security group "workload directory" to SSM
#   6. reports the applied snapshot and every created resource ID to Xshield
#
# Application workspaces consume the directory by tag (see ../modules/
# ct-workload-lookup) and never reference an Xshield name, version, or credential.
#
# Two rules keep plans reviewable:
#   * ForceNew hygiene - nothing user-editable in Xshield (display names,
#     versions) feeds an attribute that forces replacement.
#   * No per-version stamps - the snapshot version and hash live only on the
#     receipt, so a one-rule policy change plans as one rule, not as a tag
#     update on every resource in the account.
# =============================================================================

data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region
  # No version argument: resolves the server-side EXPECTED version, so the code
  # is static and converges the way every other Xshield enforcement point does.
}

locals {
  snap = data.xshield_enforcement_snapshot.this

  workspace_name = coalesce(var.enforcement_workspace_name, "ct-enforcement-${var.cloud_account_id}-${var.region}")

  groups       = { for g in local.snap.enforcement_groups : g.slug => g }
  markers      = { for m in local.snap.markers : m.slug => m }
  address_sets = { for a in local.snap.address_sets : a.slug => a }

  # Stable, content-derived for_each keys come straight from the snapshot, so a
  # cosmetic reordering upstream never churns resource addresses.
  rules_by_key = { for r in local.snap.rules : r.key => r }

  ingress_rules = { for k, r in local.rules_by_key : k => r if r.direction == "ingress" }
  egress_rules  = { for k, r in local.rules_by_key : k => r if r.direction == "egress" }

  ct_tags = merge({ "colortokens:managed" = "true" }, var.tags)

  # Peer types this configuration knows how to render. Anything else fails the
  # plan: a rule rendered without its peer is a security event, not a warning.
  known_peer_types = ["group", "marker", "addressSet", "cidr"]
  ported_protocols = ["tcp", "udp", "icmp", "icmpv6"]

  world_open_ingress = [
    for k, r in local.ingress_rules : k
    if r.peer_type == "cidr" && contains(["0.0.0.0/0", "::/0"], r.peer_ref)
  ]

  rendered_rule_ids = merge(
    { for k, r in aws_vpc_security_group_ingress_rule.ingress : k => r.security_group_rule_id },
    { for k, r in aws_vpc_security_group_egress_rule.egress : k => r.security_group_rule_id },
  )
}

# ---- 1. composed security group per enforcement group ------------------------
resource "aws_security_group" "group" {
  for_each = local.groups

  # name_prefix + create_before_destroy: any forced replacement becomes a
  # two-phase rollover instead of a destroy-first DependencyViolation wedge
  # (AWS refuses to delete a security group while an ENI still references it).
  name_prefix = "ct-seg-${each.value.slug}-"

  # Immutable slug only - description is ForceNew, and display names are
  # user-editable in Xshield.
  description = "ColorTokens enforcement group ${each.value.slug}"
  vpc_id      = var.vpc_id

  tags = merge(local.ct_tags, {
    "Name"                     = "ct-seg-${each.value.slug}"
    "colortokens:group"        = each.value.slug
    "colortokens:display-name" = each.value.display_name
  })

  lifecycle {
    create_before_destroy = true

    # AWS limits rules per security group per direction (60 by default), and a
    # referenced prefix list counts as its max_entries, not as one rule.
    precondition {
      condition     = each.value.ingress_count <= var.max_rules_per_security_group && each.value.egress_count <= var.max_rules_per_security_group
      error_message = "Enforcement group '${each.value.slug}' needs ${each.value.ingress_count} ingress and ${each.value.egress_count} egress rules; this account allows ${var.max_rules_per_security_group} per direction. Raise the account quota and max_rules_per_security_group together, or split the segment."
    }

    precondition {
      condition     = length(each.value.vpc_ids) <= 1
      error_message = "Enforcement group '${each.value.slug}' spans multiple VPCs (${join(", ", each.value.vpc_ids)}). This example renders a single VPC; use the production module's per-VPC rendering, or split the segment."
    }
  }
}

# ---- 2. marker groups (rule-less membership tokens for broad ancestors) ------
resource "aws_security_group" "marker" {
  for_each = local.markers

  name_prefix = "ct-ref-${each.value.slug}-"
  description = "ColorTokens marker (membership token) for segment ${each.value.slug}"
  vpc_id      = var.vpc_id

  tags = merge(local.ct_tags, {
    "Name"                     = "ct-ref-${each.value.slug}"
    "colortokens:marker"       = each.value.slug
    "colortokens:display-name" = each.value.display_name
  })

  lifecycle { create_before_destroy = true }
}

# ---- 3. address sets as managed prefix lists (ranges, scale-invariant) -------
resource "aws_ec2_managed_prefix_list" "pl" {
  for_each = local.address_sets

  name           = "ct-pl-${each.value.slug}"
  address_family = each.value.address_family

  # Headroom so routine range additions update entries in place instead of
  # forcing a replacement. NOTE: AWS charges max_entries (not the current entry
  # count) against the rule quota of every group that references this list.
  max_entries = length(each.value.entries) + var.prefix_list_headroom

  dynamic "entry" {
    for_each = each.value.entries
    content {
      cidr = entry.value
    }
  }

  tags = merge(local.ct_tags, {
    "Name"                    = "ct-pl-${each.value.slug}"
    "colortokens:address-set" = each.value.slug
  })

  lifecycle {
    precondition {
      condition     = contains(["IPv4", "IPv6"], each.value.address_family)
      error_message = "Address set '${each.value.slug}' has address_family '${each.value.address_family}'; AWS accepts only 'IPv4' or 'IPv6'."
    }
  }
}

# ---- 4. one rule per composed rule, by stable key ----------------------------
resource "aws_vpc_security_group_ingress_rule" "ingress" {
  for_each = local.ingress_rules

  security_group_id = aws_security_group.group[each.value.group].id
  ip_protocol       = each.value.protocol == "all" ? "-1" : each.value.protocol

  # tcp/udp carry a port range and icmp/icmpv6 carry type/code (-1 = all) in
  # the same fields; AWS requires all-protocol and other-protocol rules to omit them.
  from_port = contains(local.ported_protocols, each.value.protocol) ? each.value.from_port : null
  to_port   = contains(local.ported_protocols, each.value.protocol) ? each.value.to_port : null

  # Peers always resolve to a fabric construct or a range - never a member IP.
  # This is what makes the rendered rules invariant under autoscaling.
  referenced_security_group_id = (
    each.value.peer_type == "group" ? aws_security_group.group[each.value.peer_ref].id :
    each.value.peer_type == "marker" ? aws_security_group.marker[each.value.peer_ref].id :
    null
  )
  prefix_list_id = each.value.peer_type == "addressSet" ? aws_ec2_managed_prefix_list.pl[each.value.peer_ref].id : null
  cidr_ipv4      = each.value.peer_type == "cidr" && !strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null
  cidr_ipv6      = each.value.peer_type == "cidr" && strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null

  # Security group rule descriptions forbid "|", so the exact key lives in the tag.
  description = "ct:${replace(each.value.key, "|", " ")}"

  tags = merge(local.ct_tags, {
    "colortokens:rule-key" = each.value.key
  })

  lifecycle {
    # Content-keyed rules must never leave an enforcement gap mid-apply.
    create_before_destroy = true

    precondition {
      condition     = contains(local.known_peer_types, each.value.peer_type) && each.value.peer_ref != ""
      error_message = "Snapshot rule ${each.value.key} has peer type '${each.value.peer_type}', which this configuration cannot render; applying it would create a rule with no source. Upgrade the rendering configuration before applying this snapshot."
    }
  }
}

resource "aws_vpc_security_group_egress_rule" "egress" {
  for_each = local.egress_rules

  security_group_id = aws_security_group.group[each.value.group].id
  ip_protocol       = each.value.protocol == "all" ? "-1" : each.value.protocol
  from_port         = contains(local.ported_protocols, each.value.protocol) ? each.value.from_port : null
  to_port           = contains(local.ported_protocols, each.value.protocol) ? each.value.to_port : null

  referenced_security_group_id = (
    each.value.peer_type == "group" ? aws_security_group.group[each.value.peer_ref].id :
    each.value.peer_type == "marker" ? aws_security_group.marker[each.value.peer_ref].id :
    null
  )
  prefix_list_id = each.value.peer_type == "addressSet" ? aws_ec2_managed_prefix_list.pl[each.value.peer_ref].id : null
  cidr_ipv4      = each.value.peer_type == "cidr" && !strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null
  cidr_ipv6      = each.value.peer_type == "cidr" && strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null

  description = "ct:${replace(each.value.key, "|", " ")}"

  tags = merge(local.ct_tags, {
    "colortokens:rule-key" = each.value.key
  })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = contains(local.known_peer_types, each.value.peer_type) && each.value.peer_ref != ""
      error_message = "Snapshot rule ${each.value.key} has peer type '${each.value.peer_type}', which this configuration cannot render; applying it would create a rule with no source. Upgrade the rendering configuration before applying this snapshot."
    }
  }
}

# ---- 5. publish the tag -> security group workload directory -----------------
# Application teams resolve their groups from these parameters using ONLY their
# own tags. The path schema follows the org tagging standard, never an Xshield
# name. WRITE ACCESS TO THIS NAMESPACE MUST BE RESTRICTED TO THIS WORKSPACE'S
# ROLE - see iam-guardrails.md; a principal that can rewrite these parameters can
# redirect which security groups future workloads attach.
#
# The value changes only when a security group ID changes, so application
# workspaces reading it see no churn from routine policy versions.
resource "aws_ssm_parameter" "directory" {
  for_each = { for e in local.snap.directory : e.path => e }

  name   = "${var.directory_prefix}/${each.value.path}"
  type   = var.directory_kms_key_id == null ? "String" : "SecureString"
  key_id = var.directory_kms_key_id
  tier   = "Standard"

  value = jsonencode({
    group         = each.value.group
    sg_ids        = [aws_security_group.group[each.value.group].id]
    marker_sg_ids = [for s in local.groups[each.value.group].marker_slugs : aws_security_group.marker[s].id]
    vpc_id        = var.vpc_id
  })

  tags = merge(local.ct_tags, { "colortokens:group" = each.value.group })
}

# ---- 6. report convergence and the resource map back to Xshield --------------
# Sent only once every rendered resource exists, and only when the version or a
# resource ID changes. Xshield rejects a receipt that omits or adds to the
# snapshot's resources, so a partial render is never recorded as converged.
resource "xshield_enforcement_receipt" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region
  workspace        = local.workspace_name
  snapshot_version = local.snap.version
  content_hash     = local.snap.content_hash
  vpc_id           = var.vpc_id

  groups       = { for slug, sg in aws_security_group.group : slug => sg.id }
  markers      = { for slug, sg in aws_security_group.marker : slug => sg.id }
  address_sets = { for slug, pl in aws_ec2_managed_prefix_list.pl : slug => pl.id }
  rules        = local.rendered_rule_ids

  depends_on = [aws_ssm_parameter.directory]
}

# ---- 7. plan-time assertions (warnings; the hard gates are preconditions above
#         and the Sentinel policy set) ---------------------------------------
# Only checks that read nothing new belong here. A check with its own data
# source is re-read at apply, so every plan would show as having changes and no
# run would ever report "No changes". Drift checks live in ../monitor-workspace.
check "quarantine" {
  assert {
    condition     = local.snap.quarantined_assets <= var.max_quarantined_assets
    error_message = "Snapshot has ${local.snap.quarantined_assets} quarantined asset(s) (limit ${var.max_quarantined_assets}). Their policy is NOT rendered. Resolve with exception segments in Xshield, or raise max_quarantined_assets deliberately."
  }
}

check "world_open_ingress" {
  assert {
    condition     = length(local.world_open_ingress) == 0
    error_message = "Approved policy contains world-open ingress: ${join(", ", local.world_open_ingress)}. This is legal but should be a deliberate, reviewed decision."
  }
}
