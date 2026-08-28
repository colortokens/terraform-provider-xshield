# =============================================================================
# Account ENFORCEMENT workspace (one per account x region; SecOps-owned).
#
# This is the ONLY place ColorTokens resources are created. It:
#   1. resolves the account's expected enforcement snapshot (no version pin)
#   2. renders one composed security group per enforcement group
#   3. renders marker groups (membership tokens) and managed prefix lists
#   4. renders one rule per composed rule, keyed by a STABLE content-derived key
#   5. publishes the tag -> security group "workload directory" to SSM
#
# Application workspaces consume the directory by tag (see ../modules/
# ct-workload-lookup) and never reference an Xshield name, version, or credential.
#
# ForceNew hygiene throughout: nothing user-editable in Xshield (display names,
# versions) may feed a security-group attribute that forces replacement.
# Mutable metadata goes to tags, which update in place.
# =============================================================================

data "xshield_enforcement_snapshot" "this" {
  cloud_account_id = var.cloud_account_id
  region           = var.region
  # No version argument: resolves the server-side EXPECTED version, so the code
  # is static and converges the way every other Xshield enforcement point does.
}

locals {
  snap = data.xshield_enforcement_snapshot.this

  groups       = { for g in local.snap.enforcement_groups : g.slug => g }
  markers      = { for m in local.snap.markers : m.slug => m }
  prefix_lists = { for p in local.snap.prefix_lists : p.slug => p }

  # Stable, content-derived for_each keys come straight from the snapshot, so a
  # cosmetic reordering upstream never churns resource addresses.
  rules_by_key = { for r in local.snap.rules : r.key => r }

  ingress_rules = { for k, r in local.rules_by_key : k => r if r.direction == "ingress" }
  egress_rules  = { for k, r in local.rules_by_key : k => r if r.direction == "egress" }

  ct_tags = merge({
    "colortokens:managed"          = "true"
    "colortokens:snapshot-version" = tostring(local.snap.version)
  }, var.tags)

  # Peer types this module knows how to render. Anything else must fail loudly
  # rather than silently degrade (a mis-rendered peer is a security event).
  known_peer_types = ["group", "marker", "prefixList", "cidr"]
  unknown_peers    = [for k, r in local.rules_by_key : k if !contains(local.known_peer_types, r.peer_type)]

  # World-open ingress is legal policy but must never pass unnoticed.
  world_open_ingress = [
    for k, r in local.ingress_rules : k
    if r.peer_type == "cidr" && contains(["0.0.0.0/0", "::/0"], r.peer_ref)
  ]
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
    "Name"                      = "ct-seg-${each.value.slug}"
    "colortokens:group"         = each.value.slug
    "colortokens:display-name"  = each.value.display_name
    "colortokens:snapshot-hash" = local.snap.content_hash
  })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(each.value.vpc_ids) <= 1
      error_message = "Enforcement group '${each.value.slug}' spans multiple VPCs (${join(", ", each.value.vpc_ids)}). This example renders a single VPC; use the production module's per-VPC rendering, or split the segment."
    }
  }
}

# ---- 2. marker groups (rule-less membership tokens for broad ancestors) ------
resource "aws_security_group" "marker" {
  for_each = local.markers

  name_prefix = "${each.value.name}-"
  description = "ColorTokens marker (membership token) for segment ${each.value.slug}"
  vpc_id      = var.vpc_id

  tags = merge(local.ct_tags, {
    "Name"               = each.value.name
    "colortokens:marker" = each.value.slug
  })

  lifecycle { create_before_destroy = true }
}

# ---- 3. managed prefix lists (off-cloud peers; ranges, scale-invariant) ------
resource "aws_ec2_managed_prefix_list" "pl" {
  for_each = local.prefix_lists

  name           = each.value.name
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

  tags = merge(local.ct_tags, { "Name" = each.value.name })

  lifecycle {
    precondition {
      condition     = contains(["IPv4", "IPv6"], each.value.address_family)
      error_message = "Prefix list '${each.value.slug}' has address_family '${each.value.address_family}'; AWS accepts only 'IPv4' or 'IPv6'."
    }
  }
}

# ---- 4. one rule per composed rule, by stable key ----------------------------
resource "aws_vpc_security_group_ingress_rule" "ingress" {
  for_each = local.ingress_rules

  security_group_id = aws_security_group.group[each.value.group].id
  ip_protocol       = each.value.protocol

  # Ports apply to tcp/udp only. "-1" (all protocols) must omit ports entirely;
  # icmp/icmpv6 use from/to as type/code and are passed through unchanged.
  from_port = contains(["tcp", "udp"], each.value.protocol) ? each.value.from_port : null
  to_port   = contains(["tcp", "udp"], each.value.protocol) ? each.value.to_port : null

  # Peers always resolve to a fabric construct or a range - never a member IP.
  # This is what makes the rendered rules invariant under autoscaling.
  referenced_security_group_id = (
    each.value.peer_type == "group" ? aws_security_group.group[each.value.peer_ref].id :
    each.value.peer_type == "marker" ? aws_security_group.marker[each.value.peer_ref].id :
    null
  )
  prefix_list_id = each.value.peer_type == "prefixList" ? aws_ec2_managed_prefix_list.pl[each.value.peer_ref].id : null
  cidr_ipv4      = each.value.peer_type == "cidr" && !strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null
  cidr_ipv6      = each.value.peer_type == "cidr" && strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null

  description = "ct:${each.value.provenance_template}"

  tags = merge(local.ct_tags, {
    "colortokens:rule-key"      = each.value.key
    "colortokens:provenance"    = each.value.provenance_segment
    "colortokens:snapshot-hash" = local.snap.content_hash
  })

  # Content-keyed rules must never leave an enforcement gap mid-apply.
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_egress_rule" "egress" {
  for_each = local.egress_rules

  security_group_id = aws_security_group.group[each.value.group].id
  ip_protocol       = each.value.protocol
  from_port         = contains(["tcp", "udp"], each.value.protocol) ? each.value.from_port : null
  to_port           = contains(["tcp", "udp"], each.value.protocol) ? each.value.to_port : null

  referenced_security_group_id = (
    each.value.peer_type == "group" ? aws_security_group.group[each.value.peer_ref].id :
    each.value.peer_type == "marker" ? aws_security_group.marker[each.value.peer_ref].id :
    null
  )
  prefix_list_id = each.value.peer_type == "prefixList" ? aws_ec2_managed_prefix_list.pl[each.value.peer_ref].id : null
  cidr_ipv4      = each.value.peer_type == "cidr" && !strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null
  cidr_ipv6      = each.value.peer_type == "cidr" && strcontains(each.value.peer_ref, ":") ? each.value.peer_ref : null

  description = "ct:${each.value.provenance_template}"

  tags = merge(local.ct_tags, {
    "colortokens:rule-key"      = each.value.key
    "colortokens:provenance"    = each.value.provenance_segment
    "colortokens:snapshot-hash" = local.snap.content_hash
  })

  lifecycle { create_before_destroy = true }
}

# ---- 5. publish the tag -> security group workload directory -----------------
# Application teams resolve their groups from these parameters using ONLY their
# own tags. The path schema follows the org tagging standard, never an Xshield
# name. WRITE ACCESS TO THIS NAMESPACE MUST BE RESTRICTED TO THIS WORKSPACE'S
# ROLE - see iam-guardrails.md; a principal that can rewrite these parameters can
# redirect which security groups future workloads attach.
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
    snapshot      = local.snap.version
    content_hash  = local.snap.content_hash
  })

  tags = merge(local.ct_tags, { "colortokens:group" = each.value.group })
}

# ---- 6. plan-time assertions -------------------------------------------------
# Quarantined assets are excluded from rendering (fail-secure), but divergence
# must never be silent. `check` emits a warning on every plan; the HARD gate
# belongs in Sentinel (ct-conformance-watch) so it cannot be argued away locally.
check "quarantine" {
  assert {
    condition     = local.snap.quarantined_assets <= var.max_quarantined_assets
    error_message = "Snapshot has ${local.snap.quarantined_assets} quarantined asset(s) (limit ${var.max_quarantined_assets}). Their policy is NOT rendered. Resolve with exception segments in Xshield, or raise max_quarantined_assets deliberately."
  }
}

check "renderable_peers" {
  assert {
    condition     = length(local.unknown_peers) == 0
    error_message = "Snapshot contains rule(s) with an unrenderable peer type: ${join(", ", local.unknown_peers)}. Upgrade the module/provider rather than applying a partial policy."
  }
}

check "world_open_ingress" {
  assert {
    condition     = length(local.world_open_ingress) == 0
    error_message = "Approved policy contains world-open ingress: ${join(", ", local.world_open_ingress)}. This is legal but should be a deliberate, reviewed decision."
  }
}
