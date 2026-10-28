# =============================================================================
# Triggering DEPLOYMENT from Terraform - two variants.
#
# Authoring policy (main.tf) works with today's provider. Moving policy from
# authored -> test -> enforced is a platform ACTION, and actions are the one
# thing Terraform models awkwardly. Both variants below are supported: the first
# is the recommended target, the second is adoptable immediately with no
# platform change.
# =============================================================================

# -----------------------------------------------------------------------------
# VARIANT 1 (recommended) - a native resource.
#
# Declarative, idempotent, visible in the plan, no runner dependencies, and the
# deployment state is reconciled like any other resource.
#
# resource "xshield_policy_deployment" "pci_db" {
#   # what to deploy
#   criteria  = xshield_segment.pci_db.criteria
#   direction = "inbound"          # inbound | outbound
#   mode      = "enforced"         # test | enforced | undeploy
#
#   # deploy only what has been reviewed; unreviewed ports stay in test
#   include_reviewed   = true
#   include_unreviewed = false
#
#   # re-run when the authored policy changes
#   policy_revision = sha256(jsonencode([
#     xshield_segment.pci_db.templates,
#     xshield_template.postgres_from_app.template_ports,
#   ]))
#
#   comment = "terraform: ${var.change_ticket}"
# }
#
# Backed by the existing platform API:
#   POST /api/policy/actions/deploy                 (ports / asset policy)
#   POST /api/policy/applications/actions/deploy    (application control)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# VARIANT 2 (available now, no platform change) - external helper binary.
#
# A standard pattern for platform actions a provider does not yet model.
# Requests to Xshield are RSA-PSS signed, so a small helper is used rather than
# raw curl; the helper is a thin wrapper over the documented API.
#
# The helper is distributed with the integration; contract:
#   xshield-cli policy deploy \
#     --criteria <criteria> --direction inbound --mode enforced \
#     --reviewed-only --comment "<text>"
#   exit 0 on success (idempotent: deploying an already-enforced policy is a
#   no-op and still exits 0)
# -----------------------------------------------------------------------------

resource "terraform_data" "deploy_pci_db" {
  count = var.enable_deployment_trigger ? 1 : 0

  # Re-runs only when the authored policy actually changes - not on every apply.
  triggers_replace = {
    policy_revision = sha256(jsonencode({
      segment   = xshield_segment.pci_db.criteria
      templates = [for t in xshield_segment.pci_db.templates : t.template_id]
      ports     = xshield_template.postgres_from_app.template_ports
      mode      = var.deployment_mode
    }))
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      xshield-cli policy deploy \
        --server        "${var.xshield_server_url}" \
        --tenancy       "${var.xshield_tenancy_id}" \
        --user          "${var.xshield_user_id}" \
        --fingerprint   "${var.xshield_fingerprint}" \
        --key-file      "${var.xshield_private_key_path}" \
        --criteria      '${xshield_segment.pci_db.criteria}' \
        --direction     inbound \
        --mode          '${var.deployment_mode}' \
        --reviewed-only \
        --comment       'terraform ${var.change_ticket}'
    EOT
  }

  depends_on = [
    xshield_segment.pci_db,
    xshield_template.postgres_from_app,
  ]
}

# Safety rail that applies to BOTH variants: never let an apply flip production
# to enforced without an explicit, reviewed input.
resource "terraform_data" "deployment_guard" {
  count = var.enable_deployment_trigger ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.deployment_mode != "enforced" || var.change_ticket != ""
      error_message = "Deploying to 'enforced' requires change_ticket to be set - enforcement changes must be traceable to an approved change record."
    }
  }
}
