resource "xshield_policy_deployment" "pci_db" {
  count = var.enable_deployment_trigger ? 1 : 0

  criteria  = xshield_segment.pci_db.criteria
  direction = "inbound"
  comment   = "terraform ${var.change_ticket}"

  reviewed = {
    "*" = { mode = var.deployment_mode }
  }
  # Ports without a review decision are never enforced.
  unreviewed = {
    "*" = { mode = var.deployment_mode == "enforce" ? "test" : var.deployment_mode }
  }

  lifecycle {
    replace_triggered_by = [xshield_segment.pci_db, xshield_template.postgres_from_app]

    precondition {
      condition     = var.deployment_mode != "enforce" || var.change_ticket != ""
      error_message = "Deploying in enforce mode requires change_ticket, so every enforcement change is traceable to an approved change record."
    }
  }
}
