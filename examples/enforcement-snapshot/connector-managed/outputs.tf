output "segment_ids" {
  description = "Segments authored by this workspace."
  value = {
    all_prod = xshield_segment.all_prod.id
    pci_app  = xshield_segment.pci_app.id
    pci_db   = xshield_segment.pci_db.id
  }
}

output "template_ids" {
  value = {
    postgres_from_app = xshield_template.postgres_from_app.id
    billing_egress    = xshield_template.billing_egress.id
    node_exporter     = xshield_template.node_exporter.id
    block_legacy_ssh  = xshield_template.block_legacy_ssh.id
  }
}

output "deployment_triggered" {
  description = "Whether this workspace also drives deployment, or only authors policy."
  value       = var.enable_deployment_trigger
}
