data "xshield_templates" "block" {
  criteria = "templateType = 'block-template'"
}

output "unassigned" {
  value = [
    for t in data.xshield_templates.block.templates : t.template_name
    if t.segment_assignments == 0
  ]
}
