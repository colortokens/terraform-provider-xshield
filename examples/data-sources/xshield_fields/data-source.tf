# Which tag keys exist, and which of them a segment criteria may use.
data "xshield_fields" "asset" {
  scope = "asset"
}

output "core_tags" {
  value = data.xshield_fields.asset.core_tag_names
}
