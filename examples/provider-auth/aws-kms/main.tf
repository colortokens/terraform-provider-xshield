terraform {
  required_providers {
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

# Reads the tenant's tag keys, which needs nothing but a working sign-in.
data "xshield_fields" "asset" {
  scope = "asset"
}

output "core_tags" {
  value = data.xshield_fields.asset.core_tag_names
}
