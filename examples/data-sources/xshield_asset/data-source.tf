# Look up by ID
data "xshield_asset" "by_id" {
  id = "12345678-1234-1234-1234-123456789012"
}

# Or look up by name
data "xshield_asset" "by_name" {
  asset_name = "my-asset"
}
