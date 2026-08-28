provider "xshield" {
  server_url       = var.xshield_server_url
  tenancy_id       = var.xshield_tenancy_id
  user_id          = var.xshield_user_id
  fingerprint      = var.xshield_fingerprint
  private_key_path = var.xshield_private_key_path
}

# Production: credentials come from the workspace's assumed role - no static
# keys here. `demo_mode` exists only so the bundled offline example can `plan`
# without an AWS account; it changes nothing about the rendered resources.
provider "aws" {
  region = var.region

  # Refuse to run against the wrong account - cheap, high-value guardrail for a
  # workspace that owns an account's entire enforcement layer.
  allowed_account_ids = var.demo_mode ? null : [var.cloud_account_id]

  access_key                  = var.demo_mode ? "test" : null
  secret_key                  = var.demo_mode ? "test" : null
  skip_credentials_validation = var.demo_mode
  skip_requesting_account_id  = var.demo_mode
  skip_metadata_api_check     = var.demo_mode

  default_tags {
    tags = var.tags
  }
}
