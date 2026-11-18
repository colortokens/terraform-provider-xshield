# The workspace sets TFC_WORKLOAD_IDENTITY_AUDIENCE_XSHIELD, so each run carries
# TFC_WORKLOAD_IDENTITY_TOKEN_XSHIELD.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source = "terraform-cloud"
  }
}
