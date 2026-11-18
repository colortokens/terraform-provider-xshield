# The workflow grants permissions: id-token: write.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source   = "github-actions"
    audience = "xshield"
  }
}
