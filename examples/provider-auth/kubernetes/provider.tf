# The pod mounts a projected service account token for the trust's audience at
# /var/run/secrets/xshield/token.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source = "kubernetes"
  }
}
