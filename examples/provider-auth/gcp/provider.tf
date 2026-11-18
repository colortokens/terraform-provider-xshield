# Runs with a Google Cloud service account attached, read from the metadata server.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source   = "gcp"
    audience = "xshield"
  }
}
