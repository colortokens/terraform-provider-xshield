# The job declares the XSHIELD_ID_TOKEN ID token under id_tokens.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source = "gitlab"
  }
}
