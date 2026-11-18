# The audience is the application ID URI of an Entra app registration.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source   = "azure"
    audience = "api://xshield"
  }
}
