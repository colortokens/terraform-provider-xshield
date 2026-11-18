# The step maps SYSTEM_ACCESSTOKEN and sets XSHIELD_ADO_SERVICE_CONNECTION_ID.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source = "azure-devops"
  }
}
