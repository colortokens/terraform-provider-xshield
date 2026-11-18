provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"
  kms_key    = "azurekeyvault://<vault-name>.vault.azure.net/keys/xshield-api-key"
}
