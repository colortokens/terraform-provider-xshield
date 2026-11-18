provider "xshield" {
  server_url       = "https://<tenant>.colortokens.com"
  tenancy_id       = "<tenancy-id>"
  user_id          = "<user-id>"
  fingerprint      = "<api-key-fingerprint>"
  private_key_path = "/path/to/xshield-api-key.pem"
}
