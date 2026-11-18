provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"
  kms_key    = "gcpkms://projects/<project>/locations/global/keyRings/xshield/cryptoKeys/api-key/cryptoKeyVersions/1"
}
