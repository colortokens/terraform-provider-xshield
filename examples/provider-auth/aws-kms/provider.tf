provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"
  kms_key    = "awskms:///arn:aws:kms:us-east-1:111122223333:alias/xshield-api-key"
}
