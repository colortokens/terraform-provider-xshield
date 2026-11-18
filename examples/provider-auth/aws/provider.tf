# Runs with an IAM role allowed sts:GetWebIdentityToken, in an account with
# outbound identity federation enabled.
provider "xshield" {
  server_url = "https://<tenant>.colortokens.com"
  tenancy_id = "<tenancy-id>"
  user_id    = "<service-account-user-id>"

  oidc = {
    source   = "aws"
    audience = "xshield"
  }
}
