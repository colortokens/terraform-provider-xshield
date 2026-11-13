terraform {
  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = "0.4.0"
    }
  }
}

# In a pipeline, leave the credentials out of the block and set
# XSHIELD_SERVER_URL, XSHIELD_TENANCY_ID, XSHIELD_USER_ID, XSHIELD_FINGERPRINT
# and XSHIELD_PRIVATE_KEY (the key itself) as secret environment variables.
provider "xshield" {
  # Xshield connection config
  tenancy_id       = "xxxxxxxxxx"
  user_id          = "xxxxxxxxxx"
  fingerprint      = "xxxxxxxxxx"
  private_key_path = "/path/to/colortokens_api_key_tenant.pem"
  server_url       = "https://my-company.colortokens.com/"

  # HTTP request config [Optional]
  request_timeout  = 60
  initial_interval = 500
  max_interval     = 60000
  max_elapsed_time = 3600000
  exponent         = 1.5

  # Proxy config [Optional]
  proxy_url   = "http://proxy-ip:port"
  proxy_creds = "username:password"
}