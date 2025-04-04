terraform {
  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = "0.4.0"
    }
  }
}

provider "xshield" {
  # Xshield connection config [Required]
  tenancy_id = "xxxxxxxxxx"
  user_id = "xxxxxxxxxx"
  fingerprint = "xxxxxxxxxx"
  private_key_path = "/path/to/colortokens_api_key_tenant.pem"
  server_url = "https://region.colortokens.com/"

  # HTTP request config [Optional]
  request_timeout = 60     
  initial_interval = 500      
  max_interval = 60000       
  max_elapsed_time = 3600000   
  exponent = 1.5

  # Proxy config [Optional]
  proxy_url       = "http://proxy-ip:port"
  proxy_creds     = "username:password"
}