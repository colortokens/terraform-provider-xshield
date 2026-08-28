terraform {
  required_version = ">= 1.7.0"

  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = ">= 0.1.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Production: point this at your remote state backend. One state per
  # account x region; this state owns every ColorTokens resource in the account.
  # backend "s3" {
  #   bucket         = "my-tfstate"
  #   key            = "colortokens/enforcement/123456789012/us-east-1.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "my-tfstate-locks"
  #   encrypt        = true
  # }
}
