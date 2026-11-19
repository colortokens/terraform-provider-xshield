# A group whose name the plan does not know yet, as aws_security_group gives one declared with name_prefix
# on the run that creates it.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    xshield = {
      source = "colortokens/xshield"
    }
  }
}

variable "xshield_changes" {
  description = "What the root module would read from xshield_aws_security_group_changes."
  type = object({
    cloud_account_id = string
    region           = string
    groups           = map(set(string))
  })
}

resource "terraform_data" "group_name" {
  input = "web-20260101"
}

module "rules" {
  source = "../../.."

  xshield_changes   = var.xshield_changes
  vpc_id            = "vpc-0example"
  group_name        = terraform_data.group_name.output
  security_group_id = "sg-0example"

  ingress_rules = {
    https_all = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
  }
}

output "ingress_keys" {
  description = "Keys of the ingress rules the module declares."
  value       = module.rules.ingress_keys
}
