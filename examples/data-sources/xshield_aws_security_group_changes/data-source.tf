# Read once per account and region, in the root module, and pass it to each group you route through Full control.
data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

module "web_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-security-group-rules?ref=vX.Y.Z"

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = aws_vpc.main.id
  group_name        = aws_security_group.web.name
  security_group_id = aws_security_group.web.id

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}
