# group-lookup module

Returns the Xshield security group a database, function or service must attach, for the workspace that owns it.

```hcl
module "orders_db_xshield" {
  source = "colortokens/enforcement/xshield//modules/group-lookup"
  handle = "rds/orders-db"
}

resource "aws_db_instance" "orders" {
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}
```

`handle` is the resource's kind and name: `rds/<DB instance identifier>`, `rds-cluster/<cluster identifier>`, `lambda/<function name>`, `flink/<application name>` or `apprunner/<service name>`. The name is the one you already give the resource, so the lookup works before the resource exists.

It reads the SSM parameter `/colortokens/v1/<handle>/security-groups`, which the enforcement workspace writes, by its path `/colortokens/v1/<handle>`. It needs `ssm:GetParametersByPath` on that path and no Xshield credentials. It returns an empty list when there is no entry, such as on the run that creates the resource or before Xshield has published anything for the account, so the resource's own plan never depends on Xshield. The plan then warns, naming the handle, and goes ahead. A misspelt handle therefore attaches nothing and warns on every plan; Xshield reports the resource as `memberUnattached` once the connector observes it. An RDS handle is read in lowercase, as RDS stores identifiers.

Requires Terraform 1.7 and the AWS provider 6 or later.
