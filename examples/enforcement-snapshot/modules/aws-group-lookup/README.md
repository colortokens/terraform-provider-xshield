# aws-group-lookup module

Returns the Xshield security group a database, function or service must attach, for the workspace that owns it.

```hcl
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-group-lookup?ref=vX.Y.Z"
  handle = "rds/orders-db"
}

resource "aws_db_instance" "orders" {
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}
```

`handle` is the resource's kind and name: `rds/<DB instance identifier>`, `rds-cluster/<cluster identifier>`, `lambda/<function name>`, `flink/<application name>`, `apprunner/<service name>` or `asg/<Auto Scaling group name>`. The name is the one you already give the resource, so the lookup works before the resource exists.

It reads the SSM parameter `/colortokens/v1/<handle>/security-groups`, which the enforcement workspace writes, by its path `/colortokens/v1/<handle>`. It needs `ssm:GetParametersByPath` on that path and no Xshield credentials. It returns an empty list when there is no entry, such as on the run that creates the resource or before Xshield has published anything for the account, so the resource's own plan never depends on Xshield. The plan goes ahead and says nothing, unless `warn_when_unlisted = true`: it then warns, naming the handle. A misspelt handle therefore attaches nothing; Xshield reports the resource as `memberUnattached` once the connector observes it. An RDS handle is read in lowercase, as RDS stores identifiers.

Pass the resource's own groups as `own_security_group_ids` and the plan fails, naming the handle, when together with Xshield's they are more than AWS allows on the resource, rather than AWS failing the apply. The output `own_security_groups_allowed` says how many of its own still fit. Both use the limit Xshield last discovered for the resource; before it has discovered one, nothing is checked and the output is null.

```hcl
module "orders_db_xshield" {
  source                 = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-group-lookup?ref=vX.Y.Z"
  handle                 = "rds/orders-db"
  own_security_group_ids = [aws_security_group.orders_db.id]
}
```

Requires Terraform 1.7 and the AWS provider 6 or later.
