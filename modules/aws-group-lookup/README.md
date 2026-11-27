# aws-group-lookup module

Returns the Xshield security group a database, function or service must attach, for the workspace that owns it. The enforcement workspace creates that group and every rule in it; this module only finds the group's ID.

```hcl
module "orders_db_xshield" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/aws-group-lookup?ref=v26.4.1"
  handle = "rds/orders-db"
  vpc_id = aws_security_group.orders_db.vpc_id
}

resource "aws_db_instance" "orders" {
  # ...
  vpc_security_group_ids = concat([aws_security_group.orders_db.id], module.orders_db_xshield.security_group_ids)
}
```

`aws_security_group.orders_db` is the database's own group, with the rules its workspace declares for it; Xshield's group goes beside it. [`database/`](../../examples/enforcement-snapshot/database/) and [`apprunner/`](../../examples/enforcement-snapshot/apprunner/) are whole workspaces that use the module. In each, `xshield.tf` holds what the workspace adds for Xshield.

`handle` is the resource's kind and name: `rds/<DB instance identifier>`, `rds-cluster/<cluster identifier>`, `lambda/<function name>`, `flink/<application name>`, `apprunner/<service name>` or `asg/<Auto Scaling group name>`. The name is the one you already give the resource, so the lookup works before the resource exists.

It reads the SSM parameter `/colortokens/v1/<handle>/security-groups`, which the enforcement workspace writes, by its path `/colortokens/v1/<handle>`. It needs `ssm:GetParametersByPath` on that path and no Xshield credentials. It returns an empty list when there is no entry, such as on the run that creates the resource or before Xshield has published anything for the account, so the resource's own plan never depends on Xshield. The plan goes ahead and says nothing, unless `warn_when_unlisted = true`: it then warns, naming the handle. A misspelt handle therefore attaches nothing; Xshield reports the resource as `memberUnattached` once the connector observes it. An RDS handle is read in lowercase, as RDS stores identifiers.

`vpc_id` is the VPC the resource is in; the VPC of its own group is the simplest source. AWS refuses a security group from another VPC, so the lookup returns only Xshield's groups in that one. When the resource moves to another VPC, the run that moves it gets none of Xshield's groups and warns, naming the VPC Xshield's group is in. Once Xshield has discovered the resource in its new VPC and the enforcement workspace has applied, the resource has a group there, and the next apply here attaches it. Xshield keeps the group in the old VPC until nothing holds it, then the enforcement workspace deletes it.

Pass the resource's own groups as `own_security_group_ids` and the plan fails, naming the handle, when together with Xshield's they are more than AWS allows on the resource, rather than AWS failing the apply. The output `own_security_groups_allowed` says how many of its own still fit. Both use the limit Xshield last discovered for the resource; before it has discovered one, nothing is checked and the output is null.

```hcl
module "orders_db_xshield" {
  source                 = "github.com/colortokens/terraform-provider-xshield//modules/aws-group-lookup?ref=v26.4.1"
  handle                 = "rds/orders-db"
  vpc_id                 = aws_security_group.orders_db.vpc_id
  own_security_group_ids = [aws_security_group.orders_db.id]
}
```

Requires Terraform 1.7 and the AWS provider 6 or later.
