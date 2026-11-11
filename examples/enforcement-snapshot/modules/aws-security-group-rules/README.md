# aws-security-group-rules module

Declares the rules of one of your own security groups through Xshield Full control. The comment at the top of `main.tf` says how it works, and the variables and outputs there describe themselves. This page covers the `review` output.

## Reading what Xshield changed, in words

The `review` output is a list of sentences about the rules this group declares. It has one sentence for each:

- declared rule Xshield has taken out;
- declared rule Xshield is waiting to take out, which stays until every workload that keeps it carries its cohort group;
- declared rule that gives workloads in the group traffic a change set takes from them;
- rule the group no longer declares that a change set is waiting to take out, or that a revert puts back.

Each sentence names the group, the rule's key as your code keys it, and the rule in words:

```
Group web: rule ingress/ssh_all (TCP 22 from 0.0.0.0/0) is taken out by Xshield.
Group web: rule ingress/app_range (TCP 8000-8100 from 10.8.0.0/16) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group.
Group web: rule ingress/tcp_internal (all TCP from 10.0.0.0/8) gives workloads in the group traffic that change set cs-example takes from them.
Group web: TCP 3389 from 0.0.0.0/0 is no longer declared, and change set cs-example is waiting to take it out. Declare it again, or the workloads that keep it lose it early. Xshield leaves it out once it is safe.
Group web: all traffic to 0.0.0.0/0 is no longer declared, and the revert of change set cs-example puts it back. Declare it again: the revert waits until the group holds it.
```

A rule reads `from` its source when it is an ingress rule and `to` its destination when it is an egress rule. Ports read as `TCP 22`, `TCP 8000-8100`, `all TCP`, or `all traffic` for every protocol, the same words the enforcement module's `review` output uses.

A sentence names the change set where `xshield_aws_security_group_rules` reports one. It reports none for a rule taken out or waiting, so those two sentences name none.

The output is empty for a group no approved change applies to, and for a change that leaves every rule as declared. Such a group adds nothing to a plan.

## Exporting it from the root module

A plan shows only a root module's outputs. In each root module that calls this module, export one output named `xshield_review` that joins the `review` output of every group:

```hcl
module "web_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-security-group-rules?ref=vX.Y.Z"
  # ...
}

module "db_rules" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/aws-security-group-rules?ref=vX.Y.Z"
  # ...
}

output "xshield_review" {
  description = "What Xshield takes out of this workspace's security groups, in words."
  value       = concat(module.web_rules.review, module.db_rules.review)
}
```

Where one module block declares several groups with `for_each`, join them with `flatten([for group in module.group_rules : group.review])`.

A plan then says why a rule is going. Here the rule that was waiting is taken out:

```
  # module.web_rules.aws_vpc_security_group_ingress_rule.this["ssh_all"] will be destroyed
  # (because key ["ssh_all"] is not in for_each map)

Changes to Outputs:
  ~ xshield_review = [
      ~ "Group web: rule ingress/ssh_all (TCP 22 from 0.0.0.0/0) is waiting. Xshield takes it out once every workload that keeps it carries its cohort group." -> "Group web: rule ingress/ssh_all (TCP 22 from 0.0.0.0/0) is taken out by Xshield.",
    ]
```

Use the same output name in the enforcement workspace, for the enforcement module's `review` output. A reviewer then looks for `xshield_review` in every plan.
