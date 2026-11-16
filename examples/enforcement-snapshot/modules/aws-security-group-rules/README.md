# aws-security-group-rules module

Declares the rules of one of your own security groups through Xshield Full control. The comment at the top of `main.tf` says how it works, and the variables in `variables.tf` and the outputs in `outputs.tf` describe themselves. [`full-control/`](../../full-control/) is a whole workspace that uses the module. This page covers the `review` output, the record the module keeps in state, and the receipts it sends.

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

## The record kept in state

The module keeps one `terraform_data` resource for the group, named `xshield_routed`. It lives in Terraform's state alone: it creates nothing in AWS and calls neither AWS nor Xshield. It records the account, region, VPC and group, and whether an approved change applied to the group at the last apply.

A plan shows it three times in a group's life. The first plan with this version of the module creates it. A plan in which a change starts to apply to the group, or stops, updates it in place. A plan that removes the module call deletes it.

That last plan is why it exists. Once a workspace stops calling the module and stops reading `xshield_aws_security_group_changes`, its plan reads nothing from Xshield, so nothing in the plan says a change applies to the group. The deleted record still does, and a policy check can read it to stop a plan that would put back a rule a change took out.

## Taking a group out of the module

Removing the module call on its own destroys every rule of the group, as only the module declares them, and everything that carries the group loses that traffic. Take a group out in this order instead:

1. Revert any change that applies to the group in Xshield, and apply the workspace. The group's rules return as declared, and the module holds no receipts.
2. Replace the module call with one of these, and check that the plan destroys no rule.

   To keep declaring the rules in this workspace, declare each as a resource of its own, with the same arguments, and move it out of the module. The plan shows each rule as moved, and deletes only the record kept in state:

   ```hcl
   resource "aws_vpc_security_group_ingress_rule" "web" {
     for_each = local.web_ingress

     security_group_id = aws_security_group.web.id
     ip_protocol       = each.value.ip_protocol
     from_port         = each.value.from_port
     to_port           = each.value.to_port
     cidr_ipv4         = each.value.cidr_ipv4
   }

   moved {
     from = module.web_rules.aws_vpc_security_group_ingress_rule.this
     to   = aws_vpc_security_group_ingress_rule.web
   }
   ```

   Do the same for the egress rules. To leave the rules in AWS and stop managing them here, remove the module instead. The plan shows the rules and the record as no longer managed, and destroys nothing:

   ```hcl
   removed {
     from = module.web_rules

     lifecycle {
       destroy = false
     }
   }
   ```

3. Apply, then delete the `moved` or `removed` blocks.

## The receipts it sends

While an approved change applies to the group, the module declares two `xshield_aws_security_group_changes_receipt` resources under one ID. Each tells Xshield which change sets the group's rules come from and their states, as the plan read them from `xshield_aws_security_group_rules`:

- `applying`, with `stage = "applying"`, is sent before any rule is created or updated: the group's ingress and egress rules `depends_on` it. Xshield refuses it when the plan was made before a revert, and the apply then stops with no rule changed.
- `applied`, with `stage = "applied"` and `receipt_id` set to the `applying` receipt's ID, `depends_on` the rules, so it is sent once they are created or updated.
- The rules set `create_before_destroy`, so a rule the apply takes out of the group is destroyed only after `applied`. Without it, Terraform destroys such a rule before it sends `applying`, and a refused `applying` receipt would no longer stop it. Terraform reads that order for a rule no longer declared from the state the last apply wrote, so it holds from the second apply of this module version on: see [How a revert waits for this workspace](../../README.md#how-a-revert-waits-for-this-workspace).

A revert of a change waits for these receipts: see [How a revert waits for this workspace](../../README.md#how-a-revert-waits-for-this-workspace).

Xshield's notices name the receipts by `receipt_label` and their shared ID. The label defaults to the name of the HCP Terraform or Terraform Enterprise workspace. The API key's user must be able to create enforcement receipts as well as read cloud snapshots, as the built-in ADMIN and USER roles can.
