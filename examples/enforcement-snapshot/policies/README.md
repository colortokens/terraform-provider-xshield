# Optional checks for groups under Full control

When Xshield narrows one of your own security groups, the group's code keeps declaring its rules through
`xshield_security_group_rules`. These checks catch three things that code can do and Xshield cannot see from its side:

| Check | Reports | Default |
| --- | --- | --- |
| `xshield-reopened-access` | A plan that creates or changes a rule giving the group's workloads traffic an approved change took from some of them, such as a narrower copy of the rule Xshield moved out. Every workload in the group gets a rule's traffic, so this undoes the change for the workloads it narrowed. | Advisory |
| `xshield-removed-early` | A plan that deletes or changes a rule an approved change still needs, before every workload that keeps the rule's traffic carries its cohort group. Those workloads lose the traffic until then. Xshield leaves the rule out itself once it is safe. | Advisory |
| `xshield-revert-waiting` | A revert in progress that waits for the group's code to declare a rule again, because the code dropped it while the change was in place. | Advisory |

The reopened-access and removed-early checks fail only on rules the plan itself adds, deletes or changes. Neither fails
on a rule moved to a new key or a rule whose description or tags change, and the reopened-access check also passes a
rule the group already held, so both can be made blocking without stopping unrelated changes in the same workspace. The
revert-waiting check reports on every plan until the rule is declared again, so keep it advisory.

The checks read the facts the data source reports, `reopens`, `undeclared_pending`, `undeclared_restores` and
`security_group_id`, so they apply to rules declared through `xshield_security_group_rules` with
`aws_vpc_security_group_ingress_rule` and `aws_vpc_security_group_egress_rule`. A rule naming a security group or prefix
list is compared only with moved rules naming the same one.

## HCP Terraform and Terraform Enterprise

Create a policy set from one of these directories and attach it to the workspaces that own your security groups:

- `sentinel/` for a Sentinel policy set. `sentinel.hcl` sets the enforcement levels.
- `opa/` for an OPA policy set. `policies.hcl` sets the enforcement levels.

To make the reopened-access or removed-early check blocking, set its enforcement level to `soft-mandatory` (Sentinel) or
`mandatory` (OPA).

## Other pipelines

Run the OPA policies against the JSON plan. The first two `opa eval` commands exit non-zero when the plan reopens access
or takes out a rule an approved change still needs:

```sh
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json
opa eval --fail-defined --format raw -d policies/opa -i plan.json 'data.terraform.policies.xshield_reopened_access.deny[_]'
opa eval --fail-defined --format raw -d policies/opa -i plan.json 'data.terraform.policies.xshield_removed_early.deny[_]'
opa eval --format raw -d policies/opa -i plan.json 'data.terraform.policies.xshield_revert_waiting.warn[_]'
```

## Testing the policies

```sh
cd policies/sentinel && sentinel test
opa test policies/opa
```

The Sentinel test data was generated from a plan of four groups: one under a change that moved a broad rule for port
22, one under a change still giving its workloads their cohort groups, one being reverted, and one with no change.
