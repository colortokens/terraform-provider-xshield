# azure enforcement module

Applies the Azure resources Xshield rendered for one subscription and region.

```hcl
module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//examples/enforcement-snapshot/modules/azure?ref=vX.Y.Z"

  region = "eastus2"
}
```

It creates, from `xshield_azure_enforcement_snapshot`:

- one `azurerm_network_security_group` per network interface or subnet Xshield enforces at, named `ct-policy-` and a hash of that network interface or subnet, and tagged `ct:delivery` and `ct:level`, so the cloud connector recognises it as Xshield's;
- the group's whole rule set, given inline, so the next apply removes a rule added to the group outside Terraform unless `enable_exclusive_rules` is `false`;
- one `azurerm_network_interface_security_group_association` or `azurerm_subnet_network_security_group_association` per group, which puts the group on its network interface or subnet.

Xshield puts its group only where discovery showed no group of yours. A virtual machine's goes on each of its network interfaces when none of them carries a group of yours, and otherwise on their subnet. A database, storage account or function is reached through its subnet, so its group goes there. Your groups are never changed, and Azure applies both, so traffic passes only where your group and Xshield's both allow it. Each of Xshield's rule sets lets the load balancer's health probes in first, and ends with an allow of all traffic in each direction, so traffic no Xshield rule decides passes as it did before. A workload with no such place is refused: its entry in the `network_security_group_ids` output is empty, and Xshield says why. Workloads on one subnet share its group, each with rules of its own.

While Xshield has published nothing for the subscription and region, the module creates nothing and the plan shows no change. The run then warns, through the `xshield_published` check, that nothing is published, and says what to look at if the subscription should have policy there. If the subscription already holds network security groups Xshield rendered for a pipeline in that region, the plan fails instead: Xshield never unpublishes a subscription, so that means the provider is reading another tenant or endpoint, and applying would remove them.

To stop enforcing, withdraw the policy in Xshield. Xshield then publishes a version without the groups, and the next apply removes each association and then its group. Do not run `terraform destroy`, or remove the module block, to stop enforcing: both delete the groups while Xshield still expects them. When Xshield hands the subscription back to the cloud connector, the plan stops with `Xshield moved <subscription>/<region> to connector delivery`. The cloud connector takes over none of these groups, and Xshield hands a subscription back only once the version it expects holds none, so remove the module block then, apply once, which deletes any group the last version's apply left, and stop running the workspace.

A network interface can be deleted before discovery tells Xshield, so an association is planned only while its network interface exists, and a deleted one never fails the apply. The module lists the subscription's network interfaces to find out. The `interface_association_keys` output names the associations a run declares.

Each group holds only the rules the snapshot declares for it. A rule added to it outside Terraform, such as a just-in-time access rule, shows in the next plan as an in-place change of the group's `azurerm_network_security_group`, and the apply removes it. Set `enable_exclusive_rules = false` to leave such rules until a person removes them. The module then lists the subscription's network security groups, reads the rules of each of Xshield's that already exists, and gives every rule there not named `CT-Rule-` or `CT-Test-Rule-`, the names Xshield gives its own, back to Azure with Xshield's. Azure applies a kept rule in priority order with Xshield's, so one ahead of Xshield's rules decides traffic before them. Azure takes one rule for each priority and direction in a group, so the plan stops, naming the rule, when a kept rule is at a priority and direction one of Xshield's rules takes: move it to a priority Xshield's rules leave free, or turn exclusive rules back on. The apply writes a group's whole rule set at once, so even with exclusive rules off it removes a rule added after the plan: plan again rather than apply an old saved plan. Turning exclusive rules back on removes the kept rules at the next apply. Network security groups of your own are never managed this way.

Resource keys are the groups' names, so a plan names the group each change is for.

## Reading a change in words

The `review` output says what the applied version holds, as a list of sentences. A plan shows only a root module's outputs, so export it from the root module:

```hcl
output "xshield_review" {
  value = module.xshield_enforcement.review
}
```

A plan then lists the sentences that change under `Changes to Outputs`. Here a virtual machine's policy adds a deny of SSH to one network:

```
Changes to Outputs:
  ~ xshield_review = [
        # (2 unchanged elements hidden)
        "Group ct-policy-1b1b1b1b1b1b allows outbound TCP 443 from 10.1.0.7/32 to service tag Storage.EastUS2.",
      + "Group ct-policy-1b1b1b1b1b1b denies outbound TCP 22 from 10.1.0.7/32 to 203.0.113.0/24.",
        "Group ct-policy-1b1b1b1b1b1b denies outbound TCP 25 from 10.1.0.7/32 to anywhere.",
      - "Version 8c2f41d09a3b holds 1 group, 3 rules, 2 interface associations and 0 subnet associations for 11111111-2222-3333-4444-555555555555/eastus2.",
      + "Version e91b0c55d2f4 holds 1 group, 4 rules, 2 interface associations and 0 subnet associations for 11111111-2222-3333-4444-555555555555/eastus2.",
    ]
```

Every sentence names its group, so it reads on its own when the plan hides the others.

- The first sentence for a group says where it is associated, by the network interface's name or by the subnet and its virtual network, and which Xshield assets it is for.
- Then comes one sentence for each rule: inbound rules first, then outbound, each in the priority order Azure applies them, where the first rule that matches decides. Ports read as `TCP 443`, `TCP 22 and 3389`, `all TCP`, `all inbound ICMP`, `inbound traffic on port 123` for any protocol on that port, or `all inbound traffic`. An address reads as written, any address as `anywhere`, and a service tag such as `AzureLoadBalancer` as `service tag AzureLoadBalancer`. A sentence names the workload's own side of a rule only where the rule names it. A rule Xshield writes in test mode, which lets through traffic enforce would block so that flow logs record it, ends with `logged as traffic enforce would block`.
- Sentences leave out priorities, so a rule whose priority moves when another is added keeps its sentence, as the deny of TCP 25 does above.
- The last sentence counts the groups, rules, and network interface and subnet associations. It starts with the first twelve characters of the version, so anything that changes the version changes at least that sentence.

Two limits keep the output short enough to read. A sentence names five ports, addresses, network interfaces or assets and counts the rest. The output describes `review_max_groups` groups, 50 unless you set it, in key order. One sentence counts the groups past that number. A change these limits hide still changes the last sentence, and the plan's resource changes show it in full.

While Xshield has published nothing, the output is one sentence that says so. For a version that holds nothing, it is the last sentence alone.

## Inputs

| Name | Default | Description |
|--|--|--|
| `region` | | Azure region to enforce, by its name, such as `eastus2`. |
| `cloud_account_id` | The azurerm provider's subscription | Azure subscription ID to enforce. A snapshot for any other subscription is refused. |
| `snapshot_version` | `null` | Pins a version for break-glass rollback or forensics. |
| `tags` | `{}` | Added to every network security group. Keys starting with `ct:`, in any case, are reserved. |
| `enable_exclusive_rules` | `true` | Each group this module creates holds only the rules the snapshot declares, so the next apply removes a rule added outside Terraform. Set `false` to leave such a rule until a person removes it. |
| `review_max_groups` | `50` | How many groups the `review` output describes in words. Groups past this number are counted, not described. |

## Outputs

| Name | Description |
|--|--|
| `published` | False while Xshield has published nothing for the subscription and region. |
| `version` | Snapshot version applied. Null while nothing is published. |
| `exclusive_rules_enabled` | Whether each group this module creates holds only the rules the snapshot declares. |
| `summary` | Counts of network security groups, rules, and network interface and subnet associations. |
| `review` | What the applied version holds, as sentences: where each group is associated and for which assets, what its rules allow and deny in the order Azure applies them, and a closing count. |
| `network_security_group_ids` | The IDs of each Xshield asset's network security groups, keyed by Xshield asset ID. |
| `interface_association_keys` | The network interface associations this run declares, by snapshot key: the snapshot's, less any whose network interface no longer exists. |

Requires Terraform 1.7 and the azurerm provider 4.81.0 or later. `terraform test` runs the tests in `tests/` offline, with both providers mocked.
