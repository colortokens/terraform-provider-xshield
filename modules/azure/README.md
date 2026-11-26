# azure enforcement module

Applies the Azure resources Xshield rendered for one subscription and region.

```hcl
module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/azure?ref=v26.4.1"

  region = "eastus2"
}
```

It creates, from `xshield_azure_enforcement_snapshot`:

- one `azurerm_network_security_group` per network interface or subnet Xshield enforces at, named `ct-policy-` and a hash of that network interface or subnet, or from the cloud account's security group name template when it has one, and tagged `ct:delivery` and `ct:level`, so the cloud connector and this module recognise it as Xshield's whatever its name. A group keeps the name it was first applied under. A resource group holds one network security group per name, so where a group of yours already has the name a new group would take, Xshield gives its group that name with another hash once the cloud connector observes yours, and neither your group nor the template changes. Until then the module looks up the name of each group the last receipt does not hold, and the plan stops, naming your group: azurerm would otherwise refuse the group and suggest importing yours, which would give it Xshield's rules;
- the group's whole rule set, given inline, so the next apply removes a rule added to the group outside Terraform unless `enable_exclusive_rules` is `false`;
- one `azurerm_network_interface_security_group_association` or `azurerm_subnet_network_security_group_association` per group, which puts the group on its network interface or subnet;
- one `azurerm_network_security_rule` per rule Xshield writes into a network security group of yours, described below;
- one `xshield_azure_enforcement_receipt`, sent once every group and association exists, which tells Xshield the version is applied and names the ID of each resource created. `xshield_azure_enforcement_status` then reads `converged`, and lists those IDs, so a lost state can be rebuilt from them. The `workspace` variable sets the name Xshield shows for the workspace.
- one `terraform_data.xshield_applied_resources`, which lives in Terraform's state alone and is replaced whenever an apply creates, replaces or updates a group or association, and one `terraform_data.xshield_applied_customer_rules`, replaced whenever an apply writes a rule into a group of yours. Azure gives a group, association or rule recreated under the same name its old ID, so without them an apply that restores one would send no receipt, and Xshield would see the restored state only at its next drift observation.

Xshield puts its group where discovery showed no group of yours. A virtual machine's goes on each of its network interfaces when none of them carries a group of yours, and otherwise on their subnet. A database, storage account or function is reached through its subnet, so its group goes there. Azure applies both, so traffic passes only where your group and Xshield's both allow it. Each of Xshield's rule sets lets the load balancer's health probes in first, and ends with an allow of all traffic in each direction, so traffic no Xshield rule decides passes as it did before. Workloads on one subnet share its group, each with rules of its own.

When every network interface and subnet of a workload carries a group of yours, Xshield writes the workload's rules into your subnet's group instead, and Xshield's `customerGroupWritten` notice names the group. Each rule names only the workload's own addresses, as its destination inbound and its source outbound, and lets the load balancer's health probes reach the workload, so your rules still decide the traffic of everything else the group covers. There is no allow of all traffic: traffic Xshield's rules do not decide goes on to yours. The module reads the rules the group holds and gives Xshield's, through `xshield_azure_security_rules`, priorities below every rule of yours in their direction, keeping the priorities they already hold. A rule that moves or is added takes a priority no rule holds, so the rules apply one at a time without colliding. When your rules leave too few priorities below them, the plan stops, naming the group and the priority of your first rule: move your rules up to leave room. A workload Xshield cannot place is refused: its entry in the `network_security_group_ids` output is empty, and Xshield says why.

An apply of a group whose rules your configuration declares inline removes every rule it does not declare, Xshield's among them. List such a group's resource ID in `customer_network_security_groups_in_code`, and the module leaves it alone: declare its rules through the `xshield_azure_security_rules` data source in that configuration, which gives back your rules with Xshield's. A group with no inline rules, or whose rules your configuration declares as `azurerm_network_security_rule` resources, needs nothing.

While Xshield has published nothing for the subscription and region, the module creates nothing and the plan shows no change. The run then warns, through the `xshield_published` check, that nothing is published, and says what to look at if the subscription should have policy there. If the subscription already holds network security groups Xshield rendered for a pipeline in that region, the plan fails instead: Xshield never unpublishes a subscription, so that means the provider is reading another tenant or endpoint, and applying would remove them.

To stop enforcing, withdraw the policy in Xshield. Xshield then publishes a version without the groups, and the next apply removes each association and then its group. Do not run `terraform destroy`, or remove the module block, to stop enforcing: both delete the groups while Xshield still expects them. When Xshield hands the subscription back to the cloud connector, the plan stops with `Xshield moved <subscription>/<region> to connector delivery`. Xshield hands a subscription back only once an apply has removed all of Xshield's groups, so the workspace then holds only associations kept for a group of yours or the cloud connector's, which a destroy would clear: replace the module block with a `removed` block for the module with `lifecycle { destroy = false }`, apply once, and stop running the workspace.

Azure removes an association by clearing whatever group its network interface or subnet carries, so removing one of Xshield's would remove a group of yours put on the level since. Before a plan removes an association, the module reads the network interface or subnet, and fails the plan if it carries a group other than Xshield's, which it recognises by its `ct:delivery` tag of `pipeline`. Once the cloud connector has observed that group, Xshield holds the association: the module keeps it in its state, unchanged, the `associationHeld` notice names it, and it leaves the state once the level carries no group of yours. Your group stays where you put it throughout.

When you contain a workload, the cloud connector puts a network security group of its own on the workload's network interface or subnet in place of Xshield's, and puts Xshield's back when you revert the containment. While the workload is contained, the snapshot lists its associations as contained associations: the module keeps each in its state, unchanged, creates none the workload did not already have, and leaves them out of the receipt, so an apply never takes the connector's group off. The `assetContained` notice names the workload.

When a subscription moves from the cloud connector to pipeline delivery, a network interface or subnet the connector enforced at with a group of its own while it carried none would be left with no group if the apply associated Xshield's there, as Azure takes an association by clearing the group its level carries. The snapshot lists those associations as handover associations. The apply creates their groups but not the associations, and the `xshield_handover` check names each level that still carries the connector's group. Once the apply's receipt reaches Xshield, the cloud connector puts each of Xshield's groups in place of its own in a single change, and the next plan takes the association over: it imports one whose level carries Xshield's group, through the import blocks of [`handover-azure/handover.tf`](../../examples/enforcement-snapshot/handover-azure/handover.tf), which read the `handover_interface_association_imports` and `handover_subnet_association_imports` outputs, and creates one whose level carries no group.

A network interface can be deleted before discovery tells Xshield, so an association is planned only while its network interface exists, and a deleted one never fails the apply. The module lists the subscription's network interfaces to find out. The `interface_association_keys` output names the associations a run declares.

Each group holds only the rules the snapshot declares for it. A rule added to it outside Terraform, such as a just-in-time access rule, shows in the next plan as an in-place change of the group's `azurerm_network_security_group`, and the apply removes it. Set `enable_exclusive_rules = false` to leave such rules until a person removes them. The module then lists the subscription's network security groups, reads the rules of each of Xshield's that already exists, and gives every rule there not named `CT-Rule-` or `CT-Test-Rule-`, the names Xshield gives its own, back to Azure with Xshield's. Azure applies a kept rule in priority order with Xshield's, so one ahead of Xshield's rules decides traffic before them. Azure takes one rule for each priority and direction in a group, so the plan stops, naming the rule, when a kept rule is at a priority and direction one of Xshield's rules takes: move it to a priority Xshield's rules leave free, or turn exclusive rules back on. The apply writes a group's whole rule set at once, so even with exclusive rules off it removes a rule added after the plan: plan again rather than apply an old saved plan. Turning exclusive rules back on removes the kept rules at the next apply. The groups this setting covers are Xshield's own: the rules Xshield writes into a group of yours are rule resources of their own, and leave your rules alone either way.

Resource keys are `ct-policy-` and a hash of each network interface or subnet, which a name template does not change, so a plan names the level each change is for. A rule in a group of yours is keyed by `customer-nsg-` and a hash of the group's resource ID, then the rule's name.

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
| `customer_network_security_groups_in_code` | `[]` | Resource IDs of groups of yours whose rules a configuration declares inline. The module adds no rule to these: their configuration declares Xshield's rules through `xshield_azure_security_rules`. |
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
| `handover_interface_association_imports` | The import ID of each network interface association the cloud connector has handed over, by snapshot key. |
| `handover_subnet_association_imports` | The import ID of each subnet association the cloud connector has handed over, by snapshot key. |

Requires Terraform 1.7 and the azurerm provider 4.81.0 or later. `terraform test` runs the tests in `tests/` offline, with both providers mocked.
