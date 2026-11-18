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
- the group's whole rule set, given inline, so the next apply removes a rule added to the group outside Terraform;
- one `azurerm_network_interface_security_group_association` or `azurerm_subnet_network_security_group_association` per group, which puts the group on its network interface or subnet.

Xshield puts its group only where discovery showed no group of yours. A virtual machine's goes on each of its network interfaces when none of them carries a group of yours, and otherwise on their subnet. A database, storage account or function is reached through its subnet, so its group goes there. Your groups are never changed, and Azure applies both, so traffic passes only where your group and Xshield's both allow it. Each of Xshield's rule sets lets the load balancer's health probes in first, and ends with an allow of all traffic in each direction, so traffic no Xshield rule decides passes as it did before. A workload with no such place is refused: its entry in the `network_security_group_ids` output is empty, and Xshield says why. Workloads on one subnet share its group, each with rules of its own.

While Xshield has published nothing for the subscription and region, the module creates nothing and the plan shows no change. The run then warns, through the `xshield_published` check, that nothing is published, and says what to look at if the subscription should have policy there. If the subscription already holds network security groups Xshield rendered for a pipeline in that region, the plan fails instead: Xshield never unpublishes a subscription, so that means the provider is reading another tenant or endpoint, and applying would remove them.

To stop enforcing, withdraw the policy in Xshield. Xshield then publishes a version without the groups, and the next apply removes each association and then its group. Do not run `terraform destroy`, or remove the module block, to stop enforcing: both delete the groups while Xshield still expects them. When Xshield hands the subscription back to the cloud connector, the plan stops with `Xshield moved <subscription>/<region> to connector delivery`. The cloud connector takes over none of these groups, and Xshield hands a subscription back only once the version it expects holds none, so remove the module block then, apply once, which deletes any group the last version's apply left, and stop running the workspace.

A network interface can be deleted before discovery tells Xshield, so an association is planned only while its network interface exists, and a deleted one never fails the apply. The module lists the subscription's network interfaces to find out. The `interface_association_keys` output names the associations a run declares.

Resource keys are the groups' names, so a plan names the group each change is for.

## Inputs

| Name | Default | Description |
|--|--|--|
| `region` | | Azure region to enforce, by its name, such as `eastus2`. |
| `cloud_account_id` | The azurerm provider's subscription | Azure subscription ID to enforce. A snapshot for any other subscription is refused. |
| `snapshot_version` | `null` | Pins a version for break-glass rollback or forensics. |
| `tags` | `{}` | Added to every network security group. Keys starting with `ct:`, in any case, are reserved. |

## Outputs

| Name | Description |
|--|--|
| `published` | False while Xshield has published nothing for the subscription and region. |
| `version` | Snapshot version applied. Null while nothing is published. |
| `summary` | Counts of network security groups, rules, and network interface and subnet associations. |
| `network_security_group_ids` | The IDs of each Xshield asset's network security groups, keyed by Xshield asset ID. |
| `interface_association_keys` | The network interface associations this run declares, by snapshot key: the snapshot's, less any whose network interface no longer exists. |

Requires Terraform 1.7 and the azurerm provider 4.81.0 or later. `terraform test` runs the tests in `tests/` offline, with both providers mocked.
