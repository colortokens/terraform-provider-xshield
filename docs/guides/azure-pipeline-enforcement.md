---
page_title: "Enforce Azure policy through your own pipeline"
description: |-
  Step by step: apply the network security groups Xshield renders for an Azure subscription through your own Terraform pipeline, and keep them applied.
---

# Enforce Azure policy through your own pipeline

Xshield renders the network security groups, and their rules, that an Azure subscription and region need, and the network interface or subnet each one goes on. Your pipeline applies them with the `azure` enforcement module shipped in this provider's repository, and tells Xshield what it applied. You write no rule.

Each step below says who does it, what to run, and how to tell it worked. Take them in order: each relies on the one before it. The module's [README](https://github.com/colortokens/terraform-provider-xshield/tree/main/modules/azure) explains where each group goes, and every message the module gives.

## Before you start

- An Xshield administrator has set the subscription to pipeline delivery through the Xshield API, which needs its cloud connector to be Read-Only. Xshield keeps it Read-Only while the subscription stays on pipeline delivery, so the connector never writes beside your pipeline.
- An Xshield API key for a pipeline user, created under **Settings > API Keys**. The user's role needs `READ_ENFORCEMENT_SNAPSHOT` and `CREATE_ENFORCEMENT_RECEIPT`, which the built-in ADMIN and USER roles have, and must cover every workload in the subscription.
- Terraform 1.7 or later, and the azurerm provider 4.81.0 or a later 4.x release.

Xshield's group goes on a network interface or subnet that carries none of yours, and Azure applies both a network interface's group and its subnet's, so where yours sits beside Xshield's, traffic passes only where both allow it. Where every network interface and subnet of a workload carries a group of yours, Xshield adds the workload's rules to your subnet's group instead, ahead of your rules and naming only that workload's addresses, and leaves your rules as they are. No workspace other than the enforcement workspace changes, except one that declares subnets inline in a virtual network, or the rules of such a group inline (step 3).

The module lives in the [`modules/azure`](https://github.com/colortokens/terraform-provider-xshield/tree/main/modules/azure) directory of this provider's repository. Every `source` below is pinned to the provider release this page was published with. If you run another release of the `colortokens/xshield` provider, set `ref` to its tag, so the module and the provider match.

## Step 1: Give the runner the API key

Set these as secret environment variables on the runner of every workspace that configures the `xshield` provider. Nothing secret goes in the code.

| Variable | Value |
|--|--|
| `XSHIELD_SERVER_URL` | `https://<tenant>.colortokens.com` |
| `XSHIELD_TENANCY_ID`, `XSHIELD_USER_ID`, `XSHIELD_FINGERPRINT` | Shown with the API key under **Settings > API Keys** |
| `XSHIELD_PRIVATE_KEY` | The PEM private key itself, or set `XSHIELD_PRIVATE_KEY_PATH` to a file holding it |

Give the azurerm provider its credentials through the `ARM_*` environment variables in the same way.

**Done when** the variables are set on each runner that step 4, step 5 and step 6 use.

## Step 2: Create the enforcement role, once per subscription

Whoever owns access control in the subscription applies [`enforcement-role-azure/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-role-azure), with `pipeline_principal_ids` set to the object IDs of the service principal or managed identity your runner uses. Creating the role and its assignments takes Owner or User Access Administrator on the subscription. The role itself can write network security groups and their rules, network interfaces and subnets, and holds the join actions Azure checks when they change: no compute, identity or data access.

Azure has no condition that limits these writes to Xshield's own groups. Set `scopes` to the resource groups that hold your workloads' network interfaces and subnets, and your network security groups on those subnets, rather than leaving the role on the whole subscription. Associating a group rewrites the whole network interface or subnet, and Azure checks a join on every resource it links to where that resource is, so `scopes` must also hold the resource groups of linked resources, such as a hub's route tables.

**Done when** the apply prints `role_definition_id`.

## Step 3: Keep Xshield's groups on subnets your code declares

Azure keeps one network security group on each network interface and subnet, and the enforcement module sets Xshield's through an association resource. A workspace of yours that declares the same subnet keeps that association only if it declares the subnet as its own resource:

| Your workspace declares | What happens to Xshield's group |
|--|--|
| `azurerm_subnet` and `azurerm_network_interface` resources | Kept, including when you change them |
| Subnets inline in `azurerm_virtual_network`, as `subnet` blocks | Removed by your next apply of that workspace, even with no change to its code. Step 5's check reports `memberUnattached`, and the next enforcement apply puts the group back, so the two workspaces keep undoing each other. |
| An `azurerm_subnet_network_security_group_association` or `azurerm_network_interface_security_group_association` for a level that carries Xshield's group | The apply fails, saying an association already exists. Nothing changes. |

For each virtual network whose subnets hold workloads Xshield enforces, move every inline `subnet` block into an `azurerm_subnet` resource, with an `import` block so Terraform adopts the existing subnet rather than creating it, and leave the virtual network's `subnet` argument out:

```terraform
import {
  to = azurerm_subnet.app
  id = "/subscriptions/<subscription ID>/resourceGroups/network/providers/Microsoft.Network/virtualNetworks/main/subnets/app"
}

resource "azurerm_subnet" "app" {
  name                 = "app"
  resource_group_name  = "network"
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.20.1.0/24"]
}
```

**Done when** a plan of each such workspace shows no change to any subnet.

### Keep Xshield's rules in groups of yours that your code declares

Where every network interface and subnet of a workload carries a group of yours, the enforcement module adds the workload's rules to your subnet's group as `azurerm_network_security_rule` resources. The enforcement snapshot's `customer_network_security_groups` lists these groups. A workspace of yours that declares one of them with its rules inline, in `security_rule`, removes Xshield's rules at its next apply. For each such group, declare its rules through `xshield_azure_security_rules`, which gives back your rules with Xshield's ahead of them, and list the group's resource ID in the module's `customer_network_security_groups_in_code` in step 4:

```terraform
data "xshield_azure_security_rules" "app" {
  cloud_account_id          = "<subscription ID>"
  region                    = "eastus2"
  network_security_group_id = "/subscriptions/<subscription ID>/resourceGroups/network/providers/Microsoft.Network/networkSecurityGroups/app"
  declared_security_rules   = local.app_rules
  version                   = data.xshield_azure_enforcement_status.this.applied_version
}

data "xshield_azure_enforcement_status" "this" {
  cloud_account_id = "<subscription ID>"
  region           = "eastus2"
}

resource "azurerm_network_security_group" "app" {
  name                = "app"
  resource_group_name = "network"
  location            = "eastus2"
  security_rule       = data.xshield_azure_security_rules.app.security_rules
}
```

The enforcement apply leaves a group listed in `customer_network_security_groups_in_code` to that workspace: only its apply writes Xshield's rules into the group, or puts them back after drift. Run it after each enforcement apply. `version` reads the version the enforcement workspace last applied, so the group gets the rules of the version the subscription's other groups hold; until that workspace applies, the group keeps the previous version's rules.

Xshield's rules go ahead of yours, one each at the priority numbers below your group's first rule in each direction. Where your first rule leaves too few, the plan of a workspace that reads the group's rules, yours or the enforcement workspace, stops with an error that names the group. Once the cloud connector observes the group, Xshield refuses each workload whose rules go there, with reason `NO_FREE_PRIORITY` in `xshield_azure_enforcement_status`, whose message names the group, and the rest of the subscription and region applies. Move your rules to higher priority numbers to leave room, and Xshield writes the workloads' rules once the connector observes the group again.

That workspace configures the `xshield` provider, so give its runner the API key too (step 1). A group with no inline rules, or whose rules your code declares as `azurerm_network_security_rule` resources, needs nothing.

A group the module has already written rules into holds them in the enforcement workspace's state, and listing it makes the next enforcement apply delete them from the group. Before you list it, take them out of that state:

```shell
terraform state list | grep 'azurerm_network_security_rule.customer\["<group key>/'
terraform state rm 'module.xshield_enforcement.azurerm_network_security_rule.customer["<group key>/<rule name>"]'
```

`<group key>` is the group's key in the snapshot's `customer_network_security_groups`. Remove each rule the list shows.

**Done when** a plan of each such workspace shows only Xshield's rules added to the group.

## Step 4: Create the enforcement workspace and apply it, once per subscription and region

Start from [`enforcement-azure/`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/enforcement-azure). In your copy, change the module's `source` from `../../../modules/azure` to the repository address, or `terraform init` fails:

```terraform
provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
}

provider "xshield" {}

module "xshield_enforcement" {
  source = "github.com/colortokens/terraform-provider-xshield//modules/azure?ref=v26.4.1"

  region = var.region
}

output "xshield_review" {
  value = module.xshield_enforcement.review
}
```

The module takes no policy input. `resource_provider_registrations = "none"` keeps azurerm from registering resource providers, which the enforcement role does not allow.

If the cloud connector enforces this subscription and region today, add [`handover-azure/handover.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/handover-azure) to the workspace before the first plan. The first apply creates Xshield's groups, and where the connector's group is on a network interface or subnet that carried none before, it leaves the association for later, as Azure would clear the connector's group while it associated Xshield's. The `xshield_handover` check names each such level. Once the apply's receipt reaches Xshield, the connector puts Xshield's group in place of its own in a single change, so the workload is enforced throughout, and the next scheduled plan imports the association. Delete the file once a plan imports nothing.

```shell
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Read the plan before you apply it. Each group is named `ct-policy-` and a hash of its network interface or subnet, or from the cloud account's security group name template when it has one, and `xshield_review` says in words where each group goes, for which workloads, and what its rules allow and deny. A workload you expect Xshield to enforce but that no group names is not in this version; step 5 says how to find out why. The apply creates Xshield's groups, associates each with its network interface or subnet, and sends the receipt last.

**Done when** a second `terraform plan -detailed-exitcode` returns `0`: Azure holds what Xshield published, and Xshield has the receipt. That does not yet show any workload carrying its group: step 5 does.

## Step 5: Check that each workload is enforced

The receipt says what your pipeline applied, not what each workload carries. That shows at the cloud connector's first observation after the apply. Read it in a workspace of its own, configured as in step 1, which manages no resources:

```terraform
data "xshield_azure_enforcement_status" "this" {
  cloud_account_id = "00000000-0000-0000-0000-000000000000"
  region           = "eastus2"
}

output "xshield_enforcement" {
  value = {
    state           = data.xshield_azure_enforcement_status.this.state
    drift_evaluated = data.xshield_azure_enforcement_status.this.drift_evaluated
    findings        = [for f in data.xshield_azure_enforcement_status.this.drift_findings : "${f.kind} ${coalesce(f.resource_name, f.resource, "-")}: ${f.detail}"]
    notices         = [for n in data.xshield_azure_enforcement_status.this.notices : "${n.code} ${coalesce(n.asset_name, n.group, n.asset_id, "-")}: ${n.message}"]
  }
}
```

```shell
terraform apply -auto-approve
terraform output xshield_enforcement
```

| Check | Success | When it is not |
|--|--|--|
| The observation | `state = "converged"` and `drift_evaluated = true` | `drift_evaluated = false`: no observation has followed the apply yet. Run the check again later. If it stays false, check that the cloud connector is running and can read the subscription. |
| Each workload | Azure shows Xshield's group on its network interface or subnet, and no finding or notice names it | `assetRefused`: the notice names the workload, the reason and what to change. A workload with no group and no notice: Xshield has not yet discovered it or generated its policy. |
| Every workload | Its **Policy status** in the Xshield portal reads **Synchronized** | Any notice says what keeps the workload from its policy. |

To see the group a network interface or subnet carries:

```shell
az network nic show --ids <network interface ID> --query networkSecurityGroup.id --output tsv
az network vnet subnet show --ids <subnet ID> --query networkSecurityGroup.id --output tsv
```

**Done when** `state` is `converged`, `drift_evaluated` is `true`, `findings` is empty, `notices` holds only those you have decided to accept, and every workload reads **Synchronized**.

## Step 6: Run it on a schedule and watch it

Xshield does not notify your pipeline when it publishes a version, so plan the enforcement workspace on a schedule, and apply when `terraform plan -detailed-exitcode` returns `2`. Add the `check` blocks of the [`xshield_azure_enforcement_status` example](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/data-sources/xshield_azure_enforcement_status) to a workspace of their own and plan it on a schedule too. Each warns, without failing the run, of a refused workload, high-severity drift, or a pipeline that has stopped resolving the version Xshield expects.

**Done when** a plan of that workspace, taken after step 5's check has passed, prints no warning.

## Later

| When | Do |
|--|--|
| You want to stop enforcing a workload | Undeploy its policy in Xshield and keep running the enforcement workspace: the next apply removes the association, then the group. Do not run `terraform destroy`, or remove the module block: both delete the groups while Xshield still expects them. |
| A plan fails because a network interface or subnet carries a group of yours | Azure removes an association by clearing whatever group its level carries, so the module will not remove Xshield's once yours is there. After the cloud connector's next observation, the `associationHeld` notice names it and the plan keeps it unchanged until the level carries no group of yours. |
| A workload moves between its network interface and its subnet | An apply adds and removes associations in no set order, so removing the old one first could leave the workload with no group, or its new group without its rules, for a while. Xshield keeps the association the workload leaves, with its group and rules, until a receipt shows the new placement applied, so the workload keeps its old group for one more apply. The `associationKept` notice names the workload and the network interface or subnet it leaves. Once the cloud connector observes the subscription after that receipt, Xshield publishes a version without it, and the next apply removes the old association and its group. |
| A rule appears in one of Xshield's groups that it did not publish | The next apply removes it. To keep such rules until a person removes them, set `enable_exclusive_rules = false` on the module, as its README describes. |
| The subscription moves back to connector delivery | Undeploy its workloads in Xshield and apply the version that withdraws Xshield's groups: Xshield moves the subscription only once that apply has removed them. Once it has, the plan stops with `Xshield moved <subscription>/<region> to connector delivery`. The workspace then holds only associations it kept for a group of yours or the connector's, and a destroy would clear that group from its network interface or subnet: replace the module block with a `removed` block for the module with `lifecycle { destroy = false }`, and in the same change remove everything else that refers to `module.xshield_enforcement`, such as the `summary` and `xshield_review` outputs of the `enforcement-azure` example, `handover.tf` and `recovery.tf`, as a reference left behind fails the plan with `Reference to undeclared module`. Apply once, and stop running the workspace. The connector needs Read-Write access to enforce again, which Xshield allows only once the subscription is back on connector delivery; you can then remove the enforcement role's assignments. |
| A plan stops because a network security group of yours already has the name of one of Xshield's | A resource group holds one network security group per name. Once the cloud connector observes your group, Xshield gives its group that name with another hash, leaving your group and the name template as they are: plan again then. Do not import your group: the module would give it Xshield's rules. If a later plan still stops, rename your group or move it to another resource group. |
| You roll the provider back to a release without the `xshield_azure_*` types | That release cannot read a state that holds them: every plan fails with `no schema available`, even with a `removed` block for them. While this release is still installed, take each `xshield_azure_*` resource out of the state first: run `terraform state rm` on it, such as `'module.xshield_enforcement.xshield_azure_enforcement_receipt.this[0]'`, or, where you also remove the configuration that declares it, put a `removed` block with `lifecycle { destroy = false }` in its place and apply once. A workspace that still declares an `xshield_azure_*` resource or data source does not plan with that release either. |
| The enforcement workspace's state is lost | Add [`recovery-azure/recovery.tf`](https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot/recovery-azure) to the workspace before any other apply, and set `snapshot_version = data.xshield_azure_enforcement_status.recover.applied_version` on the module. Delete `handover.tf` first if the workspace still has it: the file imports the associations it would, and two imports to one address fail the plan. It imports, at the module's addresses, such as `module.xshield_enforcement.azurerm_network_security_group.this["<group key>"]`, each group and association the last receipt names in `xshield_azure_enforcement_status`, the associations the receipt leaves out, which Xshield holds or a contained workload keeps, and Xshield's rules in groups of yours, at `module.xshield_enforcement.azurerm_network_security_rule.customer["<group key>/<rule name>"]`, each only where the module still declares it. It also imports the receipt, `module.xshield_enforcement.xshield_azure_enforcement_receipt.this[0]`, by `<subscription ID>/<region>`, so the apply does not send a receipt for the pinned version as a new apply. That apply sends none either when all it does is restore a group or association that Azure gives its old ID, so Xshield sees the restored object at the cloud connector's next drift observation rather than at once. If the plan stops with `Cannot import non-existent remote object`, the object was deleted since the receipt: add its key to the file's `skipped_imports` variable, under its kind, and the apply creates it again. A plan stop that says Xshield clears it at its next observation stays while the pin does, as a pinned version never changes: once Xshield shows a newer version, pin that one or remove the pin, and add to `skipped_imports` any key the plan then says has no configuration. Apply once, then delete the file and the pin. |
