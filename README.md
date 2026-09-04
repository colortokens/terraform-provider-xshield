# terraform-provider-xshield

Terraform provider for ColorTokens Xshield: micro-segmentation policy as code.

Segments select assets by their tags, templates describe the ports and paths those assets may use, and
a deployment puts that policy on the firewall. This provider covers all three, and the lookups needed
to write policy without opening the portal.

## Installation

```hcl
terraform {
  required_providers {
    xshield = {
      source  = "colortokens/xshield"
      version = "0.4.0"
    }
  }
}

provider "xshield" {
  tenancy_id       = var.tenancy_id
  user_id          = var.user_id
  fingerprint      = var.fingerprint
  private_key_path = "/path/to/colortokens_api_key.pem"
  server_url       = "https://my-company.colortokens.com/"
}
```

The published version comes from the release tag, which the goreleaser workflow builds on any tag
matching `v*`. Keep the version above and `examples/provider/provider.tf` in step with it.

## Getting started

Policy reaches a firewall in four steps, and each has a resource.

1. **Tag the assets.** `xshield_tag_rule` applies core tags; segment criteria select on those tags.
2. **Describe the policy.** `xshield_template` holds the port and path rules, `xshield_named_network`
   the reusable address sets.
3. **Attach it.** `xshield_segment` selects assets by criteria and attaches templates to them.
4. **Deploy it.** `xshield_asset` turns enforcement on, then `xshield_policy_deployment` pushes the
   reviewed policy out. Nothing reaches a firewall until this step runs.

Two things surprise people, and both are documented on the resources concerned. A deployment does
nothing on an asset whose enforcement is off. And a segment criteria is stored with a `managedby`
clause the backend appends, which the provider applies during plan so no spurious diff appears.

## Resources

| Resource | What it manages |
| --- | --- |
| [`xshield_asset`](docs/resources/asset.md) | An existing asset's tags and its enforcement state. Assets are imported, not created. |
| [`xshield_named_network`](docs/resources/named_network.md) | A reusable set of addresses that policy rules refer to. |
| [`xshield_policy_deployment`](docs/resources/policy_deployment.md) | Pushes reviewed policy to the assets a criteria selects. |
| [`xshield_segment`](docs/resources/segment.md) | A set of assets selected by criteria, with the policy attached to them. |
| [`xshield_tag_rule`](docs/resources/tag_rule.md) | Applies core tags to the assets a criteria matches. |
| [`xshield_template`](docs/resources/template.md) | Port and path rules that a segment applies to its members. |

## Data sources

Looking up one object, by id or by name:

| Data source | Returns |
| --- | --- |
| [`xshield_asset`](docs/data-sources/asset.md) | One asset, with its full enforcement state. |
| [`xshield_named_network`](docs/data-sources/named_network.md) | One named network and its ranges. |
| [`xshield_segment`](docs/data-sources/segment.md) | One segment, its criteria and its attachments. |
| [`xshield_tag_rule`](docs/data-sources/tag_rule.md) | One tag rule and the tags it applies. |
| [`xshield_template`](docs/data-sources/template.md) | One template with its ports and paths. |

Selecting many objects by criteria:

| Data source | Returns |
| --- | --- |
| [`xshield_assets`](docs/data-sources/assets.md) | Assets matching a criteria, with enforcement state and ids. |
| [`xshield_named_networks`](docs/data-sources/named_networks.md) | Named networks and their ranges. |
| [`xshield_segments`](docs/data-sources/segments.md) | Segments, their membership counts and automation settings. |
| [`xshield_tag_rules`](docs/data-sources/tag_rules.md) | Tag rules and the tags they apply. |
| [`xshield_templates`](docs/data-sources/templates.md) | Templates and how widely each is assigned. |

Understanding the tenant, so policy can be written without the portal:

| Data source | Answers |
| --- | --- |
| [`xshield_criteria`](docs/data-sources/criteria.md) | Is this criteria valid, and how much does it select? |
| [`xshield_fields`](docs/data-sources/fields.md) | Which tag keys exist, and which may a segment use? |
| [`xshield_field_values`](docs/data-sources/field_values.md) | What values does this tag actually take? |
| [`xshield_open_ports`](docs/data-sources/open_ports.md) | What do these assets listen on, and what is enforced? |
| [`xshield_paths`](docs/data-sources/paths.md) | Which peers actually connect to them? |
| [`xshield_policy_changes`](docs/data-sources/policy_changes.md) | What would a deployment change, and on how many assets? |
| [`xshield_deployment_simulation`](docs/data-sources/deployment_simulation.md) | What firewall rules would one asset end up running? |
| [`xshield_work_request`](docs/data-sources/work_request.md) | Did that asynchronous change finish? |

## Running the provider locally

With a local build, through `dev_overrides`:

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/colortokens/xshield" = "<PATH>"
  }
  direct {}
}
```

Put that in `~/.terraformrc`, run `go build` in this directory, and set `<PATH>` to the result of
`go env GOBIN`, or `$HOME/go/bin` if that is empty.

To attach a debugger instead:

```sh
go run main.go --debug
# copy the TF_REATTACH_PROVIDERS value it prints, then in another terminal
cd examples/your-example
TF_REATTACH_PROVIDERS=... terraform init
TF_REATTACH_PROVIDERS=... terraform apply
```

## Contributing

The code under `internal/` is maintained by hand, so your edits will not be overwritten. Many files
still carry a `Code generated by ... DO NOT EDIT.` header from an earlier build process; treat it as
history rather than instruction.

Before changing `internal/sdk`, read [scripts/README.md](scripts/README.md). It covers how to keep
the OpenAPI document in step with the platform API, how to add or remove an operation, and the
places where the document has been wrong before.

Attribute documentation lives in the schema, not in `docs/`. Edit the `Description` on the attribute
and regenerate; editing `docs/*.md` directly means the next regeneration deletes your change.

Run `go build ./... && go vet ./... && go test ./internal/...` before opening a pull request.
