# Contributing to This Repository

This provider was originally generated from the xshield OpenAPI description. It
is now maintained directly in this repository: changes are made to the Go source
here and reviewed as pull requests.

## Reporting Issues

If you encounter a bug or have a suggestion, please open an issue on GitHub with:

- A clear and descriptive title
- The Terraform configuration that reproduces the problem, with credentials removed
- Expected and actual behavior
- Relevant logs (`TF_LOG=DEBUG terraform apply`), with credentials removed
- Your Terraform version (`terraform version`) and provider version

## Development

Requires Go (see the `go` directive in `go.mod`) and Terraform.

```
make build     # compile the provider
make test      # unit tests; acceptance tests skip without TF_ACC
make tftest    # terraform test in every module and example, providers mocked
make fmt vet   # formatting and static analysis
```

Every pull request must keep `make build`, `make test`, `make tftest`,
`make vet` and the formatting check green. These are enforced by the `Test` GitHub Actions
workflow.

`docs/` is generated from the schema descriptions, `examples/` and
`templates/guides/` by `make docs`. Change the schema, example or guide template,
then regenerate; do not edit a page by hand.

### Generated files edited by hand

Some files still carry Speakeasy's `DO NOT EDIT` header but hold hand edits that
regenerating them would drop. Before regenerating any of them, carry each edit
over, and keep the test that guards it passing:

| File | Hand edit | Test that guards it |
|--|--|--|
| `internal/sdk/internal/utils/json.go` | Reads a timestamp the API writes as `""` as unset | `internal/sdk/empty_timestamp_test.go` |
| `internal/sdk/models/shared/metadatapath.go` | `SourceAsset` and `DestinationAsset`, declared in `xshield_oas3.yaml` | `TestTemplateReadKeepsThePathsAssetPeers` |
| `internal/provider/template_resource_sdk.go` | `RefreshFromSharedTemplate` takes a path's peer ID from its asset summary when the ID is absent | `TestTemplateReadKeepsThePathsAssetPeers` |
| `internal/provider/template_resource.go` | Update re-adds an edited path with only the peers its configuration sets, and Read keeps paths and ports in state order through `reorderToStateOrder`, matching a path by its ID before its key | `internal/provider/template_path_peer_test.go`, `internal/provider/template_identity_test.go` |

The Terraform modules the AWS pipeline guide (`docs/guides`) calls live in `modules/`. The
workspaces under `examples/enforcement-snapshot` call them by a relative path,
and the docs call them by a GitHub `source` pinned with `?ref=`.

## Releasing

Run the `Release` workflow from the Actions tab with the version, such as
`0.3.0`. It sets the `colortokens/xshield` pin in `README.md` and
`examples/provider/provider.tf`, and the `?ref=` of every module source under
`modules/`, to that version, regenerates
`docs/`, commits to `main`, tags `v0.3.0` and publishes. The Registry renders
the docs at the tag, so each release's docs name that release. The workflow
pushes to `main` with `GITHUB_TOKEN`, so branch protection on `main` must let
GitHub Actions push.

Write a new pin or module source with any released version; the release
rewrites it. `make release-version VERSION=0.3.0` does the same locally, and
the `Test` workflow fails a pull request whose references do not all name the
latest release tag.

## Tests

Unit tests live alongside the code and run without credentials. They cover the
provider configuration, the schema of every resource and data source, and the
custom validators.

Acceptance tests create and destroy real objects and only run when `TF_ACC` is
set. Point them at a dedicated test tenant:

```
export TF_ACC=1
export XSHIELD_TENANCY_ID=...
export XSHIELD_USER_ID=...
export XSHIELD_FINGERPRINT=...
export XSHIELD_PRIVATE_KEY_PATH=...
export XSHIELD_SERVER_URL=...          # optional
export XSHIELD_TEST_ASSET_ID=...       # an existing asset, for xshield_asset
export XSHIELD_TEST_ASSET_NAME=...     # the same asset's name
export XSHIELD_TEST_CLOUD_ACCOUNT_ID=... # an AWS account with an enforcement snapshot published
export XSHIELD_TEST_CLOUD_REGION=...   # the region of that snapshot
make testacc
```

`xshield_asset` needs the two fixture variables because assets are registered by
the xshield agent and cannot be created through Terraform; its tests import an
existing asset and then update it.

The enforcement snapshot tests need an account and region whose policy delivery
is Terraform pipeline. The `xshield_aws_enforcement_receipt` test sends receipts with
placeholder AWS IDs, so use an account that no real pipeline applies. Without a
tenant, the unit tests in `internal/provider` cover each snapshot, status,
receipt and customer group change request against a local stand-in, and the
module tests under
`modules/aws/tests` mock both providers.

The full acceptance suite runs nightly against a matrix of Terraform versions in
the `Nightly acceptance tests` workflow.

A change to a resource or data source should come with an acceptance test that
covers create, update, read and import, plus unit coverage for any new schema
constraint.
