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
make fmt vet   # formatting and static analysis
```

Every pull request must keep `make build`, `make test`, `make vet` and the
formatting check green. These are enforced by the `Test` GitHub Actions
workflow.

Note that `docs/` is currently maintained by hand and has diverged from the
provider schemas, so `make docs` will overwrite the curated descriptions. Until
the two are reconciled, edit the affected page alongside the schema change.

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
make testacc
```

`xshield_asset` needs the two fixture variables because assets are registered by
the xshield agent and cannot be created through Terraform; its tests import an
existing asset and then update it.

The full acceptance suite runs nightly against a matrix of Terraform versions in
the `Nightly acceptance tests` workflow.

A change to a resource or data source should come with an acceptance test that
covers create, update, read and import, plus unit coverage for any new schema
constraint.
