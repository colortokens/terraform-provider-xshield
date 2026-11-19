default: build

build:
	go build -v ./...

fmt:
	gofmt -w ./internal ./tools main.go

vet:
	go vet ./...

# Unit tests. Safe to run without credentials: acceptance tests skip unless
# TF_ACC is set.
test:
	go test -v -race -cover ./...

# terraform test in every module and example, against a provider built from
# this checkout. Needs Terraform 1.11 or later; no credentials.
tftest:
	scripts/terraform-tests.sh

# Acceptance tests. These create and destroy real objects in the tenant named
# by the XSHIELD_* environment variables, so point them at a test tenant.
testacc:
	TF_ACC=1 go test -v -timeout 45m ./internal/provider/

# Regenerates docs/ from the schema descriptions and examples/; see CONTRIBUTING.
docs:
	go generate ./...

# Points every version a reader copies from the docs at VERSION, such as 0.3.0,
# and regenerates docs/. The release workflow runs it; see CONTRIBUTING.
release-version:
	scripts/release-version.sh set $(VERSION)
	go generate ./...

# Fails unless those references all read VERSION, or the latest release tag.
check-version:
	scripts/release-version.sh check $(VERSION)

.PHONY: default build fmt vet test tftest testacc docs release-version check-version
