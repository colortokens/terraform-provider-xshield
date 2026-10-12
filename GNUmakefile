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

# Acceptance tests. These create and destroy real objects in the tenant named
# by the XSHIELD_* environment variables, so point them at a test tenant.
testacc:
	TF_ACC=1 go test -v -timeout 45m ./internal/provider/

# WARNING: docs/ is currently maintained by hand and has diverged from the
# schemas. Running this regenerates every page from the schemas and examples,
# discarding the curated descriptions. Reconcile the two before relying on it.
docs:
	go generate ./...

.PHONY: default build fmt vet test testacc docs
