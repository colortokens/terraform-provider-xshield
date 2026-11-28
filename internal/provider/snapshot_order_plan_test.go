package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// snapshotGateway serves one pinned snapshot version, signed requests only, as the gateway does.
type snapshotGateway struct {
	t      *testing.T
	pub    *rsa.PublicKey
	keyPEM string
	url    string
	mu     sync.Mutex
	body   string
}

func newSnapshotGateway(t *testing.T, body string) *snapshotGateway {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &snapshotGateway{t: t, pub: &key.PublicKey, body: body,
		keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	g.url = srv.URL
	return g
}

func (g *snapshotGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if err := gatewayVerifies(r, body, g.pub); err != nil {
		g.t.Errorf("the gateway would refuse %s %s: %v", r.Method, r.RequestURI, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/versions/") {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "404 page not found")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, g.body)
}

// reversedLists is the document with every list in it reversed: the same content, as a server that hashed its lists in the
// order it built them could have published it.
func reversedLists(t *testing.T, doc string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	var reverse func(any)
	reverse = func(v any) {
		switch v := v.(type) {
		case []any:
			slices.Reverse(v)
			for _, e := range v {
				reverse(e)
			}
		case map[string]any:
			for _, e := range v {
				reverse(e)
			}
		}
	}
	reverse(v)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func editedTestdata(t *testing.T, name string, edit func(snap map[string]any)) (string, map[string]any) {
	t.Helper()
	var snap map[string]any
	if err := json.Unmarshal([]byte(readTestdata(t, name)), &snap); err != nil {
		t.Fatal(err)
	}
	edit(snap)
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), snap
}

// releasedAWSProviderRef is the latest release, which a workspace applying AWS snapshots runs. No release carries the Azure
// snapshot data source yet, so releasedAzureProviderRef is main as it was before the Azure pipeline delivery updates.
const (
	releasedAWSProviderRef   = "v26.4.1"
	releasedAzureProviderRef = "3d7e856"
)

// releasedProvider builds the provider at ref into a filesystem mirror, and points Terraform at it for colortokens/xshield
// alone, so a step can apply with that release and a later step plan with the provider under test.
func releasedProvider(t *testing.T, ref string) map[string]tfresource.ExternalProvider {
	t.Helper()
	run := func(dir string, name string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			var stderr []byte
			if exit, ok := err.(*exec.ExitError); ok {
				stderr = exit.Stderr
			}
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr)
		}
		return out
	}
	root := strings.TrimSpace(string(run(".", "git", "rev-parse", "--show-toplevel")))
	dir := t.TempDir()
	src, mirror := filepath.Join(dir, "src"), filepath.Join(dir, "mirror")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "src.tar")
	run(root, "git", "archive", "--output", archive, ref)
	run(src, "tar", "-xf", archive)
	const version = "0.0.1"
	binary := filepath.Join(mirror, "registry.terraform.io", "colortokens", "xshield", version, runtime.GOOS+"_"+runtime.GOARCH,
		"terraform-provider-xshield_v"+version)
	run(src, "go", "build", "-o", binary, ".")
	cli := filepath.Join(dir, "terraform.rc")
	if err := os.WriteFile(cli, []byte(fmt.Sprintf(`provider_installation {
  filesystem_mirror {
    path    = %q
    include = ["registry.terraform.io/colortokens/xshield"]
  }
  direct {
    exclude = ["registry.terraform.io/colortokens/xshield"]
  }
}
`, mirror)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TF_CLI_CONFIG_FILE", cli)
	return map[string]tfresource.ExternalProvider{"xshield": {Source: "colortokens/xshield", VersionConstraint: version}}
}

// snapshotOrderConfig hands the snapshot the data source reads to a resource and to an output, less the attributes whose
// schema changed since the released provider, and outputs each list whose order a module hands on: a directory entry's
// groups, which the AWS module jsonencodes into its parameter, and each workload's groups and the workloads of each subnet
// a group of yours sits on, which the Azure module outputs.
func snapshotOrderConfig(g *snapshotGateway, dataSource string, snap map[string]any, changedSchema []string) string {
	lists := `{ for handle, entry in data.%[3]s.this.directory_entries : handle => entry.security_groups }`
	if strings.Contains(dataSource, "azure") {
		lists = `{
    assets          = { for id, asset in data.%[3]s.this.assets : id => asset.network_security_groups }
    customer_groups = { for key, group in data.%[3]s.this.customer_network_security_groups : key => group.subnets }
  }`
	}
	omitted, err := json.Marshal(append([]string{}, changedSchema...))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`
terraform {
  required_providers {
    xshield = { source = "colortokens/xshield" }
  }
}

provider "xshield" {
  server_url  = %[1]q
  tenancy_id  = "tenancy"
  user_id     = "user"
  fingerprint = "fp"
  private_key = <<EOT
%[2]sEOT
}

data %[3]q "this" {
  cloud_account_id = %[4]q
  region           = %[5]q
  version          = %[6]q
}

locals {
  snapshot = { for name, value in data.%[3]s.this : name => value if !contains(%[7]s, name) }
}

resource "terraform_data" "consumed" {
  input = local.snapshot
}

output "snapshot" {
  value = local.snapshot
}

output "lists" {
  value = `+lists+`
}
`, g.url, g.keyPEM, dataSource, snap["cloudAccountId"], snap["region"], snap["version"], omitted)
}

// The provider reads each list of a snapshot in the order the server serves it, as the release before it did. The server
// serves a version as it was published, so a workspace upgraded from that release plans nothing, resource or output, on the
// version it applied, whatever order its lists were published in. A provider that sorted would reorder such a version's
// lists once, as an output change and an apply for a no-op. An attribute whose schema this provider changed is a new value,
// not a reorder, so it is left out of what the configuration hands on; the lists inside it are output on their own.
func TestAccUpgradingFromTheReleasedProviderPlansNothing(t *testing.T) {
	if os.Getenv(tfresource.EnvTfAcc) == "" {
		t.Skipf("acceptance test: set %s to build the released provider and run it", tfresource.EnvTfAcc)
	}
	for name, tc := range map[string]struct {
		releasedRef         string
		changedSchema       []string
		dataSource, fixture string
		edit                func(snap map[string]any)
		path                string
		canonical           []string
	}{
		"aws": {releasedRef: releasedAWSProviderRef, dataSource: "xshield_aws_enforcement_snapshot", fixture: "snapshot.json", edit: func(snap map[string]any) {
			plan := snap["aws"].(map[string]any)
			plan["withdrawing"] = []any{"sg-0withdrawn-a", "sg-0withdrawn-b", "sg-0withdrawn-c"}
			entry := plan["directory"].(map[string]any)["lambda/reports"].(map[string]any)
			entry["securityGroups"] = []any{"ct-cohort-0123456789abcdef", "i-app-1", "i-app-2"}
		}, path: "directory_entries.lambda/reports.security_groups", canonical: []string{"ct-cohort-0123456789abcdef", "i-app-1", "i-app-2"}},
		"azure": {releasedRef: releasedAzureProviderRef,
			changedSchema: []string{"customer_network_security_groups", "customer_network_security_groups_awaiting_room"}, dataSource: "xshield_azure_enforcement_snapshot", fixture: "azure_snapshot.json", edit: func(snap map[string]any) {
				plan := snap["azure"].(map[string]any)
				plan["assets"].(map[string]any)["web"].(map[string]any)["networkSecurityGroups"] = []any{"ct-policy-8d612d812776", "ct-policy-d2dd5b7ea0d5"}
				plan["customerNetworkSecurityGroups"] = map[string]any{"customer-nsg-5b8ff476f40c": map[string]any{
					"id":                "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-owner",
					"resourceGroupName": "rg-net", "name": "nsg-snet-owner", "securityRules": []any{},
					"subnets": map[string]any{"/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/snet-app": []any{"api", "batch", "web"}},
				}}
			}, path: "assets.web.network_security_groups", canonical: []string{"ct-policy-8d612d812776", "ct-policy-d2dd5b7ea0d5"}},
	} {
		released := releasedProvider(t, tc.releasedRef)
		for _, outOfOrder := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s published out of order %t", name, outOfOrder), func(t *testing.T) {
				clearXshieldEnv(t)
				t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "colortokens")
				served, snap := editedTestdata(t, tc.fixture, tc.edit)
				want := slices.Clone(tc.canonical)
				if outOfOrder {
					served = reversedLists(t, served)
					slices.Reverse(want)
				}
				g := newSnapshotGateway(t, served)
				config := snapshotOrderConfig(g, tc.dataSource, snap, tc.changedSchema)
				readInOrderServed := []tfresource.TestCheckFunc{}
				for i, group := range want {
					readInOrderServed = append(readInOrderServed, tfresource.TestCheckResourceAttr("data."+tc.dataSource+".this", fmt.Sprintf("%s.%d", tc.path, i), group))
				}
				plansNothing := tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}
				tfresource.Test(t, tfresource.TestCase{
					Steps: []tfresource.TestStep{
						{Config: config, ExternalProviders: released, Check: tfresource.ComposeAggregateTestCheckFunc(readInOrderServed...)},
						{Config: config, ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, ConfigPlanChecks: plansNothing,
							Check: tfresource.ComposeAggregateTestCheckFunc(readInOrderServed...)},
						{Config: config, ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, ConfigPlanChecks: plansNothing},
					},
				})
			})
		}
	}
}
