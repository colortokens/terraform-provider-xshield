package provider

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/config"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// awsEndpoint stands in for EC2 and STS: it records each call the AWS provider makes and refuses it, so a test sees
// whether an apply touched a rule and nothing leaves the machine.
type awsEndpoint struct {
	url   string
	mu    sync.Mutex
	calls []string
}

func newAWSEndpoint(t *testing.T) *awsEndpoint {
	t.Helper()
	e := &awsEndpoint{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		e.mu.Lock()
		e.calls = append(e.calls, r.Method+" "+r.URL.Path+" "+form.Get("Action"))
		e.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>UnauthorizedOperation`+
			`</Code><Message>not AWS</Message></Error></Errors><RequestID>test</RequestID></Response>`)
	}))
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

func (e *awsEndpoint) called() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

// rulesModuleConfig writes a configuration that calls the aws-security-group-rules module as the guide's step 4 does,
// for the group web declaring the rule that change set cs-1 moves, or, without the module, only the providers. It is a
// file, since a step's init installs the modules of a configuration file but not those of a configuration string.
func rulesModuleConfig(t *testing.T, g *gatewayServer, aws *awsEndpoint, withModule bool) func(config.TestStepConfigRequest) string {
	t.Helper()
	module, err := filepath.Abs("../../examples/enforcement-snapshot/modules/aws-security-group-rules")
	if err != nil {
		t.Fatal(err)
	}
	content := g.providerBlock() + fmt.Sprintf(`
terraform {
  required_providers {
    aws     = { source = "hashicorp/aws" }
    xshield = { source = "colortokens/xshield" }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  max_retries                 = 1

  endpoints {
    ec2 = %q
    sts = %[1]q
  }
}
`, aws.url)
	if withModule {
		content += fmt.Sprintf(`
data "xshield_aws_security_group_changes" "this" {
  cloud_account_id = "123456789012"
  region           = "us-east-1"
}

module "web_rules" {
  source = %q

  xshield_changes   = data.xshield_aws_security_group_changes.this
  vpc_id            = "vpc-0web"
  group_name        = "web"
  security_group_id = "sg-0web"

  ingress_rules = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}
`, module)
	}
	file := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.StaticFile(file)
}

// A workspace whose first plan is made while cs-1 narrows its group, and applied after cs-1 was reverted, is refused
// at the module's applying receipt, and the apply makes no AWS call: none of the group's rules changes. The provider
// under test is each step's, so that the step's init installs the module, and TF_ACC_PROVIDER_NAMESPACE gives it the
// source the module requires. The AWS provider comes from the configuration file, as a step reading one requires. The
// second step drops the module, since the harness cannot read a state holding the module's reads.
func TestAccTheRulesModuleChangesNoRuleWhenItsApplyingReceiptIsRefused(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "colortokens")
	g := newGatewayServer(t)
	aws := newAWSEndpoint(t)
	narrowing := strings.Replace(servedChanges(1, `{"id":"cs-1","state":"narrowing","moves":[`+httpsAllMove+`]}`),
		`"revoke":[]`, `"revoke":[`+httpsAllMove+`]`, 1)
	refusedAt := 0

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { g.serve(narrowing) },
				ConfigFile:               rulesModuleConfig(t, g, aws, true),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(`module.web_rules.aws_vpc_security_group_ingress_rule.this["ssh_office"]`, plancheck.ResourceActionCreate),
					plancheck.ExpectResourceAction("module.web_rules.xshield_aws_security_group_changes_receipt.applying[0]", plancheck.ResourceActionCreate),
					plancheck.ExpectResourceAction("module.web_rules.xshield_aws_security_group_changes_receipt.applied[0]", plancheck.ResourceActionCreate),
					changesServedBeforeApply{g: g, changes: servedChanges(2, `{"id":"cs-1","state":"restoring","moves":[`+httpsAllMove+`]}`), at: &refusedAt},
				}},
				ExpectError: wrappedText("-> 409", "Xshield no longer publishes change set cs-1 as narrowing sg-0web: it was reverted or "+
					"withdrawn after this plan was made. No rule was changed. Run a new plan and apply it."),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigFile:               rulesModuleConfig(t, g, aws, false),
				Check: func(*terraform.State) error {
					if calls := aws.called(); len(calls) != 0 {
						return fmt.Errorf("the apply called AWS %v after Xshield refused its applying receipt", calls)
					}
					applying := 0
					for _, r := range g.requests()[refusedAt:] {
						switch {
						case r.method == http.MethodPost && strings.Contains(string(r.body), `"stage":"applying"`):
							applying++
						case r.method != http.MethodGet:
							return fmt.Errorf("the apply sent Xshield %s %s %s besides its applying receipt", r.method, r.requestURI, r.body)
						}
					}
					if applying != 1 {
						return fmt.Errorf("the apply sent %d applying receipts, want 1", applying)
					}
					return nil
				},
			},
		},
	})
}
