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
// whether an apply touched a rule and nothing leaves the machine. One that holds rules authorizes, describes and revokes
// security group rules as EC2 does, so one apply can create rules and a later one take them out.
type awsEndpoint struct {
	url        string
	mu         sync.Mutex
	calls      []string
	holdsRules bool
	rules      map[string]awsRule
	revoking   func()
}

type awsRule struct {
	id, groupID, protocol, fromPort, toPort, cidr string
	egress                                        bool
}

func newAWSEndpoint(t *testing.T) *awsEndpoint {
	return startAWSEndpoint(t, &awsEndpoint{})
}

func newAWSRulesEndpoint(t *testing.T) *awsEndpoint {
	return startAWSEndpoint(t, &awsEndpoint{holdsRules: true, rules: map[string]awsRule{}})
}

func startAWSEndpoint(t *testing.T, e *awsEndpoint) *awsEndpoint {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		action := form.Get("Action")
		e.mu.Lock()
		e.calls = append(e.calls, r.Method+" "+r.URL.Path+" "+action)
		answer, answered := e.answer(action, form)
		revoking := e.revoking
		e.mu.Unlock()
		if revoking != nil && strings.HasPrefix(action, "Revoke") {
			revoking()
		}
		if answered {
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><%sResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">`+
				`<requestId>test</requestId>%s</%[1]sResponse>`, action, answer)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>UnauthorizedOperation`+
			`</Code><Message>not AWS</Message></Error></Errors><RequestID>test</RequestID></Response>`)
	}))
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

// answer is what EC2 answers a call about the rules it holds; only an endpoint holding rules answers any.
func (e *awsEndpoint) answer(action string, form url.Values) (string, bool) {
	if !e.holdsRules {
		return "", false
	}
	switch action {
	case "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress":
		rule := awsRule{id: fmt.Sprintf("sgr-%017x", len(e.calls)), groupID: form.Get("GroupId"), protocol: form.Get("IpPermissions.1.IpProtocol"),
			fromPort: form.Get("IpPermissions.1.FromPort"), toPort: form.Get("IpPermissions.1.ToPort"),
			cidr: form.Get("IpPermissions.1.IpRanges.1.CidrIp"), egress: action == "AuthorizeSecurityGroupEgress"}
		e.rules[rule.id] = rule
		return "<return>true</return><securityGroupRuleSet>" + rule.item() + "</securityGroupRuleSet>", true
	case "DescribeSecurityGroupRules":
		items := ""
		for _, id := range ruleIDs(form) {
			if rule, held := e.rules[id]; held {
				items += rule.item()
			}
		}
		return "<securityGroupRuleSet>" + items + "</securityGroupRuleSet>", true
	case "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress":
		for _, id := range ruleIDs(form) {
			delete(e.rules, id)
		}
		return "<return>true</return>", true
	}
	return "", false
}

// ruleIDs are the rule IDs a call names, directly or by a security-group-rule-id filter.
func ruleIDs(form url.Values) []string {
	var ids []string
	for key, values := range form {
		if strings.HasPrefix(key, "SecurityGroupRuleId.") {
			ids = append(ids, values...)
		}
		if name, found := strings.CutSuffix(key, ".Name"); found && strings.HasPrefix(key, "Filter.") && form.Get(key) == "security-group-rule-id" {
			for i := 1; form.Has(fmt.Sprintf("%s.Value.%d", name, i)); i++ {
				ids = append(ids, form.Get(fmt.Sprintf("%s.Value.%d", name, i)))
			}
		}
	}
	return ids
}

func (r awsRule) item() string {
	return fmt.Sprintf(`<item><securityGroupRuleId>%s</securityGroupRuleId><groupId>%s</groupId><groupOwnerId>123456789012</groupOwnerId>`+
		`<isEgress>%t</isEgress><ipProtocol>%s</ipProtocol><fromPort>%s</fromPort><toPort>%s</toPort><cidrIpv4>%s</cidrIpv4>`+
		`<securityGroupRuleArn>arn:aws:ec2:us-east-1:123456789012:security-group-rule/%[1]s</securityGroupRuleArn><tagSet/></item>`,
		r.id, r.groupID, r.egress, r.protocol, r.fromPort, r.toPort, r.cidr)
}

// onRevoke runs check as each rule is revoked, before EC2 answers.
func (e *awsEndpoint) onRevoke(check func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revoking = check
}

func (e *awsEndpoint) held() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rules)
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
				ExpectError: wrappedText("-> 409", staleNarrowingRefusal),
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

const staleNarrowingRefusal = "Xshield no longer publishes change set cs-1 as narrowing sg-0web: it was reverted or withdrawn after this " +
	"plan was made. No rule waiting on this receipt was changed. Run a new plan and apply it now: it puts back any moved rule this apply " +
	"took out of sg-0web."

// rulesModuleAtRoot writes the aws-security-group-rules module's own files as the root configuration, with the inputs
// rulesModuleConfig gives it as their defaults, since the harness cannot read a state that holds a module. Xshield's
// changes name the group web, so the module reads its rules from Xshield whatever change sets are served.
func rulesModuleAtRoot(t *testing.T, g *gatewayServer, aws *awsEndpoint) func(config.TestStepConfigRequest) string {
	t.Helper()
	module, err := filepath.Abs("../../examples/enforcement-snapshot/modules/aws-security-group-rules")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(module, "*.tf"))
	if err != nil || len(files) == 0 {
		t.Fatalf("the module's files: %v, %v", files, err)
	}
	dir := t.TempDir()
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(file)), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := g.providerBlock() + fmt.Sprintf(`
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
	inputs := `
variable "xshield_changes" {
  default = { cloud_account_id = "123456789012", region = "us-east-1", groups = { web = ["vpc-0web"] } }
}
variable "vpc_id" { default = "vpc-0web" }
variable "group_name" { default = "web" }
variable "security_group_id" { default = "sg-0web" }
variable "ingress_rules" {
  default = {
    https_all  = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "0.0.0.0/0" }
    ssh_office = { ip_protocol = "tcp", from_port = 22, to_port = 22, cidr_ipv4 = "10.0.0.0/8" }
  }
}
`
	for name, content := range map[string]string{"providers.tf": root, "inputs_override.tf": inputs} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return config.StaticDirectory(dir)
}

// A workspace whose group holds the rule cs-1 moves, and whose plan made while cs-1 narrows the group is applied after
// cs-1 was reverted, keeps the rule: Terraform destroys a rule no longer declared before it updates the applying receipt
// the rule depended on, unless the rule is created before it is destroyed, as the module's rules are, and then only
// after the applied receipt. The first apply records that order in the state, which the later applies read it from. A
// new plan applied while cs-1 still narrows the group takes the rule out once Xshield has the applied receipt.
func TestAccTheRulesModuleTakesNoRuleOutWhenItsApplyingReceiptIsRefused(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "colortokens")
	g := newGatewayServer(t)
	aws := newAWSRulesEndpoint(t)
	narrowing := strings.Replace(servedChanges(2, `{"id":"cs-1","state":"narrowing","moves":[`+httpsAllMove+`]}`),
		`"revoke":[]`, `"revoke":[`+httpsAllMove+`]`, 1)
	refusedAt, staleApplyFrom, narrowingApplyFrom := 0, 0, 0

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { g.serve(servedChanges(1, `{"id":"cs-1","state":"attaching","moves":[`+httpsAllMove+`]}`)) },
				ConfigDirectory:          rulesModuleAtRoot(t, g, aws),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					if held := aws.held(); held != 2 {
						t.Fatalf("AWS holds %d rules after the first apply, want both declared", held)
					}
					g.serve(narrowing)
					staleApplyFrom = len(aws.called())
				},
				ConfigDirectory: rulesModuleAtRoot(t, g, aws),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(`aws_vpc_security_group_ingress_rule.this["https_all"]`, plancheck.ResourceActionDestroy),
					changesServedBeforeApply{g: g, changes: servedChanges(3, `{"id":"cs-1","state":"restoring","moves":[`+httpsAllMove+`]}`), at: &refusedAt},
				}},
				ExpectError: wrappedText("-> 409", staleNarrowingRefusal),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					for _, call := range aws.called()[staleApplyFrom:] {
						if strings.HasSuffix(call, " RevokeSecurityGroupIngress") {
							t.Errorf("the apply Xshield refused the applying receipt of called AWS %s", call)
						}
					}
					if held := aws.held(); held != 2 {
						t.Errorf("AWS holds %d rules after the refused apply, want both", held)
					}
					g.serve(narrowing)
					narrowingApplyFrom = len(g.requests())
					aws.onRevoke(func() {
						for _, r := range g.requests()[narrowingApplyFrom:] {
							if r.method == http.MethodPost && strings.Contains(string(r.body), `"stage":"applied"`) {
								return
							}
						}
						t.Errorf("the apply took a rule out before Xshield had its applied receipt")
					})
				},
				ConfigDirectory: rulesModuleAtRoot(t, g, aws),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(`aws_vpc_security_group_ingress_rule.this["https_all"]`, plancheck.ResourceActionDestroy),
				}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					aws.onRevoke(nil)
					if held := aws.held(); held != 1 {
						t.Errorf("AWS holds %d rules after the narrowing apply, want ssh_office alone", held)
					}
				},
				ConfigFile: rulesModuleConfig(t, g, aws, false),
			},
		},
	})
}
