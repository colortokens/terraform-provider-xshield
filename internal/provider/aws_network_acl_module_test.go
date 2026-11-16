package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/config"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

// networkACLEndpoint stands in for EC2 holding one network ACL, acl-0a1b. As EC2 does, it holds one entry per rule
// number and direction, and refuses to create another there.
type networkACLEndpoint struct {
	url     string
	mu      sync.Mutex
	entries map[string]networkACLEntry
}

type networkACLEntry struct {
	ruleNumber int
	egress     bool
	action     string
	cidr       string
}

func networkACLEntryKey(ruleNumber string, egress string) string {
	return ruleNumber + "/" + egress
}

func newNetworkACLEndpoint(t *testing.T) *networkACLEndpoint {
	t.Helper()
	e := &networkACLEndpoint{entries: map[string]networkACLEntry{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		action := form.Get("Action")
		e.mu.Lock()
		answer, refusal := e.answer(action, form)
		e.mu.Unlock()
		if refusal != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Response><Errors><Error><Code>%s</Code>`+
				`<Message>refused</Message></Error></Errors><RequestID>test</RequestID></Response>`, refusal)
			return
		}
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><%sResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">`+
			`<requestId>test</requestId>%s</%[1]sResponse>`, action, answer)
	}))
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

func (e *networkACLEndpoint) answer(action string, form url.Values) (string, string) {
	key := networkACLEntryKey(form.Get("RuleNumber"), form.Get("Egress"))
	switch action {
	case "CreateNetworkAclEntry":
		if _, held := e.entries[key]; held {
			return "", "NetworkAclEntryAlreadyExists"
		}
		number, _ := strconv.Atoi(form.Get("RuleNumber"))
		e.entries[key] = networkACLEntry{ruleNumber: number, egress: form.Get("Egress") == "true", action: form.Get("RuleAction"), cidr: form.Get("CidrBlock")}
		return "<return>true</return>", ""
	case "DeleteNetworkAclEntry":
		if _, held := e.entries[key]; !held {
			return "", "InvalidNetworkAclEntry.NotFound"
		}
		delete(e.entries, key)
		return "<return>true</return>", ""
	case "DescribeNetworkAcls":
		items := ""
		for _, entry := range e.entries {
			items += fmt.Sprintf(`<item><ruleNumber>%d</ruleNumber><protocol>-1</protocol><ruleAction>%s</ruleAction>`+
				`<egress>%t</egress><cidrBlock>%s</cidrBlock></item>`, entry.ruleNumber, entry.action, entry.egress, entry.cidr)
		}
		return `<networkAclSet><item><networkAclId>acl-0a1b</networkAclId><vpcId>vpc-1</vpcId><default>false</default>` +
			`<entrySet>` + items + `</entrySet><associationSet/><tagSet/><ownerId>123456789012</ownerId></item></networkAclSet>`, ""
	}
	return "", "UnauthorizedOperation"
}

// changeInAWS replaces the entry at a rule number and direction outside Terraform, or deletes it when action is empty.
func (e *networkACLEndpoint) changeInAWS(ruleNumber int, egress bool, action string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := networkACLEntryKey(strconv.Itoa(ruleNumber), strconv.FormatBool(egress))
	if action == "" {
		delete(e.entries, key)
		return
	}
	entry := e.entries[key]
	entry.action = action
	e.entries[key] = entry
}

func (e *networkACLEndpoint) held() map[string]networkACLEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	held := map[string]networkACLEntry{}
	for key, entry := range e.entries {
		held[key] = entry
	}
	return held
}

// networkACLModuleConfig writes the aws module's network ACL entry resource as it stands, lifecycle included, with a
// snapshot that blocks 203.0.113.7/32 inbound at rule number 50, or, without the resource, only the provider: the
// harness cannot read a state holding a resource with for_each, so the last step takes the entry out.
func networkACLModuleConfig(t *testing.T, aws *networkACLEndpoint, withEntry bool) func(config.TestStepConfigRequest) string {
	t.Helper()
	module, err := os.ReadFile("../../examples/enforcement-snapshot/modules/aws/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(module), `resource "aws_network_acl_rule" "this" {`)
	length := strings.Index(string(module)[max(start, 0):], "\n}\n")
	if start < 0 || length < 0 {
		t.Fatal(`the aws module declares no resource "aws_network_acl_rule" "this"`)
	}
	resource := string(module)[start : start+length+2]
	if !withEntry {
		resource = ""
	}
	content := fmt.Sprintf(`
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
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
  }
}

locals {
  snap = {
    network_acl_entries = {
      %q = { network_acl_id = "acl-0a1b", egress = false, rule_number = 50, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null }
    }
  }
}

%s
`, aws.url, inboundDenyKey, resource)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.StaticDirectory(dir)
}

// An entry changed or deleted in AWS is put back at the rule number Xshield gave it by the next apply. AWS holds one
// entry per rule number and direction, so the changed entry has to go before the replacement is created.
func TestAccTheAWSModulePutsBackANetworkACLEntryChangedInAWS(t *testing.T) {
	clearXshieldEnv(t)
	aws := newNetworkACLEndpoint(t)
	entry := `aws_network_acl_rule.this["` + inboundDenyKey + `"]`
	denies := []statecheck.StateCheck{holdsTheInboundDeny{aws}}

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, true),
				ConfigStateChecks:        denies,
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { aws.changeInAWS(50, false, "allow") },
				ConfigDirectory:          networkACLModuleConfig(t, aws, true),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(entry, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				ConfigStateChecks: denies,
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { aws.changeInAWS(50, false, "") },
				ConfigDirectory:          networkACLModuleConfig(t, aws, true),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(entry, plancheck.ResourceActionCreate),
				}},
				ConfigStateChecks: denies,
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, false),
			},
		},
	})
}

// holdsTheInboundDeny checks what AWS holds after an apply: the deny of 203.0.113.7/32 inbound at rule number 50 alone.
type holdsTheInboundDeny struct{ aws *networkACLEndpoint }

func (c holdsTheInboundDeny) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	held := c.aws.held()
	if got := held[networkACLEntryKey("50", "false")]; len(held) != 1 || got.action != "deny" || got.cidr != "203.0.113.7/32" {
		resp.Error = fmt.Errorf("AWS holds %+v, want the deny of 203.0.113.7/32 inbound at rule number 50 alone", held)
	}
}
