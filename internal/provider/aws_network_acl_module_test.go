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
	"slices"
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
	writes  []string
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
		e.writes = append(e.writes, "create "+key)
		return "<return>true</return>", ""
	case "DeleteNetworkAclEntry":
		if _, held := e.entries[key]; !held {
			return "", "InvalidNetworkAclEntry.NotFound"
		}
		delete(e.entries, key)
		e.writes = append(e.writes, "delete "+key)
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

// changeInAWS writes an entry at a rule number and direction outside Terraform, in place of any entry there, or deletes
// the entry there when action is empty.
func (e *networkACLEndpoint) changeInAWS(ruleNumber int, egress bool, action, cidr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := networkACLEntryKey(strconv.Itoa(ruleNumber), strconv.FormatBool(egress))
	if action == "" {
		delete(e.entries, key)
		return
	}
	e.entries[key] = networkACLEntry{ruleNumber: ruleNumber, egress: egress, action: action, cidr: cidr}
}

func (e *networkACLEndpoint) writesSoFar() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.writes...)
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

// networkACLModuleConfig writes the aws module's network ACL code as it stands, from its read of the network ACLs to
// the entry resource, lifecycle included, with a snapshot that blocks 203.0.113.7/32 inbound at ruleNumber, or, with
// ruleNumber 0, a snapshot that blocks nothing: the harness cannot read a state holding a resource with for_each, so
// the last step of each test takes the entry out.
func networkACLModuleConfig(t *testing.T, aws *networkACLEndpoint, ruleNumber int) func(config.TestStepConfigRequest) string {
	t.Helper()
	module, err := os.ReadFile("../../examples/enforcement-snapshot/modules/aws/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(module), `data "aws_network_acls" "present" {`)
	resourceStart := strings.Index(string(module), `resource "aws_network_acl_rule" "this" {`)
	length := strings.Index(string(module)[max(resourceStart, 0):], "\n}\n")
	if start < 0 || resourceStart < start || length < 0 {
		t.Fatal(`the aws module declares no data "aws_network_acls" "present" followed by resource "aws_network_acl_rule" "this"`)
	}
	networkACLCode := string(module)[start : resourceStart+length+2]
	entries := ""
	if ruleNumber > 0 {
		entries = fmt.Sprintf(`%q = { network_acl_id = "acl-0a1b", egress = false, rule_number = %d, cidr_ipv4 = "203.0.113.7/32", cidr_ipv6 = null }`, inboundDenyKey, ruleNumber)
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
  account_id = "123456789012"
  region     = "us-east-1"
  snap = {
    network_acl_entries = {
      %s
    }
  }
}

%s
`, aws.url, entries, networkACLCode)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.StaticDirectory(dir)
}

// An entry deleted in AWS is written again at its rule number by the next apply. A move to another rule number
// writes the deny at the new number before it deletes the old one, so the address stays blocked throughout.
func TestAccTheAWSModuleWritesADeletedNetworkACLEntryAgainAndMovesOneCreatingFirst(t *testing.T) {
	clearXshieldEnv(t)
	aws := newNetworkACLEndpoint(t)
	entry := `aws_network_acl_rule.this["` + inboundDenyKey + `"]`

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ConfigStateChecks:        []statecheck.StateCheck{holdsTheInboundDeny{aws, 50}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { aws.changeInAWS(50, false, "", "") },
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(entry, plancheck.ResourceActionCreate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{holdsTheInboundDeny{aws, 50}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 48),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(entry, plancheck.ResourceActionCreateBeforeDestroy),
				}},
				ConfigStateChecks: []statecheck.StateCheck{holdsTheInboundDeny{aws, 48}, wroteLast{aws, []string{"create 48/false", "delete 50/false"}}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 0),
			},
		},
	})
}

// holdsTheInboundDeny checks what AWS holds after an apply: the deny of 203.0.113.7/32 inbound at ruleNumber alone.
type holdsTheInboundDeny struct {
	aws        *networkACLEndpoint
	ruleNumber int
}

func (c holdsTheInboundDeny) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	held := c.aws.held()
	if got := held[networkACLEntryKey(strconv.Itoa(c.ruleNumber), "false")]; len(held) != 1 || got.action != "deny" || got.cidr != "203.0.113.7/32" {
		resp.Error = fmt.Errorf("AWS holds %+v, want the deny of 203.0.113.7/32 inbound at rule number %d alone", held, c.ruleNumber)
	}
}

// wroteLast checks the last writes AWS accepted, in the order it accepted them.
type wroteLast struct {
	aws    *networkACLEndpoint
	writes []string
}

func (c wroteLast) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	writes := c.aws.writesSoFar()
	if len(writes) < len(c.writes) || !slices.Equal(writes[len(writes)-len(c.writes):], c.writes) {
		resp.Error = fmt.Errorf("AWS accepted the writes %v, want them to end with %v", writes, c.writes)
	}
}
