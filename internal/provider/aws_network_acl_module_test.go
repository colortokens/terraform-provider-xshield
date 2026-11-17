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
	"regexp"
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
// number and direction, and refuses to create another there, or one past the rules per network ACL quota when set.
type networkACLEndpoint struct {
	url     string
	mu      sync.Mutex
	entries map[string]networkACLEntry
	writes  []string
	quota   int
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
		inDirection := 0
		for _, entry := range e.entries {
			if strconv.FormatBool(entry.egress) == form.Get("Egress") {
				inDirection++
			}
		}
		if e.quota > 0 && inDirection >= e.quota {
			return "", "NetworkAclEntryLimitExceeded"
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

func (e *networkACLEndpoint) limitRulesPerDirectionTo(quota int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.quota = quota
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
func networkACLModuleConfig(t *testing.T, aws *networkACLEndpoint, ruleNumber int, extra ...string) func(config.TestStepConfigRequest) string {
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

variable "snapshot_version" {
  type    = string
  default = null
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
%s
`, aws.url, entries, networkACLCode, strings.Join(extra, "\n"))
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

// AWS holds one entry per rule number and direction, and Terraform deletes an entry by its number alone. So an
// entry written at Xshield's number outside Terraform, such as an allow of the customer's after Xshield's deny was
// deleted, must stop the plan rather than be taken into state, where a later move or removal would delete it.
func TestAccTheAWSModuleStopsBeforeHoldingAnotherEntryAtItsRuleNumber(t *testing.T) {
	clearXshieldEnv(t)
	aws := newNetworkACLEndpoint(t)

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ConfigStateChecks:        []statecheck.StateCheck{holdsTheInboundDeny{aws, 50}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { aws.changeInAWS(50, false, "allow", "10.0.0.0/8") },
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ExpectError:              regexp.MustCompile(`AWS now holds another entry at rule number 50 inbound`),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					if got := aws.held()[networkACLEntryKey("50", "false")]; got.action != "allow" || got.cidr != "10.0.0.0/8" {
						t.Fatalf("the stopped plan changed the customer's entry at rule number 50: AWS holds %+v", got)
					}
					aws.changeInAWS(50, false, "deny", "203.0.113.7/32")
				},
				ConfigDirectory: networkACLModuleConfig(t, aws, 0),
			},
		},
	})
}

// An apply that stops after AWS creates a moved deny at its new number, and before Terraform records it, leaves the
// old number in state and both in AWS. The retry is refused at the new number, and an import of the entry there does
// nothing, as the address is already in state. The deny at the old number keeps the address blocked, so the entry at
// the new number is deleted by hand, and the next apply moves the deny again.
func TestAccTheAWSModuleMovesADenyAgainAfterAnApplyStoppedPartWay(t *testing.T) {
	clearXshieldEnv(t)
	aws := newNetworkACLEndpoint(t)
	importTheNewNumber := `
import {
  to = aws_network_acl_rule.this["` + inboundDenyKey + `"]
  id = "acl-0a1b:48:-1:false"
}`

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ConfigStateChecks:        []statecheck.StateCheck{holdsTheInboundDeny{aws, 50}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig:                func() { aws.changeInAWS(48, false, "deny", "203.0.113.7/32") },
				ConfigDirectory:          networkACLModuleConfig(t, aws, 48),
				ExpectError:              regexp.MustCompile(`NetworkAclEntryAlreadyExists`),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 48, importTheNewNumber),
				ExpectError:              regexp.MustCompile(`NetworkAclEntryAlreadyExists`),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					if got := aws.held()[networkACLEntryKey("50", "false")]; got.action != "deny" || got.cidr != "203.0.113.7/32" {
						t.Fatalf("the refused retries left the address unblocked: AWS holds %+v at rule number 50", got)
					}
					aws.changeInAWS(48, false, "", "")
				},
				ConfigDirectory: networkACLModuleConfig(t, aws, 48),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(`aws_network_acl_rule.this["`+inboundDenyKey+`"]`, plancheck.ResourceActionCreateBeforeDestroy),
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

// Xshield counts a network ACL's room from the cloud connector's last observation, and the module cannot read entries
// at plan. So an entry of the customer's added since then can leave no room for the deny's new number: AWS refuses
// it, and the deny at its old number stays, with nothing deleted.
func TestAccTheAWSModuleKeepsTheDenyWhenAWSRefusesItsMoveOverTheQuota(t *testing.T) {
	clearXshieldEnv(t)
	aws := newNetworkACLEndpoint(t)

	tfresource.Test(t, tfresource.TestCase{
		Steps: []tfresource.TestStep{
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ConfigDirectory:          networkACLModuleConfig(t, aws, 50),
				ConfigStateChecks:        []statecheck.StateCheck{holdsTheInboundDeny{aws, 50}},
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					aws.limitRulesPerDirectionTo(3)
					aws.changeInAWS(40, false, "allow", "203.0.113.0/24")
					aws.changeInAWS(100, false, "allow", "0.0.0.0/0")
				},
				ConfigDirectory: networkACLModuleConfig(t, aws, 38),
				ExpectError:     regexp.MustCompile(`NetworkAclEntryLimitExceeded`),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				PreConfig: func() {
					held := aws.held()
					if len(held) != 3 || held[networkACLEntryKey("40", "false")].action != "allow" || held[networkACLEntryKey("100", "false")].action != "allow" {
						t.Fatalf("the refused move changed the customer's entries: AWS holds %+v", held)
					}
					if deny := held[networkACLEntryKey("50", "false")]; deny.action != "deny" || deny.cidr != "203.0.113.7/32" {
						t.Fatalf("the refused move unblocked the address: AWS holds %+v at rule number 50", deny)
					}
					if writes := aws.writesSoFar(); slices.Contains(writes, "delete 50/false") {
						t.Fatalf("the refused move deleted the deny: writes %v", writes)
					}
				},
				ConfigDirectory: networkACLModuleConfig(t, aws, 0),
			},
		},
	})
}
