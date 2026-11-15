package provider

import (
	"maps"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const twoChangeSets = `{"cloudAccountId":"123456789012","region":"us-east-1","version":"v-9","customerGroupChanges":{` +
	`"vpc-1/web":{"groupId":"sg-0web","revoke":[],"changeSets":[` +
	`{"id":"cs-2","state":"restoring","moves":[]},{"id":"cs-1","state":"narrowing","moves":[` +
	`{"direction":"ingress","ipProtocol":"tcp","fromPort":443,"toPort":443,"cidrIpv4":"0.0.0.0/0"}]}]}}}`

func readGroupRules(t *testing.T, answer cannedResponse, group string) awsSecurityGroupRulesDataSourceModel {
	t.Helper()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": answer})
	args := pointArgs()
	args["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
	args["group_name"] = tftypes.NewValue(tftypes.String, group)
	ruleType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"ip_protocol": tftypes.String, "from_port": tftypes.Number, "to_port": tftypes.Number,
		"cidr_ipv4": tftypes.String, "cidr_ipv6": tftypes.String, "prefix_list_id": tftypes.String,
		"referenced_security_group_id": tftypes.String, "description": tftypes.String, "tags": tftypes.Map{ElementType: tftypes.String},
	}}
	httpsAll := tftypes.NewValue(ruleType, map[string]tftypes.Value{
		"ip_protocol": tftypes.NewValue(tftypes.String, "tcp"), "from_port": tftypes.NewValue(tftypes.Number, 443),
		"to_port": tftypes.NewValue(tftypes.Number, 443), "cidr_ipv4": tftypes.NewValue(tftypes.String, "0.0.0.0/0"),
		"cidr_ipv6": tftypes.NewValue(tftypes.String, nil), "prefix_list_id": tftypes.NewValue(tftypes.String, nil),
		"referenced_security_group_id": tftypes.NewValue(tftypes.String, nil), "description": tftypes.NewValue(tftypes.String, nil),
		"tags": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
	})
	args["declared_ingress_rules"] = tftypes.NewValue(tftypes.Map{ElementType: ruleType}, map[string]tftypes.Value{"https_all": httpsAll})
	var out awsSecurityGroupRulesDataSourceModel
	if ok, errs := readDataSource(t, &awsSecurityGroupRulesDataSource{api: api}, args, &out); !ok {
		t.Fatalf("read failed: %s", errs)
	}
	return out
}

// The owner module reports what it applied from the same read its rules came from, so the data source gives each
// change set of the group by its ID with its state as Xshield served it, here for a group declaring the rule cs-1 moves.
func TestTheRulesOfAGroupNameItsChangeSetsAsServed(t *testing.T) {
	t.Parallel()

	t.Run("a changed group", func(t *testing.T) {
		t.Parallel()
		got := readGroupRules(t, cannedResponse{http.StatusOK, twoChangeSets}, "web")
		if want := map[string]string{"cs-1": "narrowing", "cs-2": "restoring"}; !maps.Equal(got.ChangeSets, want) {
			t.Errorf("change_sets %v, want %v", got.ChangeSets, want)
		}
		if got.SecurityGroupID.ValueString() != "sg-0web" || got.Version.ValueString() != "v-9" {
			t.Errorf("security_group_id %s and version %s, want sg-0web and v-9", got.SecurityGroupID, got.Version)
		}
	})

	for name, read := range map[string]struct {
		answer cannedResponse
		group  string
	}{
		"a group no change applies to": {cannedResponse{http.StatusOK, twoChangeSets}, "db"},
		"nothing published":            {cannedResponse{http.StatusNotFound, xshieldNotPublished}, "web"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := readGroupRules(t, read.answer, read.group)
			if got.ChangeSets == nil || len(got.ChangeSets) != 0 {
				t.Errorf("change_sets %v, want an empty map, so the group plans cleanly", got.ChangeSets)
			}
		})
	}
}

// Two workspaces can each declare some of one group's rules. A change set narrowing the group takes out only rules it
// moves, so a workspace declaring none of them takes nothing out: it reads the set as attaching, its receipts never list
// it narrowing, and a revert does not wait for it.
func TestAChangeSetNarrowsTheGroupForAWorkspaceOnlyWhenItDeclaresAMovedRule(t *testing.T) {
	t.Parallel()
	moved := func(direction, cidr string, port int64) wireMovedRule {
		return wireMovedRule{wireRuleMatch: wireRuleMatch{Direction: direction, IPProtocol: "tcp", FromPort: &port, ToPort: &port, CIDRIPv4: &cidr}}
	}
	change := &wireCustomerGroupChange{GroupID: "sg-0web", ChangeSets: []wireGroupChangeSet{
		{ID: "cs-https", State: changeSetNarrowing, Moves: []wireMovedRule{moved("ingress", "0.0.0.0/0", 443)}},
		{ID: "cs-https-out", State: changeSetNarrowing, Moves: []wireMovedRule{moved("ingress", "0.0.0.0/0", 3389), moved("egress", "0.0.0.0/0", 443)}},
		{ID: "cs-rdp", State: changeSetNarrowing, Moves: []wireMovedRule{moved("ingress", "0.0.0.0/0", 3389)}},
		{ID: "cs-egress-named-in", State: changeSetNarrowing, Moves: []wireMovedRule{moved("egress", "10.0.0.0/8", 22)}},
		{ID: "cs-attaching", State: changeSetAttaching, Moves: []wireMovedRule{moved("ingress", "0.0.0.0/0", 3389)}},
		{ID: "cs-restoring", State: changeSetRestoring, Moves: []wireMovedRule{moved("ingress", "0.0.0.0/0", 3389)}},
	}}
	data := webRules()
	filterDeclaredRules(data, change)
	want := map[string]string{
		"cs-https": "narrowing", "cs-https-out": "narrowing", "cs-rdp": "attaching", "cs-egress-named-in": "attaching",
		"cs-attaching": "attaching", "cs-restoring": "restoring",
	}
	if !maps.Equal(data.ChangeSets, want) {
		t.Errorf("change_sets %v, want %v", data.ChangeSets, want)
	}
}
