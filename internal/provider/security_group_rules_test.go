package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The Full control fixture is the server's fullcontrol scenario: the customer group web in
// vpc-1 gives up 0.0.0.0/0:443 while a-legacy and a-reports keep it in a cohort.
const sampleCohortKey = "ct-cohort-0123456789abcdef"

func declaredRule(protocol string, port int64, cidr string) sgrRuleModel {
	return sgrRuleModel{IPProtocol: types.StringValue(protocol), FromPort: types.Int64Value(port), ToPort: types.Int64Value(port),
		CIDRIPv4: types.StringValue(cidr), CIDRIPv6: types.StringNull(), PrefixListID: types.StringNull(),
		ReferencedSecurityGroupID: types.StringNull(), Description: types.StringNull(), Tags: types.MapNull(types.StringType)}
}

func webRules() *securityGroupRulesDataSourceModel {
	return &securityGroupRulesDataSourceModel{
		CloudAccountID: types.StringValue("123456789012"), Region: types.StringValue("us-east-1"),
		VPCID: types.StringValue("vpc-1"), GroupName: types.StringValue("web"), Version: types.StringValue(testVersion),
		Ingress: map[string]sgrRuleModel{"https_all": declaredRule("6", 443, "0.0.0.0/0"), "ssh_office": declaredRule("tcp", 22, "10.0.0.0/8")},
		Egress:  map[string]sgrRuleModel{"https_out": declaredRule("tcp", 443, "0.0.0.0/0")},
	}
}

func keysOf(values []types.String) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.ValueString())
	}
	return out
}

// narrowed is the fixture after every member was shown to carry its cohort.
func narrowed(snap wireSnapshot) wireSnapshot {
	change := snap.AWS.CustomerGroupChanges["vpc-1/web"]
	change.ChangeSets[0].State = "narrowing"
	change.Revoke = change.ChangeSets[0].Moves
	snap.AWS.CustomerGroupChanges["vpc-1/web"] = change
	return snap
}

func TestFullControlSnapshotCarriesTheCohortLikeAnyGroup(t *testing.T) {
	t.Parallel()
	m := snapshotModel(types.StringValue("123456789012"), types.StringValue("us-east-1"), ptr(loadJSON[wireSnapshot](t, "snapshot.json")))
	if g, ok := m.SecurityGroups[sampleCohortKey]; !ok || g.Name.ValueString() != sampleCohortKey || g.Tags["ct:kind"] != "cohort" {
		t.Fatalf("cohort group %+v, want it named and tagged as the connector names its cohorts", g)
	}
	if r, ok := m.IngressRules[sampleCohortKey+"/in/tcp/443/0.0.0.0/0"]; !ok || r.CIDRIPv4.ValueString() != "0.0.0.0/0" || !r.ReferencedSecurityGroupID.IsNull() {
		t.Errorf("cohort rule %+v, want the moved rule copied", r)
	} else if !r.Description.IsNull() || r.Tags["ct:change-set"] != "cs-1" {
		t.Errorf("cohort rule %+v, want no description and the change set's tag, as the connector copies it", r)
	}
	if a := m.InterfaceAttachments[sampleCohortKey+"/eni-legacy"]; a.SecurityGroup.ValueString() != sampleCohortKey {
		t.Errorf("attachment %+v, want the cohort on the instance's interface", a)
	}
	if e := m.Directory["lambda/reports"]; !slices.ContainsFunc(e.SecurityGroups, func(s types.String) bool { return s.ValueString() == sampleCohortKey }) {
		t.Errorf("directory entry %+v, want the cohort for the function's workspace to attach", e)
	}
	group := ruleModel(wireRule{SecurityGroup: sampleCohortKey, IPProtocol: "-1", ReferencedSecurityGroupID: ptr("111122223333/sg-lb")})
	if group.ReferencedSecurityGroupID.ValueString() != "111122223333/sg-lb" || !group.CIDRIPv4.IsNull() {
		t.Errorf("group-referenced rule %+v", group)
	}
}

func TestRulesFilterKeepsARuleUntilEveryMemberCarriesItsCohort(t *testing.T) {
	t.Parallel()
	data := webRules()
	filterDeclaredRules(data, groupChangeOf(loadJSON[wireSnapshot](t, "snapshot.json"), "vpc-1", "web"))

	if got := sortedKeys(data.IngressRules); !slices.Equal(got, []string{"https_all", "ssh_office"}) {
		t.Errorf("kept %v, want every declared rule while the cohort is attaching", got)
	}
	if got := keysOf(data.Pending); !slices.Equal(got, []string{"ingress/https_all"}) {
		t.Errorf("pending %v, want the broad rule named", got)
	}
	if len(data.Revoked) != 0 {
		t.Errorf("revoked %v, want none yet", keysOf(data.Revoked))
	}
}

func TestRulesFilterLeavesOutTheMovedRuleByItsContent(t *testing.T) {
	t.Parallel()
	data := webRules()
	filterDeclaredRules(data, groupChangeOf(narrowed(loadJSON[wireSnapshot](t, "snapshot.json")), "vpc-1", "web"))

	if got := sortedKeys(data.IngressRules); !slices.Equal(got, []string{"ssh_office"}) {
		t.Errorf("kept %v, want the broad 443 rule left out though it was declared with protocol 6", got)
	}
	if got := keysOf(data.Revoked); !slices.Equal(got, []string{"ingress/https_all"}) {
		t.Errorf("revoked %v", got)
	}
	if got := sortedKeys(data.EgressRules); !slices.Equal(got, []string{"https_out"}) {
		t.Errorf("egress kept %v, want the same rule outbound kept: only the ingress rule moved", got)
	}
}

func TestRulesFilterReturnsAnotherGroupUnchanged(t *testing.T) {
	t.Parallel()
	data := webRules()
	data.GroupName = types.StringValue("db")
	filterDeclaredRules(data, groupChangeOf(narrowed(loadJSON[wireSnapshot](t, "snapshot.json")), "vpc-1", "db"))

	if len(data.IngressRules) != 2 || len(data.EgressRules) != 1 || len(data.Revoked) != 0 || len(data.Pending) != 0 {
		t.Errorf("kept %v and %v, revoked %v, want everything kept", sortedKeys(data.IngressRules), sortedKeys(data.EgressRules), keysOf(data.Revoked))
	}
}

func TestRuleMatchingComparesWhatAWSCompares(t *testing.T) {
	t.Parallel()
	v6 := ptr("2001:db8::/32")
	for name, tc := range map[string]struct {
		rule sgrRuleModel
		want wireRuleMatch
		same bool
	}{
		"protocol number":           {declaredRule("6", 443, "0.0.0.0/0"), wireRuleMatch{IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443), CIDRIPv4: ptr("0.0.0.0/0")}, true},
		"other port":                {declaredRule("tcp", 8443, "0.0.0.0/0"), wireRuleMatch{IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443), CIDRIPv4: ptr("0.0.0.0/0")}, false},
		"other peer":                {declaredRule("tcp", 443, "10.0.0.0/8"), wireRuleMatch{IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443), CIDRIPv4: ptr("0.0.0.0/0")}, false},
		"all traffic ignores ports": {declaredRule("-1", 0, "0.0.0.0/0"), wireRuleMatch{IPProtocol: "-1", CIDRIPv4: ptr("0.0.0.0/0")}, true},
		"ipv6 written long": {func() sgrRuleModel {
			r := declaredRule("tcp", 443, "")
			r.CIDRIPv4, r.CIDRIPv6 = types.StringNull(), types.StringValue("2001:0db8:0000::/32")
			return r
		}(), wireRuleMatch{IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443), CIDRIPv6: v6}, true},
		"another accounts group": {func() sgrRuleModel {
			r := declaredRule("tcp", 443, "")
			r.CIDRIPv4, r.ReferencedSecurityGroupID = types.StringNull(), types.StringValue("sg-lb")
			return r
		}(), wireRuleMatch{IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443), ReferencedSecurityGroupID: ptr("111122223333/sg-lb")}, true},
	} {
		if got := ruleMatches(tc.rule, tc.want); got != tc.same {
			t.Errorf("%s: matched %v, want %v", name, got, tc.same)
		}
	}
}

func TestRuleMatchingWithoutAToPort(t *testing.T) {
	t.Parallel()
	echoRequest := declaredRule("icmp", 8, "0.0.0.0/0")
	echoRequest.ToPort = types.Int64Null()
	for name, tc := range map[string]struct {
		rule sgrRuleModel
		same bool
	}{
		"declared rule sets a to_port": {declaredRule("icmp", 8, "0.0.0.0/0"), false},
		"neither sets a to_port":       {echoRequest, true},
	} {
		if got := ruleMatches(tc.rule, wireRuleMatch{IPProtocol: "icmp", FromPort: i64(8), CIDRIPv4: ptr("0.0.0.0/0")}); got != tc.same {
			t.Errorf("%s: matched %v, want %v", name, got, tc.same)
		}
	}
}

func TestRulesFilterModelFitsTheDataSourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var resp datasource.SchemaResponse
	(&securityGroupRulesDataSource{}).Schema(ctx, datasource.SchemaRequest{}, &resp)
	data := webRules()
	filterDeclaredRules(data, groupChangeOf(narrowed(loadJSON[wireSnapshot](t, "snapshot.json")), "vpc-1", "web"))
	state := tfsdk.State{Schema: resp.Schema}
	if diags := state.Set(ctx, data); diags.HasError() {
		t.Errorf("the model does not fit the schema, so every plan would fail: %v", diags)
	}
}

func i64(v int64) *int64 { return &v }
