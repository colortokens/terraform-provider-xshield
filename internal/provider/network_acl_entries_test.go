package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const (
	inboundDenyKey  = "acl-0a1b/in/203.0.113.7/32"
	outboundDenyKey = "acl-0a1b/out/2001:db8::7/128"
)

func networkACLSnapshot(t *testing.T) wireSnapshot {
	t.Helper()
	return loadJSON[wireSnapshot](t, "snapshot_network_acl.json")
}

func TestASnapshotThatBlocksAddressesOnANetworkACLIsApplied(t *testing.T) {
	t.Parallel()
	if err := renderable(cloudAWS, networkACLSnapshot(t)); err != nil {
		t.Fatalf("a snapshot with network ACL entries was refused, so its pipeline stops: %v", err)
	}
	if err := renderable(cloudAWS, loadJSON[wireSnapshot](t, "snapshot.json")); err != nil {
		t.Fatalf("a snapshot with no network ACL entry, which Xshield still serves as schema 3, was refused: %v", err)
	}
}

func TestSnapshotMapsEachNetworkACLEntryForAnAWSNetworkACLRule(t *testing.T) {
	t.Parallel()
	snap := networkACLSnapshot(t)
	m := snapshotModel(types.StringValue("123456789012"), types.StringValue("us-east-1"), &snap)

	if got := sortedKeys(m.NetworkACLEntries); len(got) != 2 || got[0] != inboundDenyKey || got[1] != outboundDenyKey {
		t.Fatalf("network ACL entry keys %v, want the inbound and outbound deny", got)
	}
	for key, want := range snap.AWS.NetworkACLEntries {
		got := m.NetworkACLEntries[key]
		if got.NetworkACLID.ValueString() != want.NetworkACLID || got.Egress.ValueBool() != want.Egress || got.RuleNumber.ValueInt64() != want.RuleNumber {
			t.Errorf("%s: %+v, want the ACL, direction and rule number Xshield gave it: %+v", key, got, want)
		}
	}
	in, out := m.NetworkACLEntries[inboundDenyKey], m.NetworkACLEntries[outboundDenyKey]
	if in.CIDRIPv4.ValueString() != "203.0.113.7/32" || !in.CIDRIPv6.IsNull() || in.Egress.ValueBool() {
		t.Errorf("inbound IPv4 deny %+v, want its address as cidr_ipv4 and a null cidr_ipv6, as aws_network_acl_rule takes one of them", in)
	}
	if out.CIDRIPv6.ValueString() != "2001:db8::7/128" || !out.CIDRIPv4.IsNull() || !out.Egress.ValueBool() {
		t.Errorf("outbound IPv6 deny %+v, want its address as cidr_ipv6 and a null cidr_ipv4", out)
	}
}

// A configuration with for_each over the map plans the same whether Xshield sends no entry or an empty map.
func TestASnapshotWithNoNetworkACLEntryHasAnEmptyMap(t *testing.T) {
	t.Parallel()
	for name, m := range map[string]awsEnforcementSnapshotDataSourceModel{
		"schema 3":    sampleSnapshotModel(t),
		"unpublished": snapshotModel(types.StringValue("1"), types.StringValue("r"), nil),
	} {
		if m.NetworkACLEntries == nil || len(m.NetworkACLEntries) != 0 {
			t.Errorf("%s: network ACL entries %v, want an empty map", name, m.NetworkACLEntries)
		}
	}
}

func receiptWithNetworkACLEntries(entries map[string]string) awsEnforcementReceiptResourceModel {
	ctx := context.Background()
	mapOf := func(m map[string]string) types.Map {
		if m == nil {
			return types.MapNull(types.StringType)
		}
		v, _ := types.MapValueFrom(ctx, types.StringType, m)
		return v
	}
	return awsEnforcementReceiptResourceModel{
		CloudAccountID:    types.StringValue("123456789012"),
		Region:            types.StringValue("us-east-1"),
		Workspace:         types.StringValue("ws"),
		SnapshotVersion:   types.StringValue(testVersion),
		SecurityGroups:    mapOf(map[string]string{"i-db-1": "sg-0web"}),
		Rules:             mapOf(map[string]string{}),
		Attachments:       types.MapNull(types.StringType),
		NetworkACLEntries: mapOf(entries),
	}
}

// Xshield accepts a receipt only when it names every network ACL entry of the snapshot by the import ID the snapshot gives it.
// A receipt with none leaves the field out, so a server that predates network ACL entries takes it as before.
func TestReceiptNamesEachNetworkACLEntryByItsImportIDAndLeavesThemOutWhenThereAreNone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	with := receiptWithNetworkACLEntries(map[string]string{inboundDenyKey: "acl-0a1b:50:-1:false"})
	req, diags := receiptRequest(ctx, &with, "")
	if diags.HasError() {
		t.Fatal(diags)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"networkAclEntries":{"acl-0a1b/in/203.0.113.7/32":"acl-0a1b:50:-1:false"}`) {
		t.Errorf("receipt body %s does not name the entry by its import ID", body)
	}

	for name, entries := range map[string]map[string]string{"null": nil, "empty": {}} {
		without := receiptWithNetworkACLEntries(entries)
		req, diags := receiptRequest(ctx, &without, "")
		if diags.HasError() {
			t.Fatal(diags)
		}
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "networkAclEntries") {
			t.Errorf("%s: receipt body %s names network ACL entries, which a server that predates them may refuse", name, body)
		}
	}
}

// A held receipt is the one this plan sends only when it names the same network ACL entries too.
func TestAHeldReceiptIsThePlannedOneOnlyWithTheSameNetworkACLEntries(t *testing.T) {
	held := cannedResponse{http.StatusOK, `{"state":"converged","applied":{"receiptId":"receipt-1","version":"version-1",` +
		`"workspace":"enforcement","appliedAt":"2026-01-01T00:00:00Z","resources":{"securityGroups":{"web":"sg-0web"},"rules":{},` +
		`"networkAclEntries":{"` + inboundDenyKey + `":"acl-0a1b:50:-1:false"}},"exclusiveRules":false}}`}
	ids := tftypes.Map{ElementType: tftypes.String}
	entries := func(importID string) map[string]tftypes.Value {
		return map[string]tftypes.Value{"network_acl_entries": tftypes.NewValue(ids, map[string]tftypes.Value{inboundDenyKey: tftypes.NewValue(tftypes.String, importID)})}
	}

	warnings, errors := planReceipt(t, receiptPlan{held: held, planned: entries("acl-0a1b:50:-1:false"), wantRead: true})
	if errors != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "exactly what this plan sends") {
		t.Fatalf("want the resent-receipt warning, got %d error(s) and %q", errors, warnings)
	}
	for name, planned := range map[string]map[string]tftypes.Value{"another rule number": entries("acl-0a1b:52:-1:false"), "no entry": nil} {
		t.Run(name, func(t *testing.T) {
			warnings, _ := planReceipt(t, receiptPlan{held: held, planned: planned, wantRead: true})
			if len(warnings) != 1 || strings.Contains(warnings[0], "exactly what this plan sends") || !strings.Contains(warnings[0], "enforcement-snapshot/recovery") {
				t.Fatalf("want the lost-state warning, got %q", warnings)
			}
		})
	}
}

// An imported receipt names the network ACL entries Xshield holds for it, and none as null, as the aws module sends none.
func TestAnImportedReceiptTakesTheNetworkACLEntriesXshieldHolds(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		held map[string]string
		want map[string]string
	}{
		"with entries": {held: map[string]string{inboundDenyKey: "acl-0a1b:50:-1:false"}, want: map[string]string{inboundDenyKey: "acl-0a1b:50:-1:false"}},
		"without":      {},
	} {
		status := wireConvergence{Applied: &wireReceipt{ReceiptID: "receipt-1", Version: "version-1", Workspace: "enforcement",
			Resources: wireRenderedResources{SecurityGroups: map[string]string{"web": "sg-0web"}, NetworkACLEntries: c.held}}}
		var imported awsEnforcementReceiptResourceModel
		var diags diag.Diagnostics
		(&awsEnforcementReceiptResource{}).adopt(context.Background(), &imported, status, &diags)
		if diags.HasError() {
			t.Fatal(diags)
		}
		if c.want == nil {
			if !imported.NetworkACLEntries.IsNull() {
				t.Errorf("%s: network ACL entries %v, want null so the recovered state plans no change", name, imported.NetworkACLEntries)
			}
			continue
		}
		got := map[string]string{}
		imported.NetworkACLEntries.ElementsAs(context.Background(), &got, false)
		if len(got) != 1 || got[inboundDenyKey] != c.want[inboundDenyKey] {
			t.Errorf("%s: network ACL entries %v, want %v", name, got, c.want)
		}
	}
}

// Rebuilding a lost state imports each network ACL entry by the import ID the last receipt holds.
func TestStatusNamesTheNetworkACLEntriesTheLastReceiptHolds(t *testing.T) {
	t.Parallel()
	st := loadJSON[wireStatus](t, "status.json")
	st.Applied.Resources.NetworkACLEntries = map[string]string{inboundDenyKey: "acl-0a1b:50:-1:false"}
	data := awsEnforcementStatusDataSourceModel{CloudAccountID: types.StringValue("123456789012"), Region: types.StringValue("us-east-1")}
	setStatus(&data, st)
	got := map[string]string{}
	data.AppliedNetworkACLEntries.ElementsAs(context.Background(), &got, false)
	if len(got) != 1 || got[inboundDenyKey] != "acl-0a1b:50:-1:false" {
		t.Errorf("applied network ACL entries %v, want the receipt's", got)
	}

	setUnpublished(&data)
	if data.AppliedNetworkACLEntries.IsNull() || len(data.AppliedNetworkACLEntries.Elements()) != 0 {
		t.Errorf("applied network ACL entries before any receipt %v, want an empty map an import's for_each can take", data.AppliedNetworkACLEntries)
	}
}
