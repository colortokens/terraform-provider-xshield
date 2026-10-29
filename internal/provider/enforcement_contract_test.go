package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// snapshot.json and snapshot_fullcontrol.json are copies of the Xshield server's
// golden snapshot output, so these tests read what the server serves.

func loadJSON[T any](t *testing.T, name string) T {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sampleSnapshotModel(t *testing.T) enforcementSnapshotDataSourceModel {
	t.Helper()
	snap := loadJSON[wireSnapshot](t, "snapshot.json")
	if err := renderable(snap); err != nil {
		t.Fatal(err)
	}
	return snapshotModel(types.StringValue("123456789012"), types.StringValue("us-east-1"), &snap)
}

func TestSnapshotKeysNameTheWorkloadEachChangeIsFor(t *testing.T) {
	t.Parallel()
	m := sampleSnapshotModel(t)
	if got := sortedKeys(m.SecurityGroups); !slices.Equal(got, []string{"i-app-1", "i-app-2", "i-db-1", "i-db-2", "rds-cluster/orders-cluster", "rds/orders-db"}) {
		t.Errorf("security group keys %v, want instance IDs and handles", got)
	}
	for key := range m.IngressRules {
		if !strings.HasPrefix(key, m.IngressRules[key].SecurityGroup.ValueString()+"/in/") {
			t.Errorf("ingress key %s does not start with its group's key", key)
		}
	}
}

func TestSnapshotMapsEveryRuleAttributeAndKeepsNullsNull(t *testing.T) {
	t.Parallel()
	m := sampleSnapshotModel(t)
	v4, ok := m.IngressRules["i-app-1/in/tcp/443/0.0.0.0/0"]
	if !ok {
		t.Fatalf("missing the allow-any rule; have %v", sortedKeys(m.IngressRules))
	}
	if v4.SecurityGroup.ValueString() != "i-app-1" || v4.IPProtocol.ValueString() != "tcp" || v4.FromPort.ValueInt64() != 443 || v4.ToPort.ValueInt64() != 443 ||
		v4.CIDRIPv4.ValueString() != "0.0.0.0/0" || !v4.CIDRIPv6.IsNull() || !v4.PrefixListID.IsNull() {
		t.Errorf("IPv4 rule %+v", v4)
	}
	if !strings.HasPrefix(v4.Description.ValueString(), "ColorTokens authored enforce t=tmpl-web r=") || v4.Tags["ct:mode"] != "enforce" {
		t.Errorf("rule description %q tags %v, want the connector's", v4.Description.ValueString(), v4.Tags)
	}
	if v6 := m.IngressRules["i-app-1/in/tcp/443/::/0"]; v6.CIDRIPv6.ValueString() != "::/0" || !v6.CIDRIPv4.IsNull() {
		t.Errorf("IPv6 rule %+v", v6)
	}
	all := ruleModel(wireRule{SecurityGroup: "i-1", IPProtocol: "-1", CIDRIPv4: ptr("10.0.0.0/8")})
	if !all.FromPort.IsNull() || !all.ToPort.IsNull() {
		t.Errorf("an all-traffic rule's ports %v-%v, want null so aws_vpc_security_group_ingress_rule omits them", all.FromPort, all.ToPort)
	}
}

func TestSnapshotMapsAttachmentsDirectoryAndAssets(t *testing.T) {
	t.Parallel()
	m := sampleSnapshotModel(t)
	if a := m.InterfaceAttachments["i-app-1/eni-app-1-data"]; a.SecurityGroup.ValueString() != "i-app-1" || a.NetworkInterfaceID.ValueString() != "eni-app-1-data" {
		t.Errorf("attachment %+v", a)
	}
	db := m.Directory["rds/orders-db"]
	if db.ParameterName.ValueString() != "/colortokens/v1/rds/orders-db/security-groups" || db.Handle.ValueString() != "rds/orders-db" || len(db.SecurityGroups) != 1 || db.SecurityGroups[0].ValueString() != "rds/orders-db" {
		t.Errorf("directory entry %+v", db)
	}
	if a := m.Assets["a-orders-db"]; a.AttachedBy.ValueString() != "owner" || a.SecurityGroup.ValueString() != "rds/orders-db" {
		t.Errorf("owner-attached asset %+v", a)
	}
	if a := m.Assets["a-db-1"]; a.AttachedBy.ValueString() != "pipeline" {
		t.Errorf("interface-attached asset %+v", a)
	}
}

func TestEverySnapshotModelFitsTheDataSourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var resp datasource.SchemaResponse
	(&enforcementSnapshotDataSource{}).Schema(ctx, datasource.SchemaRequest{}, &resp)
	for name, m := range map[string]enforcementSnapshotDataSourceModel{
		"sample":       sampleSnapshotModel(t),
		"empty":        snapshotModel(types.StringValue("1"), types.StringValue("r"), ptr(loadJSON[wireSnapshot](t, "snapshot.json").emptied())),
		"pinned":       withVersion(sampleSnapshotModel(t), 7),
		"nothing":      snapshotModel(types.StringValue("1"), types.StringValue("r"), &wireSnapshot{SchemaVersion: supportedSnapshotSchema, AWS: loadJSON[wireSnapshot](t, "snapshot.json").emptied().AWS}),
		"full control": snapshotModel(types.StringValue("123456789012"), types.StringValue("us-east-1"), ptr(loadJSON[wireSnapshot](t, "snapshot_fullcontrol.json"))),
		"unpublished":  snapshotModel(types.StringValue("1"), types.StringValue("r"), nil),
	} {
		state := tfsdk.State{Schema: resp.Schema}
		if diags := state.Set(ctx, m); diags.HasError() {
			t.Errorf("%s: the model does not fit the schema, so every plan would fail: %v", name, diags)
		}
	}
}

func (s wireSnapshot) emptied() wireSnapshot {
	empty := s
	plan := *s.AWS
	plan.SecurityGroups, plan.IngressRules, plan.EgressRules = nil, nil, nil
	plan.InterfaceAttachments, plan.Directory, plan.Assets, plan.Withdrawing = nil, nil, nil, nil
	empty.AWS = &plan
	return empty
}

func withVersion(m enforcementSnapshotDataSourceModel, v int64) enforcementSnapshotDataSourceModel {
	m.Version = types.Int64Value(v)
	return m
}

func TestSnapshotOfAnotherFormatIsRefusedRatherThanAppliedInPart(t *testing.T) {
	t.Parallel()
	snap := loadJSON[wireSnapshot](t, "snapshot.json")
	snap.SchemaVersion = "3"
	if err := renderable(snap); err == nil || !strings.Contains(err.Error(), "Upgrade the xshield provider") {
		t.Errorf("a newer snapshot schema was accepted: %v", err)
	}
	snap = loadJSON[wireSnapshot](t, "snapshot.json")
	snap.AWS = nil
	if err := renderable(snap); err == nil {
		t.Error("a snapshot without an AWS plan was accepted")
	}
}

func TestStatusMapsPendingWorkNoticesAndDrift(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := loadJSON[wireStatus](t, "status.json")
	st.Notices = append(st.Notices, struct {
		Code    string `json:"code"`
		Reason  string `json:"reason"`
		AssetID string `json:"assetId"`
		Group   string `json:"group"`
		Message string `json:"message"`
	}{Code: "assetRefused", Reason: "NO_FREE_SLOT", AssetID: "a-db-1", Message: "the connector would refuse this workload's policy"})

	data := enforcementStatusDataSourceModel{CloudAccountID: types.StringValue("123456789012"), Region: types.StringValue("us-east-1"), DriftFindings: []driftFindingModel{}}
	setStatus(&data, st)
	setDrift(&data, loadJSON[wireDrift](t, "drift.json"))

	if data.State.ValueString() != "pending" || data.AppliedVersion.ValueInt64() != 42 || data.ExpectedVersion.ValueInt64() != 43 {
		t.Errorf("state %s applied %v expected %v, want pending 42 -> 43", data.State, data.AppliedVersion, data.ExpectedVersion)
	}
	if len(data.PendingRulesAdded) != 4 || !strings.HasPrefix(data.PendingRulesAdded[0].ValueString(), "i-db-1/in/tcp/6432/") {
		t.Errorf("pending rules %v, want the four pgbouncer rules", data.PendingRulesAdded)
	}
	if len(data.Notices) != 1 || data.Notices[0].Reason.ValueString() != "NO_FREE_SLOT" || !data.Notices[0].Group.IsNull() {
		t.Errorf("notices %+v", data.Notices)
	}
	kinds := []string{}
	for _, f := range data.DriftFindings {
		kinds = append(kinds, f.Kind.ValueString()+"/"+f.Restoration.ValueString())
	}
	if !slices.Equal(kinds, []string{"memberUnattached/workload", "ruleMissing/pipeline"}) || !data.DriftEvaluated.ValueBool() {
		t.Errorf("drift %v evaluated %v", kinds, data.DriftEvaluated)
	}

	var resp datasource.SchemaResponse
	(&enforcementStatusDataSource{}).Schema(ctx, datasource.SchemaRequest{}, &resp)
	state := tfsdk.State{Schema: resp.Schema}
	if diags := state.Set(ctx, data); diags.HasError() {
		t.Errorf("the status model does not fit its schema: %v", diags)
	}
}

func TestReceiptModelFitsTheResourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var resp resource.SchemaResponse
	(&enforcementReceiptResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	mapOf := func(m map[string]string) types.Map {
		v, _ := types.MapValueFrom(ctx, types.StringType, m)
		return v
	}
	data := enforcementReceiptResourceModel{
		ID: types.StringValue("rcpt-1"), CloudAccountID: types.StringValue("123456789012"), Region: types.StringValue("us-east-1"),
		Workspace: types.StringValue("ws"), SnapshotVersion: types.Int64Value(42), ContentHash: types.StringValue("sha256:abc"),
		SecurityGroups: mapOf(map[string]string{"i-db-1": "sg-1"}), Rules: mapOf(map[string]string{"k": "sgr-1"}),
		Attachments: mapOf(map[string]string{"i-db-1/eni-1": "sg-1_eni-1"}), RunID: types.StringValue(""), AppliedAt: types.StringValue("2026-01-01T00:00:00Z"),
	}
	state := tfsdk.State{Schema: resp.Schema}
	if diags := state.Set(ctx, data); diags.HasError() {
		t.Errorf("the receipt model does not fit its schema: %v", diags)
	}
}

func TestRefusedReceiptSaysWhatToChange(t *testing.T) {
	t.Parallel()
	for status, phrase := range map[int]string{
		http.StatusConflict:            "content_hash",
		http.StatusUnprocessableEntity: "missing or unknown",
		http.StatusNotFound:            "remove the pin",
	} {
		if got := receiptAdvice(&snapshotAPIError{Status: status}); !strings.Contains(got, phrase) {
			t.Errorf("advice for %d is %q, want it to mention %q", status, got, phrase)
		}
	}
}

func ptr[T any](v T) *T { return &v }
