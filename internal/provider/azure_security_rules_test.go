package provider

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// azure_snapshot_customer_group.json is the Xshield server's Azure renderer output for web, whose network interface and
// subnet both carry groups of the customer's, so its rules go into the subnet's group nsg-snet-owner.
const (
	azureTestCustomerGroupKey = "customer-nsg-5b8ff476f40c"
	azureTestCustomerGroupID  = "/subscriptions/" + azureTestSubscription + "/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-owner"
)

func yourAllowRule(name string, priority int64) azInlineSecurityRuleModel {
	return azInlineSecurityRuleModel{Name: types.StringValue(name), Description: types.StringNull(), Priority: types.Int64Value(priority),
		Direction: types.StringValue("Inbound"), Access: types.StringValue("Allow"), Protocol: types.StringValue("Tcp"),
		SourceAddressPrefix: types.StringValue("VirtualNetwork"), DestinationAddressPrefix: types.StringValue("*"),
		SourcePortRange: types.StringValue("*"), DestinationPortRange: types.StringValue("22")}
}

func readAzureSecurityRules(t *testing.T, routes map[string]cannedResponse, in azureSecurityRulesDataSourceModel) (azureSecurityRulesDataSourceModel, bool, string, []string) {
	t.Helper()
	ctx := context.Background()
	api, requested := newRoutedSnapshotAPI(t, routes)
	ds := &azureSecurityRulesDataSource{api: api}
	var schemaResp datasource.SchemaResponse
	ds.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	config := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	if diags := config.Set(ctx, in); diags.HasError() {
		t.Fatalf("building the configuration: %v", diags)
	}
	req := datasource.ReadRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: config.Raw}}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}}
	ds.Read(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		var sb strings.Builder
		for _, d := range resp.Diagnostics.Errors() {
			sb.WriteString(d.Summary() + ": " + d.Detail() + "\n")
		}
		return azureSecurityRulesDataSourceModel{}, false, sb.String(), *requested
	}
	var out azureSecurityRulesDataSourceModel
	if diags := resp.State.Get(ctx, &out); diags.HasError() {
		t.Fatalf("reading state back: %v", diags)
	}
	return out, true, "", *requested
}

func customerGroupRead(groupID string, declared ...azInlineSecurityRuleModel) azureSecurityRulesDataSourceModel {
	return azureSecurityRulesDataSourceModel{CloudAccountID: types.StringValue(azureTestSubscription), Region: types.StringValue("eastus2"),
		NetworkSecurityGroupID: types.StringValue(groupID), DeclaredSecurityRules: declared}
}

// publishedCustomerGroupSnapshot serves the expected version from status, as a read that is not the enforcement plan's asks.
func publishedCustomerGroupSnapshot(t *testing.T) map[string]cannedResponse {
	t.Helper()
	version := loadJSON[wireSnapshot](t, "azure_snapshot_customer_group.json").Version
	return map[string]cannedResponse{
		"/expected":            {http.StatusOK, `{"version":"` + version + `"}`},
		"/status":              {http.StatusOK, `{"state":"converged","expected":{"version":"` + version + `"}}`},
		"/versions/" + version: {http.StatusOK, readTestdata(t, "azure_snapshot_customer_group.json")},
	}
}

func inlineRuleNamed(t *testing.T, rules []azInlineSecurityRuleModel, name string) azInlineSecurityRuleModel {
	t.Helper()
	for _, r := range rules {
		if r.Name.ValueString() == name {
			return r
		}
	}
	t.Fatalf("no rule %s", name)
	return azInlineSecurityRuleModel{}
}

func TestAzureSnapshotMapsYourGroupThatTakesXshieldsRules(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSnapshot(t, publishedCustomerGroupSnapshot(t))
	if !ok {
		t.Fatal(errs)
	}
	g, found := m.CustomerNetworkSecurityGroups[azureTestCustomerGroupKey]
	if !found {
		t.Fatalf("customer groups %v, want %s", sortedKeys(m.CustomerNetworkSecurityGroups), azureTestCustomerGroupKey)
	}
	if g.ID.ValueString() != azureTestCustomerGroupID || g.Name.ValueString() != "nsg-snet-owner" || g.ResourceGroupName.ValueString() != "rg-net" {
		t.Errorf("group %v %v %v, want nsg-snet-owner in rg-net by its ID", g.ID, g.Name, g.ResourceGroupName)
	}
	if len(g.SecurityRules) != 4 || g.SecurityRules[0].SourceAddressPrefix.ValueString() != "AzureLoadBalancer" {
		t.Errorf("rules %+v, want the renderer's four with the probe allow first", g.SecurityRules)
	}
	if subnets := sortedKeys(g.Subnets); len(subnets) != 1 || !strings.HasSuffix(subnets[0], "/subnets/snet-app") || keysOf(g.Subnets[subnets[0]])[0] != "web" {
		t.Errorf("subnets %v, want snet-app with web", g.Subnets)
	}
	web := m.Assets["web"]
	if web.Level.ValueString() != "subnet" || len(web.NetworkSecurityGroups) != 0 || !slices.Equal(keysOf(web.CustomerNetworkSecurityGroups), []string{azureTestCustomerGroupKey}) {
		t.Errorf("web %+v, want it enforced at its subnet through your group alone", web)
	}
}

func TestAzureSnapshotWithoutYourGroupsMapsNoneAndAnAssetsListIsEmpty(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, readTestdata(t, "azure_snapshot.json")))
	if !ok {
		t.Fatal(errs)
	}
	if m.CustomerNetworkSecurityGroups == nil || len(m.CustomerNetworkSecurityGroups) != 0 {
		t.Errorf("customer groups %v, want an empty map a module can iterate", m.CustomerNetworkSecurityGroups)
	}
	for id, a := range m.Assets {
		if a.CustomerNetworkSecurityGroups == nil {
			t.Errorf("asset %s has a null list of your groups, want an empty one", id)
		}
	}
}

func TestXshieldsRulesForYourGroupComeNumberedAheadOfYourDeclaredRules(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), customerGroupRead(azureTestCustomerGroupID, yourAllowRule("allow-ssh", 110)))
	if !ok {
		t.Fatal(errs)
	}
	if !m.Published.ValueBool() || m.Version.ValueString() != loadJSON[wireSnapshot](t, "azure_snapshot_customer_group.json").Version {
		t.Errorf("published %v version %v, want the expected version", m.Published, m.Version)
	}
	if len(m.XshieldSecurityRules) != 4 {
		t.Fatalf("xshield rules %d, want the renderer's four", len(m.XshieldSecurityRules))
	}
	for _, r := range m.XshieldSecurityRules {
		if r.Direction.ValueString() == "Inbound" && r.Priority.ValueInt64() >= 110 {
			t.Errorf("%s at %d, want it below your rule at 110", r.Name.ValueString(), r.Priority.ValueInt64())
		}
		if r.Description.IsNull() || r.SourceApplicationSecurityGroupIDs == nil || r.DestinationApplicationSecurityGroupIDs == nil {
			t.Errorf("%s leaves a field null, which azurerm's security_rule refuses", r.Name.ValueString())
		}
	}
	probe := m.XshieldSecurityRules[0]
	if probe.SourceAddressPrefix.ValueString() != "AzureLoadBalancer" || len(probe.SourceAddressPrefixes) != 0 || probe.DestinationAddressPrefix.ValueString() != "10.1.0.4/32" {
		t.Errorf("probe allow %+v, want a single address in the singular field", probe)
	}
	if len(m.SecurityRules) != 5 || m.SecurityRules[0].Name.ValueString() != "allow-ssh" {
		t.Fatalf("security rules %d, want your rule and then Xshield's four", len(m.SecurityRules))
	}
	yours := m.SecurityRules[0]
	if yours.Description.ValueString() != "" || yours.SourceAddressPrefixes == nil || yours.Priority.ValueInt64() != 110 {
		t.Errorf("your rule %+v, want it unchanged with its unset fields as azurerm reads them back", yours)
	}
}

func TestXshieldsRulesKeepThePrioritiesYourGroupHoldsThemAt(t *testing.T) {
	t.Parallel()
	in := customerGroupRead(azureTestCustomerGroupID)
	in.CurrentSecurityRules = []azRulePriorityModel{
		{Name: types.StringValue("CT-Rule-Allow-89dbc7f62dbc"), Priority: types.Int64Value(140), Direction: types.StringValue("Inbound")},
		{Name: types.StringValue("allow-ssh"), Priority: types.Int64Value(200), Direction: types.StringValue("Inbound")},
	}
	m, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), in)
	if !ok {
		t.Fatal(errs)
	}
	if p := inlineRuleNamed(t, m.XshieldSecurityRules, "CT-Rule-Allow-89dbc7f62dbc").Priority.ValueInt64(); p != 140 {
		t.Errorf("the 443 allow moved to %d from the 140 the group holds it at", p)
	}
	if p := inlineRuleNamed(t, m.XshieldSecurityRules, "CT-Rule-Deny-7afbbb662c01").Priority.ValueInt64(); p <= 140 || p >= 200 {
		t.Errorf("the inbound deny at %d, want it after the allow at 140 and before your rule at 200", p)
	}
	if len(m.SecurityRules) != len(m.XshieldSecurityRules) {
		t.Errorf("security rules %d, want Xshield's alone: a current rule is not declared, so it is not passed on", len(m.SecurityRules))
	}
}

func TestAnotherGroupGetsItsDeclaredRulesBackUnchanged(t *testing.T) {
	t.Parallel()
	other := strings.Replace(azureTestCustomerGroupID, "nsg-snet-owner", "nsg-other", 1)
	m, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), customerGroupRead(other, yourAllowRule("allow-ssh", 100)))
	if !ok {
		t.Fatal(errs)
	}
	if len(m.XshieldSecurityRules) != 0 || len(m.SecurityRules) != 1 || m.SecurityRules[0].Priority.ValueInt64() != 100 {
		t.Errorf("xshield %d rules %d, want none of Xshield's and yours as declared", len(m.XshieldSecurityRules), len(m.SecurityRules))
	}
}

func TestYourGroupIsMatchedWhateverTheCaseOfItsID(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), customerGroupRead(strings.ToLower(azureTestCustomerGroupID)))
	if !ok {
		t.Fatal(errs)
	}
	if len(m.XshieldSecurityRules) != 4 {
		t.Errorf("xshield rules %d, want four: Azure resource IDs are not case-sensitive", len(m.XshieldSecurityRules))
	}
}

func TestNothingPublishedGivesYourDeclaredRulesBack(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSecurityRules(t, map[string]cannedResponse{"/status": {http.StatusNotFound, xshieldNotPublished}},
		customerGroupRead(azureTestCustomerGroupID, yourAllowRule("allow-ssh", 100)))
	if !ok {
		t.Fatal(errs)
	}
	if m.Published.ValueBool() || !m.Version.IsNull() || len(m.XshieldSecurityRules) != 0 || len(m.SecurityRules) != 1 {
		t.Errorf("published %v version %v xshield %d rules %d, want yours alone", m.Published, m.Version, len(m.XshieldSecurityRules), len(m.SecurityRules))
	}
}

func TestADeclaredRuleNamedAsXshieldNamesItsOwnFailsThePlan(t *testing.T) {
	t.Parallel()
	_, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), customerGroupRead(azureTestCustomerGroupID, yourAllowRule("CT-Rule-Allow-89dbc7f62dbc", 300)))
	if ok || !strings.Contains(errs, "CT-Rule-Allow-89dbc7f62dbc") {
		t.Errorf("ok %v errors %q, want the plan to fail naming the rule: passing Xshield's rules back as yours would hold them at your priorities", ok, errs)
	}
}

func TestYourRuleAtTheLowestPriorityFailsThePlanNamingTheGroup(t *testing.T) {
	t.Parallel()
	_, ok, errs, _ := readAzureSecurityRules(t, publishedCustomerGroupSnapshot(t), customerGroupRead(azureTestCustomerGroupID, yourAllowRule("allow-ssh", 100)))
	if ok || !strings.Contains(errs, "nsg-snet-owner") || !strings.Contains(errs, "priority 100") {
		t.Errorf("ok %v errors %q, want the plan to fail naming the group and your rule's priority", ok, errs)
	}
}

func TestAPinnedVersionIsReadWithoutAskingWhichXshieldExpects(t *testing.T) {
	t.Parallel()
	version := loadJSON[wireSnapshot](t, "azure_snapshot_customer_group.json").Version
	in := customerGroupRead(azureTestCustomerGroupID)
	in.Version = types.StringValue(version)
	m, ok, errs, requested := readAzureSecurityRules(t, map[string]cannedResponse{"/versions/" + version: {http.StatusOK, readTestdata(t, "azure_snapshot_customer_group.json")}}, in)
	if !ok {
		t.Fatal(errs)
	}
	if m.Version.ValueString() != version || len(m.XshieldSecurityRules) != 4 || len(requested) != 1 {
		t.Errorf("version %v rules %d requested %v, want the pinned version's alone", m.Version, len(m.XshieldSecurityRules), requested)
	}
}
