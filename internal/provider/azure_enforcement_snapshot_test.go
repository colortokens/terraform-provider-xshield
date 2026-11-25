package provider

import (
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// azure_snapshot.json is the Xshield server's Azure renderer output for three workloads: web on its network interface,
// api on its subnet as its interface carries a group of the customer's, and db refused as both of its levels do.
const (
	azureTestSubscription = "11111111-2222-3333-4444-555555555555"
	azureTestWebGroup     = "ct-policy-d2dd5b7ea0d5"
	azureTestAPIGroup     = "ct-policy-8d612d812776"
)

func azurePointArgs() map[string]tftypes.Value {
	return map[string]tftypes.Value{
		"cloud_account_id": tftypes.NewValue(tftypes.String, azureTestSubscription),
		"region":           tftypes.NewValue(tftypes.String, "eastus2"),
		"enforcement_plan": tftypes.NewValue(tftypes.Bool, true),
	}
}

func readAzureSnapshot(t *testing.T, routes map[string]cannedResponse) (azureEnforcementSnapshotDataSourceModel, bool, string, []string) {
	t.Helper()
	api, requested := newRoutedSnapshotAPI(t, routes)
	var m azureEnforcementSnapshotDataSourceModel
	ok, errs := readDataSource(t, &azureEnforcementSnapshotDataSource{api: api}, azurePointArgs(), &m)
	return m, ok, errs, *requested
}

func publishedAzureSnapshot(t *testing.T, body string) map[string]cannedResponse {
	t.Helper()
	version := loadJSON[wireSnapshot](t, "azure_snapshot.json").Version
	return map[string]cannedResponse{
		"/expected":            {http.StatusOK, `{"version":"` + version + `"}`},
		"/versions/" + version: {http.StatusOK, body},
	}
}

func azureRuleNamed(t *testing.T, group azNetworkSecurityGroupModel, name string) azSecurityRuleModel {
	t.Helper()
	for _, r := range group.SecurityRules {
		if r.Name.ValueString() == name {
			return r
		}
	}
	t.Fatalf("group %s holds no rule %s", group.Name, name)
	return azSecurityRuleModel{}
}

func strs(values ...string) []types.String {
	return toStrList(values)
}

func TestAzureSnapshotIsReadFromTheSubscriptionsAzurePoint(t *testing.T) {
	t.Parallel()
	m, ok, errs, requested := readAzureSnapshot(t, publishedAzureSnapshot(t, readTestdata(t, "azure_snapshot.json")))
	if !ok {
		t.Fatal(errs)
	}
	point := "/api/policies/cloudsnapshots/azure/" + azureTestSubscription + "/eastus2/"
	if len(requested) != 2 || requested[0] != point+"expected" || !strings.HasPrefix(requested[1], point+"versions/") {
		t.Errorf("requested %v, want the expected version and then that version, both of the azure point", requested)
	}
	if !m.Published.ValueBool() || m.Version.ValueString() != loadJSON[wireSnapshot](t, "azure_snapshot.json").Version {
		t.Errorf("published %v version %v, want the version Xshield expects", m.Published, m.Version)
	}
}

func TestAzureSnapshotMapsEachGroupAndWhereItGoes(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, readTestdata(t, "azure_snapshot.json")))
	if !ok {
		t.Fatal(errs)
	}
	if got := sortedKeys(m.NetworkSecurityGroups); !slices.Equal(got, []string{azureTestAPIGroup, azureTestWebGroup}) {
		t.Fatalf("groups %v, want web's and api's", got)
	}
	web := m.NetworkSecurityGroups[azureTestWebGroup]
	if web.Name.ValueString() != azureTestWebGroup || web.ResourceGroupName.ValueString() != "rg-app" || web.Location.ValueString() != "eastus2" {
		t.Errorf("web's group is %s in %s at %s, want %s in its interface's rg-app at eastus2", web.Name, web.ResourceGroupName, web.Location, azureTestWebGroup)
	}
	if web.Tags["ct:delivery"] != "pipeline" || web.Tags["ct:level"] != "networkInterface" {
		t.Errorf("web's group tags %v, want the pipeline's delivery and level", web.Tags)
	}
	webInterface := azureTestResourceID("rg-app", "networkInterfaces/nic-web")
	if got := m.InterfaceAssociations[azureTestWebGroup]; got.NetworkSecurityGroup.ValueString() != azureTestWebGroup || got.NetworkInterfaceID.ValueString() != webInterface {
		t.Errorf("web's association %+v, want its group on %s", got, webInterface)
	}
	apiSubnet := azureTestResourceID("rg-net", "virtualNetworks/vnet-a/subnets/snet-app")
	if got := m.SubnetAssociations[azureTestAPIGroup]; got.NetworkSecurityGroup.ValueString() != azureTestAPIGroup || got.SubnetID.ValueString() != apiSubnet {
		t.Errorf("api's association %+v, want its group on %s", got, apiSubnet)
	}
	if len(m.InterfaceAssociations) != 1 || len(m.SubnetAssociations) != 1 {
		t.Errorf("%d interface and %d subnet associations, want one each", len(m.InterfaceAssociations), len(m.SubnetAssociations))
	}
	for id, want := range map[string]azAssetModel{
		"web": {Level: types.StringValue("networkInterface"), NetworkSecurityGroups: strs(azureTestWebGroup)},
		"api": {Level: types.StringValue("subnet"), NetworkSecurityGroups: strs(azureTestAPIGroup)},
		"db":  {Level: types.StringNull(), NetworkSecurityGroups: strs()},
	} {
		got := m.Assets[id]
		if !got.Level.Equal(want.Level) || !sameList(got.NetworkSecurityGroups, want.NetworkSecurityGroups) {
			t.Errorf("asset %s is %+v, want %+v", id, got, want)
		}
	}
}

func azureTestResourceID(resourceGroup, resource string) string {
	return "/subscriptions/sub-a/resourceGroups/" + resourceGroup + "/providers/Microsoft.Network/" + resource
}

// Azure refuses `*` and a service tag in a plural field, so a single value goes in the singular one, and an applied
// rule reads back from Azure with the unused field empty.
func TestAzureRuleTakesASingleValueInItsSingularFieldAndSeveralInItsPlural(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, readTestdata(t, "azure_snapshot.json")))
	if !ok {
		t.Fatal(errs)
	}
	web := m.NetworkSecurityGroups[azureTestWebGroup]
	for _, tc := range []struct {
		rule string
		want azSecurityRuleModel
	}{
		{"CT-Rule-Allow-faf81b0d4310", azSecurityRuleModel{Priority: types.Int64Value(501), Direction: types.StringValue("Inbound"),
			Access: types.StringValue("Allow"), Protocol: types.StringValue("Tcp"),
			SourceAddressPrefix: types.StringValue(""), SourceAddressPrefixes: strs("10.20.0.0/16", "10.21.0.0/16"),
			DestinationAddressPrefix: types.StringValue("10.1.0.4/32"), DestinationAddressPrefixes: strs(),
			SourcePortRange: types.StringValue("*"), SourcePortRanges: strs(),
			DestinationPortRange: types.StringValue("443"), DestinationPortRanges: strs()}},
		{"CT-Rule-Allow-096c9d78174c", azSecurityRuleModel{Priority: types.Int64Value(501), Direction: types.StringValue("Outbound"),
			Access: types.StringValue("Allow"), Protocol: types.StringValue("Tcp"),
			SourceAddressPrefix: types.StringValue("10.1.0.4/32"), SourceAddressPrefixes: strs(),
			DestinationAddressPrefix: types.StringValue("Storage.EastUS2"), DestinationAddressPrefixes: strs(),
			SourcePortRange: types.StringValue("*"), SourcePortRanges: strs(),
			DestinationPortRange: types.StringValue("443"), DestinationPortRanges: strs()}},
		{"CT-Rule-Allow-AzureLoadBalancer", azSecurityRuleModel{Priority: types.Int64Value(100), Direction: types.StringValue("Inbound"),
			Access: types.StringValue("Allow"), Protocol: types.StringValue("*"),
			SourceAddressPrefix: types.StringValue("AzureLoadBalancer"), SourceAddressPrefixes: strs(),
			DestinationAddressPrefix: types.StringValue("*"), DestinationAddressPrefixes: strs(),
			SourcePortRange: types.StringValue("*"), SourcePortRanges: strs(),
			DestinationPortRange: types.StringValue("*"), DestinationPortRanges: strs()}},
	} {
		tc.want.Name = types.StringValue(tc.rule)
		if got := azureRuleNamed(t, web, tc.rule); !azureRulesEqual(got, tc.want) {
			t.Errorf("rule %s is\n%+v\nwant\n%+v", tc.rule, got, tc.want)
		}
	}
	api := m.NetworkSecurityGroups[azureTestAPIGroup]
	if got := azureRuleNamed(t, api, "CT-Rule-Allow-049ab4a026fc"); got.DestinationPortRange.ValueString() != "8000-8080" {
		t.Errorf("api's port range reads as %s, want 8000-8080", got.DestinationPortRange)
	}
	if len(web.SecurityRules) != 6 || len(api.SecurityRules) != 4 {
		t.Errorf("web holds %d rules and api %d, want every rule Xshield rendered: 6 and 4", len(web.SecurityRules), len(api.SecurityRules))
	}
}

// sameList tells a null list, which reads back as nil, from an empty one.
func sameList(a, b []types.String) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

func azureRulesEqual(a, b azSecurityRuleModel) bool {
	return a.Name.Equal(b.Name) && a.Priority.Equal(b.Priority) && a.Direction.Equal(b.Direction) && a.Access.Equal(b.Access) &&
		a.Protocol.Equal(b.Protocol) &&
		a.SourceAddressPrefix.Equal(b.SourceAddressPrefix) && sameList(a.SourceAddressPrefixes, b.SourceAddressPrefixes) &&
		a.DestinationAddressPrefix.Equal(b.DestinationAddressPrefix) && sameList(a.DestinationAddressPrefixes, b.DestinationAddressPrefixes) &&
		a.SourcePortRange.Equal(b.SourcePortRange) && sameList(a.SourcePortRanges, b.SourcePortRanges) &&
		a.DestinationPortRange.Equal(b.DestinationPortRange) && sameList(a.DestinationPortRanges, b.DestinationPortRanges)
}

func TestAzureNothingPublishedReadsAsAnEmptySnapshot(t *testing.T) {
	t.Parallel()
	m, ok, errs, requested := readAzureSnapshot(t, map[string]cannedResponse{"/expected": {http.StatusNotFound, xshieldNotPublished}})
	if !ok {
		t.Fatalf("a subscription with nothing published must plan, not fail: %s", errs)
	}
	if m.Published.ValueBool() || !m.Version.IsNull() || len(requested) != 1 {
		t.Errorf("published %v version %v after %v, want false and null from the expected version alone", m.Published, m.Version, requested)
	}
	if m.NetworkSecurityGroups == nil || m.SubnetAssociations == nil || m.InterfaceAssociations == nil || m.Assets == nil ||
		len(m.NetworkSecurityGroups)+len(m.SubnetAssociations)+len(m.InterfaceAssociations)+len(m.Assets) != 0 {
		t.Errorf("an unpublished snapshot must hold empty maps, never null ones: %+v", m)
	}
}

// The Azure connector takes over none of the pipeline's groups, so the advice is to delete them, never to keep them.
func TestAzureHandedOverSaysToRemoveTheModule(t *testing.T) {
	t.Parallel()
	_, ok, errs, _ := readAzureSnapshot(t, map[string]cannedResponse{
		"/expected": {http.StatusConflict, `{"status":409,"code":"handedOver","message":"handed over"}`},
	})
	if ok || !strings.Contains(errs, "moved "+azureTestSubscription+"/eastus2 to connector delivery") ||
		!strings.Contains(errs, "takes over none") || strings.Contains(errs, "destroy = false") {
		t.Errorf("ok=%v %q, want the hand-over refused with the Azure advice", ok, errs)
	}
}

func TestAzureSnapshotForAnotherSubscriptionIsRefused(t *testing.T) {
	t.Parallel()
	other := strings.Replace(readTestdata(t, "azure_snapshot.json"), azureTestSubscription, "99999999-2222-3333-4444-555555555555", 1)
	_, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, other))
	if ok || !strings.Contains(errs, "another account or region") {
		t.Errorf("ok=%v %q, want a snapshot of another subscription refused", ok, errs)
	}
}

func TestEachCloudsSnapshotIsRenderedOnlyByItsOwnDataSource(t *testing.T) {
	t.Parallel()
	azure, aws := loadJSON[wireSnapshot](t, "azure_snapshot.json"), loadJSON[wireSnapshot](t, "snapshot.json")
	if err := renderable(cloudAzure, azure); err != nil {
		t.Errorf("the Azure snapshot was refused: %v", err)
	}
	for name, refused := range map[string]error{
		"an AWS snapshot read as Azure's": renderable(cloudAzure, aws),
		"an Azure snapshot read as AWS's": renderable(cloudAWS, azure),
	} {
		if refused == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	newer := azure
	newer.SchemaVersion = "2"
	if err := renderable(cloudAzure, newer); err == nil || !strings.Contains(err.Error(), "Upgrade the xshield provider") {
		t.Errorf("a newer Azure schema was accepted: %v", err)
	}
	planless := azure
	planless.Azure = nil
	if err := renderable(cloudAzure, planless); err == nil || !strings.Contains(err.Error(), "no Azure plan") {
		t.Errorf("a snapshot without an Azure plan was accepted: %v", err)
	}
}

func TestAzureSnapshotMapsTheAssociationsItHoldsAndReleases(t *testing.T) {
	t.Parallel()
	oldInterface := azureTestResourceID("rg-app", "networkInterfaces/nic-old")
	oldSubnet := azureTestResourceID("rg-net", "virtualNetworks/vnet-a/subnets/snet-old")
	oldGroupID := azureTestResourceID("rg-app", "networkSecurityGroups/ct-policy-0123456789ab")
	body := strings.Replace(readTestdata(t, "azure_snapshot.json"), `"azure": {`, `"azure": {
    "heldInterfaceAssociations": {"ct-policy-0123456789ab": {"levelId": "`+oldInterface+`", "networkSecurityGroupId": "`+oldGroupID+`"}},
    "releasedInterfaceAssociations": {"ct-policy-ba9876543210": "`+oldInterface+`"},
    "releasedSubnetAssociations": {"ct-policy-ffffffffffff": "`+oldSubnet+`"},`, 1)
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, body))
	if !ok {
		t.Fatal(errs)
	}
	held := m.HeldInterfaceAssociations["ct-policy-0123456789ab"]
	if len(m.HeldInterfaceAssociations) != 1 || held.LevelID.ValueString() != oldInterface || held.NetworkSecurityGroupID.ValueString() != oldGroupID {
		t.Errorf("held interface associations %+v, want the one the server holds on %s", m.HeldInterfaceAssociations, oldInterface)
	}
	if m.HeldSubnetAssociations == nil || len(m.HeldSubnetAssociations) != 0 {
		t.Errorf("held subnet associations %+v, want an empty map", m.HeldSubnetAssociations)
	}
	if got := m.ReleasedInterfaceAssociations["ct-policy-ba9876543210"]; len(m.ReleasedInterfaceAssociations) != 1 || got.ValueString() != oldInterface {
		t.Errorf("released interface associations %+v, want the one on %s", m.ReleasedInterfaceAssociations, oldInterface)
	}
	if got := m.ReleasedSubnetAssociations["ct-policy-ffffffffffff"]; len(m.ReleasedSubnetAssociations) != 1 || got.ValueString() != oldSubnet {
		t.Errorf("released subnet associations %+v, want the one on %s", m.ReleasedSubnetAssociations, oldSubnet)
	}
}

func TestAzureSnapshotMapsTheAssociationsTheConnectorHandsOver(t *testing.T) {
	t.Parallel()
	subnet := azureTestResourceID("rg-net", "virtualNetworks/vnet-a/subnets/snet-handover")
	nic := azureTestResourceID("rg-app", "networkInterfaces/nic-handover")
	body := strings.Replace(readTestdata(t, "azure_snapshot.json"), `"azure": {`, `"azure": {
    "handoverSubnetAssociations": {"ct-policy-aaaaaaaaaaaa": {"networkSecurityGroup": "ct-policy-aaaaaaaaaaaa", "subnetId": "`+subnet+`"}},
    "handoverInterfaceAssociations": {"ct-policy-bbbbbbbbbbbb": {"networkSecurityGroup": "ct-policy-bbbbbbbbbbbb", "networkInterfaceId": "`+nic+`"}},`, 1)
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, body))
	if !ok {
		t.Fatal(errs)
	}
	subnetAssociation := m.HandoverSubnetAssociations["ct-policy-aaaaaaaaaaaa"]
	if len(m.HandoverSubnetAssociations) != 1 || subnetAssociation.SubnetID.ValueString() != subnet ||
		subnetAssociation.NetworkSecurityGroup.ValueString() != "ct-policy-aaaaaaaaaaaa" {
		t.Errorf("handover subnet associations %+v, want the one on %s", m.HandoverSubnetAssociations, subnet)
	}
	nicAssociation := m.HandoverInterfaceAssociations["ct-policy-bbbbbbbbbbbb"]
	if len(m.HandoverInterfaceAssociations) != 1 || nicAssociation.NetworkInterfaceID.ValueString() != nic ||
		nicAssociation.NetworkSecurityGroup.ValueString() != "ct-policy-bbbbbbbbbbbb" {
		t.Errorf("handover interface associations %+v, want the one on %s", m.HandoverInterfaceAssociations, nic)
	}
	if _, inSubnets := m.SubnetAssociations["ct-policy-aaaaaaaaaaaa"]; inSubnets {
		t.Error("an association the connector hands over is also listed as one to create")
	}
	if _, inInterfaces := m.InterfaceAssociations["ct-policy-bbbbbbbbbbbb"]; inInterfaces {
		t.Error("an association the connector hands over is also listed as one to create")
	}
}

func TestAzureSnapshotWithoutHandoversReadsThemAsEmptyMaps(t *testing.T) {
	t.Parallel()
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, readTestdata(t, "azure_snapshot.json")))
	if !ok {
		t.Fatal(errs)
	}
	if m.HandoverSubnetAssociations == nil || len(m.HandoverSubnetAssociations) != 0 ||
		m.HandoverInterfaceAssociations == nil || len(m.HandoverInterfaceAssociations) != 0 {
		t.Errorf("handover associations %+v %+v, want empty maps", m.HandoverSubnetAssociations, m.HandoverInterfaceAssociations)
	}
}

func TestAzureSnapshotMapsTheAssociationsOfAContainedWorkload(t *testing.T) {
	t.Parallel()
	nic := azureTestResourceID("rg-app", "networkInterfaces/nic-web")
	subnet := azureTestResourceID("rg-net", "virtualNetworks/vnet-a/subnets/snet-db")
	groupID := azureTestResourceID("rg-app", "networkSecurityGroups/ct-policy-0123456789ab")
	body := strings.Replace(readTestdata(t, "azure_snapshot.json"), `"azure": {`, `"azure": {
    "containedInterfaceAssociations": {"ct-policy-0123456789ab": {"levelId": "`+nic+`", "networkSecurityGroupId": "`+groupID+`"}},
    "containedSubnetAssociations": {"ct-policy-ba9876543210": {"levelId": "`+subnet+`", "networkSecurityGroupId": "`+groupID+`"}},`, 1)
	m, ok, errs, _ := readAzureSnapshot(t, publishedAzureSnapshot(t, body))
	if !ok {
		t.Fatal(errs)
	}
	want := map[string]azHeldAssociationModel{"ct-policy-0123456789ab": {LevelID: types.StringValue(nic), NetworkSecurityGroupID: types.StringValue(groupID)}}
	if !reflect.DeepEqual(m.ContainedInterfaceAssociations, want) {
		t.Errorf("contained interface associations %+v, want %+v", m.ContainedInterfaceAssociations, want)
	}
	if got := m.ContainedSubnetAssociations["ct-policy-ba9876543210"]; len(m.ContainedSubnetAssociations) != 1 || got.LevelID.ValueString() != subnet {
		t.Errorf("contained subnet associations %+v, want the one on %s", m.ContainedSubnetAssociations, subnet)
	}
}
