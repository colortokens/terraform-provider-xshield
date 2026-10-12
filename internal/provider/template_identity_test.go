package provider

import (
	"fmt"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func inboundPathFromSegment(segmentID string) tfTypes.MetadataPath {
	return tfTypes.MetadataPath{
		Direction: types.StringValue("inbound"),
		Port:      types.StringValue("443"),
		Protocol:  types.StringValue("TCP"),
		SourceTagBasedPolicy: &tfTypes.MetadataTagBasedPolicyReference{
			TagBasedPolicyID: types.StringValue(segmentID),
		},
	}
}

// The old key was port:protocol:direction, so two rules that differ only in
// their peer collapsed onto one entry. Read kept whichever came last and
// dropped the other from state; Update then diffed the survivor against the
// wrong rule and re-added the missing one on every plan.
func TestTemplatePathKeyDistinguishesPeers(t *testing.T) {
	t.Parallel()
	fromApp := inboundPathFromSegment("seg-app")
	fromWeb := inboundPathFromSegment("seg-web")

	oldKey := func(p tfTypes.MetadataPath) string {
		return fmt.Sprintf("%s:%s:%s", p.Port.ValueString(), p.Protocol.ValueString(), p.Direction.ValueString())
	}
	if oldKey(fromApp) != oldKey(fromWeb) {
		t.Fatal("the port:protocol:direction key was expected to collide; this test no longer proves anything")
	}

	if templatePathKey(fromApp) == templatePathKey(fromWeb) {
		t.Errorf("two inbound 443/TCP rules from different segments share a key: %q", templatePathKey(fromApp))
	}
}

func TestTemplatePathKeySeparatesEverySelectorKind(t *testing.T) {
	t.Parallel()
	base := func() tfTypes.MetadataPath {
		return tfTypes.MetadataPath{
			Direction: types.StringValue("inbound"),
			Port:      types.StringValue("443"),
			Protocol:  types.StringValue("TCP"),
		}
	}
	withSrcIP := base()
	withSrcIP.SrcIP = types.StringValue("10.0.0.1")

	withAsset := base()
	withAsset.SourceAssetID = types.StringValue("asset-1")

	withNamedNetwork := base()
	withNamedNetwork.SourceNamedNetwork = &tfTypes.MetadataNamedNetworkReference{
		NamedNetworkID: types.StringValue("nn-1"),
	}

	withSegment := inboundPathFromSegment("seg-1")

	seen := map[string]string{}
	for name, p := range map[string]tfTypes.MetadataPath{
		"src_ip":               withSrcIP,
		"source_asset_id":      withAsset,
		"source_named_network": withNamedNetwork,
		"source_segment":       withSegment,
	} {
		key := templatePathKey(p)
		if other, clash := seen[key]; clash {
			t.Errorf("%s and %s produce the same key %q", name, other, key)
		}
		seen[key] = name
	}
}

func TestTemplatePathKeyIgnoresNonIdentifyingFields(t *testing.T) {
	t.Parallel()
	// The backend's channel hash does not cover the port name, so two rules
	// differing only there are the same rule and must not be re-created.
	a := inboundPathFromSegment("seg-1")
	b := inboundPathFromSegment("seg-1")
	b.PortName = types.StringValue("https")

	if templatePathKey(a) != templatePathKey(b) {
		t.Errorf("port_name changed the identity:\n a: %q\n b: %q", templatePathKey(a), templatePathKey(b))
	}
}

func TestTemplatePathKeyDistinguishesDirectionAndProcess(t *testing.T) {
	t.Parallel()
	inbound := inboundPathFromSegment("seg-1")

	outbound := inbound
	outbound.Direction = types.StringValue("outbound")
	if templatePathKey(inbound) == templatePathKey(outbound) {
		t.Error("direction must be part of the identity")
	}

	withProcess := inbound
	withProcess.DstProcess = types.StringValue("nginx")
	if templatePathKey(inbound) == templatePathKey(withProcess) {
		t.Error("dst_process must be part of the identity")
	}
}

func TestTemplatePortKeyDistinguishesPortAndProtocol(t *testing.T) {
	t.Parallel()
	tcp443 := tfTypes.MetadataPort{
		ListenPort:         types.StringValue("443"),
		ListenPortProtocol: types.StringValue("TCP"),
	}
	udp443 := tcp443
	udp443.ListenPortProtocol = types.StringValue("UDP")
	tcp80 := tcp443
	tcp80.ListenPort = types.StringValue("80")

	if templatePortKey(tcp443) == templatePortKey(udp443) {
		t.Error("protocol must be part of the port identity")
	}
	if templatePortKey(tcp443) == templatePortKey(tcp80) {
		t.Error("port must be part of the port identity")
	}

	// The review state is a property of the rule, not part of its identity;
	// changing it is an edit, not a different port.
	reviewed := tcp443
	reviewed.ListenPortReviewed = types.StringValue("allow-any")
	if templatePortKey(tcp443) != templatePortKey(reviewed) {
		t.Error("listen_port_reviewed must not change the port identity")
	}
}

func TestTemplatePathKeysMatch(t *testing.T) {
	t.Parallel()
	if !templatePathKeysMatch(inboundPathFromSegment("seg-1"), inboundPathFromSegment("seg-1")) {
		t.Error("identical rules should match")
	}
	if templatePathKeysMatch(inboundPathFromSegment("seg-1"), inboundPathFromSegment("seg-2")) {
		t.Error("rules with different sources should not match")
	}
}

func TestReorderToStateOrderKeepsStateOrderAndAppendsNew(t *testing.T) {
	t.Parallel()
	key := func(s string) string { return s }

	got := reorderToStateOrder([]string{"c", "a", "b", "d"}, []string{"a", "b", "c"}, key)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReorderToStateOrderDropsRulesTheAPINoLongerHas(t *testing.T) {
	t.Parallel()
	key := func(s string) string { return s }

	got := reorderToStateOrder([]string{"a"}, []string{"a", "removed"}, key)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("got %v, want just the rule the API still reports", got)
	}
}

// Two rules on the same port used to share a key, so the reorder kept one and
// silently dropped the other from state; the next plan then re-added it.
func TestReorderToStateOrderKeepsBothRulesOnOnePort(t *testing.T) {
	t.Parallel()
	fromApp := inboundPathFromSegment("seg-app")
	fromWeb := inboundPathFromSegment("seg-web")

	got := reorderToStateOrder(
		[]tfTypes.MetadataPath{fromWeb, fromApp},
		[]tfTypes.MetadataPath{fromApp, fromWeb},
		templatePathKey)

	if len(got) != 2 {
		t.Fatalf("kept %d of 2 rules that differ only by source", len(got))
	}
	if templatePathKey(got[0]) != templatePathKey(fromApp) {
		t.Errorf("first entry is %q, want the order held in state", templatePathKey(got[0]))
	}
}
