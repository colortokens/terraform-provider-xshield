package provider

import (
	"strings"
	"testing"
)

func azureTestRule(name, direction, access string, order int64) wireAzureSecurityRule {
	return wireAzureSecurityRule{Name: name, Direction: direction, Access: access, Priority: order, Protocol: "Tcp",
		SourceAddressPrefixes: []string{"10.0.0.0/8"}, DestinationAddressPrefixes: []string{"10.1.0.4/32"},
		SourcePortRanges: []string{"*"}, DestinationPortRanges: []string{"443"}}
}

func yourRule(name, direction string, priority int64) azurePriorityHolder {
	return azurePriorityHolder{name: name, direction: direction, priority: priority}
}

func prioritiesOf(t *testing.T, rules []wireAzureSecurityRule) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, r := range rules {
		out[r.Name] = r.Priority
	}
	return out
}

// The renderer's snapshot priorities give only the order: a probe allow, then allows, then a deny, in each direction.
func workloadRules() []wireAzureSecurityRule {
	return []wireAzureSecurityRule{
		azureTestRule("CT-Rule-Allow-probe", "Inbound", "Allow", 100),
		azureTestRule("CT-Rule-Allow-https", "Inbound", "Allow", 501),
		azureTestRule("CT-Rule-Deny-in", "Inbound", "Deny", 3001),
		azureTestRule("CT-Rule-Deny-out", "Outbound", "Deny", 3001),
	}
}

func TestXshieldsRulesTakeTheFirstPrioritiesBelowYoursInTheOrderTheSnapshotGives(t *testing.T) {
	t.Parallel()
	numbered, err := numberAheadOfYours("nsg-app", workloadRules(), []azurePriorityHolder{yourRule("allow-lb", "Inbound", 200), yourRule("deny-all", "Inbound", 4000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := prioritiesOf(t, numbered)
	if got["CT-Rule-Allow-probe"] >= got["CT-Rule-Deny-in"] || got["CT-Rule-Allow-https"] >= got["CT-Rule-Deny-in"] {
		t.Errorf("priorities %v, want both allows before the deny", got)
	}
	for name, p := range got {
		if p < 100 || p >= 200 {
			t.Errorf("%s at %d, want it from 100 and below your first rule at 200", name, p)
		}
	}
	if got["CT-Rule-Deny-out"] != 100 {
		t.Errorf("outbound deny at %d, want 100: your inbound rules leave every outbound priority free", got["CT-Rule-Deny-out"])
	}
}

func TestXshieldsRulesKeepThePrioritiesTheGroupHoldsThemAt(t *testing.T) {
	t.Parallel()
	current := []azurePriorityHolder{yourRule("CT-Rule-Allow-probe", "Inbound", 150), yourRule("CT-Rule-Allow-https", "Inbound", 120),
		yourRule("CT-Rule-Deny-in", "Inbound", 180), yourRule("CT-Rule-Deny-out", "Outbound", 300), yourRule("deny-all", "Inbound", 4000)}
	numbered, err := numberAheadOfYours("nsg-app", workloadRules(), nil, current)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"CT-Rule-Allow-probe": 150, "CT-Rule-Allow-https": 120, "CT-Rule-Deny-in": 180, "CT-Rule-Deny-out": 300}
	for name, p := range prioritiesOf(t, numbered) {
		if want[name] != p {
			t.Errorf("%s moved from %d to %d; the order still held, so the apply has nothing to change", name, want[name], p)
		}
	}
}

func TestANewXshieldRuleTakesNoPriorityARuleHoldsNow(t *testing.T) {
	t.Parallel()
	current := []azurePriorityHolder{yourRule("CT-Rule-Allow-gone", "Inbound", 100), yourRule("CT-Rule-Allow-probe", "Inbound", 101),
		yourRule("deny-all", "Inbound", 4000)}
	numbered, err := numberAheadOfYours("nsg-app", workloadRules()[:3], nil, current)
	if err != nil {
		t.Fatal(err)
	}
	got := prioritiesOf(t, numbered)
	if got["CT-Rule-Allow-https"] == 100 || got["CT-Rule-Deny-in"] == 100 {
		t.Errorf("priorities %v: a rule leaving the group frees 100 only once it is deleted, and rule resources apply in no set order", got)
	}
	if got["CT-Rule-Allow-probe"] != 101 {
		t.Errorf("probe allow at %d, want it kept at 101", got["CT-Rule-Allow-probe"])
	}
}

func TestAHeldRuleThatWouldBreakTheOrderMoves(t *testing.T) {
	t.Parallel()
	current := []azurePriorityHolder{yourRule("CT-Rule-Deny-in", "Inbound", 100), yourRule("deny-all", "Inbound", 4000)}
	numbered, err := numberAheadOfYours("nsg-app", workloadRules()[:3], nil, current)
	if err != nil {
		t.Fatal(err)
	}
	got := prioritiesOf(t, numbered)
	if got["CT-Rule-Deny-in"] <= got["CT-Rule-Allow-https"] || got["CT-Rule-Deny-in"] <= got["CT-Rule-Allow-probe"] {
		t.Errorf("priorities %v: kept at 100 the deny would decide the traffic the allows let in", got)
	}
}

func TestAHeldRuleAtOrBelowOneOfYoursMovesAheadOfIt(t *testing.T) {
	t.Parallel()
	current := []azurePriorityHolder{yourRule("CT-Rule-Deny-out", "Outbound", 250), yourRule("allow-dns", "Outbound", 200)}
	numbered, err := numberAheadOfYours("nsg-app", workloadRules()[3:], nil, current)
	if err != nil {
		t.Fatal(err)
	}
	if p := prioritiesOf(t, numbered)["CT-Rule-Deny-out"]; p >= 200 {
		t.Errorf("deny at %d, want it below your rule at 200", p)
	}
}

func TestADeclaredRuleCountsAsYoursAsMuchAsACurrentOne(t *testing.T) {
	t.Parallel()
	numbered, err := numberAheadOfYours("nsg-app", workloadRules()[3:], []azurePriorityHolder{yourRule("allow-dns", "Outbound", 102)},
		[]azurePriorityHolder{yourRule("CT-Rule-Deny-out", "Outbound", 300)})
	if err != nil {
		t.Fatal(err)
	}
	if p := prioritiesOf(t, numbered)["CT-Rule-Deny-out"]; p >= 102 {
		t.Errorf("deny at %d, want it below the declared rule at 102, which the next apply puts there", p)
	}
}

func TestHeldPrioritiesThatLeaveNoRoomAreGivenUpRatherThanFailingThePlan(t *testing.T) {
	t.Parallel()
	current := []azurePriorityHolder{yourRule("CT-Rule-Allow-https", "Inbound", 103), yourRule("deny-all", "Inbound", 104)}
	numbered, err := numberAheadOfYours("nsg-app", workloadRules()[:3], nil, current)
	if err != nil {
		t.Fatalf("%v: numbering afresh fits all three below 104", err)
	}
	got := prioritiesOf(t, numbered)
	if got["CT-Rule-Deny-in"] >= 104 || got["CT-Rule-Deny-in"] <= got["CT-Rule-Allow-https"] {
		t.Errorf("priorities %v, want the allows then the deny, all below 104", got)
	}
}

func TestNoRoomAheadOfYourRulesFailsNamingTheGroupAndThePriority(t *testing.T) {
	t.Parallel()
	_, err := numberAheadOfYours("nsg-app", workloadRules(), []azurePriorityHolder{yourRule("allow-lb", "Inbound", 101)}, nil)
	if err == nil {
		t.Fatal("three inbound rules fitted below 101")
	}
	for _, want := range []string{"nsg-app", "inbound", "priority 101", "at least 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestSameAccessRunsSplitWhereTheAccessChanges(t *testing.T) {
	t.Parallel()
	rules := []wireAzureSecurityRule{azureTestRule("d", "Inbound", "Deny", 3001), azureTestRule("a", "Inbound", "Allow", 100),
		azureTestRule("c", "Inbound", "Allow", 600), azureTestRule("b", "Inbound", "Deny", 300)}
	runs := sameAccessRuns(rules)
	var shape []string
	for _, run := range runs {
		var names []string
		for _, r := range run {
			names = append(names, r.Name)
		}
		shape = append(shape, strings.Join(names, ","))
	}
	if strings.Join(shape, " | ") != "a | b | c | d" {
		t.Errorf("runs %v, want allow a, deny b, allow c and deny d apart, as each change of access is a boundary", shape)
	}
}
