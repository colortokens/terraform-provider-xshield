package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func reopenKeys(reopens []sgrReopenModel) []string {
	out := []string{}
	for _, r := range reopens {
		out = append(out, r.Rule.ValueString()+"@"+r.ChangeSet.ValueString())
	}
	return out
}

func tcpMatch(from, to int64, cidr string) wireRuleMatch {
	return wireRuleMatch{Direction: "ingress", IPProtocol: "tcp", FromPort: i64(from), ToPort: i64(to), CIDRIPv4: ptr(cidr)}
}

func protocolMatch(protocol string, cidr string) wireRuleMatch {
	m := wireRuleMatch{Direction: "ingress", IPProtocol: protocol, CIDRIPv4: ptr(cidr)}
	if hasPortRange(protocol) {
		m.FromPort, m.ToPort = i64(0), i64(maxPort)
	} else if hasTypeAndCode(protocol) {
		m.FromPort, m.ToPort = i64(allPorts), i64(allPorts)
	}
	return m
}

// The fixture's change moves 0.0.0.0/0:443 out of web while a-app-1 keeps none of it.
func TestReopens_aNarrowerDeclaredRuleGivesBackWhatAMemberLost(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"attaching", "narrowing"} {
		changes := loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json")
		if state == "narrowing" {
			changes = narrowed(changes)
		}
		data := webRules()
		data.Ingress["https_lb"] = declaredRule("tcp", 443, "10.0.0.0/8")
		filterDeclaredRules(data, groupChangeOf(changes, "vpc-1", "web"))

		if got := reopenKeys(data.Reopens); !slices.Equal(got, []string{"ingress/https_lb@cs-1"}) {
			t.Errorf("%s: reopens %v, want the 10.0.0.0/8:443 rule: the moved rule itself is pending or revoked, 22 and egress are not moved", state, got)
		}
		if data.SecurityGroupID.ValueString() != "sg-web" {
			t.Errorf("%s: security group id %v", state, data.SecurityGroupID)
		}
		if _, kept := data.IngressRules["https_lb"]; !kept {
			t.Errorf("%s: the data source only reports a reopening rule, it still returns it", state)
		}
	}
}

func TestReopens_notARuleEveryMemberKeeps(t *testing.T) {
	t.Parallel()
	changes := narrowed(loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json"))
	change := changes.Groups["vpc-1/web"]
	change.ChangeSets[0].Moves[0].KeptByEveryMember = []wireRuleMatch{change.ChangeSets[0].Moves[0].wireRuleMatch}
	data := webRules()
	data.Ingress["https_lb"] = declaredRule("tcp", 443, "10.0.0.0/8")
	filterDeclaredRules(data, &change)

	if len(data.Reopens) != 0 {
		t.Errorf("reopens %v, want none: every member keeps the moved rule whole", reopenKeys(data.Reopens))
	}
}

func TestReopens_noChangeNoGroupID(t *testing.T) {
	t.Parallel()
	data := webRules()
	filterDeclaredRules(data, nil)
	if !data.SecurityGroupID.IsNull() || data.Reopens == nil || data.UndeclaredRestores == nil || data.UndeclaredPending == nil {
		t.Errorf("group id %v, reopens %v, restores %v, pending %v: want null and empty lists", data.SecurityGroupID, data.Reopens,
			data.UndeclaredRestores, data.UndeclaredPending)
	}
}

func TestGivesBack(t *testing.T) {
	t.Parallel()
	portN := wireMovedRule{wireRuleMatch: tcpMatch(0, maxPort, "10.0.0.0/8"),
		KeptByEveryMember: []wireRuleMatch{tcpMatch(0, 21, "10.0.0.0/8"), tcpMatch(23, maxPort, "10.0.0.0/8")}}
	allTraffic := wireMovedRule{wireRuleMatch: wireRuleMatch{Direction: "ingress", IPProtocol: "-1", CIDRIPv4: ptr("10.0.0.0/8")},
		KeptByEveryMember: []wireRuleMatch{protocolMatch("icmp", "10.0.0.0/8"), tcpMatch(0, 21, "10.0.0.0/8"), tcpMatch(23, maxPort, "10.0.0.0/8"),
			protocolMatch("udp", "10.0.0.0/8")}}
	unsent := wireMovedRule{wireRuleMatch: tcpMatch(0, maxPort, "10.0.0.0/8")}
	group := wireMovedRule{wireRuleMatch: wireRuleMatch{Direction: "ingress", IPProtocol: "tcp", FromPort: i64(443), ToPort: i64(443),
		ReferencedSecurityGroupID: ptr("111122223333/sg-lb")}}
	withPeer := func(r sgrRuleModel, v4 string, v6 string, group string) sgrRuleModel {
		r.CIDRIPv4, r.CIDRIPv6, r.ReferencedSecurityGroupID = types.StringNull(), types.StringNull(), types.StringNull()
		switch {
		case v4 != "":
			r.CIDRIPv4 = types.StringValue(v4)
		case v6 != "":
			r.CIDRIPv6 = types.StringValue(v6)
		default:
			r.ReferencedSecurityGroupID = types.StringValue(group)
		}
		return r
	}
	icmp := func(icmpType, code int64) sgrRuleModel {
		r := declaredRule("icmp", icmpType, "10.1.0.0/16")
		r.ToPort = types.Int64Value(code)
		return r
	}
	icmpMatch := func(icmpType int64) wireRuleMatch {
		return wireRuleMatch{Direction: "ingress", IPProtocol: "icmp", FromPort: i64(icmpType), ToPort: i64(allPorts), CIDRIPv4: ptr("10.0.0.0/8")}
	}
	icmpKept := func(icmpType int64) wireMovedRule {
		return wireMovedRule{wireRuleMatch: protocolMatch("icmp", "10.0.0.0/8"), KeptByEveryMember: []wireRuleMatch{icmpMatch(icmpType)}}
	}
	icmpMoved := func(icmpType int64) wireMovedRule { return wireMovedRule{wireRuleMatch: icmpMatch(icmpType)} }
	ranged := func(from, to int64) sgrRuleModel {
		r := declaredRule("tcp", from, "10.1.0.0/16")
		r.ToPort = types.Int64Value(to)
		return r
	}
	for name, tc := range map[string]struct {
		declared sgrRuleModel
		moved    wireMovedRule
		want     bool
	}{
		"port N: another port every member keeps":   {declaredRule("tcp", 80, "10.1.0.0/16"), portN, false},
		"port N: the port a member gave up":         {declaredRule("tcp", 22, "10.1.0.0/16"), portN, true},
		"port N: a range across it":                 {ranged(20, 25), portN, true},
		"port N: a range beside it":                 {ranged(23, 30), portN, false},
		"port N: a broader peer, only shared part":  {declaredRule("tcp", 80, "0.0.0.0/0"), portN, false},
		"port N: a broader peer on the given port":  {declaredRule("tcp", 22, "0.0.0.0/0"), portN, true},
		"port N: another protocol":                  {declaredRule("udp", 22, "10.1.0.0/16"), portN, false},
		"port N: all traffic":                       {declaredRule("-1", 0, "10.1.0.0/16"), portN, true},
		"another peer":                              {declaredRule("tcp", 22, "192.168.0.0/16"), portN, false},
		"another address family":                    {withPeer(declaredRule("tcp", 22, ""), "", "2001:db8::/32", ""), portN, false},
		"all traffic: kept TCP":                     {declaredRule("tcp", 443, "10.1.0.0/16"), allTraffic, false},
		"all traffic: the TCP port given up":        {declaredRule("tcp", 22, "10.1.0.0/16"), allTraffic, true},
		"all traffic: a kept ICMP type":             {icmp(8, -1), allTraffic, false},
		"all traffic: a protocol no fragment keeps": {declaredRule("50", 0, "10.1.0.0/16"), allTraffic, true},
		"all traffic: all traffic":                  {declaredRule("-1", 0, "10.1.0.0/16"), allTraffic, true},
		"a server that does not say what is kept":   {declaredRule("tcp", 80, "10.1.0.0/16"), unsent, true},
		"the same group, by its own id":             {withPeer(declaredRule("tcp", 443, ""), "", "", "sg-lb"), group, true},
		"a group against an address":                {withPeer(declaredRule("tcp", 80, ""), "", "", "sg-lb"), portN, false},
		"icmp: another type than the one kept":      {icmp(8, -1), icmpKept(0), true},
		"icmp: the type kept":                       {icmp(0, 3), icmpKept(0), false},
		"icmp: another type than the one moved":     {icmp(8, -1), icmpMoved(3), false},
		"icmp: a code of the type moved":            {icmp(3, 4), icmpMoved(3), true},
	} {
		declared, ok := declaredTraffic(tc.declared)
		if !ok {
			t.Fatalf("%s: declared rule unreadable", name)
		}
		if got := givesBack(declared, tc.moved); got != tc.want {
			t.Errorf("%s: gives back %v, want %v", name, got, tc.want)
		}
	}
}

func TestUndeclaredRestores(t *testing.T) {
	t.Parallel()
	https, ssh := tcpMatch(443, 443, "0.0.0.0/0"), tcpMatch(22, 22, "10.0.0.0/8")
	reverting := func(state string) *wireCustomerGroupChange {
		return &wireCustomerGroupChange{GroupID: "sg-web", Revoke: []wireRuleMatch{ssh},
			ChangeSets: []wireGroupChangeSet{{ID: "cs-1", State: state, Moves: []wireMovedRule{{wireRuleMatch: https}, {wireRuleMatch: ssh}}}}}
	}
	data := webRules()
	delete(data.Ingress, "https_all")
	delete(data.Ingress, "ssh_office")
	filterDeclaredRules(data, reverting("restoring"))
	if len(data.UndeclaredRestores) != 1 || data.UndeclaredRestores[0].FromPort.ValueInt64() != 443 ||
		data.UndeclaredRestores[0].CIDRIPv4.ValueString() != "0.0.0.0/0" || data.UndeclaredRestores[0].ChangeSet.ValueString() != "cs-1" ||
		!data.UndeclaredRestores[0].CIDRIPv6.IsNull() {
		t.Errorf("restores %+v, want 0.0.0.0/0:443 alone: 22 stays revoked for the change set that moves it again", data.UndeclaredRestores)
	}

	declared := webRules()
	declared.Ingress["https_lb"] = declaredRule("tcp", 443, "10.0.0.0/8")
	filterDeclaredRules(declared, reverting("restoring"))
	if len(declared.UndeclaredRestores) != 0 {
		t.Errorf("restores %+v, want none: the group declares the rule again, as protocol 6", declared.UndeclaredRestores)
	}
	if len(declared.Reopens) != 0 {
		t.Errorf("reopens %v, want none: a reverting change set gives the access back itself", reopenKeys(declared.Reopens))
	}

	open := webRules()
	delete(open.Ingress, "https_all")
	filterDeclaredRules(open, reverting("narrowing"))
	if len(open.UndeclaredRestores) != 0 {
		t.Errorf("restores %+v, want none while the change set is not reverting", open.UndeclaredRestores)
	}
}

// The fixture's attaching change set moves 0.0.0.0/0:443 out of web, which webRules declares as https_all.
func TestUndeclaredPending(t *testing.T) {
	t.Parallel()
	fixture := func() *wireCustomerGroupChange {
		return groupChangeOf(loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json"), "vpc-1", "web")
	}
	declared := webRules()
	filterDeclaredRules(declared, fixture())
	if len(declared.UndeclaredPending) != 0 {
		t.Errorf("pending %+v, want none: the group declares the moved rule, as protocol 6", declared.UndeclaredPending)
	}

	dropped := webRules()
	delete(dropped.Ingress, "https_all")
	withEgress := fixture()
	egress := tcpMatch(443, 443, "0.0.0.0/0")
	egress.Direction = "egress"
	withEgress.ChangeSets[0].Moves = append(withEgress.ChangeSets[0].Moves, wireMovedRule{wireRuleMatch: egress})
	filterDeclaredRules(dropped, withEgress)
	if len(dropped.UndeclaredPending) != 1 || dropped.UndeclaredPending[0].FromPort.ValueInt64() != 443 ||
		dropped.UndeclaredPending[0].CIDRIPv4.ValueString() != "0.0.0.0/0" || dropped.UndeclaredPending[0].ChangeSet.ValueString() != "cs-1" ||
		dropped.UndeclaredPending[0].Direction.ValueString() != "ingress" {
		t.Errorf("pending %+v, want the ingress 0.0.0.0/0:443 of cs-1: the egress one is declared as egress", dropped.UndeclaredPending)
	}
	if len(dropped.UndeclaredRestores) != 0 {
		t.Errorf("restores %+v, want none: the change set is not reverting", dropped.UndeclaredRestores)
	}

	narrowing := webRules()
	delete(narrowing.Ingress, "https_all")
	filterDeclaredRules(narrowing, groupChangeOf(narrowed(loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json")), "vpc-1", "web"))
	if len(narrowing.UndeclaredPending) != 0 {
		t.Errorf("pending %+v, want none: the change set leaves the rule out itself once it narrows", narrowing.UndeclaredPending)
	}

	revokedElsewhere := fixture()
	ssh := tcpMatch(22, 22, "10.0.0.0/8")
	revokedElsewhere.Revoke = []wireRuleMatch{ssh}
	revokedElsewhere.ChangeSets[0].Moves = append(revokedElsewhere.ChangeSets[0].Moves, wireMovedRule{wireRuleMatch: ssh})
	both := webRules()
	delete(both.Ingress, "https_all")
	delete(both.Ingress, "ssh_office")
	filterDeclaredRules(both, revokedElsewhere)
	if len(both.UndeclaredPending) != 1 || both.UndeclaredPending[0].FromPort.ValueInt64() != 443 {
		t.Errorf("pending %+v, want 0.0.0.0/0:443 alone: 22 is revoked already, so removing it takes nothing early", both.UndeclaredPending)
	}
}

func TestRulesFilterModelWithFindingsFitsTheDataSourceSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var resp datasource.SchemaResponse
	(&securityGroupRulesDataSource{}).Schema(ctx, datasource.SchemaRequest{}, &resp)
	data := webRules()
	data.Ingress["https_lb"] = declaredRule("tcp", 443, "10.0.0.0/8")
	delete(data.Ingress, "https_all")
	change := groupChangeOf(loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json"), "vpc-1", "web")
	restoring := *change
	restoring.ChangeSets = append(slices.Clone(change.ChangeSets), wireGroupChangeSet{ID: "cs-0", State: "restoring",
		Moves: []wireMovedRule{{wireRuleMatch: wireRuleMatch{Direction: "ingress", IPProtocol: "-1", CIDRIPv6: ptr("::/0")}}}})
	filterDeclaredRules(data, &restoring)
	if len(data.Reopens) == 0 || len(data.UndeclaredRestores) == 0 || len(data.UndeclaredPending) == 0 {
		t.Fatalf("reopens %v, restores %v and pending %v, want each set", reopenKeys(data.Reopens), data.UndeclaredRestores, data.UndeclaredPending)
	}
	state := tfsdk.State{Schema: resp.Schema}
	if diags := state.Set(ctx, data); diags.HasError() {
		t.Errorf("the model does not fit the schema, so every plan would fail: %v", diags)
	}
}
