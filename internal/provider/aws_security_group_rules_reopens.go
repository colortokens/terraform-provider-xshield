package provider

import (
	"net/netip"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	changeSetAttaching = "attaching"
	changeSetNarrowing = "narrowing"
	changeSetRestoring = "restoring"
	allPorts           = -1
	maxPort            = 65535
)

type sgrReopenModel struct {
	Rule      types.String `tfsdk:"rule"`
	ChangeSet types.String `tfsdk:"change_set"`
}

type sgrMoveModel struct {
	Direction                 types.String `tfsdk:"direction"`
	IPProtocol                types.String `tfsdk:"ip_protocol"`
	FromPort                  types.Int64  `tfsdk:"from_port"`
	ToPort                    types.Int64  `tfsdk:"to_port"`
	CIDRIPv4                  types.String `tfsdk:"cidr_ipv4"`
	CIDRIPv6                  types.String `tfsdk:"cidr_ipv6"`
	PrefixListID              types.String `tfsdk:"prefix_list_id"`
	ReferencedSecurityGroupID types.String `tfsdk:"referenced_security_group_id"`
	ChangeSet                 types.String `tfsdk:"change_set"`
}

// reopenedBy names the open change set whose moved traffic the declared rule gives back to a member that does not keep it.
func reopenedBy(direction string, rule sgrRuleModel, change *wireCustomerGroupChange) string {
	declared, ok := declaredTraffic(rule)
	if !ok {
		return ""
	}
	for _, cs := range change.ChangeSets {
		if (cs.State != changeSetAttaching && cs.State != changeSetNarrowing) || matchesAnyMove(direction, rule, cs.Moves) {
			continue
		}
		for _, moved := range cs.Moves {
			if moved.Direction == direction && givesBack(declared, moved) {
				return cs.ID
			}
		}
	}
	return ""
}

// undeclaredMoves are the moved rules of the change sets in the state that the group declares no longer. A rule the change
// revokes stays out whatever the code declares, so a revert does not wait on it and removing it takes no access.
func undeclaredMoves(data *awsSecurityGroupRulesDataSourceModel, change *wireCustomerGroupChange, state string) []sgrMoveModel {
	out := []sgrMoveModel{}
	for _, cs := range change.ChangeSets {
		if cs.State != state {
			continue
		}
		for _, moved := range cs.Moves {
			declared := data.DeclaredIngressRules
			if moved.Direction == "egress" {
				declared = data.DeclaredEgressRules
			}
			if slices.ContainsFunc(change.Revoke, func(r wireRuleMatch) bool { return sameMatch(r, moved.wireRuleMatch) }) ||
				declaresMatch(declared, moved.wireRuleMatch) {
				continue
			}
			out = append(out, moveModel(moved.wireRuleMatch, cs.ID))
		}
	}
	return out
}

func declaresMatch(declared map[string]sgrRuleModel, m wireRuleMatch) bool {
	for _, rule := range declared {
		if ruleMatches(rule, m) {
			return true
		}
	}
	return false
}

func matchesAnyMove(direction string, rule sgrRuleModel, moves []wireMovedRule) bool {
	return slices.ContainsFunc(moves, func(m wireMovedRule) bool { return m.Direction == direction && ruleMatches(rule, m.wireRuleMatch) })
}

func sameMatch(a, b wireRuleMatch) bool {
	samePtr := func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	sameInt := func(x, y *int64) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return a.Direction == b.Direction && canonicalProtocol(a.IPProtocol) == canonicalProtocol(b.IPProtocol) &&
		sameInt(a.FromPort, b.FromPort) && sameInt(a.ToPort, b.ToPort) && samePtr(a.CIDRIPv4, b.CIDRIPv4) && samePtr(a.CIDRIPv6, b.CIDRIPv6) &&
		samePtr(a.PrefixListID, b.PrefixListID) && samePtr(a.ReferencedSecurityGroupID, b.ReferencedSecurityGroupID)
}

func moveModel(m wireRuleMatch, changeSet string) sgrMoveModel {
	optional := func(s *string) types.String {
		if s == nil {
			return types.StringNull()
		}
		return types.StringValue(*s)
	}
	port := func(p *int64) types.Int64 {
		if p == nil {
			return types.Int64Null()
		}
		return types.Int64Value(*p)
	}
	return sgrMoveModel{Direction: types.StringValue(m.Direction), IPProtocol: types.StringValue(m.IPProtocol), FromPort: port(m.FromPort),
		ToPort: port(m.ToPort), CIDRIPv4: optional(m.CIDRIPv4), CIDRIPv6: optional(m.CIDRIPv6), PrefixListID: optional(m.PrefixListID),
		ReferencedSecurityGroupID: optional(m.ReferencedSecurityGroupID), ChangeSet: types.StringValue(changeSet)}
}

// traffic is a rule's access: TCP and UDP by port range; ICMP by type in from and code in to, -1 for every one.
type traffic struct {
	protocol string
	from, to int64
	peer     peer
}

type peer struct {
	prefix netip.Prefix
	id     string
}

func declaredTraffic(rule sgrRuleModel) (traffic, bool) {
	p, ok := peerOf(rule.CIDRIPv4, rule.CIDRIPv6, rule.PrefixListID, rule.ReferencedSecurityGroupID)
	return trafficOf(rule.IPProtocol.ValueString(), int64Or(rule.FromPort), int64Or(rule.ToPort), p), ok
}

func matchTraffic(m wireRuleMatch) (traffic, bool) {
	p, ok := peerOf(types.StringPointerValue(m.CIDRIPv4), types.StringPointerValue(m.CIDRIPv6), types.StringPointerValue(m.PrefixListID),
		types.StringPointerValue(m.ReferencedSecurityGroupID))
	from, to := int64(allPorts), int64(allPorts)
	if m.FromPort != nil {
		from = *m.FromPort
	}
	if m.ToPort != nil {
		to = *m.ToPort
	}
	return trafficOf(m.IPProtocol, from, to, p), ok
}

func int64Or(v types.Int64) int64 {
	if v.IsNull() || v.IsUnknown() {
		return allPorts
	}
	return v.ValueInt64()
}

func trafficOf(protocol string, from, to int64, p peer) traffic {
	t := traffic{protocol: canonicalProtocol(protocol), from: from, to: to, peer: p}
	if hasPortRange(t.protocol) && from == allPorts {
		t.from, t.to = 0, maxPort
	}
	return t
}

func hasPortRange(protocol string) bool { return protocol == "tcp" || protocol == "udp" }

func hasTypeAndCode(protocol string) bool { return protocol == "icmp" || protocol == "icmpv6" }

// peerOf reads the one peer a rule names; a group by its own id, since another account's is named "<account>/<group>".
func peerOf(v4, v6, prefixList, group types.String) (peer, bool) {
	for _, cidr := range []types.String{v4, v6} {
		if cidr.IsNull() || cidr.IsUnknown() {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr.ValueString())
		return peer{prefix: prefix.Masked()}, err == nil
	}
	switch {
	case !prefixList.IsNull() && !prefixList.IsUnknown():
		return peer{id: "pl:" + prefixList.ValueString()}, true
	case !group.IsNull() && !group.IsUnknown():
		return peer{id: "sg:" + groupOf(group.ValueString())}, true
	}
	return peer{}, false
}

// within: a group or prefix list matches only itself, since its addresses are not known at plan time.
func (p peer) within(outer peer) bool {
	if p.id != "" || outer.id != "" {
		return p.id == outer.id
	}
	return p.prefix.Addr().Is4() == outer.prefix.Addr().Is4() && outer.prefix.Bits() <= p.prefix.Bits() && outer.prefix.Contains(p.prefix.Addr())
}

func sharedPeer(a, b peer) (peer, bool) {
	switch {
	case a.within(b):
		return a, true
	case b.within(a):
		return b, true
	}
	return peer{}, false
}

// givesBack: the declared rule allows traffic of the moved rule that some member does not keep.
func givesBack(declared traffic, moved wireMovedRule) bool {
	m, ok := matchTraffic(moved.wireRuleMatch)
	if !ok {
		return false
	}
	shared, ok := sharedTraffic(declared, m)
	if !ok {
		return false
	}
	kept := []traffic{}
	for _, k := range moved.KeptByEveryMember {
		if t, ok := matchTraffic(k); ok && shared.peer.within(t.peer) {
			kept = append(kept, t)
		}
	}
	return !covered(shared, kept)
}

// sharedTraffic is the access both rules allow, if any.
func sharedTraffic(a, b traffic) (traffic, bool) {
	p, ok := sharedPeer(a.peer, b.peer)
	if !ok {
		return traffic{}, false
	}
	switch {
	case a.protocol == "-1":
		b.peer = p
		return b, true
	case b.protocol == "-1":
		a.peer = p
		return a, true
	case a.protocol != b.protocol:
		return traffic{}, false
	case hasPortRange(a.protocol):
		from, to := max(a.from, b.from), min(a.to, b.to)
		return traffic{protocol: a.protocol, from: from, to: to, peer: p}, from <= to
	case hasTypeAndCode(a.protocol):
		icmpType, okType := sharedCode(a.from, b.from)
		code, okCode := sharedCode(a.to, b.to)
		return traffic{protocol: a.protocol, from: icmpType, to: code, peer: p}, okType && okCode
	}
	return traffic{protocol: a.protocol, peer: p}, true
}

func sharedCode(a, b int64) (int64, bool) {
	switch {
	case a == allPorts:
		return b, true
	case b == allPorts || a == b:
		return a, true
	}
	return 0, false
}

// covered: the kept traffic, all of the shared peer, allows every part of the shared access.
func covered(shared traffic, kept []traffic) bool {
	if slices.ContainsFunc(kept, func(k traffic) bool { return k.protocol == "-1" }) {
		return true
	}
	if shared.protocol == "-1" {
		return false
	}
	same := slices.DeleteFunc(slices.Clone(kept), func(k traffic) bool { return k.protocol != shared.protocol })
	switch {
	case hasPortRange(shared.protocol):
		next := shared.from
		slices.SortFunc(same, func(a, b traffic) int { return int(a.from - b.from) })
		for _, k := range same {
			if k.from <= next && next <= k.to {
				next = k.to + 1
			}
		}
		return next > shared.to
	case hasTypeAndCode(shared.protocol):
		return slices.ContainsFunc(same, func(k traffic) bool { return coversCode(k.from, shared.from) && coversCode(k.to, shared.to) })
	}
	return len(same) > 0
}

func coversCode(kept, shared int64) bool { return kept == allPorts || kept == shared }
