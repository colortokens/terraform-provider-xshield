package provider

import (
	"strings"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
)

// Template rules have no stable server id to diff against: the backend derives
// both ids from the rule's own content, so editing a rule changes its id. These
// helpers rebuild the same identity locally, which is what lets Update tell an
// edited rule from a new one.

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func namedNetworkKey(ref *tfTypes.MetadataNamedNetworkReference) string {
	if ref == nil {
		return ""
	}
	return firstNonEmpty(ref.NamedNetworkID.ValueString(), ref.NamedNetworkName.ValueString())
}

func tagBasedPolicyKey(ref *tfTypes.MetadataTagBasedPolicyReference) string {
	if ref == nil {
		return ""
	}
	return firstNonEmpty(ref.TagBasedPolicyID.ValueString(), ref.TagBasedPolicyName.ValueString())
}

// templatePortKey identifies a listening port within a template. The backend
// hashes port, end port, protocol and direction; template ports carry a single
// direction, so port and protocol are enough here.
func templatePortKey(port tfTypes.MetadataPort) string {
	return strings.Join([]string{
		port.ListenPort.ValueString(),
		port.ListenPortProtocol.ValueString(),
	}, "|")
}

// templatePathKey identifies a path rule within a template.
//
// Keying on port, protocol and direction alone was not an identity: two inbound
// rules opening 443/TCP to different sources collapsed onto one key, so Read
// dropped one of them from state and Update diffed the survivor against the
// wrong rule. The peer selectors are what distinguish them, exactly as they do
// in the backend's channel hash.
func templatePathKey(p tfTypes.MetadataPath) string {
	source := firstNonEmpty(
		tagBasedPolicyKey(p.SourceTagBasedPolicy),
		p.SourceAssetID.ValueString(),
		namedNetworkKey(p.SourceNamedNetwork),
		p.SrcIP.ValueString(),
	)
	destination := firstNonEmpty(
		tagBasedPolicyKey(p.DestinationTagBasedPolicy),
		p.DestinationAssetID.ValueString(),
		namedNetworkKey(p.DestinationNamedNetwork),
		p.Domain.ValueString(),
		p.DstIP.ValueString(),
	)
	return strings.Join([]string{
		p.Direction.ValueString(),
		source,
		destination,
		p.Port.ValueString(),
		p.Protocol.ValueString(),
		p.Method.ValueString(),
		p.URI.ValueString(),
		p.SrcProcess.ValueString(),
		p.DstProcess.ValueString(),
	}, "|")
}

// templatePathKeysMatch reports whether two paths are the same rule.
func templatePathKeysMatch(a, b tfTypes.MetadataPath) bool {
	return templatePathKey(a) == templatePathKey(b)
}

// reorderToStateOrder returns the items the API reported, ordered to match the
// order already held in state, with anything the API added appended after.
//
// Terraform compares lists positionally, so returning the API's order would show
// a reshuffle as a change. Each state item takes the API item its first identity
// names, or its next where that one names none, so a field a newer read fills in
// moves no item whose earlier identity still matches.
func reorderToStateOrder[T any](apiItems, stateItems []T, identities ...func(T) string) []T {
	firstWith := make([]map[string]int, len(identities))
	for n, identity := range identities {
		firstWith[n] = make(map[string]int, len(apiItems))
		for i, item := range apiItems {
			if k := identity(item); k != "" {
				if _, seen := firstWith[n][k]; !seen {
					firstWith[n][k] = i
				}
			}
		}
	}

	taken := make([]bool, len(apiItems))
	ordered := make([]T, 0, len(apiItems))
	for _, stateItem := range stateItems {
		for n, identity := range identities {
			if i, ok := firstWith[n][identity(stateItem)]; ok && !taken[i] {
				taken[i] = true
				ordered = append(ordered, apiItems[i])
				break
			}
		}
	}
	for i, item := range apiItems {
		if !taken[i] {
			ordered = append(ordered, item)
		}
	}
	return ordered
}

func templatePathID(p tfTypes.MetadataPath) string {
	return p.ID.ValueString()
}
