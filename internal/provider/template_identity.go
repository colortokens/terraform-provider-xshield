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
// a reshuffle as a change. Keying by rule identity is what makes this safe: the
// previous key collapsed distinct rules onto one entry, so a template with two
// rules on the same port lost one of them here on every read.
func reorderToStateOrder[T any](apiItems, stateItems []T, key func(T) string) []T {
	remaining := make(map[string]T, len(apiItems))
	apiOrder := make([]string, 0, len(apiItems))
	for _, item := range apiItems {
		k := key(item)
		if _, seen := remaining[k]; !seen {
			apiOrder = append(apiOrder, k)
		}
		remaining[k] = item
	}

	ordered := make([]T, 0, len(apiItems))
	take := func(k string) {
		if item, ok := remaining[k]; ok {
			ordered = append(ordered, item)
			delete(remaining, k)
		}
	}
	for _, stateItem := range stateItems {
		take(key(stateItem))
	}
	for _, k := range apiOrder {
		take(k)
	}
	return ordered
}
