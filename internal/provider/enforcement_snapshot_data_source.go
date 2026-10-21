package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &EnforcementSnapshotDataSource{}
var _ datasource.DataSourceWithConfigure = &EnforcementSnapshotDataSource{}

func NewEnforcementSnapshotDataSource() datasource.DataSource {
	return &EnforcementSnapshotDataSource{}
}

// EnforcementSnapshotDataSource only reads: the customer's pipeline performs
// every cloud write from what it returns.
type EnforcementSnapshotDataSource struct {
	api cloudSnapshotAPI
}

type esRuleModel struct {
	Key                types.String `tfsdk:"key"`
	Group              types.String `tfsdk:"group"`
	Direction          types.String `tfsdk:"direction"`
	Protocol           types.String `tfsdk:"protocol"`
	FromPort           types.Int64  `tfsdk:"from_port"`
	ToPort             types.Int64  `tfsdk:"to_port"`
	PeerType           types.String `tfsdk:"peer_type"`
	PeerRef            types.String `tfsdk:"peer_ref"`
	ProvenanceSegment  types.String `tfsdk:"provenance_segment"`
	ProvenanceTemplate types.String `tfsdk:"provenance_template"`
}

type esGroupModel struct {
	Slug         types.String   `tfsdk:"slug"`
	DisplayName  types.String   `tfsdk:"display_name"`
	VPCIDs       []types.String `tfsdk:"vpc_ids"`
	MarkerSlugs  []types.String `tfsdk:"marker_slugs"`
	IngressCount types.Int64    `tfsdk:"ingress_count"`
	EgressCount  types.Int64    `tfsdk:"egress_count"`
}

type esMarkerModel struct {
	Slug types.String `tfsdk:"slug"`
	Name types.String `tfsdk:"name"`
}

type esPrefixListModel struct {
	Slug          types.String   `tfsdk:"slug"`
	Name          types.String   `tfsdk:"name"`
	AddressFamily types.String   `tfsdk:"address_family"`
	Entries       []types.String `tfsdk:"entries"`
}

type esDirectoryModel struct {
	Path      types.String   `tfsdk:"path"`
	Group     types.String   `tfsdk:"group"`
	SGRefKeys []types.String `tfsdk:"sg_ref_keys"`
}

type EnforcementSnapshotDataSourceModel struct {
	CloudAccountID    types.String        `tfsdk:"cloud_account_id"`
	Region            types.String        `tfsdk:"region"`
	Version           types.Int64         `tfsdk:"version"`
	ContentHash       types.String        `tfsdk:"content_hash"`
	QuarantinedAssets types.Int64         `tfsdk:"quarantined_assets"`
	BindingKeys       []types.String      `tfsdk:"binding_keys"`
	EnforcementGroups []esGroupModel      `tfsdk:"enforcement_groups"`
	Rules             []esRuleModel       `tfsdk:"rules"`
	Markers           []esMarkerModel     `tfsdk:"markers"`
	PrefixLists       []esPrefixListModel `tfsdk:"prefix_lists"`
	Directory         []esDirectoryModel  `tfsdk:"directory"`
	PayloadJSON       types.String        `tfsdk:"payload_json"`
}

func (d *EnforcementSnapshotDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_snapshot"
}

func (d *EnforcementSnapshotDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	str := func() schema.StringAttribute { return schema.StringAttribute{Computed: true} }
	strList := func() schema.ListAttribute {
		return schema.ListAttribute{Computed: true, ElementType: types.StringType}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Resolves the expected (or a pinned) cloud enforcement snapshot for an account and region, and exposes its enforcement groups, composed rules, markers, prefix lists and the tag-keyed workload directory for rendering.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true},
			"region":           schema.StringAttribute{Required: true},
			"version": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Pins a version for break-glass or forensics. When omitted, the server-side expected version is resolved, which is what lets the configuration stay static while policy changes.",
			},
			"content_hash":       str(),
			"quarantined_assets": schema.Int64Attribute{Computed: true},
			"binding_keys": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Tag keys, in order, whose values form a directory path. Workloads resolve their group from these tags.",
			},
			"payload_json": str(),
			"enforcement_groups": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"slug":          str(),
					"display_name":  str(),
					"vpc_ids":       strList(),
					"marker_slugs":  strList(),
					"ingress_count": schema.Int64Attribute{Computed: true},
					"egress_count":  schema.Int64Attribute{Computed: true},
				}},
			},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"key":                 str(),
					"group":               str(),
					"direction":           str(),
					"protocol":            str(),
					"from_port":           schema.Int64Attribute{Computed: true},
					"to_port":             schema.Int64Attribute{Computed: true},
					"peer_type":           str(),
					"peer_ref":            str(),
					"provenance_segment":  str(),
					"provenance_template": str(),
				}},
			},
			"markers": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"slug": str(),
					"name": str(),
				}},
			},
			"prefix_lists": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"slug":           str(),
					"name":           str(),
					"address_family": str(),
					"entries":        strList(),
				}},
			},
			"directory": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"path":        str(),
					"group":       str(),
					"sg_ref_keys": strList(),
				}},
			},
		},
	}
}

func (d *EnforcementSnapshotDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError("unexpected data source configure type", fmt.Sprintf("expected *sdk.Xshield, got %T", req.ProviderData))
		return
	}
	d.api = cloudSnapshotAPI{client: client}
}

type wireSnapshot struct {
	Version           int      `json:"version"`
	ContentHash       string   `json:"contentHash"`
	BindingKeys       []string `json:"bindingKeys"`
	EnforcementGroups map[string]struct {
		Slug        string         `json:"slug"`
		DisplayName string         `json:"displayName"`
		VPCIDs      []string       `json:"vpcIds"`
		MarkerSlugs []string       `json:"markerSlugs"`
		RuleCounts  map[string]int `json:"ruleCounts"`
	} `json:"enforcementGroups"`
	Rules []struct {
		Key       string `json:"key"`
		Group     string `json:"group"`
		Direction string `json:"direction"`
		Protocol  string `json:"protocol"`
		FromPort  int    `json:"fromPort"`
		ToPort    int    `json:"toPort"`
		Peer      struct {
			Type       string `json:"type"`
			Group      string `json:"group"`
			Marker     string `json:"marker"`
			PrefixList string `json:"prefixList"`
			CIDR       string `json:"cidr"`
		} `json:"peer"`
		Provenance struct {
			Segment  string `json:"segment"`
			Template string `json:"template"`
		} `json:"provenance"`
	} `json:"rules"`
	Markers map[string]struct {
		Name string `json:"name"`
	} `json:"markers"`
	PrefixLists map[string]struct {
		Name          string   `json:"name"`
		AddressFamily string   `json:"addressFamily"`
		Entries       []string `json:"entries"`
	} `json:"prefixLists"`
	Directory []struct {
		Path      string   `json:"path"`
		Group     string   `json:"group"`
		SGRefKeys []string `json:"sgRefKeys"`
	} `json:"directory"`
	Conformance struct {
		QuarantinedAssets int `json:"quarantinedAssets"`
	} `json:"conformance"`
}

type wireExpected struct {
	Version     int    `json:"version"`
	ContentHash string `json:"contentHash"`
}

func (d *EnforcementSnapshotDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data EnforcementSnapshotDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}

	account, region := data.CloudAccountID.ValueString(), data.Region.ValueString()
	version := data.Version.ValueInt64()
	if data.Version.IsNull() || data.Version.IsUnknown() {
		var exp wireExpected
		if err := d.api.get(ctx, d.api.endpoint(account, region, "expected"), &exp); err != nil {
			resp.Diagnostics.AddError("failed to resolve expected snapshot version", err.Error())
			return
		}
		version = int64(exp.Version)
	}

	var snap wireSnapshot
	if err := d.api.get(ctx, d.api.endpoint(account, region, "versions", strconv.FormatInt(version, 10)), &snap); err != nil {
		resp.Diagnostics.AddError("failed to fetch enforcement snapshot", err.Error())
		return
	}

	raw, _ := json.Marshal(snap)
	data.PayloadJSON = types.StringValue(string(raw))
	data.Version = types.Int64Value(int64(snap.Version))
	data.ContentHash = types.StringValue(snap.ContentHash)
	data.QuarantinedAssets = types.Int64Value(int64(snap.Conformance.QuarantinedAssets))
	data.BindingKeys = toStrList(snap.BindingKeys)

	// Lists are always non-nil and always sorted: map iteration order is random,
	// and an unstable order in state would show as a diff on every plan.
	data.EnforcementGroups = []esGroupModel{}
	data.Rules = []esRuleModel{}
	data.Markers = []esMarkerModel{}
	data.PrefixLists = []esPrefixListModel{}
	data.Directory = []esDirectoryModel{}

	for _, slug := range sortedKeys(snap.EnforcementGroups) {
		g := snap.EnforcementGroups[slug]
		data.EnforcementGroups = append(data.EnforcementGroups, esGroupModel{
			Slug:         types.StringValue(g.Slug),
			DisplayName:  types.StringValue(g.DisplayName),
			VPCIDs:       toStrList(g.VPCIDs),
			MarkerSlugs:  toStrList(g.MarkerSlugs),
			IngressCount: types.Int64Value(int64(g.RuleCounts["ingress"])),
			EgressCount:  types.Int64Value(int64(g.RuleCounts["egress"])),
		})
	}
	for _, r := range snap.Rules {
		pt, pr := peerTypeRef(r.Peer.Type, r.Peer.Group, r.Peer.Marker, r.Peer.PrefixList, r.Peer.CIDR)
		data.Rules = append(data.Rules, esRuleModel{
			Key:                types.StringValue(r.Key),
			Group:              types.StringValue(r.Group),
			Direction:          types.StringValue(r.Direction),
			Protocol:           types.StringValue(r.Protocol),
			FromPort:           types.Int64Value(int64(r.FromPort)),
			ToPort:             types.Int64Value(int64(r.ToPort)),
			PeerType:           types.StringValue(pt),
			PeerRef:            types.StringValue(pr),
			ProvenanceSegment:  types.StringValue(r.Provenance.Segment),
			ProvenanceTemplate: types.StringValue(r.Provenance.Template),
		})
	}
	for _, slug := range sortedKeys(snap.Markers) {
		data.Markers = append(data.Markers, esMarkerModel{
			Slug: types.StringValue(slug),
			Name: types.StringValue(snap.Markers[slug].Name),
		})
	}
	for _, slug := range sortedKeys(snap.PrefixLists) {
		p := snap.PrefixLists[slug]
		data.PrefixLists = append(data.PrefixLists, esPrefixListModel{
			Slug:          types.StringValue(slug),
			Name:          types.StringValue(p.Name),
			AddressFamily: types.StringValue(p.AddressFamily),
			Entries:       toStrList(p.Entries),
		})
	}
	for _, e := range snap.Directory {
		data.Directory = append(data.Directory, esDirectoryModel{
			Path:      types.StringValue(e.Path),
			Group:     types.StringValue(e.Group),
			SGRefKeys: toStrList(e.SGRefKeys),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// peerTypeRef passes an unrecognised peer type through verbatim rather than
// coercing it to a CIDR, so the renderer can refuse what it cannot render.
func peerTypeRef(t, group, marker, pl, cidr string) (string, string) {
	switch t {
	case "group":
		return t, group
	case "marker":
		return t, marker
	case "prefixList":
		return t, pl
	case "cidr":
		return t, cidr
	default:
		return t, ""
	}
}

func toStrList(in []string) []types.String {
	out := make([]types.String, 0, len(in))
	for _, s := range in {
		out = append(out, types.StringValue(s))
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
