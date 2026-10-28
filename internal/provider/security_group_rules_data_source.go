package provider

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &SecurityGroupRulesDataSource{}
var _ datasource.DataSourceWithConfigure = &SecurityGroupRulesDataSource{}

func NewSecurityGroupRulesDataSource() datasource.DataSource {
	return &SecurityGroupRulesDataSource{}
}

// SecurityGroupRulesDataSource is how Full control reaches a customer's own group in pipeline
// delivery: the group's code passes its rules through it and declares what comes back.
type SecurityGroupRulesDataSource struct {
	api cloudSnapshotAPI
}

type sgrRuleModel struct {
	IPProtocol                types.String `tfsdk:"ip_protocol"`
	FromPort                  types.Int64  `tfsdk:"from_port"`
	ToPort                    types.Int64  `tfsdk:"to_port"`
	CIDRIPv4                  types.String `tfsdk:"cidr_ipv4"`
	CIDRIPv6                  types.String `tfsdk:"cidr_ipv6"`
	PrefixListID              types.String `tfsdk:"prefix_list_id"`
	ReferencedSecurityGroupID types.String `tfsdk:"referenced_security_group_id"`
	Description               types.String `tfsdk:"description"`
	Tags                      types.Map    `tfsdk:"tags"`
}

type SecurityGroupRulesDataSourceModel struct {
	CloudAccountID types.String            `tfsdk:"cloud_account_id"`
	Region         types.String            `tfsdk:"region"`
	VPCID          types.String            `tfsdk:"vpc_id"`
	GroupName      types.String            `tfsdk:"group_name"`
	Version        types.Int64             `tfsdk:"version"`
	Published      types.Bool              `tfsdk:"published"`
	Ingress        map[string]sgrRuleModel `tfsdk:"ingress"`
	Egress         map[string]sgrRuleModel `tfsdk:"egress"`
	IngressRules   map[string]sgrRuleModel `tfsdk:"ingress_rules"`
	EgressRules    map[string]sgrRuleModel `tfsdk:"egress_rules"`
	Revoked        []types.String          `tfsdk:"revoked"`
	Pending        []types.String          `tfsdk:"pending"`
}

var sgrRuleType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"ip_protocol": types.StringType, "from_port": types.Int64Type, "to_port": types.Int64Type,
	"cidr_ipv4": types.StringType, "cidr_ipv6": types.StringType, "prefix_list_id": types.StringType,
	"referenced_security_group_id": types.StringType, "description": types.StringType, "tags": esTagsType,
}}

func (d *SecurityGroupRulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_security_group_rules"
}

// Schema takes the declared rules as nested attributes, so a rule sets only what it uses, and
// returns the rules to keep as a map of objects, which Terraform's test mocks can set.
func (d *SecurityGroupRulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	declared := func(direction string) schema.MapNestedAttribute {
		optional := func(description string) schema.StringAttribute {
			return schema.StringAttribute{Optional: true, MarkdownDescription: description}
		}
		return schema.MapNestedAttribute{
			Optional: true,
			MarkdownDescription: "The " + direction + " rules the group declares, keyed as your code keys them, with the arguments of " +
				"`aws_vpc_security_group_" + direction + "_rule`.",
			NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
				"ip_protocol":                  schema.StringAttribute{Required: true, MarkdownDescription: "`tcp`, `udp`, `icmp`, `icmpv6`, `-1`, or a protocol number."},
				"from_port":                    schema.Int64Attribute{Optional: true, MarkdownDescription: "Start of the port range, or the ICMP type."},
				"to_port":                      schema.Int64Attribute{Optional: true, MarkdownDescription: "End of the port range, or the ICMP code."},
				"cidr_ipv4":                    optional("IPv4 source or destination."),
				"cidr_ipv6":                    optional("IPv6 source or destination."),
				"prefix_list_id":               optional("Prefix list source or destination."),
				"referenced_security_group_id": optional("Security group source or destination."),
				"description":                  optional("Rule description, returned as given."),
				"tags":                         schema.MapAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Rule tags, returned as given."},
			}},
		}
	}
	kept := func(direction string) schema.MapAttribute {
		return schema.MapAttribute{Computed: true, ElementType: sgrRuleType,
			MarkdownDescription: "The declared " + direction + " rules to keep, under the same keys and with the same arguments. " +
				"Declare these with `aws_vpc_security_group_" + direction + "_rule`, not the input."}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Applies Full control to one of your own security groups when a Terraform pipeline delivers the account. " +
			"Pass the rules the group's code declares, and declare the rules that come back. When no approved change applies to the " +
			"group, every rule comes back unchanged. When Xshield narrows a broad rule, the rule is left out once every workload that " +
			"still needs it carries its `ct-cohort-` group, so no workload loses access part-way. Rules are matched by their content, " +
			"and the group by its name and VPC, so neither your code nor this data source needs AWS rule IDs.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, MarkdownDescription: "AWS account the group is in."},
			"region":           schema.StringAttribute{Required: true, MarkdownDescription: "AWS region the group is in."},
			"vpc_id":           schema.StringAttribute{Required: true, MarkdownDescription: "VPC the group is in."},
			"group_name":       schema.StringAttribute{Required: true, MarkdownDescription: "The group's name."},
			"version": schema.Int64Attribute{Optional: true, Computed: true,
				MarkdownDescription: "Pins a snapshot version. When omitted, the version Xshield expects is read."},
			"published": schema.BoolAttribute{Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this account and region; every declared rule " +
					"then comes back unchanged and `version` is null. Any other failure to read the snapshot fails the plan."},
			"ingress":       declared("ingress"),
			"egress":        declared("egress"),
			"ingress_rules": kept("ingress"),
			"egress_rules":  kept("egress"),
			"revoked": schema.ListAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "The declared rules left out, as `ingress/<key>` or `egress/<key>`."},
			"pending": schema.ListAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "The declared rules an approved change will leave out once every workload that keeps them carries its cohort."},
		},
	}
}

func (d *SecurityGroupRulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *SecurityGroupRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SecurityGroupRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	snap, ok := fetchSnapshot(ctx, d.api, data.CloudAccountID.ValueString(), data.Region.ValueString(), data.Version, &resp.Diagnostics)
	if !ok {
		return
	}
	var change *wireCustomerGroupChange
	data.Published, data.Version = types.BoolValue(snap != nil), types.Int64Null()
	if snap != nil {
		data.Version = types.Int64Value(snap.Version)
		change = groupChangeOf(*snap, data.VPCID.ValueString(), data.GroupName.ValueString())
	}
	filterDeclaredRules(&data, change)
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

// groupChangeOf finds the group by name and VPC; nil when no approved change applies to it.
func groupChangeOf(snap wireSnapshot, vpcID, name string) *wireCustomerGroupChange {
	if change, ok := snap.AWS.CustomerGroupChanges[vpcID+"/"+name]; ok {
		return &change
	}
	return nil
}

// filterDeclaredRules never returns a nil map or list, so an unchanged group plans cleanly.
func filterDeclaredRules(data *SecurityGroupRulesDataSourceModel, change *wireCustomerGroupChange) {
	data.IngressRules, data.EgressRules = map[string]sgrRuleModel{}, map[string]sgrRuleModel{}
	data.Revoked, data.Pending = []types.String{}, []types.String{}
	for _, dir := range []struct {
		name     string
		declared map[string]sgrRuleModel
		kept     map[string]sgrRuleModel
	}{{"ingress", data.Ingress, data.IngressRules}, {"egress", data.Egress, data.EgressRules}} {
		for _, key := range sortedKeys(dir.declared) {
			rule := dir.declared[key]
			if change != nil && matchesAny(dir.name, rule, change.Revoke) {
				data.Revoked = append(data.Revoked, types.StringValue(dir.name+"/"+key))
				continue
			}
			if change != nil && pendingMove(dir.name, rule, change) {
				data.Pending = append(data.Pending, types.StringValue(dir.name+"/"+key))
			}
			if rule.Tags.IsNull() || rule.Tags.IsUnknown() {
				rule.Tags = types.MapValueMust(types.StringType, map[string]attr.Value{})
			}
			dir.kept[key] = rule
		}
	}
}

func pendingMove(direction string, rule sgrRuleModel, change *wireCustomerGroupChange) bool {
	for _, cs := range change.ChangeSets {
		if cs.State == "attaching" && matchesAny(direction, rule, cs.Moves) {
			return true
		}
	}
	return false
}

func matchesAny(direction string, rule sgrRuleModel, matches []wireRuleMatch) bool {
	for _, m := range matches {
		if m.Direction == direction && ruleMatches(rule, m) {
			return true
		}
	}
	return false
}

// ruleMatches compares what AWS compares: protocol, ports where the protocol has them, and the peer.
func ruleMatches(rule sgrRuleModel, m wireRuleMatch) bool {
	if canonicalProtocol(rule.IPProtocol.ValueString()) != canonicalProtocol(m.IPProtocol) {
		return false
	}
	if m.FromPort != nil && (rule.FromPort.IsNull() || rule.FromPort.ValueInt64() != *m.FromPort || rule.ToPort.ValueInt64() != *m.ToPort) {
		return false
	}
	switch {
	case m.CIDRIPv4 != nil:
		return samePrefix(rule.CIDRIPv4, *m.CIDRIPv4)
	case m.CIDRIPv6 != nil:
		return samePrefix(rule.CIDRIPv6, *m.CIDRIPv6)
	case m.PrefixListID != nil:
		return rule.PrefixListID.ValueString() == *m.PrefixListID
	case m.ReferencedSecurityGroupID != nil:
		return groupOf(rule.ReferencedSecurityGroupID.ValueString()) == groupOf(*m.ReferencedSecurityGroupID)
	}
	return false
}

var protocolNames = map[string]string{"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "all": "-1"}

func canonicalProtocol(p string) string {
	p = strings.ToLower(p)
	if name, ok := protocolNames[p]; ok {
		return name
	}
	return p
}

func samePrefix(declared types.String, want string) bool {
	got, err := netip.ParsePrefix(declared.ValueString())
	if err != nil {
		return false
	}
	w, err := netip.ParsePrefix(want)
	return err == nil && got.Masked() == w.Masked()
}

// groupOf drops the "<account>/" another account's group is named with.
func groupOf(ref string) string {
	return ref[strings.LastIndex(ref, "/")+1:]
}
