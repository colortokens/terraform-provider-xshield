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

var _ datasource.DataSource = &awsSecurityGroupRulesDataSource{}
var _ datasource.DataSourceWithConfigure = &awsSecurityGroupRulesDataSource{}

func newAWSSecurityGroupRulesDataSource() datasource.DataSource {
	return &awsSecurityGroupRulesDataSource{}
}

// awsSecurityGroupRulesDataSource is how Full control reaches a customer's own group in pipeline
// delivery: the group's code passes its rules through it and declares what comes back.
type awsSecurityGroupRulesDataSource struct {
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

type awsSecurityGroupRulesDataSourceModel struct {
	CloudAccountID           types.String            `tfsdk:"cloud_account_id"`
	Region                   types.String            `tfsdk:"region"`
	VPCID                    types.String            `tfsdk:"vpc_id"`
	GroupName                types.String            `tfsdk:"group_name"`
	Version                  types.String            `tfsdk:"version"`
	Published                types.Bool              `tfsdk:"published"`
	DeclaredIngressRules     map[string]sgrRuleModel `tfsdk:"declared_ingress_rules"`
	DeclaredEgressRules      map[string]sgrRuleModel `tfsdk:"declared_egress_rules"`
	IngressRules             map[string]sgrRuleModel `tfsdk:"ingress_rules"`
	EgressRules              map[string]sgrRuleModel `tfsdk:"egress_rules"`
	RevokedRules             []types.String          `tfsdk:"revoked_rules"`
	PendingRules             []types.String          `tfsdk:"pending_rules"`
	SecurityGroupID          types.String            `tfsdk:"security_group_id"`
	ReopeningRules           []sgrReopenModel        `tfsdk:"reopening_rules"`
	UndeclaredRestoringRules []sgrMoveModel          `tfsdk:"undeclared_restoring_rules"`
	UndeclaredPendingRules   []sgrMoveModel          `tfsdk:"undeclared_pending_rules"`
}

var sgrRuleType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"ip_protocol": types.StringType, "from_port": types.Int64Type, "to_port": types.Int64Type,
	"cidr_ipv4": types.StringType, "cidr_ipv6": types.StringType, "prefix_list_id": types.StringType,
	"referenced_security_group_id": types.StringType, "description": types.StringType, "tags": esTagsType,
}}

var sgrReopenType = types.ObjectType{AttrTypes: map[string]attr.Type{"rule": types.StringType, "change_set": types.StringType}}

var sgrMoveType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"direction": types.StringType, "ip_protocol": types.StringType, "from_port": types.Int64Type, "to_port": types.Int64Type,
	"cidr_ipv4": types.StringType, "cidr_ipv6": types.StringType, "prefix_list_id": types.StringType,
	"referenced_security_group_id": types.StringType, "change_set": types.StringType,
}}

func (d *awsSecurityGroupRulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_security_group_rules"
}

// Schema takes the declared rules as nested attributes, so a rule sets only what it uses, and
// returns the rules to keep as a map of objects, which Terraform's test mocks can set.
func (d *awsSecurityGroupRulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
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
				"Declare these with `aws_vpc_security_group_" + direction + "_rule`, not the input. " +
				"Each holds what its declared rule holds: `ip_protocol`, `from_port`, `to_port`, `cidr_ipv4`, `cidr_ipv6`, " +
				"`prefix_list_id`, `referenced_security_group_id`, `description` and `tags`."}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Applies Full control to one of your own security groups when a Terraform pipeline delivers the account. " +
			"Pass the rules the group's code declares, and declare the rules that come back. When no approved change applies to the " +
			"group, every rule comes back unchanged. When Xshield narrows a broad rule, the rule is left out once every workload that " +
			"still needs it carries its `ct-cohort-` group, so no workload loses access part-way. Rules are matched by their content, " +
			"and the group by its name and VPC, so neither your code nor this data source needs AWS rule IDs. Read it only for a " +
			"group `xshield_aws_security_group_changes` lists: another group plans without it, even where its VPC or rules are values " +
			"the plan learns only at apply. A group it is read for needs its VPC and every declared rule known when the plan " +
			"runs, so a rule naming a security group the same plan creates goes in after that group is applied.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, MarkdownDescription: "AWS account the group is in."},
			"region":           schema.StringAttribute{Required: true, MarkdownDescription: "AWS region the group is in."},
			"vpc_id":           schema.StringAttribute{Required: true, MarkdownDescription: "VPC the group is in."},
			"group_name":       schema.StringAttribute{Required: true, MarkdownDescription: "The group's name."},
			"version": schema.StringAttribute{Computed: true,
				MarkdownDescription: "Version of the changes to customer groups Xshield published for the account and region, which it " +
					"publishes apart from the enforcement snapshot, so a released change needs no enforcement apply."},
			"published": schema.BoolAttribute{Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this account and region; every declared rule " +
					"then comes back unchanged and `version` is null. Any other failure to read the changes fails the plan."},
			"declared_ingress_rules": declared("ingress"),
			"declared_egress_rules":  declared("egress"),
			"ingress_rules":          kept("ingress"),
			"egress_rules":           kept("egress"),
			"revoked_rules": schema.ListAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "The declared rules left out, as `ingress/<key>` or `egress/<key>`."},
			"pending_rules": schema.ListAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "The declared rules an approved change will leave out once every workload that keeps them carries its cohort."},
			"security_group_id": schema.StringAttribute{Computed: true,
				MarkdownDescription: "The group's AWS ID while an approved change applies to it, and null otherwise. The optional policy " +
					"checks use it to find the group's rules in a plan."},
			"reopening_rules": schema.ListAttribute{Computed: true, ElementType: sgrReopenType,
				MarkdownDescription: "The declared rules that give a workload in the group traffic an approved change takes from it, each as " +
					"`rule` (`ingress/<key>` or `egress/<key>`) with the `change_set` it undoes part of. Every workload in the group gets a " +
					"rule's traffic, including the workloads the change narrowed. A rule that is exactly the moved rule is in `pending_rules` or " +
					"`revoked_rules` instead, and a rule that allows only traffic every workload keeps through the change is not listed. A rule " +
					"naming a security group or prefix list is compared only with moved rules naming the same one."},
			"undeclared_restoring_rules": schema.ListAttribute{Computed: true, ElementType: sgrMoveType,
				MarkdownDescription: "The rules a revert puts back that the group no longer declares, each with the `change_set` being " +
					"reverted. The revert waits until the group holds them again, keeping the access every workload has now; declare them " +
					"to end it. " +
					"`direction`: `ingress` or `egress`. `ip_protocol`, `from_port`, `to_port`: the rule's protocol and ports. " +
					"`cidr_ipv4`, `cidr_ipv6`, `prefix_list_id`, `referenced_security_group_id`: the rule's source or destination."},
			"undeclared_pending_rules": schema.ListAttribute{Computed: true, ElementType: sgrMoveType,
				MarkdownDescription: "The rules an approved change will leave out once every workload that keeps them carries its cohort, " +
					"which the group no longer declares, each with the `change_set` that moves it. Until then the group must hold them: a " +
					"plan that removes one takes its traffic from those workloads early. Declare them again, and Xshield leaves each out " +
					"once it is safe. A rule a change already leaves out is not listed. " +
					"`direction`: `ingress` or `egress`. `ip_protocol`, `from_port`, `to_port`: the rule's protocol and ports. " +
					"`cidr_ipv4`, `cidr_ipv6`, `prefix_list_id`, `referenced_security_group_id`: the rule's source or destination."},
		},
	}
}

func (d *awsSecurityGroupRulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *awsSecurityGroupRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data awsSecurityGroupRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	changes, published, diags := d.api.publishedGroupChanges(ctx, data.CloudAccountID.ValueString(), data.Region.ValueString())
	if resp.Diagnostics.Append(diags...); diags.HasError() {
		return
	}
	var change *wireCustomerGroupChange
	data.Published, data.Version = types.BoolValue(published), types.StringNull()
	if published {
		data.Version = types.StringValue(changes.Version)
		change = groupChangeOf(changes, data.VPCID.ValueString(), data.GroupName.ValueString())
	}
	filterDeclaredRules(&data, change)
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

// groupChangeOf finds the group by name and VPC; nil when no approved change applies to it.
func groupChangeOf(changes wireCustomerGroupChanges, vpcID, name string) *wireCustomerGroupChange {
	if change, ok := changes.Groups[vpcID+"/"+name]; ok {
		return &change
	}
	return nil
}

// filterDeclaredRules never returns a nil map or list, so an unchanged group plans cleanly.
func filterDeclaredRules(data *awsSecurityGroupRulesDataSourceModel, change *wireCustomerGroupChange) {
	data.IngressRules, data.EgressRules = map[string]sgrRuleModel{}, map[string]sgrRuleModel{}
	data.RevokedRules, data.PendingRules = []types.String{}, []types.String{}
	data.SecurityGroupID, data.ReopeningRules = types.StringNull(), []sgrReopenModel{}
	data.UndeclaredRestoringRules, data.UndeclaredPendingRules = []sgrMoveModel{}, []sgrMoveModel{}
	if change != nil && change.GroupID != "" {
		data.SecurityGroupID = types.StringValue(change.GroupID)
	}
	for _, dir := range []struct {
		name     string
		declared map[string]sgrRuleModel
		kept     map[string]sgrRuleModel
	}{{"ingress", data.DeclaredIngressRules, data.IngressRules}, {"egress", data.DeclaredEgressRules, data.EgressRules}} {
		for _, key := range sortedKeys(dir.declared) {
			rule := dir.declared[key]
			if change != nil && matchesAny(dir.name, rule, change.Revoke) {
				data.RevokedRules = append(data.RevokedRules, types.StringValue(dir.name+"/"+key))
				continue
			}
			if change != nil && pendingMove(dir.name, rule, change) {
				data.PendingRules = append(data.PendingRules, types.StringValue(dir.name+"/"+key))
			}
			if change != nil {
				if changeSet := reopenedBy(dir.name, rule, change); changeSet != "" {
					data.ReopeningRules = append(data.ReopeningRules, sgrReopenModel{Rule: types.StringValue(dir.name + "/" + key), ChangeSet: types.StringValue(changeSet)})
				}
			}
			dir.kept[key] = rule
		}
	}
	if change != nil {
		data.UndeclaredRestoringRules = undeclaredMoves(data, change, changeSetRestoring)
		data.UndeclaredPendingRules = undeclaredMoves(data, change, changeSetAttaching)
	}
}

func pendingMove(direction string, rule sgrRuleModel, change *wireCustomerGroupChange) bool {
	for _, cs := range change.ChangeSets {
		if cs.State == changeSetAttaching && matchesAnyMove(direction, rule, cs.Moves) {
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
	if m.FromPort != nil && !(samePort(rule.FromPort, m.FromPort) && samePort(rule.ToPort, m.ToPort)) {
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

func samePort(declared types.Int64, want *int64) bool {
	if want == nil {
		return declared.IsNull()
	}
	return !declared.IsNull() && declared.ValueInt64() == *want
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
