package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &azureSecurityRulesDataSource{}
var _ datasource.DataSourceWithConfigure = &azureSecurityRulesDataSource{}

func newAzureSecurityRulesDataSource() datasource.DataSource {
	return &azureSecurityRulesDataSource{}
}

// azureSecurityRulesDataSource is how Xshield's rules reach a network security group of yours: Xshield writes a workload's
// rules into one when every network interface or subnet of the workload carries a group of yours.
type azureSecurityRulesDataSource struct {
	api cloudSnapshotAPI
}

// azInlineSecurityRuleModel has every field of azurerm's security_rule, so a list of them can be a group's rule set.
type azInlineSecurityRuleModel struct {
	Name                                   types.String   `tfsdk:"name"`
	Description                            types.String   `tfsdk:"description"`
	Priority                               types.Int64    `tfsdk:"priority"`
	Direction                              types.String   `tfsdk:"direction"`
	Access                                 types.String   `tfsdk:"access"`
	Protocol                               types.String   `tfsdk:"protocol"`
	SourceAddressPrefix                    types.String   `tfsdk:"source_address_prefix"`
	SourceAddressPrefixes                  []types.String `tfsdk:"source_address_prefixes"`
	SourceApplicationSecurityGroupIDs      []types.String `tfsdk:"source_application_security_group_ids"`
	DestinationAddressPrefix               types.String   `tfsdk:"destination_address_prefix"`
	DestinationAddressPrefixes             []types.String `tfsdk:"destination_address_prefixes"`
	DestinationApplicationSecurityGroupIDs []types.String `tfsdk:"destination_application_security_group_ids"`
	SourcePortRange                        types.String   `tfsdk:"source_port_range"`
	SourcePortRanges                       []types.String `tfsdk:"source_port_ranges"`
	DestinationPortRange                   types.String   `tfsdk:"destination_port_range"`
	DestinationPortRanges                  []types.String `tfsdk:"destination_port_ranges"`
}

type azRulePriorityModel struct {
	Name      types.String `tfsdk:"name"`
	Priority  types.Int64  `tfsdk:"priority"`
	Direction types.String `tfsdk:"direction"`
}

type azureSecurityRulesDataSourceModel struct {
	CloudAccountID         types.String                `tfsdk:"cloud_account_id"`
	Region                 types.String                `tfsdk:"region"`
	NetworkSecurityGroupID types.String                `tfsdk:"network_security_group_id"`
	Version                types.String                `tfsdk:"version"`
	Published              types.Bool                  `tfsdk:"published"`
	DeclaredSecurityRules  []azInlineSecurityRuleModel `tfsdk:"declared_security_rules"`
	CurrentSecurityRules   []azRulePriorityModel       `tfsdk:"current_security_rules"`
	XshieldSecurityRules   []azInlineSecurityRuleModel `tfsdk:"xshield_security_rules"`
	SecurityRules          []azInlineSecurityRuleModel `tfsdk:"security_rules"`
}

var azInlineSecurityRuleType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name": types.StringType, "description": types.StringType, "priority": types.Int64Type, "direction": types.StringType,
	"access": types.StringType, "protocol": types.StringType,
	"source_address_prefix": types.StringType, "source_address_prefixes": azStringsType, "source_application_security_group_ids": azStringsType,
	"destination_address_prefix": types.StringType, "destination_address_prefixes": azStringsType,
	"destination_application_security_group_ids": azStringsType,
	"source_port_range":                          types.StringType, "source_port_ranges": azStringsType,
	"destination_port_range": types.StringType, "destination_port_ranges": azStringsType,
}}

func (d *azureSecurityRulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_security_rules"
}

func (d *azureSecurityRulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	optionalString := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, MarkdownDescription: description}
	}
	optionalStrings := func(description string) schema.ListAttribute {
		return schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: description}
	}
	ruleFields := "Each rule has the fields of azurerm's `security_rule`: `name`, `description`, `priority`, `direction`, `access`, `protocol`, " +
		"`source_address_prefix` or `source_address_prefixes`, `source_application_security_group_ids`, `destination_address_prefix` or " +
		"`destination_address_prefixes`, `destination_application_security_group_ids`, `source_port_range` or `source_port_ranges`, and " +
		"`destination_port_range` or `destination_port_ranges`."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Gives Xshield's rules for one of your network security groups, numbered ahead of your rules. Xshield writes " +
			"a workload's rules into your subnet's group when every network interface or subnet of the workload carries a group of " +
			"yours; each rule names only the workload's own addresses, so your rules still decide the traffic of everything else the " +
			"group covers. The `azure` enforcement module adds them to your group as rules of their own. Where your configuration " +
			"declares the group's rules inline, which removes every rule it does not declare, pass those rules here as " +
			"`declared_security_rules`, give the group `security_rules` in their place, and list the group in the module's " +
			"`customer_network_security_groups_in_code`. Give the group's resource ID as a string: the group's own `id` would make " +
			"the group depend on the rules it is given. When Xshield has no rules for the group, `security_rules` is the declared " +
			"rules unchanged.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id":          schema.StringAttribute{Required: true, MarkdownDescription: "Azure subscription ID the group is in."},
			"region":                    schema.StringAttribute{Required: true, MarkdownDescription: "Azure region the group is in, by its name, such as `eastus2`."},
			"network_security_group_id": schema.StringAttribute{Required: true, MarkdownDescription: "Resource ID of your network security group."},
			"version": schema.StringAttribute{Optional: true, Computed: true,
				MarkdownDescription: "The snapshot version the rules are from. Set it to read the version an enforcement workspace applies, " +
					"as the `azure` enforcement module does. When omitted, the version Xshield expects is read."},
			"published": schema.BoolAttribute{Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this subscription and region; `xshield_security_rules` " +
					"is then empty and `version` null. Any other failure to read the snapshot fails the plan."},
			"declared_security_rules": schema.ListNestedAttribute{Optional: true,
				MarkdownDescription: "The rules your configuration declares for the group, with the arguments of azurerm's `security_rule`. " +
					"Xshield's rules are numbered below the lowest priority among them in each direction.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":                                  schema.StringAttribute{Required: true, MarkdownDescription: "Rule name. Xshield's rules are named `CT-Rule-` or `CT-Test-Rule-`, so yours cannot be."},
					"description":                           optionalString("Rule description."),
					"priority":                              schema.Int64Attribute{Required: true, MarkdownDescription: "Rule priority."},
					"direction":                             schema.StringAttribute{Required: true, MarkdownDescription: "`Inbound` or `Outbound`."},
					"access":                                schema.StringAttribute{Required: true, MarkdownDescription: "`Allow` or `Deny`."},
					"protocol":                              schema.StringAttribute{Required: true, MarkdownDescription: "Rule protocol."},
					"source_address_prefix":                 optionalString("Source address prefix."),
					"source_address_prefixes":               optionalStrings("Source address prefixes."),
					"source_application_security_group_ids": optionalStrings("Source application security groups."),
					"destination_address_prefix":            optionalString("Destination address prefix."),
					"destination_address_prefixes":          optionalStrings("Destination address prefixes."),
					"destination_application_security_group_ids": optionalStrings("Destination application security groups."),
					"source_port_range":                          optionalString("Source port range."),
					"source_port_ranges":                         optionalStrings("Source port ranges."),
					"destination_port_range":                     optionalString("Destination port range."),
					"destination_port_ranges":                    optionalStrings("Destination port ranges."),
				}},
			},
			"current_security_rules": schema.ListNestedAttribute{Optional: true,
				MarkdownDescription: "Every rule the group holds now, as azurerm's `azurerm_network_security_group` data source reads it. " +
					"Xshield's rules then keep the priorities they hold, and a rule that moves or is added takes a priority no rule holds, " +
					"so rules applied one at a time never collide. A rule of yours here also counts as one of yours.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":      schema.StringAttribute{Required: true, MarkdownDescription: "Rule name."},
					"priority":  schema.Int64Attribute{Required: true, MarkdownDescription: "Rule priority."},
					"direction": schema.StringAttribute{Required: true, MarkdownDescription: "`Inbound` or `Outbound`."},
				}},
			},
			"xshield_security_rules": schema.ListAttribute{Computed: true, ElementType: azInlineSecurityRuleType,
				MarkdownDescription: "Xshield's rules for the group, with the fields of azurerm's `security_rule`, each at a priority below " +
					"every rule of yours in its direction. " + ruleFields + " A single address or port is in the singular field with the " +
					"plural one empty; two or more are in the plural field with the singular one empty."},
			"security_rules": schema.ListAttribute{Computed: true, ElementType: azInlineSecurityRuleType,
				MarkdownDescription: "The declared rules followed by `xshield_security_rules`, every field set as azurerm reads a rule " +
					"back, so the list can be the group's `security_rule`. " + ruleFields},
		},
	}
}

func (d *azureSecurityRulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *azureSecurityRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data azureSecurityRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	declared := make([]azInlineSecurityRuleModel, 0, len(data.DeclaredSecurityRules))
	for _, r := range data.DeclaredSecurityRules {
		if isXshieldRuleName(r.Name.ValueString()) {
			resp.Diagnostics.AddError("A declared rule has a name Xshield gives its own rules",
				fmt.Sprintf("%s starts with CT-Rule- or CT-Test-Rule-, which name Xshield's rules. Rename it, and pass only the rules your configuration declares.", r.Name.ValueString()))
			return
		}
		declared = append(declared, asAzureReadsBack(r))
	}
	snap, ok := fetchSnapshot(ctx, d.api, cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), data.Version, false, &resp.Diagnostics)
	if !ok {
		return
	}
	data.Published, data.Version = types.BoolValue(snap != nil), types.StringNull()
	xshield := []azInlineSecurityRuleModel{}
	if snap != nil {
		data.Version = types.StringValue(snap.Version)
		group, found := customerGroupWithID(snap.Azure, data.NetworkSecurityGroupID.ValueString())
		if found {
			numbered, err := numberAheadOfYours(group.Name, group.SecurityRules, priorityHolders(data.DeclaredSecurityRules), currentPriorityHolders(data.CurrentSecurityRules))
			if err != nil {
				resp.Diagnostics.AddError("Xshield's rules do not fit ahead of yours", err.Error())
				return
			}
			for _, r := range numbered {
				xshield = append(xshield, azureInlineRuleModel(r))
			}
		}
	}
	data.XshieldSecurityRules = xshield
	data.SecurityRules = append(declared, xshield...)
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

func customerGroupWithID(plan *wireAzurePlan, id string) (wireAzureCustomerNetworkSecurityGroup, bool) {
	for _, g := range plan.CustomerNetworkSecurityGroups {
		if strings.EqualFold(g.ID, id) {
			return g, true
		}
	}
	return wireAzureCustomerNetworkSecurityGroup{}, false
}

func priorityHolders(rules []azInlineSecurityRuleModel) []azurePriorityHolder {
	holders := make([]azurePriorityHolder, 0, len(rules))
	for _, r := range rules {
		holders = append(holders, azurePriorityHolder{name: r.Name.ValueString(), direction: r.Direction.ValueString(), priority: r.Priority.ValueInt64()})
	}
	return holders
}

func currentPriorityHolders(rules []azRulePriorityModel) []azurePriorityHolder {
	holders := make([]azurePriorityHolder, 0, len(rules))
	for _, r := range rules {
		holders = append(holders, azurePriorityHolder{name: r.Name.ValueString(), direction: r.Direction.ValueString(), priority: r.Priority.ValueInt64()})
	}
	return holders
}

func azureInlineRuleModel(r wireAzureSecurityRule) azInlineSecurityRuleModel {
	m := azureRuleModel(r)
	return azInlineSecurityRuleModel{
		Name: m.Name, Description: types.StringValue(""), Priority: m.Priority, Direction: m.Direction, Access: m.Access, Protocol: m.Protocol,
		SourceAddressPrefix: m.SourceAddressPrefix, SourceAddressPrefixes: m.SourceAddressPrefixes, SourceApplicationSecurityGroupIDs: []types.String{},
		DestinationAddressPrefix: m.DestinationAddressPrefix, DestinationAddressPrefixes: m.DestinationAddressPrefixes,
		DestinationApplicationSecurityGroupIDs: []types.String{},
		SourcePortRange:                        m.SourcePortRange, SourcePortRanges: m.SourcePortRanges,
		DestinationPortRange: m.DestinationPortRange, DestinationPortRanges: m.DestinationPortRanges,
	}
}

// asAzureReadsBack gives a field the declaration leaves unset the empty value azurerm reads back for it, so the rule
// passed on unchanged plans no change once applied.
func asAzureReadsBack(r azInlineSecurityRuleModel) azInlineSecurityRuleModel {
	emptyIfNull := func(s types.String) types.String {
		if s.IsNull() {
			return types.StringValue("")
		}
		return s
	}
	emptyIfNil := func(l []types.String) []types.String {
		if l == nil {
			return []types.String{}
		}
		return l
	}
	r.Description, r.SourceAddressPrefix, r.DestinationAddressPrefix = emptyIfNull(r.Description), emptyIfNull(r.SourceAddressPrefix), emptyIfNull(r.DestinationAddressPrefix)
	r.SourcePortRange, r.DestinationPortRange = emptyIfNull(r.SourcePortRange), emptyIfNull(r.DestinationPortRange)
	r.SourceAddressPrefixes, r.DestinationAddressPrefixes = emptyIfNil(r.SourceAddressPrefixes), emptyIfNil(r.DestinationAddressPrefixes)
	r.SourceApplicationSecurityGroupIDs, r.DestinationApplicationSecurityGroupIDs = emptyIfNil(r.SourceApplicationSecurityGroupIDs), emptyIfNil(r.DestinationApplicationSecurityGroupIDs)
	r.SourcePortRanges, r.DestinationPortRanges = emptyIfNil(r.SourcePortRanges), emptyIfNil(r.DestinationPortRanges)
	return r
}
