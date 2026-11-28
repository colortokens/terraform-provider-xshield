package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &azureSecurityRulesDataSource{}
var _ datasource.DataSourceWithConfigure = &azureSecurityRulesDataSource{}

func newAzureSecurityRulesDataSource() datasource.DataSource {
	return &azureSecurityRulesDataSource{}
}

// azureSecurityRulesDataSource is how Xshield's rules reach a network security group of yours: Xshield writes a workload's
// rules into the group of yours its network interface, or for a subnet scope its subnet, carries.
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
			"a workload's rules into the group of yours on the network interface its enforcement scope names, or on its subnet for a " +
			"subnet scope or an interface that cannot take a group; each rule names only the workload's own addresses, so your rules " +
			"still decide the traffic of everything else the group covers. The `azure` enforcement module adds them to your group as " +
			"rules of their own, whatever your configuration declares. Where your configuration declares the group's rules inline, which " +
			"removes every rule it does not declare, pass those rules here as `declared_security_rules`, the rules the group holds as " +
			"`current_security_rules`, and give the group `security_rules` in their place, so its apply keeps Xshield's rules at the " +
			"priorities the module gives them. Give the group's resource ID as a string: the group's own `id` would make the group depend " +
			"on the rules it is given. Where your declared rules leave too few priorities free ahead of them, for Xshield's rules or for " +
			"workloads Xshield refused with `NO_FREE_PRIORITY` for want of room there, `security_rules` moves them up, in their order, by " +
			"as few priorities as those rules need, which your plan shows; the plan fails where Xshield's rules placed now would pass " +
			"priority 4096, and room for refused workloads that cannot be made is not made. When Xshield has no rules for the group, " +
			"`security_rules` is the declared rules unchanged, so your rules go back to the priorities your configuration gives them.",
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
					"Xshield's rules are numbered below the lowest priority among them in each direction, after moving them up where " +
					"they leave too little room.",
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
				MarkdownDescription: "The declared rules, moved up where Xshield's need room, followed by `xshield_security_rules`, every field set as azurerm reads a rule " +
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
	read := d.api.azureCustomerGroups(ctx, data.CloudAccountID.ValueString(), data.Region.ValueString(), data.Version)
	resp.Diagnostics.Append(read.diags...)
	if !read.ok {
		return
	}
	data.Published, data.Version = types.BoolValue(read.published), types.StringNull()
	xshield := []azInlineSecurityRuleModel{}
	if read.published {
		data.Version = types.StringValue(read.version)
		group, found := customerGroupWithID(read.groups, data.NetworkSecurityGroupID.ValueString())
		awaiting, awaits := read.roomWanted[strings.ToLower(data.NetworkSecurityGroupID.ValueString())]
		if !found {
			group.Name = awaiting.name
		}
		if found || awaits {
			moved, numbered, err := moveYoursUpForRoom(group.Name, group.SecurityRules, awaiting.priorities,
				priorityHolders(data.DeclaredSecurityRules), currentPriorityHolders(data.CurrentSecurityRules))
			if err != nil {
				resp.Diagnostics.AddError("Xshield's rules do not fit ahead of yours", err.Error())
				return
			}
			for i, r := range declared {
				if p, ok := moved[r.Name.ValueString()]; ok {
					declared[i].Priority = types.Int64Value(p)
				}
			}
			for _, r := range numbered {
				xshield = append(xshield, azureInlineRuleModel(r))
			}
			if field, n := azureAddressesPast(append(slices.Clone(declared), xshield...)); field != "" {
				resp.Diagnostics.AddError("Xshield's rules and yours pass what Azure holds in one group", fmt.Sprintf("your network security group "+
					"%s would hold rules naming %d %s, past Azure's limit of %d %s in a group's rules, so Azure would reject the group "+
					"part-way through the apply. Xshield refuses such a workload PREFIX_BUDGET once it sees your rules: name fewer "+
					"addresses or ports in your declared rules, or remove your group so Xshield places one of its own.",
					group.Name, n, field, azureAddressLimit, field))
				return
			}
			if n := len(declared) + len(xshield); n > azureRuleLimit {
				resp.Diagnostics.AddError("Xshield's rules and yours pass what Azure holds in one group", fmt.Sprintf("your network security group "+
					"%s would hold %d rules, past Azure's limit of %d rules in a group, so Azure would reject the group part-way through "+
					"the apply. Xshield refuses such a workload RULE_BUDGET once it sees your rules: declare fewer rules, or remove your "+
					"group so Xshield places one of its own.", group.Name, n, azureRuleLimit))
				return
			}
		}
	}
	data.XshieldSecurityRules = xshield
	data.SecurityRules = append(declared, xshield...)
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

// azureCustomerGroupsReads holds one snapshot read per provider configuration, subscription, region and pinned version for the
// run: every customer group's data source in a workspace reads the same snapshot, and one read gives them all one version.
var azureCustomerGroupsReads sync.Map

type azureCustomerGroupsKey struct {
	client                   *sdk.Xshield
	account, region, version string
}

type azureCustomerGroupsRead struct {
	once       sync.Once
	ok         bool
	diags      diag.Diagnostics
	published  bool
	version    string
	groups     map[string]wireAzureCustomerNetworkSecurityGroup
	roomWanted map[string]azureRoomAwaited
}

type azureRoomAwaited struct {
	name       string
	priorities map[string]int64
}

func (a cloudSnapshotAPI) azureCustomerGroups(ctx context.Context, account, region string, pinned types.String) *azureCustomerGroupsRead {
	key := azureCustomerGroupsKey{client: a.client, account: account, region: region}
	if !pinned.IsNull() && !pinned.IsUnknown() {
		key.version = pinned.ValueString()
	}
	value, _ := azureCustomerGroupsReads.LoadOrStore(key, &azureCustomerGroupsRead{})
	read := value.(*azureCustomerGroupsRead)
	read.once.Do(func() {
		snap, ok := fetchSnapshot(ctx, a, cloudAzure, account, region, pinned, false, &read.diags)
		read.ok = ok
		if snap != nil {
			read.published, read.version, read.groups = true, snap.Version, snap.Azure.CustomerNetworkSecurityGroups
			read.roomWanted = map[string]azureRoomAwaited{}
			for _, g := range snap.Azure.CustomerNetworkSecurityGroupsAwaitingRoom {
				read.roomWanted[strings.ToLower(g.ID)] = azureRoomAwaited{name: g.Name, priorities: g.PrioritiesWanted}
			}
		}
	})
	return read
}

// Azure caps each address and port field apart over a group's rules, counting `*`, a service tag or a single address as one.
const azureAddressLimit = 6000

const azureRuleLimit = 2000

func azureAddressesPast(rules []azInlineSecurityRuleModel) (string, int) {
	count := func(single types.String, many []types.String) int {
		if single.ValueString() != "" {
			return len(many) + 1
		}
		return len(many)
	}
	fields := []string{"source addresses", "destination addresses", "source port ranges", "destination port ranges"}
	load := make([]int, len(fields))
	for _, r := range rules {
		load[0] += count(r.SourceAddressPrefix, r.SourceAddressPrefixes)
		load[1] += count(r.DestinationAddressPrefix, r.DestinationAddressPrefixes)
		load[2] += count(r.SourcePortRange, r.SourcePortRanges)
		load[3] += count(r.DestinationPortRange, r.DestinationPortRanges)
	}
	for i, n := range load {
		if n > azureAddressLimit {
			return fields[i], n
		}
	}
	return "", 0
}

func customerGroupWithID(groups map[string]wireAzureCustomerNetworkSecurityGroup, id string) (wireAzureCustomerNetworkSecurityGroup, bool) {
	for _, g := range groups {
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
