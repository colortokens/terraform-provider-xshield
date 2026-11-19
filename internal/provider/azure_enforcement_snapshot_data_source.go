package provider

import (
	"context"
	"fmt"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &azureEnforcementSnapshotDataSource{}
var _ datasource.DataSourceWithConfigure = &azureEnforcementSnapshotDataSource{}

func newAzureEnforcementSnapshotDataSource() datasource.DataSource {
	return &azureEnforcementSnapshotDataSource{}
}

type azureEnforcementSnapshotDataSource struct {
	api cloudSnapshotAPI
}

type azNetworkSecurityGroupModel struct {
	Name              types.String          `tfsdk:"name"`
	ResourceGroupName types.String          `tfsdk:"resource_group_name"`
	Location          types.String          `tfsdk:"location"`
	Tags              map[string]string     `tfsdk:"tags"`
	SecurityRules     []azSecurityRuleModel `tfsdk:"security_rules"`
}

type azSecurityRuleModel struct {
	Name                       types.String   `tfsdk:"name"`
	Priority                   types.Int64    `tfsdk:"priority"`
	Direction                  types.String   `tfsdk:"direction"`
	Access                     types.String   `tfsdk:"access"`
	Protocol                   types.String   `tfsdk:"protocol"`
	SourceAddressPrefix        types.String   `tfsdk:"source_address_prefix"`
	SourceAddressPrefixes      []types.String `tfsdk:"source_address_prefixes"`
	DestinationAddressPrefix   types.String   `tfsdk:"destination_address_prefix"`
	DestinationAddressPrefixes []types.String `tfsdk:"destination_address_prefixes"`
	SourcePortRange            types.String   `tfsdk:"source_port_range"`
	SourcePortRanges           []types.String `tfsdk:"source_port_ranges"`
	DestinationPortRange       types.String   `tfsdk:"destination_port_range"`
	DestinationPortRanges      []types.String `tfsdk:"destination_port_ranges"`
}

type azSubnetAssociationModel struct {
	NetworkSecurityGroup types.String `tfsdk:"network_security_group"`
	SubnetID             types.String `tfsdk:"subnet_id"`
}

type azInterfaceAssociationModel struct {
	NetworkSecurityGroup types.String `tfsdk:"network_security_group"`
	NetworkInterfaceID   types.String `tfsdk:"network_interface_id"`
}

type azHeldAssociationModel struct {
	LevelID                types.String `tfsdk:"level_id"`
	NetworkSecurityGroupID types.String `tfsdk:"network_security_group_id"`
}

type azAssetModel struct {
	Level                 types.String   `tfsdk:"level"`
	NetworkSecurityGroups []types.String `tfsdk:"network_security_groups"`
}

type azureEnforcementSnapshotDataSourceModel struct {
	CloudAccountID        types.String                           `tfsdk:"cloud_account_id"`
	Region                types.String                           `tfsdk:"region"`
	EnforcementPlan       types.Bool                             `tfsdk:"enforcement_plan"`
	Published             types.Bool                             `tfsdk:"published"`
	Version               types.String                           `tfsdk:"version"`
	NetworkSecurityGroups map[string]azNetworkSecurityGroupModel `tfsdk:"network_security_groups"`
	SubnetAssociations    map[string]azSubnetAssociationModel    `tfsdk:"subnet_associations"`
	InterfaceAssociations map[string]azInterfaceAssociationModel `tfsdk:"interface_associations"`
	Assets                map[string]azAssetModel                `tfsdk:"assets"`

	HeldInterfaceAssociations     map[string]azHeldAssociationModel `tfsdk:"held_interface_associations"`
	HeldSubnetAssociations        map[string]azHeldAssociationModel `tfsdk:"held_subnet_associations"`
	ReleasedInterfaceAssociations map[string]types.String           `tfsdk:"released_interface_associations"`
	ReleasedSubnetAssociations    map[string]types.String           `tfsdk:"released_subnet_associations"`
}

type wireAzureHeldAssociation struct {
	LevelID                string `json:"levelId"`
	NetworkSecurityGroupID string `json:"networkSecurityGroupId"`
}

type wireAzureSecurityRule struct {
	Name                       string   `json:"name"`
	Priority                   int64    `json:"priority"`
	Direction                  string   `json:"direction"`
	Access                     string   `json:"access"`
	Protocol                   string   `json:"protocol"`
	SourceAddressPrefixes      []string `json:"sourceAddressPrefixes"`
	DestinationAddressPrefixes []string `json:"destinationAddressPrefixes"`
	SourcePortRanges           []string `json:"sourcePortRanges"`
	DestinationPortRanges      []string `json:"destinationPortRanges"`
}

type wireAzurePlan struct {
	NetworkSecurityGroups map[string]struct {
		Name              string                  `json:"name"`
		ResourceGroupName string                  `json:"resourceGroupName"`
		Location          string                  `json:"location"`
		Tags              map[string]string       `json:"tags"`
		SecurityRules     []wireAzureSecurityRule `json:"securityRules"`
	} `json:"networkSecurityGroups"`
	SubnetAssociations map[string]struct {
		NetworkSecurityGroup string `json:"networkSecurityGroup"`
		SubnetID             string `json:"subnetId"`
	} `json:"subnetAssociations"`
	InterfaceAssociations map[string]struct {
		NetworkSecurityGroup string `json:"networkSecurityGroup"`
		NetworkInterfaceID   string `json:"networkInterfaceId"`
	} `json:"interfaceAssociations"`
	Assets map[string]struct {
		Level                 string   `json:"level"`
		NetworkSecurityGroups []string `json:"networkSecurityGroups"`
	} `json:"assets"`
	HeldInterfaceAssociations     map[string]wireAzureHeldAssociation `json:"heldInterfaceAssociations"`
	HeldSubnetAssociations        map[string]wireAzureHeldAssociation `json:"heldSubnetAssociations"`
	ReleasedInterfaceAssociations map[string]string                   `json:"releasedInterfaceAssociations"`
	ReleasedSubnetAssociations    map[string]string                   `json:"releasedSubnetAssociations"`
}

func (d *azureEnforcementSnapshotDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_enforcement_snapshot"
}

var (
	azStringsType         = types.ListType{ElemType: types.StringType}
	azHeldAssociationType = types.ObjectType{AttrTypes: map[string]attr.Type{"level_id": types.StringType, "network_security_group_id": types.StringType}}
	azSecurityRuleType    = types.ObjectType{AttrTypes: map[string]attr.Type{
		"name": types.StringType, "priority": types.Int64Type, "direction": types.StringType, "access": types.StringType,
		"protocol": types.StringType, "source_address_prefix": types.StringType, "source_address_prefixes": azStringsType,
		"destination_address_prefix": types.StringType, "destination_address_prefixes": azStringsType,
		"source_port_range": types.StringType, "source_port_ranges": azStringsType,
		"destination_port_range": types.StringType, "destination_port_ranges": azStringsType,
	}}
)

func (d *azureEnforcementSnapshotDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	objects := func(elem attr.Type, description string) schema.MapAttribute {
		return schema.MapAttribute{Computed: true, ElementType: elem, MarkdownDescription: description}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Fetches the Azure resources Xshield expects in one subscription and region, already rendered: a network " +
			"security group of Xshield's own for each network interface or subnet it enforces at, with the group's whole rule set, " +
			"and the association that puts each group there. Xshield places its group only on a network interface or subnet " +
			"that carries no group of yours, so your groups are never changed, and Azure applies both. The groups and " +
			"associations are keyed by the group's name, so a plan names the group each change is for.\n\n" +
			"Use it through the `azure` enforcement module, which creates these resources.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, MarkdownDescription: "Azure subscription ID the snapshot is for."},
			"region":           schema.StringAttribute{Required: true, MarkdownDescription: "Azure region the snapshot is for, by its name, such as `eastus2`."},
			"version": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "The snapshot's version, which is the hash of everything it asks for. Set it to pin a version, " +
					"for break-glass rollback or forensics. When omitted, the version Xshield expects is fetched, so the " +
					"configuration never changes when policy does.",
			},
			"enforcement_plan": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Set to `true` where this read is the enforcement workspace's plan, as the `azure` enforcement " +
					"module sets it. Xshield then records the read as the pipeline's `last_checked_at`, and refuses it once the " +
					"subscription is handed back to the cloud connector. Leave it unset for a read made to review the snapshot, so " +
					"that the read cannot hide a stopped pipeline.",
			},
			"published": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this subscription and region, such as before " +
					"the subscription is onboarded with policy delivery set to Terraform pipeline: every map is empty and `version` " +
					"is null, so a configuration built on it plans no change. Only Xshield's own answer that nothing is published " +
					"counts; any other failure to read the snapshot fails the plan.",
			},
			"network_security_groups": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"name": types.StringType, "resource_group_name": types.StringType, "location": types.StringType,
				"tags": types.MapType{ElemType: types.StringType}, "security_rules": types.ListType{ElemType: azSecurityRuleType},
			}}, "One network security group per network interface or subnet Xshield enforces at, keyed by its name. "+
				"`name`: `ct-policy-` and a hash of the network interface or subnet, fixed for the group's life. "+
				"`resource_group_name`: resource group the group is created in, that of its network interface or subnet. "+
				"`location`: region the group is created in. "+
				"`tags`: `ct:delivery` and `ct:level`, which let the cloud connector recognise the group as Xshield's, never as one of yours. "+
				"`security_rules`: the group's whole rule set, which replaces any rule the group holds that it does not list. "+
				"Each rule has Azure's fields: `name`, `priority`, `direction`, `access` and `protocol`, and the source and "+
				"destination as `source_address_prefix` or `source_address_prefixes`, `destination_address_prefix` or "+
				"`destination_address_prefixes`, `source_port_range` or `source_port_ranges`, and `destination_port_range` or "+
				"`destination_port_ranges`. A single value, which is how Azure takes `*` and a service tag, is in the singular "+
				"field with the plural one empty; two or more are in the plural field with the singular one empty. Every rule "+
				"set ends with an allow of all traffic in each direction at priority 4096, so traffic no Xshield rule decides "+
				"passes as it did before the group, and lets the load balancer's health probes in at priority 100."),
			"subnet_associations": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"network_security_group": types.StringType, "subnet_id": types.StringType,
			}}, "Each subnet a group goes on, keyed by the group's name. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`subnet_id`: resource ID of the subnet to associate it with."),
			"interface_associations": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"network_security_group": types.StringType, "network_interface_id": types.StringType,
			}}, "Each network interface a group goes on, keyed by the group's name. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`network_interface_id`: resource ID of the network interface to associate it with."),
			"assets": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"level": types.StringType, "network_security_groups": azStringsType,
			}}, "Where each Xshield asset is enforced, keyed by Xshield asset ID. "+
				"`level`: `networkInterface` or `subnet`. Null when the asset was refused, when its policy writes no rule, or when Xshield enforces it nowhere. "+
				"`network_security_groups`: keys, in `network_security_groups`, of the groups that carry the asset's rules. "+
				"Empty when `level` is null."),
			"held_interface_associations": objects(azHeldAssociationType, "Associations an earlier apply made whose network "+
				"interface now carries a network security group of yours in place of Xshield's, keyed by Xshield's group name. "+
				"Azure removes an association by taking whatever group its network interface carries off it, so removing one of "+
				"these would remove your group. The `azure` enforcement module keeps each in its state unchanged while the "+
				"network interface carries a group other than Xshield's, and Xshield drops it once the interface carries none. "+
				"`level_id`: resource ID of the network interface. "+
				"`network_security_group_id`: resource ID of the group the apply associated, as the state holds it."),
			"held_subnet_associations": objects(azHeldAssociationType, "As `held_interface_associations`, for a subnet. "+
				"`level_id`: resource ID of the subnet. "+
				"`network_security_group_id`: resource ID of the group the apply associated. azurerm reads a subnet "+
				"association's group back from the subnet, so the module gives a held one the group the subnet carries now."),
			"released_interface_associations": schema.MapAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "Associations an earlier apply made that this version removes, keyed by Xshield's group " +
					"name, each with its network interface's resource ID. The `azure` enforcement module reads each network " +
					"interface before it plans the removal, and fails the plan when the interface carries a group other than " +
					"Xshield's, so a group of yours put there since Xshield last observed the subscription is never removed."},
			"released_subnet_associations": schema.MapAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "As `released_interface_associations`, for a subnet, with the subnet's resource ID."},
		},
	}
}

func (d *azureEnforcementSnapshotDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *azureEnforcementSnapshotDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data azureEnforcementSnapshotDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}
	snap, ok := fetchSnapshot(ctx, d.api, cloudAzure, data.CloudAccountID.ValueString(), data.Region.ValueString(), data.Version, data.EnforcementPlan.ValueBool(), &resp.Diagnostics)
	if !ok {
		return
	}
	model := azureSnapshotModel(data.CloudAccountID, data.Region, snap)
	model.EnforcementPlan = data.EnforcementPlan
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func azureSnapshotModel(account, region types.String, snap *wireSnapshot) azureEnforcementSnapshotDataSourceModel {
	m := azureEnforcementSnapshotDataSourceModel{
		CloudAccountID:        account,
		Region:                region,
		Published:             types.BoolValue(snap != nil),
		Version:               types.StringNull(),
		NetworkSecurityGroups: map[string]azNetworkSecurityGroupModel{},
		SubnetAssociations:    map[string]azSubnetAssociationModel{},
		InterfaceAssociations: map[string]azInterfaceAssociationModel{},
		Assets:                map[string]azAssetModel{},

		HeldInterfaceAssociations:     map[string]azHeldAssociationModel{},
		HeldSubnetAssociations:        map[string]azHeldAssociationModel{},
		ReleasedInterfaceAssociations: map[string]types.String{},
		ReleasedSubnetAssociations:    map[string]types.String{},
	}
	if snap == nil {
		return m
	}
	plan := snap.Azure
	m.Version = types.StringValue(snap.Version)
	for key, g := range plan.NetworkSecurityGroups {
		rules := make([]azSecurityRuleModel, 0, len(g.SecurityRules))
		for _, r := range g.SecurityRules {
			rules = append(rules, azureRuleModel(r))
		}
		m.NetworkSecurityGroups[key] = azNetworkSecurityGroupModel{Name: types.StringValue(g.Name), ResourceGroupName: types.StringValue(g.ResourceGroupName),
			Location: types.StringValue(g.Location), Tags: nonNilTags(g.Tags), SecurityRules: rules}
	}
	for key, a := range plan.SubnetAssociations {
		m.SubnetAssociations[key] = azSubnetAssociationModel{NetworkSecurityGroup: types.StringValue(a.NetworkSecurityGroup), SubnetID: types.StringValue(a.SubnetID)}
	}
	for key, a := range plan.InterfaceAssociations {
		m.InterfaceAssociations[key] = azInterfaceAssociationModel{NetworkSecurityGroup: types.StringValue(a.NetworkSecurityGroup),
			NetworkInterfaceID: types.StringValue(a.NetworkInterfaceID)}
	}
	for id, a := range plan.Assets {
		m.Assets[id] = azAssetModel{Level: optionalString(a.Level), NetworkSecurityGroups: toStrList(a.NetworkSecurityGroups)}
	}
	for key, h := range plan.HeldInterfaceAssociations {
		m.HeldInterfaceAssociations[key] = azHeldAssociationModel{LevelID: types.StringValue(h.LevelID), NetworkSecurityGroupID: types.StringValue(h.NetworkSecurityGroupID)}
	}
	for key, h := range plan.HeldSubnetAssociations {
		m.HeldSubnetAssociations[key] = azHeldAssociationModel{LevelID: types.StringValue(h.LevelID), NetworkSecurityGroupID: types.StringValue(h.NetworkSecurityGroupID)}
	}
	for key, levelID := range plan.ReleasedInterfaceAssociations {
		m.ReleasedInterfaceAssociations[key] = types.StringValue(levelID)
	}
	for key, levelID := range plan.ReleasedSubnetAssociations {
		m.ReleasedSubnetAssociations[key] = types.StringValue(levelID)
	}
	return m
}

func azureRuleModel(r wireAzureSecurityRule) azSecurityRuleModel {
	sourceAddress, sourceAddresses := singleOrPlural(r.SourceAddressPrefixes)
	destinationAddress, destinationAddresses := singleOrPlural(r.DestinationAddressPrefixes)
	sourcePort, sourcePorts := singleOrPlural(r.SourcePortRanges)
	destinationPort, destinationPorts := singleOrPlural(r.DestinationPortRanges)
	return azSecurityRuleModel{
		Name: types.StringValue(r.Name), Priority: types.Int64Value(r.Priority), Direction: types.StringValue(r.Direction),
		Access: types.StringValue(r.Access), Protocol: types.StringValue(r.Protocol),
		SourceAddressPrefix: sourceAddress, SourceAddressPrefixes: sourceAddresses,
		DestinationAddressPrefix: destinationAddress, DestinationAddressPrefixes: destinationAddresses,
		SourcePortRange: sourcePort, SourcePortRanges: sourcePorts,
		DestinationPortRange: destinationPort, DestinationPortRanges: destinationPorts,
	}
}

// singleOrPlural splits a list as Azure's rule fields take it, since Azure refuses `*` and a service tag in a plural
// field. The empty forms are what azurerm reads back for a field Azure left unset, so a rule passed on unchanged plans
// no change once applied.
func singleOrPlural(values []string) (types.String, []types.String) {
	if len(values) == 1 {
		return types.StringValue(values[0]), []types.String{}
	}
	return types.StringValue(""), toStrList(values)
}
