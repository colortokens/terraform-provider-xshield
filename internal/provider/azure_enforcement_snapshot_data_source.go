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
	Level                         types.String   `tfsdk:"level"`
	NetworkSecurityGroups         []types.String `tfsdk:"network_security_groups"`
	CustomerNetworkSecurityGroups []types.String `tfsdk:"customer_network_security_groups"`
}

type azCustomerNetworkSecurityGroupModel struct {
	ID                types.String              `tfsdk:"id"`
	ResourceGroupName types.String              `tfsdk:"resource_group_name"`
	Name              types.String              `tfsdk:"name"`
	SecurityRules     []azSecurityRuleModel     `tfsdk:"security_rules"`
	Subnets           map[string][]types.String `tfsdk:"subnets"`
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

	HandoverSubnetAssociations    map[string]azSubnetAssociationModel    `tfsdk:"handover_subnet_associations"`
	HandoverInterfaceAssociations map[string]azInterfaceAssociationModel `tfsdk:"handover_interface_associations"`

	Assets map[string]azAssetModel `tfsdk:"assets"`

	CustomerNetworkSecurityGroups map[string]azCustomerNetworkSecurityGroupModel `tfsdk:"customer_network_security_groups"`

	HeldInterfaceAssociations     map[string]azHeldAssociationModel `tfsdk:"held_interface_associations"`
	HeldSubnetAssociations        map[string]azHeldAssociationModel `tfsdk:"held_subnet_associations"`
	ReleasedInterfaceAssociations map[string]types.String           `tfsdk:"released_interface_associations"`
	ReleasedSubnetAssociations    map[string]types.String           `tfsdk:"released_subnet_associations"`

	ContainedInterfaceAssociations map[string]azHeldAssociationModel `tfsdk:"contained_interface_associations"`
	ContainedSubnetAssociations    map[string]azHeldAssociationModel `tfsdk:"contained_subnet_associations"`
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

type wireAzureCustomerNetworkSecurityGroup struct {
	ID                string                  `json:"id"`
	ResourceGroupName string                  `json:"resourceGroupName"`
	Name              string                  `json:"name"`
	SecurityRules     []wireAzureSecurityRule `json:"securityRules"`
	Subnets           map[string][]string     `json:"subnets"`
}

type wireAzureSubnetAssociation struct {
	NetworkSecurityGroup string `json:"networkSecurityGroup"`
	SubnetID             string `json:"subnetId"`
}

type wireAzureInterfaceAssociation struct {
	NetworkSecurityGroup string `json:"networkSecurityGroup"`
	NetworkInterfaceID   string `json:"networkInterfaceId"`
}

type wireAzurePlan struct {
	NetworkSecurityGroups map[string]struct {
		Name              string                  `json:"name"`
		ResourceGroupName string                  `json:"resourceGroupName"`
		Location          string                  `json:"location"`
		Tags              map[string]string       `json:"tags"`
		SecurityRules     []wireAzureSecurityRule `json:"securityRules"`
	} `json:"networkSecurityGroups"`
	SubnetAssociations            map[string]wireAzureSubnetAssociation    `json:"subnetAssociations"`
	InterfaceAssociations         map[string]wireAzureInterfaceAssociation `json:"interfaceAssociations"`
	HandoverSubnetAssociations    map[string]wireAzureSubnetAssociation    `json:"handoverSubnetAssociations"`
	HandoverInterfaceAssociations map[string]wireAzureInterfaceAssociation `json:"handoverInterfaceAssociations"`
	Assets                        map[string]struct {
		Level                         string   `json:"level"`
		NetworkSecurityGroups         []string `json:"networkSecurityGroups"`
		CustomerNetworkSecurityGroups []string `json:"customerNetworkSecurityGroups"`
	} `json:"assets"`
	CustomerNetworkSecurityGroups  map[string]wireAzureCustomerNetworkSecurityGroup `json:"customerNetworkSecurityGroups"`
	HeldInterfaceAssociations      map[string]wireAzureHeldAssociation              `json:"heldInterfaceAssociations"`
	HeldSubnetAssociations         map[string]wireAzureHeldAssociation              `json:"heldSubnetAssociations"`
	ReleasedInterfaceAssociations  map[string]string                                `json:"releasedInterfaceAssociations"`
	ReleasedSubnetAssociations     map[string]string                                `json:"releasedSubnetAssociations"`
	ContainedInterfaceAssociations map[string]wireAzureHeldAssociation              `json:"containedInterfaceAssociations"`
	ContainedSubnetAssociations    map[string]wireAzureHeldAssociation              `json:"containedSubnetAssociations"`
}

func (d *azureEnforcementSnapshotDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_enforcement_snapshot"
}

var (
	azStringsType              = types.ListType{ElemType: types.StringType}
	azSubnetAssociationType    = types.ObjectType{AttrTypes: map[string]attr.Type{"network_security_group": types.StringType, "subnet_id": types.StringType}}
	azInterfaceAssociationType = types.ObjectType{AttrTypes: map[string]attr.Type{"network_security_group": types.StringType, "network_interface_id": types.StringType}}
	azHeldAssociationType      = types.ObjectType{AttrTypes: map[string]attr.Type{"level_id": types.StringType, "network_security_group_id": types.StringType}}
	azSecurityRuleType         = types.ObjectType{AttrTypes: map[string]attr.Type{
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
			"and the association that puts each group there. Xshield places its group on a network interface or subnet that " +
			"carries no group of yours, and Azure applies both. Where every network interface or subnet of a workload carries a " +
			"group of yours, Xshield's rules for the workload go into your subnet's group instead, ahead of your rules and naming " +
			"only the workload's own addresses, so your rules still decide the traffic of everything else the group covers. " +
			"The groups and associations are keyed by `ct-policy-` and a hash of their network interface or subnet, which stays " +
			"the same when a group's name comes from the subscription's name template, so a plan names the level each change is for.\n\n" +
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
			}}, "One network security group per network interface or subnet Xshield enforces at, keyed by `ct-policy-` and a hash of it. "+
				"`name`: the key, or, when the subscription has a security group name template, the template's name for the group. "+
				"A group keeps the name it was first applied under, so changing the template names only new groups. "+
				"`resource_group_name`: resource group the group is created in, that of its network interface or subnet. "+
				"`location`: region the group is created in. "+
				"`tags`: `ct:delivery` and `ct:level`, which let the cloud connector recognise the group as Xshield's, never as one of yours. "+
				"`security_rules`: the group's whole rule set. With the `azure` enforcement module's `enable_exclusive_rules` "+
				"on, the default, it replaces any rule the group holds that it does not list; with it off, a rule not named as "+
				"Xshield's stays alongside. "+
				"Each rule has Azure's fields: `name`, `priority`, `direction`, `access` and `protocol`, and the source and "+
				"destination as `source_address_prefix` or `source_address_prefixes`, `destination_address_prefix` or "+
				"`destination_address_prefixes`, `source_port_range` or `source_port_ranges`, and `destination_port_range` or "+
				"`destination_port_ranges`. A single value, which is how Azure takes `*` and a service tag, is in the singular "+
				"field with the plural one empty; two or more are in the plural field with the singular one empty. Every rule "+
				"set ends with an allow of all traffic in each direction at priority 4096, so traffic no Xshield rule decides "+
				"passes as it did before the group, and lets the load balancer's health probes in at priority 100."),
			"subnet_associations": objects(azSubnetAssociationType, "Each subnet a group goes on, keyed by the group's key. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`subnet_id`: resource ID of the subnet to associate it with."),
			"interface_associations": objects(azInterfaceAssociationType, "Each network interface a group goes on, keyed by the group's key. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`network_interface_id`: resource ID of the network interface to associate it with."),
			"handover_subnet_associations": objects(azSubnetAssociationType, "Associations of subnets the cloud connector "+
				"enforced at with a group of its own while the subnet had none, keyed by the group's key. Azure takes an association by clearing whatever group its subnet carries, so creating one "+
				"while the connector's group is on the subnet would leave it with no group until the apply ends. Once this "+
				"version's groups are applied, the connector puts each one in place of its own group in a single change, and the "+
				"`azure` enforcement module then takes the association over by importing it, so the subnet is never left without "+
				"a group. Each moves to `subnet_associations` once an apply has taken it over. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`subnet_id`: resource ID of the subnet."),
			"handover_interface_associations": objects(azInterfaceAssociationType, "As `handover_subnet_associations`, for a "+
				"network interface. "+
				"`network_security_group`: key, in `network_security_groups`, of the group to associate. "+
				"`network_interface_id`: resource ID of the network interface."),
			"assets": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"level": types.StringType, "network_security_groups": azStringsType, "customer_network_security_groups": azStringsType,
			}}, "Where each Xshield asset is enforced, keyed by Xshield asset ID. "+
				"`level`: `networkInterface` or `subnet`. Null when the asset was refused, when its policy writes no rule, or when Xshield enforces it nowhere. "+
				"`network_security_groups`: keys, in `network_security_groups`, of Xshield's groups that carry the asset's rules. "+
				"`customer_network_security_groups`: keys, in `customer_network_security_groups`, of your groups that carry them. "+
				"Both are empty when `level` is null."),
			"customer_network_security_groups": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"id": types.StringType, "resource_group_name": types.StringType, "name": types.StringType,
				"security_rules": types.ListType{ElemType: azSecurityRuleType}, "subnets": types.MapType{ElemType: azStringsType},
			}}, "Each network security group of yours that takes Xshield's rules for the workloads in its subnet, because every "+
				"network interface or subnet of those workloads carries a group of yours, keyed by `customer-nsg-` and a hash of "+
				"its resource ID. "+
				"`id`, `resource_group_name` and `name`: the group's resource ID, resource group and name. "+
				"`security_rules`: Xshield's rules for the group, each naming only its workload's own addresses, with no allow "+
				"of all traffic, as your rules decide the rest. Their `priority` gives only the order Azure is to evaluate them "+
				"in: read them through `xshield_azure_security_rules`, which numbers them ahead of your rules. "+
				"`subnets`: each subnet whose workloads the rules are for, by resource ID, with the Xshield asset IDs of those workloads."),
			"held_interface_associations": objects(azHeldAssociationType, "Associations an earlier apply made whose network "+
				"interface now carries a network security group of yours in place of Xshield's, keyed by the group's key. "+
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
				MarkdownDescription: "Associations an earlier apply made that this version removes, keyed by the group's " +
					"key, each with its network interface's resource ID. The `azure` enforcement module reads each network " +
					"interface before it plans the removal, and fails the plan when the interface carries a group other than " +
					"Xshield's, so a group of yours put there since Xshield last observed the subscription is never removed."},
			"released_subnet_associations": schema.MapAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "As `released_interface_associations`, for a subnet, with the subnet's resource ID."},
			"contained_interface_associations": objects(azHeldAssociationType, "Associations of a workload Xshield's cloud "+
				"connector contains, keyed by the group's key. The connector contains a workload by putting a network security "+
				"group of its own on the network interface in place of Xshield's, and puts Xshield's back when the containment is "+
				"reverted, so the `azure` enforcement module keeps each association in its state unchanged and creates none: "+
				"either would take the connector's group off. An association no earlier apply made is left out until the "+
				"containment is reverted. "+
				"`level_id`: resource ID of the network interface. "+
				"`network_security_group_id`: resource ID of the group the apply associated, as the state holds it."),
			"contained_subnet_associations": objects(azHeldAssociationType, "As `contained_interface_associations`, for a subnet. "+
				"`level_id`: resource ID of the subnet. "+
				"`network_security_group_id`: resource ID of the group the apply associated. azurerm reads a subnet "+
				"association's group back from the subnet, so the module gives a contained one the group the subnet carries now."),
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

		HandoverSubnetAssociations:    map[string]azSubnetAssociationModel{},
		HandoverInterfaceAssociations: map[string]azInterfaceAssociationModel{},

		HeldInterfaceAssociations:     map[string]azHeldAssociationModel{},
		HeldSubnetAssociations:        map[string]azHeldAssociationModel{},
		ReleasedInterfaceAssociations: map[string]types.String{},
		ReleasedSubnetAssociations:    map[string]types.String{},
		CustomerNetworkSecurityGroups: map[string]azCustomerNetworkSecurityGroupModel{},

		ContainedInterfaceAssociations: map[string]azHeldAssociationModel{},
		ContainedSubnetAssociations:    map[string]azHeldAssociationModel{},
	}
	if snap == nil {
		return m
	}
	plan := snap.Azure
	m.Version = types.StringValue(snap.Version)
	for key, g := range plan.NetworkSecurityGroups {
		m.NetworkSecurityGroups[key] = azNetworkSecurityGroupModel{Name: types.StringValue(g.Name), ResourceGroupName: types.StringValue(g.ResourceGroupName),
			Location: types.StringValue(g.Location), Tags: nonNilTags(g.Tags), SecurityRules: azureRuleModels(g.SecurityRules)}
	}
	for key, g := range plan.CustomerNetworkSecurityGroups {
		subnets := make(map[string][]types.String, len(g.Subnets))
		for subnetID, assetIDs := range g.Subnets {
			subnets[subnetID] = toStrList(assetIDs)
		}
		m.CustomerNetworkSecurityGroups[key] = azCustomerNetworkSecurityGroupModel{ID: types.StringValue(g.ID), ResourceGroupName: types.StringValue(g.ResourceGroupName),
			Name: types.StringValue(g.Name), SecurityRules: azureRuleModels(g.SecurityRules), Subnets: subnets}
	}
	m.SubnetAssociations = azureSubnetAssociationModels(plan.SubnetAssociations)
	m.InterfaceAssociations = azureInterfaceAssociationModels(plan.InterfaceAssociations)
	m.HandoverSubnetAssociations = azureSubnetAssociationModels(plan.HandoverSubnetAssociations)
	m.HandoverInterfaceAssociations = azureInterfaceAssociationModels(plan.HandoverInterfaceAssociations)
	for id, a := range plan.Assets {
		m.Assets[id] = azAssetModel{Level: optionalString(a.Level), NetworkSecurityGroups: toStrList(a.NetworkSecurityGroups),
			CustomerNetworkSecurityGroups: toStrList(a.CustomerNetworkSecurityGroups)}
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
	for key, c := range plan.ContainedInterfaceAssociations {
		m.ContainedInterfaceAssociations[key] = azHeldAssociationModel{LevelID: types.StringValue(c.LevelID), NetworkSecurityGroupID: types.StringValue(c.NetworkSecurityGroupID)}
	}
	for key, c := range plan.ContainedSubnetAssociations {
		m.ContainedSubnetAssociations[key] = azHeldAssociationModel{LevelID: types.StringValue(c.LevelID), NetworkSecurityGroupID: types.StringValue(c.NetworkSecurityGroupID)}
	}
	return m
}

func azureSubnetAssociationModels(wire map[string]wireAzureSubnetAssociation) map[string]azSubnetAssociationModel {
	models := make(map[string]azSubnetAssociationModel, len(wire))
	for key, a := range wire {
		models[key] = azSubnetAssociationModel{NetworkSecurityGroup: types.StringValue(a.NetworkSecurityGroup), SubnetID: types.StringValue(a.SubnetID)}
	}
	return models
}

func azureInterfaceAssociationModels(wire map[string]wireAzureInterfaceAssociation) map[string]azInterfaceAssociationModel {
	models := make(map[string]azInterfaceAssociationModel, len(wire))
	for key, a := range wire {
		models[key] = azInterfaceAssociationModel{NetworkSecurityGroup: types.StringValue(a.NetworkSecurityGroup), NetworkInterfaceID: types.StringValue(a.NetworkInterfaceID)}
	}
	return models
}

func azureRuleModels(rules []wireAzureSecurityRule) []azSecurityRuleModel {
	models := make([]azSecurityRuleModel, 0, len(rules))
	for _, r := range rules {
		models = append(models, azureRuleModel(r))
	}
	return models
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
