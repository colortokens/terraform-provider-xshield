package provider

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &enforcementSnapshotDataSource{}
var _ datasource.DataSourceWithConfigure = &enforcementSnapshotDataSource{}

func newEnforcementSnapshotDataSource() datasource.DataSource {
	return &enforcementSnapshotDataSource{}
}

// enforcementSnapshotDataSource only reads: the customer's pipeline performs
// every cloud write from what it returns.
type enforcementSnapshotDataSource struct {
	api cloudSnapshotAPI
}

type esSecurityGroupModel struct {
	Name        types.String      `tfsdk:"name"`
	Description types.String      `tfsdk:"description"`
	VPCID       types.String      `tfsdk:"vpc_id"`
	Tags        map[string]string `tfsdk:"tags"`
}

type esRuleModel struct {
	SecurityGroup             types.String      `tfsdk:"security_group"`
	IPProtocol                types.String      `tfsdk:"ip_protocol"`
	FromPort                  types.Int64       `tfsdk:"from_port"`
	ToPort                    types.Int64       `tfsdk:"to_port"`
	CIDRIPv4                  types.String      `tfsdk:"cidr_ipv4"`
	CIDRIPv6                  types.String      `tfsdk:"cidr_ipv6"`
	PrefixListID              types.String      `tfsdk:"prefix_list_id"`
	ReferencedSecurityGroupID types.String      `tfsdk:"referenced_security_group_id"`
	Description               types.String      `tfsdk:"description"`
	Tags                      map[string]string `tfsdk:"tags"`
}

type esAttachmentModel struct {
	SecurityGroup      types.String `tfsdk:"security_group"`
	NetworkInterfaceID types.String `tfsdk:"network_interface_id"`
	SlotLimit          types.Int64  `tfsdk:"slot_limit"`
}

type esDirectoryModel struct {
	ParameterName  types.String      `tfsdk:"parameter_name"`
	Handle         types.String      `tfsdk:"handle"`
	SecurityGroups []types.String    `tfsdk:"security_groups"`
	Tags           map[string]string `tfsdk:"tags"`
	SlotLimit      types.Int64       `tfsdk:"slot_limit"`
}

type esAssetModel struct {
	SecurityGroup types.String `tfsdk:"security_group"`
	AttachedBy    types.String `tfsdk:"attached_by"`
}

type enforcementSnapshotDataSourceModel struct {
	CloudAccountID       types.String                    `tfsdk:"cloud_account_id"`
	Region               types.String                    `tfsdk:"region"`
	Published            types.Bool                      `tfsdk:"published"`
	Version              types.String                    `tfsdk:"version"`
	SecurityGroups       map[string]esSecurityGroupModel `tfsdk:"security_groups"`
	IngressRules         map[string]esRuleModel          `tfsdk:"ingress_rules"`
	EgressRules          map[string]esRuleModel          `tfsdk:"egress_rules"`
	InterfaceAttachments map[string]esAttachmentModel    `tfsdk:"interface_attachments"`
	Directory            map[string]esDirectoryModel     `tfsdk:"directory"`
	Assets               map[string]esAssetModel         `tfsdk:"assets"`
	Withdrawing          []types.String                  `tfsdk:"withdrawing"`
}

func (d *enforcementSnapshotDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_snapshot"
}

var (
	esTagsType = types.MapType{ElemType: types.StringType}
	esRuleType = types.ObjectType{AttrTypes: map[string]attr.Type{
		"security_group": types.StringType, "ip_protocol": types.StringType, "from_port": types.Int64Type, "to_port": types.Int64Type,
		"cidr_ipv4": types.StringType, "cidr_ipv6": types.StringType, "prefix_list_id": types.StringType,
		"referenced_security_group_id": types.StringType, "description": types.StringType, "tags": esTagsType,
	}}
)

// Schema declares the collections as maps of objects rather than nested
// attributes: Terraform's test mocks cannot set a computed nested attribute,
// and a team testing its own modules against this data source needs to.
func (d *enforcementSnapshotDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	objects := func(elem attr.Type, description string) schema.MapAttribute {
		return schema.MapAttribute{Computed: true, ElementType: elem, MarkdownDescription: description}
	}
	rules := func(direction string) schema.MapAttribute {
		return objects(esRuleType, "Every "+direction+" rule, one per source, keyed `<security group key>/<in|out>/<protocol>/<ports>/<source>`. "+
			"A key encodes the rule's content, so a changed rule plans as one removal and one addition. Each value can be passed "+
			"to `aws_vpc_security_group_"+direction+"_rule` as it is; attributes that do not apply are null. "+
			"`security_group`: key, in `security_groups`, of the group the rule belongs to. "+
			"`ip_protocol`: `tcp`, `udp`, `icmp`, `icmpv6`, `-1` for all traffic, or a protocol number. "+
			"`from_port`, `to_port`: the port range, or the ICMP type and code (`-1` for all). Null for a protocol without ports. "+
			"`cidr_ipv4`, `cidr_ipv6`, `prefix_list_id`, `referenced_security_group_id`: the source; exactly one is set. "+
			"`referenced_security_group_id` is set on a Full control cohort's copy of a customer rule that names a group, and on a rule that names another workload's Xshield group in place of its private addresses. "+
			"`description`, `tags`: the rule description and tags the cloud connector writes.")
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Fetches the AWS resources Xshield expects in one account and region, already rendered: each workload's " +
			"own security group and rules, exactly as the cloud connector would write them, the interface attachments for " +
			"instances, and a directory entry for each resource its own workspace attaches. Every map is keyed for `for_each`, " +
			"by an instance ID or a handle such as `rds/orders-db`, so a plan names the workload each change is for.\n\n" +
			"Use it through the `aws` enforcement module, which creates these resources and reports the apply to Xshield.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, MarkdownDescription: "AWS account the snapshot is for."},
			"region":           schema.StringAttribute{Required: true, MarkdownDescription: "AWS region the snapshot is for."},
			"version": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "The snapshot's version, which is the hash of everything it asks for; Xshield accepts a receipt only " +
					"for a version it published. Set it to pin a version, for break-glass rollback or forensics. When omitted, the version " +
					"Xshield expects is fetched, so the configuration never changes when policy does. While a pin is in place, Xshield " +
					"reports the account as pending.",
			},
			"published": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this account and region, such as before the " +
					"account is onboarded with policy delivery set to Terraform pipeline: every map is empty and `version` is null, " +
					"so a configuration built on it plans no change. Only Xshield's own answer that nothing " +
					"is published counts; any other failure to read the snapshot fails the plan.",
			},
			"security_groups": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"name": types.StringType, "description": types.StringType, "vpc_id": types.StringType, "tags": esTagsType,
			}}, "One security group per workload, or per Aurora cluster, keyed by its instance ID or handle, and at Full "+
				"control one `ct-cohort-` group per cohort, keyed by its name, for the workloads that keep a rule their customer group gives up. "+
				"`name`, `description`: fixed for the group's life, named as the cloud connector names its groups. "+
				"`vpc_id`: VPC the group is created in. "+
				"`tags`: let the cloud connector recognise the group as Xshield's, never as a customer group."),
			"ingress_rules": rules("ingress"),
			"egress_rules":  rules("egress"),
			"interface_attachments": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"security_group": types.StringType, "network_interface_id": types.StringType, "slot_limit": types.Int64Type,
			}}, "Each instance interface a group goes on, keyed `<security group key>/<interface ID>`. The attachment adds the "+
				"group and leaves the interface's other groups in place, as the connector does. A contained instance's attachment "+
				"is left out until the containment is reverted. "+
				"`security_group`: key, in `security_groups`, of the group to attach. "+
				"`network_interface_id`: interface to attach it to. "+
				"`slot_limit`: how many security groups the account allows on the interface, as Xshield last discovered it; null when it has not."),
			"directory": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"parameter_name": types.StringType, "handle": types.StringType, "security_groups": types.ListType{ElemType: types.StringType}, "tags": esTagsType,
				"slot_limit": types.Int64Type,
			}}, "One SSM parameter per database, function or service its own workspace attaches, keyed by handle. The "+
				"`group-lookup` module reads it. An entry listing no group attaches nothing. "+
				"`parameter_name`: `/colortokens/v1/<handle>/security-groups`. "+
				"`handle`: the resource's kind and name, such as `rds/orders-db` or `lambda/orders-api`. "+
				"`security_groups`: keys, in `security_groups`, of the groups the resource attaches. "+
				"`tags`: tags for the parameter. "+
				"`slot_limit`: how many security groups AWS allows on the resource, as Xshield last discovered it; null when it has not."),
			"assets": objects(types.ObjectType{AttrTypes: map[string]attr.Type{
				"security_group": types.StringType, "attached_by": types.StringType,
			}}, "How each Xshield asset carries its group, keyed by Xshield asset ID. "+
				"`security_group`: key, in `security_groups`, of the asset's group. Null when its group was refused, or for an instance whose policy holds no rule. "+
				"`attached_by`: `pipeline` when this plan attaches it to the asset's interfaces, `owner` when the asset's own workspace does."),
			"withdrawing": schema.ListAttribute{
				Computed: true, ElementType: types.StringType,
				MarkdownDescription: "Keys of groups policy no longer uses but a resource may still carry. They keep their rules " +
					"until Xshield sees them detached, because AWS refuses to delete an attached group.",
			},
		},
	}
}

func (d *enforcementSnapshotDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type wireRule struct {
	SecurityGroup string  `json:"securityGroup"`
	IPProtocol    string  `json:"ipProtocol"`
	FromPort      *int64  `json:"fromPort"`
	ToPort        *int64  `json:"toPort"`
	CIDRIPv4      *string `json:"cidrIpv4"`
	CIDRIPv6      *string `json:"cidrIpv6"`
	PrefixListID  *string `json:"prefixListId"`
	// ReferencedSecurityGroupID names another account's group as "<account>/<group>".
	ReferencedSecurityGroupID *string           `json:"referencedSecurityGroupId"`
	Description               string            `json:"description"`
	Tags                      map[string]string `json:"tags"`
}

// wireRuleMatch is a customer rule by its content, since the customer's code holds no rule ids.
type wireRuleMatch struct {
	Direction                 string  `json:"direction"`
	IPProtocol                string  `json:"ipProtocol"`
	FromPort                  *int64  `json:"fromPort"`
	ToPort                    *int64  `json:"toPort"`
	CIDRIPv4                  *string `json:"cidrIpv4"`
	CIDRIPv6                  *string `json:"cidrIpv6"`
	PrefixListID              *string `json:"prefixListId"`
	ReferencedSecurityGroupID *string `json:"referencedSecurityGroupId"`
}

// wireCustomerGroupChange is a Full control change to one of the customer's own groups; GroupID is its AWS id.
type wireCustomerGroupChange struct {
	GroupID    string               `json:"groupId"`
	Revoke     []wireRuleMatch      `json:"revoke"`
	ChangeSets []wireGroupChangeSet `json:"changeSets"`
}

type wireGroupChangeSet struct {
	ID    string          `json:"id"`
	State string          `json:"state"`
	Moves []wireMovedRule `json:"moves"`
}

// wireMovedRule.KeptByEveryMember is what every member of the group keeps of the moved rule; a server that does not
// send it leaves it empty, so any traffic of the moved rule counts as taken from some member.
type wireMovedRule struct {
	wireRuleMatch
	KeptByEveryMember []wireRuleMatch `json:"keptByEveryMember"`
}

type wireSnapshot struct {
	SchemaVersion  string `json:"schemaVersion"`
	Version        string `json:"version"`
	CloudAccountID string `json:"cloudAccountId"`
	Region         string `json:"region"`
	AWS            *struct {
		SecurityGroups map[string]struct {
			Name        string            `json:"name"`
			Description string            `json:"description"`
			VPCID       string            `json:"vpcId"`
			Tags        map[string]string `json:"tags"`
		} `json:"securityGroups"`
		IngressRules         map[string]wireRule `json:"ingressRules"`
		EgressRules          map[string]wireRule `json:"egressRules"`
		InterfaceAttachments map[string]struct {
			SecurityGroup      string `json:"securityGroup"`
			NetworkInterfaceID string `json:"networkInterfaceId"`
			SlotLimit          int64  `json:"slotLimit"`
		} `json:"interfaceAttachments"`
		Directory map[string]struct {
			ParameterName  string            `json:"parameterName"`
			Handle         string            `json:"handle"`
			SecurityGroups []string          `json:"securityGroups"`
			Tags           map[string]string `json:"tags"`
			SlotLimit      int64             `json:"slotLimit"`
		} `json:"directory"`
		Assets map[string]struct {
			SecurityGroup *string `json:"securityGroup"`
			AttachedBy    string  `json:"attachedBy"`
		} `json:"assets"`
		Withdrawing []string `json:"withdrawing"`
	} `json:"aws"`
}

// wireCustomerGroupChanges is what Xshield takes out of the customer's own groups, published apart
// from the snapshot, by "<vpcId>/<groupName>".
type wireCustomerGroupChanges struct {
	CloudAccountID string                             `json:"cloudAccountId"`
	Region         string                             `json:"region"`
	Version        string                             `json:"version"`
	Groups         map[string]wireCustomerGroupChange `json:"customerGroupChanges"`
}

// supportedSnapshotSchema is the snapshot format this provider renders. A newer
// format may carry resources this provider would silently leave out.
const supportedSnapshotSchema = "3"

func renderable(snap wireSnapshot) error {
	if snap.SchemaVersion != supportedSnapshotSchema {
		return fmt.Errorf("this provider applies snapshot schema %q, and Xshield sent schema %q. Upgrade the xshield provider; "+
			"applying with this one could leave out resources the snapshot asks for", supportedSnapshotSchema, snap.SchemaVersion)
	}
	if snap.AWS == nil {
		return fmt.Errorf("the snapshot holds no AWS plan; this account's cloud is not one this provider can apply yet")
	}
	return nil
}

const codeHandedOver = "handedOver"

type wireExpected struct {
	Version string `json:"version"`
}

func (d *enforcementSnapshotDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data enforcementSnapshotDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.api.client == nil {
		resp.Diagnostics.AddError("provider not configured", "the xshield provider block was not configured before this data source was read")
		return
	}

	snap, ok := fetchSnapshot(ctx, d.api, data.CloudAccountID.ValueString(), data.Region.ValueString(), data.Version, true, &resp.Diagnostics)
	if !ok {
		return
	}
	if snap != nil && (snap.CloudAccountID != data.CloudAccountID.ValueString() || snap.Region != data.Region.ValueString()) {
		resp.Diagnostics.AddError("Xshield served a snapshot for another account or region",
			fmt.Sprintf("asked for %s/%s, got %s/%s; nothing is applied", data.CloudAccountID.ValueString(), data.Region.ValueString(), snap.CloudAccountID, snap.Region))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, snapshotModel(data.CloudAccountID, data.Region, snap))...)
}

// fetchSnapshot returns a nil snapshot, and no error, only when Xshield says
// it has published nothing; a pinned version must exist. Only the enforcement
// module's read is a heartbeat: reading /expected records it as the pipeline's
// last check, pinned or not, while other readers take the version from /status.
func fetchSnapshot(ctx context.Context, api cloudSnapshotAPI, account, region string, pinned types.String, heartbeat bool, diags *diag.Diagnostics) (*wireSnapshot, bool) {
	isPinned := !pinned.IsNull() && !pinned.IsUnknown()
	version := pinned.ValueString()
	if heartbeat || !isPinned {
		expected, published, err := expectedVersion(ctx, api, account, region, heartbeat)
		switch {
		case isAPIRefusal(err, http.StatusConflict, codeHandedOver):
			diags.AddError("Xshield moved "+account+"/"+region+" to connector delivery",
				"The cloud connector now keeps the groups, rules and attachments this workspace created, so applying would remove "+
					"what it enforces. Replace the module block with removed blocks that keep them (lifecycle { destroy = false }), as "+
					"the provider's enforcement-snapshot/leave example shows, then stop running this workspace.")
			return nil, false
		case err != nil:
			diags.AddError("Cannot resolve the snapshot Xshield expects for "+account+"/"+region,
				err.Error()+"\n\nCheck the provider's endpoint, and that the API key's user may read cloud snapshots.")
			return nil, false
		case isPinned:
		case !published:
			return nil, true
		default:
			version = expected
		}
	}
	var snap wireSnapshot
	if err := api.get(ctx, api.endpoint(cloudAWS, account, region, "versions", version), &snap); err != nil {
		diags.AddError(fmt.Sprintf("Cannot fetch snapshot version %s for %s/%s", version, account, region), err.Error())
		return nil, false
	}
	if err := renderable(snap); err != nil {
		diags.AddError("This provider version cannot apply this snapshot", fmt.Sprintf("%s/%s: %s", account, region, err))
		return nil, false
	}
	return &snap, true
}

func expectedVersion(ctx context.Context, api cloudSnapshotAPI, account, region string, heartbeat bool) (string, bool, error) {
	var version string
	var err error
	if heartbeat {
		var exp wireExpected
		err = api.get(ctx, api.endpoint(cloudAWS, account, region, "expected"), &exp)
		version = exp.Version
	} else {
		var st wireStatus
		err = api.get(ctx, api.endpoint(cloudAWS, account, region, "status"), &st)
		version = st.Expected.Version
	}
	if isAPIRefusal(err, http.StatusNotFound, codeNotPublished) {
		return "", false, nil
	}
	return version, err == nil, err
}

// snapshotModel never returns a nil map or list: an empty account still plans
// cleanly, and an attribute that switched between null and empty would show
// as a change on every plan.
func snapshotModel(account, region types.String, snap *wireSnapshot) enforcementSnapshotDataSourceModel {
	m := enforcementSnapshotDataSourceModel{
		CloudAccountID:       account,
		Region:               region,
		Published:            types.BoolValue(snap != nil),
		Version:              types.StringNull(),
		SecurityGroups:       map[string]esSecurityGroupModel{},
		IngressRules:         map[string]esRuleModel{},
		EgressRules:          map[string]esRuleModel{},
		InterfaceAttachments: map[string]esAttachmentModel{},
		Directory:            map[string]esDirectoryModel{},
		Assets:               map[string]esAssetModel{},
		Withdrawing:          []types.String{},
	}
	if snap == nil {
		return m
	}
	plan := snap.AWS
	m.Version = types.StringValue(snap.Version)
	m.Withdrawing = toStrList(plan.Withdrawing)
	for key, g := range plan.SecurityGroups {
		m.SecurityGroups[key] = esSecurityGroupModel{Name: types.StringValue(g.Name), Description: types.StringValue(g.Description),
			VPCID: types.StringValue(g.VPCID), Tags: nonNilTags(g.Tags)}
	}
	for key, r := range plan.IngressRules {
		m.IngressRules[key] = ruleModel(r)
	}
	for key, r := range plan.EgressRules {
		m.EgressRules[key] = ruleModel(r)
	}
	for key, a := range plan.InterfaceAttachments {
		m.InterfaceAttachments[key] = esAttachmentModel{SecurityGroup: types.StringValue(a.SecurityGroup), NetworkInterfaceID: types.StringValue(a.NetworkInterfaceID),
			SlotLimit: knownLimit(a.SlotLimit)}
	}
	for key, e := range plan.Directory {
		m.Directory[key] = esDirectoryModel{ParameterName: types.StringValue(e.ParameterName), Handle: types.StringValue(e.Handle),
			SecurityGroups: toStrList(e.SecurityGroups), Tags: nonNilTags(e.Tags), SlotLimit: knownLimit(e.SlotLimit)}
	}
	for id, a := range plan.Assets {
		m.Assets[id] = esAssetModel{SecurityGroup: types.StringPointerValue(a.SecurityGroup), AttachedBy: types.StringValue(a.AttachedBy)}
	}
	return m
}

// knownLimit is null for a limit Xshield has not discovered, which the snapshot leaves out.
func knownLimit(limit int64) types.Int64 {
	if limit == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(limit)
}

func ruleModel(r wireRule) esRuleModel {
	return esRuleModel{
		SecurityGroup:             types.StringValue(r.SecurityGroup),
		IPProtocol:                types.StringValue(r.IPProtocol),
		FromPort:                  types.Int64PointerValue(r.FromPort),
		ToPort:                    types.Int64PointerValue(r.ToPort),
		CIDRIPv4:                  types.StringPointerValue(r.CIDRIPv4),
		CIDRIPv6:                  types.StringPointerValue(r.CIDRIPv6),
		PrefixListID:              types.StringPointerValue(r.PrefixListID),
		ReferencedSecurityGroupID: types.StringPointerValue(r.ReferencedSecurityGroupID),
		Description:               optionalString(r.Description),
		Tags:                      nonNilTags(r.Tags),
	}
}

func nonNilTags(tags map[string]string) map[string]string {
	if tags == nil {
		return map[string]string{}
	}
	return tags
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
