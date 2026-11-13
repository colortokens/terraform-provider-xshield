package provider

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &awsSecurityGroupChangesDataSource{}
var _ datasource.DataSourceWithConfigure = &awsSecurityGroupChangesDataSource{}

func newAWSSecurityGroupChangesDataSource() datasource.DataSource {
	return &awsSecurityGroupChangesDataSource{}
}

// awsSecurityGroupChangesDataSource needs only the account and region, so the plan reads it even where a group's own
// VPC or rules are not known until the apply, and a group it does not list never reads xshield_aws_security_group_rules.
type awsSecurityGroupChangesDataSource struct {
	api cloudSnapshotAPI
}

type awsSecurityGroupChangesDataSourceModel struct {
	CloudAccountID types.String        `tfsdk:"cloud_account_id"`
	Region         types.String        `tfsdk:"region"`
	Published      types.Bool          `tfsdk:"published"`
	Version        types.String        `tfsdk:"version"`
	Groups         map[string][]string `tfsdk:"groups"`
}

func (d *awsSecurityGroupChangesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_security_group_changes"
}

func (d *awsSecurityGroupChangesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists your own security groups that an approved Full control change applies to, in one account and region, " +
			"when a Terraform pipeline delivers the account. Read it once, in the root module, and read " +
			"`xshield_aws_security_group_rules` only for a group it lists: every other group keeps the rules its code declares, and " +
			"its plan shows nothing from Xshield. It needs only the account and region, so it is read when the plan starts, even " +
			"in a configuration that creates the VPC or the security groups it lists.",
		Attributes: map[string]schema.Attribute{
			"cloud_account_id": schema.StringAttribute{Required: true, MarkdownDescription: "AWS account the groups are in."},
			"region":           schema.StringAttribute{Required: true, MarkdownDescription: "AWS region the groups are in."},
			"published": schema.BoolAttribute{Computed: true,
				MarkdownDescription: "False while Xshield has published nothing for this account and region; `groups` is then empty " +
					"and `version` is null. Any other failure to read the changes fails the plan."},
			"version": schema.StringAttribute{Computed: true,
				MarkdownDescription: "Version of the changes to customer groups Xshield published for the account and region."},
			"groups": schema.MapAttribute{Computed: true, ElementType: types.SetType{ElemType: types.StringType},
				MarkdownDescription: "Each group an approved change applies to, by its name, with the IDs of the VPCs it is in. " +
					"A group not listed here keeps every rule its code declares."},
		},
	}
}

func (d *awsSecurityGroupChangesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *awsSecurityGroupChangesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data awsSecurityGroupChangesDataSourceModel
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
	data.Published, data.Version, data.Groups = types.BoolValue(published), types.StringNull(), map[string][]string{}
	if published {
		data.Version, data.Groups = types.StringValue(changes.Version), changedGroups(changes)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

// changedGroups inverts the "<vpc>/<name>" keys groupChangeOf looks a group up by, cutting at the first slash: a
// VPC ID holds none, and a group name may.
func changedGroups(changes wireCustomerGroupChanges) map[string][]string {
	groups := map[string][]string{}
	for key := range changes.Groups {
		if vpc, name, ok := strings.Cut(key, "/"); ok {
			groups[name] = append(groups[name], vpc)
		}
	}
	for _, vpcs := range groups {
		slices.Sort(vpcs)
	}
	return groups
}

// publishedGroupChanges is false, with no error, while Xshield has published nothing for the account and region.
func (a cloudSnapshotAPI) publishedGroupChanges(ctx context.Context, account, region string) (wireCustomerGroupChanges, bool, diag.Diagnostics) {
	changes, err := a.customerGroupChanges(ctx, account, region)
	if isAPIRefusal(err, http.StatusNotFound, codeNotPublished) {
		return wireCustomerGroupChanges{}, false, nil
	}
	var diags diag.Diagnostics
	if err != nil {
		diags.AddError("Cannot read the changes Xshield made to customer groups in "+account+"/"+region,
			err.Error()+"\n\nCheck the provider's endpoint, and that the API key's user may read cloud snapshots.")
		return changes, true, diags
	}
	// Changes are matched to a group by VPC and name alone, so another account's would take a rule out of a group here.
	if changes.CloudAccountID != account || changes.Region != region {
		diags.AddError("Xshield served the changes to customer groups of another account or region",
			fmt.Sprintf("asked for %s/%s, got %s/%s; no rule is left out", account, region, changes.CloudAccountID, changes.Region))
	}
	return changes, true, diags
}
