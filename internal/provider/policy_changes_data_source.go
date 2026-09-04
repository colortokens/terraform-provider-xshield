package provider

import (
	"context"
	"net/http"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &PolicyChangesDataSource{}
var _ datasource.DataSourceWithConfigure = &PolicyChangesDataSource{}

func NewPolicyChangesDataSource() datasource.DataSource { return &PolicyChangesDataSource{} }

type PolicyChangesDataSource struct{ client *sdk.Xshield }

type deploymentPortModel struct {
	ListenPort           types.String `tfsdk:"listen_port"`
	ListenPortProtocol   types.String `tfsdk:"listen_port_protocol"`
	ListenPortName       types.String `tfsdk:"listen_port_name"`
	PortCategory         types.String `tfsdk:"port_category"`
	IsDeploymentRequired types.Bool   `tfsdk:"is_deployment_required"`
	AffectedAssetsCount  types.Int64  `tfsdk:"affected_assets_count"`
	ViolationCount       types.Int64  `tfsdk:"violation_count"`
	AverageDaysInTest    types.Int64  `tfsdk:"average_days_in_test"`
}

type PolicyChangesDataSourceModel struct {
	Criteria           types.String          `tfsdk:"criteria"`
	Direction          types.String          `tfsdk:"direction"`
	Filter             types.String          `tfsdk:"filter"`
	MinDaysInTest      types.Int64           `tfsdk:"min_days_in_test"`
	ViolationThreshold types.Int64           `tfsdk:"violation_threshold"`
	ReviewedPorts      []deploymentPortModel `tfsdk:"reviewed_ports"`
	UnreviewedPorts    []deploymentPortModel `tfsdk:"unreviewed_ports"`
	PendingCount       types.Int64           `tfsdk:"pending_count"`
}

func (d *PolicyChangesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_changes"
}

func (d *PolicyChangesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "What a deployment would change, and on how many assets.\n\n" +
			"Read this before running `xshield_policy_deployment` to see the size of the change. " +
			"`pending` lists ports whose review decision the assets are not yet enforcing; `under_test` " +
			"lists ports already deployed in test mode, which is the set a move to enforce would affect.\n\n" +
			"The violation and days-in-test figures are how to judge whether a port is ready to enforce: " +
			"a port under test for weeks with no violations is safe to enforce, one with violations is not.",
		Attributes: map[string]schema.Attribute{
			"criteria": criteriaAttribute(true, "Criteria selecting the assets, written against the asset scope."),
			"direction": schema.StringAttribute{
				Optional:    true,
				Description: "Which direction of policy to report on. Defaults to inbound.",
				Validators:  []validator.String{stringvalidator.OneOf("inbound", "outbound")},
			},
			"filter": schema.StringAttribute{
				Optional: true,
				Description: "`pending` reports ports whose review state differs from what is enforced. " +
					"`under_test` reports ports already deployed in test mode. Defaults to `pending`.",
				Validators: []validator.String{stringvalidator.OneOf("pending", "under_test")},
			},
			"min_days_in_test": schema.Int64Attribute{
				Optional: true,
				Description: "With `under_test`, report only ports that have been under test at least this " +
					"long. Ignored for `pending`.",
			},
			"violation_threshold": schema.Int64Attribute{
				Optional: true,
				Description: "With `under_test`, report only ports at or above this violation count. " +
					"Ignored for `pending`.",
			},
			"pending_count": schema.Int64Attribute{
				Computed:    true,
				Description: "How many reported ports need a deployment to take effect.",
			},
			"reviewed_ports": schema.ListNestedAttribute{
				Computed:     true,
				Description:  "Ports carrying a review decision.",
				NestedObject: deploymentPortSchema(),
			},
			"unreviewed_ports": schema.ListNestedAttribute{
				Computed: true,
				Description: "Ports with no review decision. A deployment leaves these logging rather than " +
					"blocking, whatever mode it runs in.",
				NestedObject: deploymentPortSchema(),
			},
		},
	}
}

func deploymentPortSchema() schema.NestedAttributeObject {
	return schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"listen_port":          schema.StringAttribute{Computed: true, Description: "Port number, or a range."},
			"listen_port_protocol": schema.StringAttribute{Computed: true},
			"listen_port_name":     schema.StringAttribute{Computed: true},
			"port_category":        schema.StringAttribute{Computed: true},
			"is_deployment_required": schema.BoolAttribute{
				Computed:    true,
				Description: "True when the port's decision is not yet what the assets enforce.",
			},
			"affected_assets_count": schema.Int64Attribute{
				Computed:    true,
				Description: "How many of the matched assets this port change would touch.",
			},
			"violation_count": schema.Int64Attribute{
				Computed: true,
				Description: "Traffic that would have been blocked had this port been enforced. " +
					"Above zero means enforcing it would break something.",
			},
			"average_days_in_test": schema.Int64Attribute{
				Computed:    true,
				Description: "How long the port has been deployed in test mode, averaged over the affected assets.",
			},
		},
	}
}

func (d *PolicyChangesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *PolicyChangesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PolicyChangesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	direction := "inbound"
	if !data.Direction.IsNull() && data.Direction.ValueString() != "" {
		direction = data.Direction.ValueString()
	}
	base := shared.PortTestModeInput{
		Criteria:  data.Criteria.ValueString(),
		Direction: &direction,
	}

	var ports *shared.DeploymentPorts
	var err error

	if data.Filter.ValueString() == "under_test" {
		input := shared.PortEnforceModeInput{Criteria: base.Criteria, Direction: base.Direction}
		if !data.MinDaysInTest.IsNull() {
			input.MinDaysInTest = data.MinDaysInTest.ValueInt64Pointer()
		}
		if !data.ViolationThreshold.IsNull() {
			input.ViolationThreshold = data.ViolationThreshold.ValueInt64Pointer()
		}
		var res *operations.ListTestPortsResponse
		res, err = d.client.Policy.ListTestPorts(ctx, input)
		if err == nil {
			err = deploymentPortsError(res.StatusCode, res.ErrorResponse, res.RawResponse)
			ports = res.DeploymentPorts
		}
	} else {
		var res *operations.ListChangedPortsResponse
		res, err = d.client.Policy.ListChangedPorts(ctx, base)
		if err == nil {
			err = deploymentPortsError(res.StatusCode, res.ErrorResponse, res.RawResponse)
			ports = res.DeploymentPorts
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot read pending policy changes", err.Error())
		return
	}

	data.ReviewedPorts = convertDeploymentPorts(portsOf(ports, true))
	data.UnreviewedPorts = convertDeploymentPorts(portsOf(ports, false))

	pending := int64(0)
	for _, list := range [][]deploymentPortModel{data.ReviewedPorts, data.UnreviewedPorts} {
		for _, port := range list {
			if port.IsDeploymentRequired.ValueBool() {
				pending++
			}
		}
	}
	data.PendingCount = types.Int64Value(pending)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func portsOf(ports *shared.DeploymentPorts, reviewed bool) []shared.DeploymentPort {
	if ports == nil {
		return nil
	}
	if reviewed {
		return ports.ReviewedPorts
	}
	return ports.UnreviewedPorts
}

func convertDeploymentPorts(items []shared.DeploymentPort) []deploymentPortModel {
	out := make([]deploymentPortModel, 0, len(items))
	for _, item := range items {
		out = append(out, deploymentPortModel{
			ListenPort:           types.StringPointerValue(item.ListenPort),
			ListenPortProtocol:   types.StringPointerValue(item.ListenPortProtocol),
			ListenPortName:       types.StringPointerValue(item.ListenPortName),
			PortCategory:         types.StringPointerValue(item.PortCategory),
			IsDeploymentRequired: types.BoolPointerValue(item.IsDeploymentRequired),
			AffectedAssetsCount:  int64OrNull(item.AffectedAssetsCount),
			ViolationCount:       int64OrNull(item.AffectedViolationCount),
			AverageDaysInTest:    int64OrNull(item.AffectedAvgDaysInTest),
		})
	}
	return out
}

// deploymentPortsError turns a non-success status into an error. A 404 means the
// criteria matched nothing to report on, which is an empty result rather than a
// failure.
func deploymentPortsError(status int, errResp *shared.ErrorResponse, raw *http.Response) error {
	switch status {
	case 200, 404:
		return nil
	default:
		return classifyDeploymentError(status, apiErrorDetail(errResp, raw))
	}
}
