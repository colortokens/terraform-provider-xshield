package provider

import (
	"context"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &DeploymentSimulationDataSource{}
var _ datasource.DataSourceWithConfigure = &DeploymentSimulationDataSource{}

func NewDeploymentSimulationDataSource() datasource.DataSource {
	return &DeploymentSimulationDataSource{}
}

type DeploymentSimulationDataSource struct{ client *sdk.Xshield }

type DeploymentSimulationDataSourceModel struct {
	AssetID        types.String `tfsdk:"asset_id"`
	Direction      types.String `tfsdk:"direction"`
	Mode           types.String `tfsdk:"mode"`
	CurrentRules   types.String `tfsdk:"current_rules"`
	CandidateRules types.String `tfsdk:"candidate_rules"`
	RulesChanged   types.Bool   `tfsdk:"rules_changed"`
}

func (d *DeploymentSimulationDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_deployment_simulation"
}

func (d *DeploymentSimulationDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The firewall rules one asset would run before and after a deployment.\n\n" +
			"This previews the effect of `xshield_policy_deployment` on a single asset without applying " +
			"anything. It is the closest thing to a dry run: the rule text is what the agent would enforce.\n\n" +
			"The simulation covers a whole-asset deployment in the given mode. Per-port plans are not " +
			"previewed here; use `xshield_policy_changes` to see which ports a plan would touch.",
		Attributes: map[string]schema.Attribute{
			"asset_id": schema.StringAttribute{
				Required:    true,
				Description: "Asset to simulate against. One asset at a time, since the output is its rule set.",
			},
			"direction": schema.StringAttribute{
				Optional:    true,
				Description: "Which direction of policy to simulate. Defaults to inbound.",
				Validators:  []validator.String{stringvalidator.OneOf("inbound", "outbound")},
			},
			"mode": schema.StringAttribute{
				Optional:    true,
				Description: "The deployment mode to preview. Defaults to enforce, the state worth checking before applying.",
				Validators:  []validator.String{stringvalidator.OneOf("test", "intranet-test", "enforce", "undeploy")},
			},
			"current_rules": schema.StringAttribute{
				Computed:    true,
				Description: "The firewall rules the asset runs today.",
			},
			"candidate_rules": schema.StringAttribute{
				Computed:    true,
				Description: "The firewall rules the asset would run after the deployment.",
			},
			"rules_changed": schema.BoolAttribute{
				Computed:    true,
				Description: "False when the deployment would leave the asset's rules exactly as they are.",
			},
		},
	}
}

func (d *DeploymentSimulationDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *DeploymentSimulationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DeploymentSimulationDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	direction := "inbound"
	if !data.Direction.IsNull() && data.Direction.ValueString() != "" {
		direction = data.Direction.ValueString()
	}
	mode := "enforce"
	if !data.Mode.IsNull() && data.Mode.ValueString() != "" {
		mode = data.Mode.ValueString()
	}

	// A simulation takes the same body as the real deploy. Both wildcard keys
	// make it a whole-asset preview rather than a per-port one.
	deployment := &PolicyDeploymentResourceModel{
		Criteria:  types.StringValue("assetId = '" + data.AssetID.ValueString() + "'"),
		Direction: types.StringValue(direction),
		Mode:      types.StringValue(mode),
	}
	input := (&PolicyDeploymentResource{}).buildInput(deployment)

	res, err := d.client.Policy.SimulateDeploy(ctx, operations.SimulateDeployRequest{
		AssetID:             data.AssetID.ValueString(),
		PortDeploymentInput: input,
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot simulate the deployment", err.Error())
		return
	}
	if res.StatusCode == 404 {
		resp.Diagnostics.AddError("No such asset",
			"The simulation service reported no asset with id "+data.AssetID.ValueString()+".")
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError("Cannot simulate the deployment",
			classifyDeploymentError(res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse)).Error())
		return
	}
	if res.FirewallSimulation == nil {
		resp.Diagnostics.AddError("Cannot simulate the deployment", "the API returned no rule sets")
		return
	}

	data.CurrentRules = types.StringValue(res.FirewallSimulation.CurrentRules)
	data.CandidateRules = types.StringValue(res.FirewallSimulation.CandidateRules)
	data.RulesChanged = types.BoolValue(res.FirewallSimulation.CurrentRules != res.FirewallSimulation.CandidateRules)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
