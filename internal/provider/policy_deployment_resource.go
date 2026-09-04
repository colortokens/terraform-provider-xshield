package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &PolicyDeploymentResource{}
var _ resource.ResourceWithConfigure = &PolicyDeploymentResource{}
var _ resource.ResourceWithValidateConfig = &PolicyDeploymentResource{}

func NewPolicyDeploymentResource() resource.Resource { return &PolicyDeploymentResource{} }

type PolicyDeploymentResource struct {
	client *sdk.Xshield
}

type deploymentPlanEntryModel struct {
	Mode           types.String `tfsdk:"mode"`
	TargetAssets   types.String `tfsdk:"target_assets"`
	BypassWarnings types.Bool   `tfsdk:"bypass_warnings"`
}

type PolicyDeploymentResourceModel struct {
	ID                types.String                        `tfsdk:"id"`
	Criteria          types.String                        `tfsdk:"criteria"`
	Direction         types.String                        `tfsdk:"direction"`
	Mode              types.String                        `tfsdk:"mode"`
	Reviewed          map[string]deploymentPlanEntryModel `tfsdk:"reviewed"`
	Unreviewed        map[string]deploymentPlanEntryModel `tfsdk:"unreviewed"`
	Comment           types.String                        `tfsdk:"comment"`
	UndeployOnDestroy types.Bool                          `tfsdk:"undeploy_on_destroy"`
	LastDeployedAt    types.String                        `tfsdk:"last_deployed_at"`
	AssetsChanged     types.Bool                          `tfsdk:"assets_changed"`
	PortsPending      types.Int64                         `tfsdk:"ports_pending_deployment"`
}

func (r *PolicyDeploymentResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_deployment"
}

func (r *PolicyDeploymentResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Deploys reviewed policy to the assets a criteria selects.\n\n" +
			"Templates and segments describe intent; nothing reaches a firewall until a deployment runs. " +
			"This resource is that step.\n\n" +
			"Two things decide whether it does anything. Enforcement has to be enabled on the asset first, " +
			"through `inbound_enforcement` or `outbound_enforcement` on `xshield_asset`; a deployment is a " +
			"silent no-op on an asset whose enforcement is off, so order the two with `depends_on`. And a " +
			"plan naming individual ports is a micro-deployment, which the tenant must permit and every " +
			"matched asset must support.\n\n" +
			"Deployments are serialised per tenant. A deployment refused because another is running is " +
			"retried automatically.\n\n" +
			"This resource records an action rather than an object. Destroying it removes it from state " +
			"and, unless `undeploy_on_destroy` is set, leaves the deployed policy in place.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Identifier for this deployment, derived from the criteria and direction.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"criteria": schema.StringAttribute{
				Required:    true,
				Description: "Criteria selecting the assets to deploy to, written against the asset scope.",
			},
			"direction": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("inbound"),
				Description: "Which direction of policy to deploy.",
				Validators:  []validator.String{stringvalidator.OneOf("inbound", "outbound")},
			},
			"mode": schema.StringAttribute{
				Optional: true,
				Description: "Deploy the whole asset in this mode, rather than naming ports. " +
					"`test` deploys the rules but logs what would be blocked instead of blocking it, " +
					"`enforce` blocks, and `undeploy` withdraws the policy. " +
					"Set either this or the port maps, not both.",
				Validators: []validator.String{stringvalidator.OneOf("test", "intranet-test", "enforce", "undeploy")},
			},
			"reviewed": schema.MapNestedAttribute{
				Optional: true,
				Description: "How to deploy ports that carry a review decision, keyed by protocol and port " +
					"such as `TCP:443`, a range such as `TCP:8000-8100`, or `*` for all of them.",
				NestedObject: deploymentPlanEntrySchema(),
			},
			"unreviewed": schema.MapNestedAttribute{
				Optional: true,
				Description: "How to deploy ports with no review decision. Only the `*` key is honoured; " +
					"the backend ignores any other key here.",
				NestedObject: deploymentPlanEntrySchema(),
			},
			"comment": schema.StringAttribute{
				Optional:    true,
				Description: "Note recorded against the deployment in the audit log. At most 500 characters.",
				Validators:  []validator.String{stringvalidator.LengthAtMost(500)},
			},
			"undeploy_on_destroy": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Withdraw the deployed policy when this resource is destroyed. " +
					"Off by default, because removing a deployment from a configuration is usually a " +
					"bookkeeping change rather than an instruction to stop enforcing.",
			},
			"last_deployed_at": schema.StringAttribute{
				Computed:    true,
				Description: "When this resource last sent a deployment.",
			},
			"assets_changed": schema.BoolAttribute{
				Computed: true,
				Description: "Whether the last deployment changed any asset. False means every matched " +
					"asset was already in the requested state, which the API reports as not modified.",
			},
			"ports_pending_deployment": schema.Int64Attribute{
				Computed: true,
				Description: "Ports whose review state differs from what is enforced on the matched assets. " +
					"Above zero means intent has moved on since the last deployment and another is due.",
			},
		},
	}
}

func deploymentPlanEntrySchema() schema.NestedAttributeObject {
	return schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"mode": schema.StringAttribute{
				Required:    true,
				Description: "How to deploy these ports.",
				Validators:  []validator.String{stringvalidator.OneOf("test", "intranet-test", "enforce", "undeploy")},
			},
			"target_assets": schema.StringAttribute{
				Optional: true,
				Description: "Which of the matched assets to act on: `all`, or `affected` to limit the " +
					"deployment to assets the port change actually touches.",
				Validators: []validator.String{stringvalidator.OneOf("all", "affected")},
			},
			"bypass_warnings": schema.BoolAttribute{
				Optional:    true,
				Description: "Proceed even when the platform warns the change is risky.",
			},
		},
	}
}

func (r *PolicyDeploymentResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *sdk.Xshield, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	r.client = client
}

func (r *PolicyDeploymentResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data PolicyDeploymentResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasMode := !data.Mode.IsNull() && !data.Mode.IsUnknown()
	hasPlan := len(data.Reviewed) > 0 || len(data.Unreviewed) > 0

	switch {
	case hasMode && hasPlan:
		resp.Diagnostics.AddError(
			"Set either mode or the port maps, not both",
			"mode deploys every port on the asset, while reviewed and unreviewed name individual ports. "+
				"Naming ports as well as a whole-asset mode would leave it ambiguous which the backend should apply.")
	case !hasMode && !hasPlan:
		resp.Diagnostics.AddError(
			"Nothing to deploy",
			"Set mode to deploy the whole asset, or set reviewed and unreviewed to deploy individual ports.")
	}

	// Only the wildcard key means anything on the unreviewed side, and a key that
	// is quietly ignored is worse than one that is refused.
	for key := range data.Unreviewed {
		if key != "*" {
			resp.Diagnostics.AddAttributeError(
				path.Root("unreviewed").AtMapKey(key),
				"Only the \"*\" key is honoured for unreviewed ports",
				"An unreviewed port has no decision to deploy per port, so the backend reads only the "+
					"\"*\" entry here and ignores the rest. Move this entry to reviewed, or replace the map "+
					"with a single \"*\" entry.")
		}
	}
}

// isWholeAssetDeploy reports whether the backend will treat this as a
// whole-asset deployment rather than a micro-deployment.
//
// The distinction is not a flag: it holds only when both maps carry the
// wildcard key. Anything else deploys named ports, which the tenant has to
// permit and every matched asset has to support.
// Source: GetDeployPortList in common-policy-enforcement/pkg/deployment/utils.go.
func isWholeAssetDeploy(reviewed, unreviewed map[string]deploymentPlanEntryModel) bool {
	_, reviewedAll := reviewed["*"]
	_, unreviewedAll := unreviewed["*"]
	return reviewedAll && unreviewedAll
}

func (r *PolicyDeploymentResource) buildInput(data *PolicyDeploymentResourceModel) shared.PortDeploymentInput {
	reviewed := data.Reviewed
	unreviewed := data.Unreviewed

	// The whole-asset shorthand is both wildcard keys carrying the same mode,
	// which is what makes the backend skip the micro-deployment requirements.
	if !data.Mode.IsNull() && data.Mode.ValueString() != "" {
		entry := deploymentPlanEntryModel{Mode: data.Mode}
		reviewed = map[string]deploymentPlanEntryModel{"*": entry}
		unreviewed = map[string]deploymentPlanEntryModel{"*": entry}
	}

	input := shared.PortDeploymentInput{
		DeploymentCriteria: shared.PortEnforceModeInput{
			Criteria:  data.Criteria.ValueString(),
			Direction: data.Direction.ValueStringPointer(),
		},
		DeploymentPlan: shared.DeploymentPlan{
			Reviewed:   convertPlanEntries(reviewed),
			Unreviewed: convertPlanEntries(unreviewed),
		},
	}
	if !data.Comment.IsNull() && data.Comment.ValueString() != "" {
		input.Comment = data.Comment.ValueStringPointer()
	}
	return input
}

func convertPlanEntries(entries map[string]deploymentPlanEntryModel) map[string]shared.DeploymentConfig {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]shared.DeploymentConfig, len(entries))
	for key, entry := range entries {
		config := shared.DeploymentConfig{
			DeploymentMode: shared.DeploymentMode(entry.Mode.ValueString()),
		}
		if !entry.TargetAssets.IsNull() && entry.TargetAssets.ValueString() != "" {
			target := shared.TargetAssets(entry.TargetAssets.ValueString())
			config.TargetAssets = &target
		}
		if !entry.BypassWarnings.IsNull() {
			config.BypassWarnings = entry.BypassWarnings.ValueBoolPointer()
		}
		out[key] = config
	}
	return out
}

// deploy sends the deployment and reports whether any asset changed.
func (r *PolicyDeploymentResource) deploy(ctx context.Context, input shared.PortDeploymentInput) (changed bool, err error) {
	err = retryWhileDeploymentInProgress(ctx, "deploying policy", func() error {
		res, callErr := r.client.Policy.DeployPorts(ctx, input)
		if callErr != nil {
			return callErr
		}
		switch res.StatusCode {
		case 200:
			changed = true
			return nil
		case 304:
			// Every matched asset was already in the requested state.
			changed = false
			return nil
		default:
			return classifyDeploymentError(res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
		}
	})
	return changed, err
}

// countPendingPorts reports how many ports have a review state the assets are
// not yet enforcing, which is what makes a further deployment necessary.
func (r *PolicyDeploymentResource) countPendingPorts(ctx context.Context, data *PolicyDeploymentResourceModel) (int64, error) {
	res, err := r.client.Policy.ListChangedPorts(ctx, shared.PortTestModeInput{
		Criteria:  data.Criteria.ValueString(),
		Direction: data.Direction.ValueStringPointer(),
	})
	if err != nil {
		return 0, err
	}
	if res.StatusCode == 404 {
		return 0, nil
	}
	if res.StatusCode != 200 {
		return 0, classifyDeploymentError(res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
	}
	if res.DeploymentPorts == nil {
		return 0, nil
	}
	pending := int64(0)
	for _, port := range res.DeploymentPorts.ReviewedPorts {
		if port.IsDeploymentRequired != nil && *port.IsDeploymentRequired {
			pending++
		}
	}
	for _, port := range res.DeploymentPorts.UnreviewedPorts {
		if port.IsDeploymentRequired != nil && *port.IsDeploymentRequired {
			pending++
		}
	}
	return pending, nil
}

// deploymentID identifies the deployment by what it acts on, since the API
// returns no identifier of its own.
func deploymentID(data *PolicyDeploymentResourceModel) string {
	return fmt.Sprintf("%s|%s", data.Direction.ValueString(), data.Criteria.ValueString())
}

func (r *PolicyDeploymentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PolicyDeploymentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.applyDeployment(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PolicyDeploymentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data PolicyDeploymentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.applyDeployment(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PolicyDeploymentResource) applyDeployment(ctx context.Context, data *PolicyDeploymentResourceModel, diags *diag.Diagnostics) {
	changed, err := r.deploy(ctx, r.buildInput(data))
	if err != nil {
		diags.AddError("Cannot deploy policy", err.Error())
		return
	}

	data.ID = types.StringValue(deploymentID(data))
	data.AssetsChanged = types.BoolValue(changed)
	data.LastDeployedAt = types.StringValue(time.Now().UTC().Format(time.RFC3339))

	pending, err := r.countPendingPorts(ctx, data)
	if err != nil {
		// The deployment itself succeeded, so this is reported but not fatal.
		diags.AddWarning("Cannot count ports still awaiting deployment", err.Error())
		data.PortsPending = types.Int64Value(0)
		return
	}
	data.PortsPending = types.Int64Value(pending)
}

func (r *PolicyDeploymentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PolicyDeploymentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// A deployment is an action, so there is no object to re-read. What can drift
	// is whether intent has moved on since it ran, which is what this reports.
	pending, err := r.countPendingPorts(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddWarning("Cannot count ports still awaiting deployment", err.Error())
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}
	data.PortsPending = types.Int64Value(pending)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PolicyDeploymentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PolicyDeploymentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !data.UndeployOnDestroy.ValueBool() {
		// Removing the record leaves the deployed policy running, which is what
		// destroying a bookkeeping resource should do.
		return
	}

	undeploy := deploymentPlanEntryModel{Mode: types.StringValue("undeploy")}
	input := r.buildInput(&PolicyDeploymentResourceModel{
		Criteria:   data.Criteria,
		Direction:  data.Direction,
		Comment:    data.Comment,
		Reviewed:   map[string]deploymentPlanEntryModel{"*": undeploy},
		Unreviewed: map[string]deploymentPlanEntryModel{"*": undeploy},
	})
	if _, err := r.deploy(ctx, input); err != nil {
		resp.Diagnostics.AddError("Cannot withdraw the deployed policy", err.Error())
	}
}
