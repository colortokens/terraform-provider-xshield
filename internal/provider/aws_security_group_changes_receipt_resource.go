package provider

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &awsSecurityGroupChangesReceiptResource{}
var _ resource.ResourceWithConfigure = &awsSecurityGroupChangesReceiptResource{}
var _ resource.ResourceWithImportState = &awsSecurityGroupChangesReceiptResource{}

func newAWSSecurityGroupChangesReceiptResource() resource.Resource {
	return &awsSecurityGroupChangesReceiptResource{}
}

// awsSecurityGroupChangesReceiptResource tells Xshield which customer group changes a workspace applied. It sends the
// values its plan holds, so a saved plan made before a revert reports the changes as they were before it.
type awsSecurityGroupChangesReceiptResource struct {
	api cloudSnapshotAPI
}

type awsSecurityGroupChangesReceiptModel struct {
	ID             types.String `tfsdk:"id"`
	CloudAccountID types.String `tfsdk:"cloud_account_id"`
	Region         types.String `tfsdk:"region"`
	Version        types.String `tfsdk:"version"`
	Groups         types.Map    `tfsdk:"groups"`
	Label          types.String `tfsdk:"label"`
}

var groupChangesReceiptLabel = regexp.MustCompile(`^[A-Za-z0-9 ._:/@-]+$`)

const groupChangesReceiptLabelMaxLength = 256

func (r *awsSecurityGroupChangesReceiptResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_security_group_changes_receipt"
}

func (r *awsSecurityGroupChangesReceiptResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Tells Xshield which changes to your own security groups a workspace has applied. The " +
			"`aws-security-group-rules` module declares one for each group an approved Full control change applies to, " +
			"after the group's rules, so it is sent once they are applied. The API key's user needs permission to create " +
			"enforcement receipts as well as to read cloud snapshots, which the built-in ADMIN and USER roles both have.\n\n" +
			"When a change is reverted, Xshield keeps the access it moved into `ct-cohort-` groups until every receipt that " +
			"reported the change narrowing a group reports, after the revert, that it no longer does, and it then sees the " +
			"group hold the rules again. The receipt sends what the plan read, so a plan saved before the revert and applied " +
			"after it reports the change still narrowing the group: Xshield keeps the access, and a notice says to plan and " +
			"apply that workspace again.\n\n" +
			"Changing what it reports sends it again under the same `id`. Destroying it tells Xshield to forget it, so no " +
			"revert waits on it. A receipt whose workspace was deleted without being destroyed keeps a revert waiting: import " +
			"it by the `id` the notice names, in any configuration, and destroy it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "A UUID generated when the receipt is created and kept for its life. Each apply replaces " +
					"what this ID reported before, and Xshield names it in a notice that waits on it.",
			},
			"cloud_account_id": schema.StringAttribute{
				Required:            true,
				PlanModifiers:       replace,
				MarkdownDescription: "AWS account the groups are in.",
			},
			"region": schema.StringAttribute{
				Required:            true,
				PlanModifiers:       replace,
				MarkdownDescription: "AWS region the groups are in.",
			},
			"version": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Version of the changes to customer groups the plan read, the `version` of " +
					"`xshield_aws_security_group_rules`.",
			},
			"groups": schema.MapAttribute{
				Required:    true,
				ElementType: types.MapType{ElemType: types.StringType},
				Validators: []validator.Map{
					mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
					mapvalidator.ValueMapsAre(mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
						mapvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))),
				},
				MarkdownDescription: "The groups whose rules were applied, each by its AWS ID, the `security_group_id` of " +
					"`xshield_aws_security_group_rules`, with the state of each change set that applies to it, its " +
					"`change_sets`, as the plan read them.",
			},
			"label": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(groupChangesReceiptLabelMaxLength),
					stringvalidator.RegexMatches(groupChangesReceiptLabel, "may hold only letters, digits, spaces and . _ : / @ -"),
				},
				PlanModifiers: []planmodifier.String{workspaceNameLabel{}},
				MarkdownDescription: "What Xshield's notices call this receipt besides its `id`, such as the workspace that sends " +
					"it: at most 256 letters, digits, spaces and `. _ : / @ -`. Defaults to the HCP Terraform or Terraform " +
					"Enterprise workspace's name, `TFC_WORKSPACE_NAME`, and is null where that is not set.",
			},
		},
	}
}

func (r *awsSecurityGroupChangesReceiptResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*sdk.Xshield)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *sdk.Xshield, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}
	r.api = cloudSnapshotAPI{client: client}
}

type workspaceNameLabel struct{}

func (workspaceNameLabel) Description(ctx context.Context) string {
	return "Defaults to TFC_WORKSPACE_NAME."
}

func (m workspaceNameLabel) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (workspaceNameLabel) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if !req.ConfigValue.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	resp.PlanValue = types.StringNull()
	name := os.Getenv("TFC_WORKSPACE_NAME")
	if name == "" {
		return
	}
	if len(name) > groupChangesReceiptLabelMaxLength || !groupChangesReceiptLabel.MatchString(name) {
		resp.Diagnostics.AddAttributeWarning(req.Path, "The workspace name cannot label this receipt",
			fmt.Sprintf("TFC_WORKSPACE_NAME %q is not at most 256 letters, digits, spaces and . _ : / @ -, so the receipt is sent "+
				"without a label and Xshield's notices name it by its id. Set label to name it.", name))
		return
	}
	resp.PlanValue = types.StringValue(name)
}

type wireGroupChangesReceipt struct {
	ID      string                         `json:"id"`
	Label   string                         `json:"label,omitempty"`
	Version string                         `json:"version"`
	Groups  []wireGroupChangesReceiptGroup `json:"groups"`
}

type wireGroupChangesReceiptGroup struct {
	GroupID    string                             `json:"groupId"`
	ChangeSets []wireGroupChangesReceiptChangeSet `json:"changeSets"`
}

type wireGroupChangesReceiptChangeSet struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// groupChangesReceiptRequest lists the groups and change sets in ID order, so the same plan always sends the same body.
func groupChangesReceiptRequest(ctx context.Context, data awsSecurityGroupChangesReceiptModel) (wireGroupChangesReceipt, diag.Diagnostics) {
	var groups map[string]map[string]string
	diags := data.Groups.ElementsAs(ctx, &groups, false)
	body := wireGroupChangesReceipt{ID: data.ID.ValueString(), Label: data.Label.ValueString(), Version: data.Version.ValueString(),
		Groups: []wireGroupChangesReceiptGroup{}}
	for _, groupID := range slices.Sorted(maps.Keys(groups)) {
		group := wireGroupChangesReceiptGroup{GroupID: groupID, ChangeSets: []wireGroupChangesReceiptChangeSet{}}
		for _, changeSetID := range slices.Sorted(maps.Keys(groups[groupID])) {
			group.ChangeSets = append(group.ChangeSets, wireGroupChangesReceiptChangeSet{ID: changeSetID, State: groups[groupID][changeSetID]})
		}
		body.Groups = append(body.Groups, group)
	}
	return body, diags
}

func (r *awsSecurityGroupChangesReceiptResource) receiptsEndpoint(data awsSecurityGroupChangesReceiptModel, id ...string) string {
	return r.api.endpoint(cloudAWS, data.CloudAccountID.ValueString(), data.Region.ValueString(), append([]string{"customergroupchanges", "receipts"}, id...)...)
}

const groupChangesReceiptAdvice = "The group's rules are applied. Apply again to send this receipt once the cause is fixed. " +
	"Until Xshield has it, a revert of a change it reports keeps the access Xshield moved into ct-cohort- groups."

// send reports whether Xshield may hold the receipt now, which it does unless it answered with a refusal.
func (r *awsSecurityGroupChangesReceiptResource) send(ctx context.Context, data awsSecurityGroupChangesReceiptModel) (bool, diag.Diagnostics) {
	body, diags := groupChangesReceiptRequest(ctx, data)
	if diags.HasError() {
		return false, diags
	}
	if err := r.api.post(ctx, r.receiptsEndpoint(data), body, http.StatusCreated, nil); err != nil {
		advice := groupChangesReceiptAdvice
		if isAPIRefusal(err, http.StatusNotFound, codeNotPublished) {
			advice = "The group's rules are applied, but Xshield has no published snapshot for this account and region, so the " +
				"changes this plan read no longer exist: run a new plan and apply it."
		}
		diags.AddError("Xshield did not accept the customer group changes receipt", err.Error()+"\n\n"+advice)
		return mayHaveBeenRecorded(err), diags
	}
	return true, diags
}

func mayHaveBeenRecorded(err error) bool {
	var apiErr *snapshotAPIError
	return !errors.As(err, &apiErr) || apiErr.Status >= http.StatusInternalServerError
}

// Create keeps a receipt whose answer did not arrive in state, where Terraform marks it tainted: the next apply
// deletes its id, which Xshield may have recorded, before it sends the receipt under a new one.
func (r *awsSecurityGroupChangesReceiptResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data awsSecurityGroupChangesReceiptModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := newGroupChangesReceiptID()
	if err != nil {
		resp.Diagnostics.AddError("Cannot generate the receipt's id", err.Error())
		return
	}
	data.ID = types.StringValue(id)
	recorded, diags := r.send(ctx, data)
	resp.Diagnostics.Append(diags...)
	if recorded {
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	}
}

// Update leaves the state as it was when the receipt is not accepted, so the next plan sends it again.
func (r *awsSecurityGroupChangesReceiptResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data awsSecurityGroupChangesReceiptModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, diags := r.send(ctx, data)
	if resp.Diagnostics.Append(diags...); diags.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read keeps the state: Xshield serves no receipt back, and what it holds for the id is what was last sent.
func (r *awsSecurityGroupChangesReceiptResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

func (r *awsSecurityGroupChangesReceiptResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data awsSecurityGroupChangesReceiptModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.api.do(ctx, http.MethodDelete, r.receiptsEndpoint(data, url.PathEscape(data.ID.ValueString())), nil, http.StatusNoContent, nil)
	if err != nil && !isAPIStatus(err, http.StatusNotFound) {
		resp.Diagnostics.AddError("Xshield did not forget the customer group changes receipt", err.Error()+"\n\n"+
			"Until it does, a revert of a change this receipt reported narrowing a group keeps the access Xshield moved into "+
			"ct-cohort- groups. Destroy it again once the cause is fixed.")
	}
}

// isAPIStatus is true for any answer with the status: a DELETE answered 404 has nothing left to forget, whether Xshield
// no longer knows the account and region or serves no receipts there.
func isAPIStatus(err error, status int) bool {
	var apiErr *snapshotAPIError
	return errors.As(err, &apiErr) && apiErr.Status == status
}

var groupChangesReceiptID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r *awsSecurityGroupChangesReceiptResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !groupChangesReceiptID.MatchString(parts[2]) {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("expected <cloud_account_id>/<region>/<receipt id>, the receipt id being the lowercase UUID Xshield's notice names, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cloud_account_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("region"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[2])...)
}

// newGroupChangesReceiptID is a random (version 4) UUID.
func newGroupChangesReceiptID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
