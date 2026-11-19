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
	Stage          types.String `tfsdk:"stage"`
	ReceiptID      types.String `tfsdk:"receipt_id"`
	CloudAccountID types.String `tfsdk:"cloud_account_id"`
	Region         types.String `tfsdk:"region"`
	Version        types.String `tfsdk:"version"`
	Groups         types.Map    `tfsdk:"groups"`
	Label          types.String `tfsdk:"label"`
}

var groupChangesReceiptLabel = regexp.MustCompile(`^[A-Za-z0-9 ._:/@-]+$`)

const groupChangesReceiptLabelMaxLength = 256

const (
	receiptStageApplying = "applying"
	receiptStageApplied  = "applied"
)

func (r *awsSecurityGroupChangesReceiptResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_security_group_changes_receipt"
}

func (r *awsSecurityGroupChangesReceiptResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Tells Xshield which changes to your own security groups a workspace applies. The " +
			"`aws-security-group-rules` module declares two for each group an approved Full control change applies to, " +
			"under one ID: one with `stage = \"applying\"` that the group's rules depend on, so it is sent before any rule is " +
			"created or updated, and one with `stage = \"applied\"` that depends on the rules, so it is sent once they are. The " +
			"module's rules set `create_before_destroy`, so a rule the apply takes out of the group is destroyed after the " +
			"`applied` receipt; without it, Terraform destroys such a rule before it sends the `applying` receipt. Terraform " +
			"reads that order for a rule no longer declared from the state the last apply wrote, so it holds from the second " +
			"apply of rules that set it. Rules wired to these receipts by hand need `create_before_destroy` too. The " +
			"API key's user needs permission to create enforcement receipts as well as to read cloud snapshots, which the " +
			"built-in ADMIN and USER roles both have.\n\n" +
			"When a change is reverted, Xshield keeps the access it moved into `ct-cohort-` groups until every receipt ID " +
			"that reported the change narrowing a group sends an `applied` receipt, after the revert, that no longer does, " +
			"and it then sees the group hold the rules again. Each receipt sends what the plan read, so a plan made while the " +
			"change narrowed the group and applied after it was reverted reports it still narrowing the group. Xshield " +
			"refuses that `applying` receipt, and the apply stops before any rule that waits for it changes.\n\n" +
			"Changing what it reports sends it again under the same `id`. Destroying the receipt that generated the ID tells " +
			"Xshield to forget it, so no revert waits on it; destroying one sent under `receipt_id` sends nothing. A receipt ID that a workspace no longer declares, because its state lost the receipt or the " +
			"workspace was deleted without being destroyed, keeps a revert waiting: import it by the ID the notice names, in " +
			"any configuration, and destroy it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "The receipt's ID: `receipt_id` where it is set, and otherwise a UUID generated when the " +
					"receipt is created. It is kept for the receipt's life. Each apply replaces what this ID reported before " +
					"at this stage, and Xshield names it in a notice that waits on it.",
			},
			"stage": schema.StringAttribute{
				Required:      true,
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(receiptStageApplying, receiptStageApplied)},
				MarkdownDescription: "When in the apply the receipt is sent. `applying`: before the rules it reports are " +
					"changed, which `depends_on` it, so Xshield can refuse a plan made before a revert while no rule has changed. " +
					"`applied`: once those rules are applied, which it `depends_on`.",
			},
			"receipt_id": schema.StringAttribute{
				Optional:      true,
				PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.RegexMatches(groupChangesReceiptID,
					"must be a lowercase UUID, the id of the receipt sent before the rules")},
				MarkdownDescription: "The ID to send the receipt under instead of a generated one: on the `applied` receipt, the " +
					"`id` of the `applying` receipt sent before the same rules, so Xshield matches the two. Destroying a receipt " +
					"that sets it leaves the ID to the receipt that generated it.",
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
	Stage   string                         `json:"stage"`
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
	body := wireGroupChangesReceipt{ID: data.ID.ValueString(), Stage: data.Stage.ValueString(), Label: data.Label.ValueString(),
		Version: data.Version.ValueString(), Groups: []wireGroupChangesReceiptGroup{}}
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

const (
	// codeNotNarrowing refuses a receipt listing a change set narrowing a group that Xshield no longer publishes so.
	codeNotNarrowing = "notNarrowing"
	// codeChangeSetsChanged refuses an applying receipt listing a change set attaching or restoring a group that Xshield
	// no longer publishes so.
	codeChangeSetsChanged = "changeSetsChanged"
)

// groupChangesReceiptAdvice says what the apply did, whichever way the rules are wired: rules that wait for the receipt
// have not changed, and those it waits for are applied.
func groupChangesReceiptAdvice(err error, body wireGroupChangesReceipt) string {
	applying := body.Stage == receiptStageApplying
	switch {
	case isAPIRefusal(err, http.StatusConflict, codeHandedOver):
		return handedOverReceiptAdvice(applying)
	case isAPIRefusal(err, http.StatusConflict, codeNotNarrowing):
		return notNarrowingAdvice(body, applying)
	case isAPIRefusal(err, http.StatusConflict, codeChangeSetsChanged) && applying:
		return changeSetsChangedAdvice(body)
	case isAPIRefusal(err, http.StatusNotFound, codeNotPublished) && applying:
		return "Xshield has no published snapshot for this account and region, so the changes this plan read no longer exist. " +
			"No rule waiting on this receipt was changed. Run a new plan and apply it."
	case isAPIRefusal(err, http.StatusNotFound, codeNotPublished):
		return "The rules this receipt waits for are applied, and no rule waiting on it was changed, but Xshield has no published " +
			"snapshot for this account and region, so the changes this plan read no longer exist: run a new plan and apply it."
	case applying:
		return "No rule waiting on this receipt was changed. Apply again once the cause is fixed."
	}
	return "The rules this receipt waits for are applied, and no rule waiting on it was changed. Apply again to send this " +
		"receipt once the cause is fixed. Until Xshield has it, a revert of a change it reports keeps the access Xshield moved " +
		"into ct-cohort- groups."
}

// handedOverReceiptAdvice answers a receipt Xshield refuses because the account and region moved to connector delivery,
// which it refuses for every receipt from then on.
func handedOverReceiptAdvice(applying bool) string {
	done := "The rules this receipt waits for are applied, and no rule waiting on it was changed."
	if applying {
		done = "No rule waiting on this receipt was changed."
	}
	return done + " This account and region has been handed over to the cloud connector, which now changes the rules of your " +
		"groups that a change applies to, so Xshield refuses every receipt from this workspace, and an apply of it would put back " +
		"a rule the connector took out, or take out one it put back. Stop this workspace's runs, then stop managing these rules " +
		"as step 6 of the enforcement-snapshot example's Stop enforcing section says " +
		"(https://github.com/colortokens/terraform-provider-xshield/tree/main/examples/enforcement-snapshot#stop-enforcing): " +
		"replace each rules module block with removed blocks that keep the group's rules (lifecycle { destroy = false }), remove " +
		"xshield_aws_security_group_changes and what reads it, and apply once."
}

// notNarrowingAdvice names what the receipt listed narrowing; Xshield's refusal names which of those it no longer publishes.
func notNarrowingAdvice(body wireGroupChangesReceipt, applying bool) string {
	var listed []string
	group := ""
	for _, g := range body.Groups {
		for _, cs := range g.ChangeSets {
			if cs.State == changeSetNarrowing {
				listed = append(listed, fmt.Sprintf("change set %s as narrowing %s", cs.ID, g.GroupID))
				group = g.GroupID
			}
		}
	}
	lead, where := "a change set this plan read as narrowing, as its refusal names: it was", "the group"
	switch {
	case len(listed) == 1:
		lead, where = listed[0]+": it was", group
	case len(listed) > 1:
		lead = "one or more of the change sets this plan read as narrowing, as its refusal names (" + strings.Join(listed, ", ") + "): they were"
		where = "those groups"
	}
	return "Xshield no longer publishes " + lead + " reverted or withdrawn after this plan was made. No rule waiting on this receipt was " +
		"changed. Run a new plan and apply it now: it puts back any moved rule this apply took out of " + where + "."
}

// changeSetsChangedAdvice names what the receipt listed other than narrowing; Xshield's refusal names which of those it
// no longer publishes as listed.
func changeSetsChangedAdvice(body wireGroupChangesReceipt) string {
	var listed []string
	for _, g := range body.Groups {
		for _, cs := range g.ChangeSets {
			if cs.State != changeSetNarrowing {
				listed = append(listed, fmt.Sprintf("change set %s as %s %s", cs.ID, cs.State, g.GroupID))
			}
		}
	}
	lead := "a change set this plan read, as its refusal names: its revert ended or it was"
	switch {
	case len(listed) == 1:
		lead = listed[0] + ": its revert ended or it was"
	case len(listed) > 1:
		lead = "one or more of the change sets this plan read, as its refusal names (" + strings.Join(listed, ", ") +
			"): their reverts ended or they were"
	}
	return "Xshield no longer publishes " + lead + " withdrawn after this plan was made. No rule waiting on this receipt was changed. " +
		"Run a new plan and apply it."
}

// send reports whether Xshield may hold the receipt now, which it does unless it answered with a refusal.
func (r *awsSecurityGroupChangesReceiptResource) send(ctx context.Context, data awsSecurityGroupChangesReceiptModel) (bool, diag.Diagnostics) {
	body, diags := groupChangesReceiptRequest(ctx, data)
	if diags.HasError() {
		return false, diags
	}
	if err := r.api.post(ctx, r.receiptsEndpoint(data), body, http.StatusCreated, nil); err != nil {
		diags.AddError("Xshield did not accept the customer group changes receipt", err.Error()+"\n\n"+groupChangesReceiptAdvice(err, body))
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
	data.ID = data.ReceiptID
	if data.ReceiptID.IsNull() {
		id, err := newGroupChangesReceiptID()
		if err != nil {
			resp.Diagnostics.AddError("Cannot generate the receipt's id", err.Error())
			return
		}
		data.ID = types.StringValue(id)
	}
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

// Delete forgets the id only for the receipt that generated it. One sent under receipt_id shares the id with the receipt
// sent before the same rules, whose report must outlive a replacement of this one.
func (r *awsSecurityGroupChangesReceiptResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data awsSecurityGroupChangesReceiptModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() || !data.ReceiptID.IsNull() {
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
