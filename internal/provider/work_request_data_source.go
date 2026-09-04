package provider

import (
	"context"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &WorkRequestDataSource{}
var _ datasource.DataSourceWithConfigure = &WorkRequestDataSource{}

func NewWorkRequestDataSource() datasource.DataSource { return &WorkRequestDataSource{} }

type WorkRequestDataSource struct{ client *sdk.Xshield }

type WorkRequestDataSourceModel struct {
	ID           types.String `tfsdk:"id"`
	Status       types.String `tfsdk:"status"`
	Action       types.String `tfsdk:"action"`
	ResourceID   types.String `tfsdk:"resource_id"`
	ResourceName types.String `tfsdk:"resource_name"`
	Subject      types.String `tfsdk:"subject"`
	CreatedAt    types.String `tfsdk:"created_at"`
	CompletedAt  types.String `tfsdk:"completed_at"`
	RetryCounter types.Int64  `tfsdk:"retry_counter"`
	Terminal     types.Bool   `tfsdk:"terminal"`
}

func (d *WorkRequestDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_work_request"
}

func (d *WorkRequestDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The state of one asynchronous operation.\n\n" +
			"Mutating calls that do work in the background return a work request id in the " +
			"`x-ct-workrequest-id` response header. Read it here to see whether that work finished.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Work request id, as returned in the x-ct-workrequest-id header.",
			},
			"status": schema.StringAttribute{
				Computed: true,
				Description: "One of Pending, InProgress, Retry, Completed, Cancelled or Superseded. " +
					"Superseded means a later request for the same resource replaced this one.",
			},
			"action":        schema.StringAttribute{Computed: true, Description: "What triggered the work, such as AssetUpdated or TemplateEdit."},
			"resource_id":   schema.StringAttribute{Computed: true, Description: "Object the work applies to."},
			"resource_name": schema.StringAttribute{Computed: true},
			"subject":       schema.StringAttribute{Computed: true, Description: "Principal that submitted the work."},
			"created_at":    schema.StringAttribute{Computed: true},
			"completed_at":  schema.StringAttribute{Computed: true, Description: "When the work reached a terminal status, if it has."},
			"retry_counter": schema.Int64Attribute{Computed: true, Description: "How many times the work has been retried."},
			"terminal": schema.BoolAttribute{
				Computed:    true,
				Description: "True once the status is one the work will not move on from.",
			},
		},
	}
}

func (d *WorkRequestDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configureDataSourceClient(req, resp)
}

func (d *WorkRequestDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data WorkRequestDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := d.client.Workrequests.GetWorkRequest(ctx,
		operations.GetWorkRequestRequest{WorkID: data.ID.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Cannot read the work request", err.Error())
		return
	}
	if res.StatusCode != 200 {
		resp.Diagnostics.AddError(
			"Cannot read the work request",
			apiErrorDetail(res.ErrorResponse, res.RawResponse))
		return
	}
	if res.WorkrequestWorkRequest == nil {
		// The endpoint answers 200 with an empty body when the id is unknown.
		resp.Diagnostics.AddError(
			"No such work request",
			"The API reported no work request with id "+data.ID.ValueString()+
				". Work requests are removed once their retention window passes.")
		return
	}

	wr := res.WorkrequestWorkRequest
	data.Action = types.StringValue(string(wr.Action))
	data.ResourceID = types.StringValue(wr.ResourceID)
	data.ResourceName = types.StringPointerValue(wr.ResourceName)
	data.Subject = types.StringValue(wr.Subject)
	data.RetryCounter = int64OrNull(wr.RetryCounter)

	data.Status = types.StringNull()
	data.Terminal = types.BoolValue(false)
	if wr.Status != nil {
		status := string(*wr.Status)
		data.Status = types.StringValue(status)
		data.Terminal = types.BoolValue(workRequestIsTerminal(status))
	}

	data.CreatedAt = timeOrNull(wr.CreatedAt)
	data.CompletedAt = timeOrNull(wr.CompletedAt)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// workRequestIsTerminal reports whether a status is one the work will not leave.
// Retry is deliberately absent: the work is still scheduled to run again.
func workRequestIsTerminal(status string) bool {
	switch status {
	case "Completed", "Cancelled", "Superseded":
		return true
	default:
		return false
	}
}

func timeOrNull(t *time.Time) types.String {
	if t == nil || t.IsZero() {
		return types.StringNull()
	}
	return types.StringValue(t.Format(time.RFC3339))
}
