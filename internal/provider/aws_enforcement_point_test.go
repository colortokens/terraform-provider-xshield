package provider

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const awsPointPath = "/api/policies/cloudsnapshots/aws/123456789012/us-east-1"

func receiptSchema(ctx context.Context) schema.Schema {
	var resp resource.SchemaResponse
	(&awsEnforcementReceiptResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	return resp.Schema
}

// The receipt and the status name AWS in their type, so every request they make is for an AWS account and region.
func TestReceiptAndStatusRequestTheAWSEnforcementPoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	held := loadJSON[wireConvergence](t, "status.json")
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/receipts": {http.StatusCreated, `{"receiptId":"receipt-2","appliedAt":"2026-01-02T00:00:00Z"}`},
		"/status":   {http.StatusOK, readTestdata(t, "status.json")},
	})
	receipt := &awsEnforcementReceiptResource{api: api}
	s := receiptSchema(ctx)

	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	plan := receiptObject(t, s, map[string]tftypes.Value{"id": unknown, "applied_at": unknown, "run_id": unknown})
	created := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
	receipt.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: plan}}, &created)
	if created.Diagnostics.HasError() {
		t.Fatalf("create: %v", created.Diagnostics)
	}

	stored := tfsdk.State{Schema: s, Raw: receiptObject(t, s, map[string]tftypes.Value{
		"id": tftypes.NewValue(tftypes.String, held.Applied.ReceiptID),
	})}
	read := resource.ReadResponse{State: stored}
	receipt.Read(ctx, resource.ReadRequest{State: stored}, &read)
	if read.Diagnostics.HasError() {
		t.Fatalf("read: %v", read.Diagnostics)
	}

	var m awsEnforcementStatusDataSourceModel
	if ok, errs := readDataSource(t, &awsEnforcementStatusDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatal(errs)
	}

	want := []string{awsPointPath + "/receipts", awsPointPath + "/status", awsPointPath + "/status"}
	if !slices.Equal(*requested, want) {
		t.Errorf("requested %v, want %v", *requested, want)
	}
}

// The import id names an AWS account and region. No region holds a slash, so an id with more parts is refused rather
// than read as an account whose region holds one.
func TestReceiptImportIDIsAnAWSAccountAndRegion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := receiptSchema(ctx)
	importID := func(id string) (resource.ImportStateResponse, bool) {
		resp := resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
		(&awsEnforcementReceiptResource{}).ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
		return resp, !resp.Diagnostics.HasError()
	}

	resp, ok := importID("123456789012/us-east-1")
	if !ok {
		t.Fatalf("an account and region were refused: %v", resp.Diagnostics)
	}
	var account, region types.String
	resp.State.GetAttribute(ctx, path.Root("cloud_account_id"), &account)
	resp.State.GetAttribute(ctx, path.Root("region"), &region)
	if account.ValueString() != "123456789012" || region.ValueString() != "us-east-1" {
		t.Errorf("imported %s %s", account, region)
	}

	for _, id := range []string{"aws/123456789012/us-east-1", "123456789012", "123456789012/", "/us-east-1"} {
		if resp, ok := importID(id); ok || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "<cloud_account_id>/<region>") {
			t.Errorf("import id %q was accepted", id)
		}
	}
}
