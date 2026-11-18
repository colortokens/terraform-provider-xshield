package provider

import (
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func readAzureStatus(t *testing.T, status cannedResponse) (azureEnforcementStatusDataSourceModel, []string) {
	t.Helper()
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/status": status})
	var m azureEnforcementStatusDataSourceModel
	args := map[string]tftypes.Value{
		"cloud_account_id": tftypes.NewValue(tftypes.String, azureTestSubscription),
		"region":           tftypes.NewValue(tftypes.String, "eastus2"),
	}
	if ok, errs := readDataSource(t, &azureEnforcementStatusDataSource{api: api}, args, &m); !ok {
		t.Fatalf("read: %s", errs)
	}
	return m, *requested
}

// The snapshot leaves a refused workload out, so the status is the only place Terraform can see the refusal.
func TestAzureStatusReportsARefusedWorkload(t *testing.T) {
	m, requested := readAzureStatus(t, cannedResponse{http.StatusOK, `{"cloudProvider":"azure","state":"unapplied",
		"expected":{"version":"v1","publishedAt":"2026-11-18T22:38:25Z"},"lastCheckedAt":"2026-11-18T22:40:00Z",
		"notices":[{"code":"assetRefused","assetId":"a-db","assetName":"crm-db","reason":"NO_FREE_LEVEL",
		"message":"both levels carry a network security group of yours"}]}`})
	want := "/api/policies/cloudsnapshots/azure/" + azureTestSubscription + "/eastus2/status"
	if len(requested) != 1 || requested[0] != want {
		t.Fatalf("want one request to %s, got %v", want, requested)
	}
	if !m.Published.ValueBool() || m.State.ValueString() != "unapplied" || m.ExpectedVersion.ValueString() != "v1" ||
		m.LastCheckedAt.ValueString() != "2026-11-18T22:40:00Z" {
		t.Fatalf("unexpected point: %+v", m)
	}
	if len(m.Notices) != 1 {
		t.Fatalf("want one notice, got %d", len(m.Notices))
	}
	n := m.Notices[0]
	if n.Code.ValueString() != "assetRefused" || n.Reason.ValueString() != "NO_FREE_LEVEL" || n.AssetID.ValueString() != "a-db" ||
		n.AssetName.ValueString() != "crm-db" || !n.Group.IsNull() || !n.Since.IsNull() {
		t.Fatalf("unexpected notice: %+v", n)
	}
}

func TestAzureStatusOfAnUnpublishedPointIsQuiet(t *testing.T) {
	m, _ := readAzureStatus(t, cannedResponse{http.StatusNotFound, xshieldNotPublished})
	if m.Published.ValueBool() || m.State.ValueString() != "unpublished" || !m.ExpectedVersion.IsNull() ||
		!m.LastCheckedAt.IsNull() || m.Notices == nil || len(m.Notices) != 0 {
		t.Fatalf("unexpected point: %+v", m)
	}
}
