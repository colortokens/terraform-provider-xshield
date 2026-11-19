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

func TestAzureStatusReportsDriftFromTheConnectorsObservation(t *testing.T) {
	m, _ := readAzureStatus(t, cannedResponse{http.StatusOK, `{"cloudProvider":"azure","state":"converged",
		"expected":{"version":"v1","publishedAt":"2026-11-18T22:38:25Z"},
		"applied":{"version":"v1","appliedAt":"2026-11-18T22:39:00Z","resources":{}},
		"drift":{"observedAt":"2026-11-18T22:50:00Z","observationStale":false,"findings":[
		{"kind":"memberUnattached","severity":"high","restoration":"pipeline","resource":"a-web","key":"nic-web",
		"detail":"web-nic no longer carries its group nic-web; it is not enforced","detectedAt":"2026-11-18T22:50:01Z"},
		{"kind":"ruleMissing","severity":"medium","restoration":"pipeline","resource":"nsg-id/securityRules/CT-Rule-Allow-1",
		"resourceName":"CT-Rule-Allow-1","key":"nic-web/CT-Rule-Allow-1","detail":"approved rule was removed out of band"}]}}`})
	if !m.DriftEvaluated.ValueBool() || m.DriftObservedAt.ValueString() != "2026-11-18T22:50:00Z" || len(m.DriftFindings) != 2 {
		t.Fatalf("unexpected drift: %+v", m)
	}
	unattached, missing := m.DriftFindings[0], m.DriftFindings[1]
	if unattached.Kind.ValueString() != "memberUnattached" || unattached.Resource.ValueString() != "a-web" ||
		!unattached.ResourceName.IsNull() || unattached.DetectedAt.ValueString() != "2026-11-18T22:50:01Z" {
		t.Fatalf("unexpected finding: %+v", unattached)
	}
	if missing.Key.ValueString() != "nic-web/CT-Rule-Allow-1" || missing.ResourceName.ValueString() != "CT-Rule-Allow-1" || !missing.DetectedAt.IsNull() {
		t.Fatalf("unexpected finding: %+v", missing)
	}
}

// An observation older than the latest apply describes what that apply replaced, so it is not evaluated.
func TestAzureStatusDoesNotEvaluateAnObservationOlderThanTheApply(t *testing.T) {
	m, _ := readAzureStatus(t, cannedResponse{http.StatusOK, `{"cloudProvider":"azure","state":"converged",
		"expected":{"version":"v2","publishedAt":"2026-11-18T22:38:25Z"},
		"applied":{"version":"v2","appliedAt":"2026-11-18T22:39:00Z","resources":{}},
		"drift":{"observedAt":"2026-11-18T22:30:00Z","observationStale":true,"findings":[]}}`})
	if m.DriftEvaluated.ValueBool() || m.DriftObservedAt.ValueString() != "2026-11-18T22:30:00Z" || m.DriftFindings == nil || len(m.DriftFindings) != 0 {
		t.Fatalf("unexpected drift: %+v", m)
	}
}

func TestAzureStatusWithNoObservationIsNotEvaluated(t *testing.T) {
	m, _ := readAzureStatus(t, cannedResponse{http.StatusNotFound, xshieldNotPublished})
	if m.DriftEvaluated.ValueBool() || !m.DriftObservedAt.IsNull() || m.DriftFindings == nil || len(m.DriftFindings) != 0 {
		t.Fatalf("unexpected drift: %+v", m)
	}
}
