package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// A read made to review the snapshot must not count as the enforcement pipeline's plan, or it would hide a stopped pipeline.
func TestAReviewReadLeavesThePipelinesLastCheckAlone(t *testing.T) {
	t.Parallel()
	served := loadJSON[wireSnapshot](t, "snapshot.json")
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{
		"/status":                     {http.StatusOK, `{"state":"converged","expected":{"version":"` + served.Version + `"}}`},
		"/versions/" + served.Version: {http.StatusOK, readTestdata(t, "snapshot.json")},
	})
	args := pointArgs()
	delete(args, "enforcement_plan")

	var m awsEnforcementSnapshotDataSourceModel
	if ok, errs := readDataSource(t, &awsEnforcementSnapshotDataSource{api: api}, args, &m); !ok {
		t.Fatalf("a review read failed: %s (requested %v)", errs, *requested)
	}
	if m.Version.ValueString() != served.Version || len(m.SecurityGroups) == 0 {
		t.Errorf("version %v with %d groups, want the expected version's snapshot", m.Version, len(m.SecurityGroups))
	}
	if slices.ContainsFunc(*requested, func(p string) bool { return strings.HasSuffix(p, "/expected") }) {
		t.Errorf("requested %v; a review read must not read /expected, which records the pipeline's check", *requested)
	}
}
