package provider

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// A platform that predates unacknowledgedCarriers never sends the key, so its absence must read as no carriers.
func TestUnacknowledgedCarriersAreReadForTheGroupAndEmptyWhenTheServerSendsNone(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		carriers any
		want     []string
	}{
		"absent":    {nil, []string{}},
		"empty":     {[]string{}, []string{}},
		"two names": {[]string{"lb-public", "vpce-s3"}, []string{"lb-public", "vpce-s3"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("testdata", "customer_group_changes.json"))
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			web := document["customerGroupChanges"].(map[string]any)["vpc-1/web"].(map[string]any)
			if tc.carriers != nil {
				web["unacknowledgedCarriers"] = tc.carriers
			}
			served, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": {http.StatusOK, string(served)}})
			args := pointArgs()
			args["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
			args["group_name"] = tftypes.NewValue(tftypes.String, "web")
			var rules awsSecurityGroupRulesDataSourceModel
			if ok, errs := readDataSource(t, &awsSecurityGroupRulesDataSource{api: api}, args, &rules); !ok {
				t.Fatalf("read failed: %s", errs)
			}
			if got := keysOf(rules.UnacknowledgedCarriers); rules.UnacknowledgedCarriers == nil || !slices.Equal(got, tc.want) {
				t.Errorf("unacknowledged carriers %v (nil %v), want %v and never null", got, rules.UnacknowledgedCarriers == nil, tc.want)
			}
		})
	}
}

func TestAGroupWithNoChangeHasNoUnacknowledgedCarriers(t *testing.T) {
	t.Parallel()
	data := webRules()
	filterDeclaredRules(data, nil)
	if data.UnacknowledgedCarriers == nil || len(data.UnacknowledgedCarriers) != 0 {
		t.Errorf("unacknowledged carriers %v, want an empty list", data.UnacknowledgedCarriers)
	}
}
