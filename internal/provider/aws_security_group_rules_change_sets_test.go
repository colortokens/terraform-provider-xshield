package provider

import (
	"maps"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const twoChangeSets = `{"cloudAccountId":"123456789012","region":"us-east-1","version":"v-9","customerGroupChanges":{` +
	`"vpc-1/web":{"groupId":"sg-0web","revoke":[],"changeSets":[` +
	`{"id":"cs-2","state":"restoring","moves":[]},{"id":"cs-1","state":"narrowing","moves":[]}]}}}`

func readGroupRules(t *testing.T, answer cannedResponse, group string) awsSecurityGroupRulesDataSourceModel {
	t.Helper()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": answer})
	args := pointArgs()
	args["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
	args["group_name"] = tftypes.NewValue(tftypes.String, group)
	var out awsSecurityGroupRulesDataSourceModel
	if ok, errs := readDataSource(t, &awsSecurityGroupRulesDataSource{api: api}, args, &out); !ok {
		t.Fatalf("read failed: %s", errs)
	}
	return out
}

// The owner module reports what it applied from the same read its rules came from, so the data source gives each
// change set of the group by its ID with its state as Xshield served it.
func TestTheRulesOfAGroupNameItsChangeSetsAsServed(t *testing.T) {
	t.Parallel()

	t.Run("a changed group", func(t *testing.T) {
		t.Parallel()
		got := readGroupRules(t, cannedResponse{http.StatusOK, twoChangeSets}, "web")
		if want := map[string]string{"cs-1": "narrowing", "cs-2": "restoring"}; !maps.Equal(got.ChangeSets, want) {
			t.Errorf("change_sets %v, want %v", got.ChangeSets, want)
		}
		if got.SecurityGroupID.ValueString() != "sg-0web" || got.Version.ValueString() != "v-9" {
			t.Errorf("security_group_id %s and version %s, want sg-0web and v-9", got.SecurityGroupID, got.Version)
		}
	})

	for name, read := range map[string]struct {
		answer cannedResponse
		group  string
	}{
		"a group no change applies to": {cannedResponse{http.StatusOK, twoChangeSets}, "db"},
		"nothing published":            {cannedResponse{http.StatusNotFound, xshieldNotPublished}, "web"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := readGroupRules(t, read.answer, read.group)
			if got.ChangeSets == nil || len(got.ChangeSets) != 0 {
				t.Errorf("change_sets %v, want an empty map, so the group plans cleanly", got.ChangeSets)
			}
		})
	}
}
