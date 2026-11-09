package provider

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// A group skips xshield_security_group_rules when the listing leaves it out, so the listing must hold exactly the
// groups that data source finds a change for, or a skipped group would keep a rule a change takes out.
func TestChangedGroupsListExactlyTheGroupsARulesReadFindsAChangeFor(t *testing.T) {
	t.Parallel()
	changes := wireCustomerGroupChanges{Groups: map[string]wireCustomerGroupChange{
		"vpc-1/web": {}, "vpc-2/web": {}, "vpc-1/team/api": {}, "vpc-3/db": {},
	}}
	listed := changedGroups(changes)
	if !slices.Equal(listed["web"], []string{"vpc-1", "vpc-2"}) || !slices.Equal(listed["team/api"], []string{"vpc-1"}) {
		t.Errorf("listed %v, want each name with every VPC it has a change in, a slash kept in the name", listed)
	}
	for _, vpc := range []string{"vpc-1", "vpc-2", "vpc-3", "vpc-4"} {
		for _, name := range []string{"web", "team/api", "team", "api", "db", "Web"} {
			found := groupChangeOf(changes, vpc, name) != nil
			if slices.Contains(listed[name], vpc) != found {
				t.Errorf("%s/%s: listed %v, but the rules read finds a change: %v", vpc, name, slices.Contains(listed[name], vpc), found)
			}
		}
	}
}

func TestGroupChangesListNothingWhileNothingIsPublished(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": {http.StatusNotFound, xshieldNotPublished}})
	var m securityGroupChangesDataSourceModel
	if ok, errs := readDataSource(t, &securityGroupChangesDataSource{api: api}, pointArgs(), &m); !ok {
		t.Fatalf("an account with nothing published must plan: %s", errs)
	}
	if m.Published.ValueBool() || !m.Version.IsNull() || m.Groups == nil || len(m.Groups) != 0 {
		t.Errorf("published %v version %v groups %v, want an empty listing and no version", m.Published, m.Version, m.Groups)
	}
}

func TestGroupChangesAndEveryGroupsRulesShareOneRead(t *testing.T) {
	t.Parallel()
	released, err := json.Marshal(narrowed(loadJSON[wireCustomerGroupChanges](t, "customer_group_changes.json")))
	if err != nil {
		t.Fatal(err)
	}
	api, requested := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": {http.StatusOK, string(released)}})
	var listing securityGroupChangesDataSourceModel
	if ok, errs := readDataSource(t, &securityGroupChangesDataSource{api: api}, pointArgs(), &listing); !ok {
		t.Fatalf("read failed: %s", errs)
	}
	if !listing.Published.ValueBool() || listing.Version.ValueString() == "" || !slices.Equal(listing.Groups["web"], []string{"vpc-1"}) || len(listing.Groups) != 1 {
		t.Errorf("published %v version %v groups %v, want web in vpc-1 alone", listing.Published, listing.Version, listing.Groups)
	}
	args := pointArgs()
	args["vpc_id"] = tftypes.NewValue(tftypes.String, "vpc-1")
	args["group_name"] = tftypes.NewValue(tftypes.String, "web")
	var rules securityGroupRulesDataSourceModel
	if ok, errs := readDataSource(t, &securityGroupRulesDataSource{api: api}, args, &rules); !ok {
		t.Fatalf("read failed: %s", errs)
	}
	if rules.Version != listing.Version || len(*requested) != 1 {
		t.Errorf("versions %v and %v over requests %v, want one read giving both the same version", listing.Version, rules.Version, *requested)
	}
}

func TestGroupChangesFailThePlanWhenXshieldCannotBeRead(t *testing.T) {
	t.Parallel()
	api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/customergroupchanges": {http.StatusForbidden, `{"status":403,"message":"forbidden"}`}})
	var m securityGroupChangesDataSourceModel
	if ok, errs := readDataSource(t, &securityGroupChangesDataSource{api: api}, pointArgs(), &m); ok || !strings.Contains(errs, "Cannot read the changes Xshield made") {
		t.Errorf("ok=%v %q: a listing that cannot be read must fail the plan, as an empty one would keep every rule", ok, errs)
	}
}
