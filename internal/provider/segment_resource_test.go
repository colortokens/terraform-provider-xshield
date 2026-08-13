package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func testAccSegmentConfig(name, description, criteria string, timeline int64) string {
	return testAccConfig(fmt.Sprintf(`
resource "xshield_segment" "test" {
  tag_based_policy_name      = %q
  description                = %q
  criteria                   = %q
  target_breach_impact_score = 50
  timeline                   = %d
}
`, name, description, criteria, timeline))
}

func TestAccSegmentResource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-segment")
	updatedName := acctest.RandomWithPrefix("tf-acc-segment")
	criteria := fmt.Sprintf("'osName' in ('%s')", name)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSegmentConfig(name, "created by acceptance test", criteria, 10),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("tag_based_policy_name"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("description"), knownvalue.StringExact("created by acceptance test")),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("timeline"), knownvalue.Int64Exact(10)),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("target_breach_impact_score"), knownvalue.Int64Exact(50)),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccSegmentConfig(updatedName, "updated by acceptance test", criteria, 20),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("tag_based_policy_name"), knownvalue.StringExact(updatedName)),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("description"), knownvalue.StringExact("updated by acceptance test")),
					statecheck.ExpectKnownValue("xshield_segment.test", tfjsonpath.New("timeline"), knownvalue.Int64Exact(20)),
				},
			},
			{
				ResourceName:            "xshield_segment.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"criteria"},
			},
		},
	})
}

// TestAccSegmentDefaults pins the schema defaults, which are applied by the
// provider rather than the API and so are invisible to an API-level test.
func TestAccSegmentDefaults(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-segment-def")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(fmt.Sprintf(`
resource "xshield_segment" "defaults" {
  tag_based_policy_name = %q
  criteria              = "'osName' in ('%s')"
}
`, name, name)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_segment.defaults", tfjsonpath.New("timeline"), knownvalue.Int64Exact(90)),
					statecheck.ExpectKnownValue("xshield_segment.defaults", tfjsonpath.New("target_breach_impact_score"), knownvalue.Int64Exact(50)),
				},
			},
		},
	})
}

// TestAccSegmentRejectsInvalidValues exercises the schema validators without
// reaching the API, so a validator regression surfaces as a plan-time error
// rather than a confusing server rejection.
func TestAccSegmentRejectsInvalidValues(t *testing.T) {
	tests := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"timeline below minimum": {
			config:      testAccSegmentConfig(acctest.RandomWithPrefix("tf-acc-segment"), "invalid timeline", "'osName' in ('plan-only')", 0),
			expectError: regexp.MustCompile(`must be at least 1`),
		},
		"breach impact score above maximum": {
			config: testAccConfig(fmt.Sprintf(`
resource "xshield_segment" "test" {
  tag_based_policy_name      = %q
  criteria                   = "'osName' in ('plan-only')"
  target_breach_impact_score = 101
}
`, acctest.RandomWithPrefix("tf-acc-segment"))),
			expectError: regexp.MustCompile(`must be between 0 and 100`),
		},
		"missing required name": {
			config: testAccConfig(`
resource "xshield_segment" "test" {
  criteria = "'osName' in ('plan-only')"
}
`),
			expectError: regexp.MustCompile(`(?s)The argument "tag_based_policy_name" is required`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      test.config,
						PlanOnly:    true,
						ExpectError: test.expectError,
					},
				},
			})
		})
	}
}

func TestAccSegmentDataSource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-segment-ds")
	criteria := fmt.Sprintf("'osName' in ('%s')", name)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The data source supports lookup by id or by name; both must
				// resolve to the segment just created.
				Config: testAccSegmentConfig(name, "read by acceptance test", criteria, 10) + fmt.Sprintf(`
data "xshield_segment" "by_id" {
  id = xshield_segment.test.id
}

data "xshield_segment" "by_name" {
  tag_based_policy_name = %q

  depends_on = [xshield_segment.test]
}
`, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"xshield_segment.test", tfjsonpath.New("id"),
						"data.xshield_segment.by_id", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"xshield_segment.test", tfjsonpath.New("id"),
						"data.xshield_segment.by_name", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.ExpectKnownValue("data.xshield_segment.by_name", tfjsonpath.New("tag_based_policy_name"), knownvalue.StringExact(name)),
				},
			},
		},
	})
}
