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

func testAccNamedNetworkConfig(name, description, ipRange string) string {
	return testAccConfig(fmt.Sprintf(`
resource "xshield_named_network" "test" {
  named_network_name        = %q
  named_network_description = %q

  ip_ranges = [
    {
      ip_range = %q
    },
  ]
}
`, name, description, ipRange))
}

func TestAccNamedNetworkResource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-nn")
	updatedName := acctest.RandomWithPrefix("tf-acc-nn")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNamedNetworkConfig(name, "created by acceptance test", "10.20.30.0/24"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("named_network_name"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("named_network_description"), knownvalue.StringExact("created by acceptance test")),
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("ip_ranges"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccNamedNetworkConfig(updatedName, "updated by acceptance test", "10.20.40.0/24"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("named_network_name"), knownvalue.StringExact(updatedName)),
					statecheck.ExpectKnownValue("xshield_named_network.test", tfjsonpath.New("named_network_description"), knownvalue.StringExact("updated by acceptance test")),
				},
			},
		{
			ResourceName:            "xshield_named_network.test",
			ImportState:             true,
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"ip_ranges.0.id", "ip_ranges.0.ip_count"},
		},
		},
	})
}

// TestAccNamedNetworkRejectsInvalidValues pins the nested-object validator that
// requires ip_range on every element, which is easy to lose in a refactor.
func TestAccNamedNetworkRejectsInvalidValues(t *testing.T) {
	tests := map[string]struct {
		config      string
		expectError *regexp.Regexp
	}{
		"ip range element missing ip_range": {
			config: testAccConfig(fmt.Sprintf(`
resource "xshield_named_network" "test" {
  named_network_name = %q

  ip_ranges = [
    {},
  ]
}
`, acctest.RandomWithPrefix("tf-acc-nn"))),
			expectError: regexp.MustCompile(`(?s)ip_range`),
		},
		"missing required name": {
			config: testAccConfig(`
resource "xshield_named_network" "test" {
  named_network_description = "no name"
}
`),
			expectError: regexp.MustCompile(`(?s)The argument "named_network_name" is required`),
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

func TestAccNamedNetworkDataSource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-nn-ds")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccNamedNetworkConfig(name, "read by acceptance test", "10.20.50.0/24") + fmt.Sprintf(`
data "xshield_named_network" "by_id" {
  id = xshield_named_network.test.id
}

data "xshield_named_network" "by_name" {
  named_network_name = %q

  depends_on = [xshield_named_network.test]
}
`, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"xshield_named_network.test", tfjsonpath.New("id"),
						"data.xshield_named_network.by_id", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"xshield_named_network.test", tfjsonpath.New("id"),
						"data.xshield_named_network.by_name", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}
