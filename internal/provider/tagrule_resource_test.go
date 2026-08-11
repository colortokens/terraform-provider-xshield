package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func testAccTagRuleConfig(name, description string, enabled bool, onMatchValue string) string {
	return testAccConfig(fmt.Sprintf(`
resource "xshield_tag_rule" "test" {
  rule_name        = %q
  rule_description = %q
  rule_criteria    = "tags.Environment = 'terraform-acceptance'"
  rule_enabled     = %t

  on_match = {
    Environment = %q
  }
}
`, name, description, enabled, onMatchValue))
}

func TestAccTagRuleResource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-tagrule")
	updatedName := acctest.RandomWithPrefix("tf-acc-tagrule")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTagRuleConfig(name, "created by acceptance test", true, "staging"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("rule_name"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("rule_description"), knownvalue.StringExact("created by acceptance test")),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("rule_enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("on_match"), knownvalue.MapExact(map[string]knownvalue.Check{
						"Environment": knownvalue.StringExact("staging"),
					})),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccTagRuleConfig(updatedName, "updated by acceptance test", false, "production"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("rule_name"), knownvalue.StringExact(updatedName)),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("rule_enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue("xshield_tag_rule.test", tfjsonpath.New("on_match"), knownvalue.MapExact(map[string]knownvalue.Check{
						"Environment": knownvalue.StringExact("production"),
					})),
				},
			},
			{
				ResourceName:      "xshield_tag_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccTagRuleDataSource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-tagrule-ds")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTagRuleConfig(name, "read by acceptance test", true, "staging") + fmt.Sprintf(`
data "xshield_tag_rule" "by_id" {
  id = xshield_tag_rule.test.id
}

data "xshield_tag_rule" "by_name" {
  rule_name = %q

  depends_on = [xshield_tag_rule.test]
}
`, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"xshield_tag_rule.test", tfjsonpath.New("id"),
						"data.xshield_tag_rule.by_id", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"xshield_tag_rule.test", tfjsonpath.New("id"),
						"data.xshield_tag_rule.by_name", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}
