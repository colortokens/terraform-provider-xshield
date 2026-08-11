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

func testAccTemplateConfig(name, description, listenPort string) string {
	return testAccConfig(fmt.Sprintf(`
resource "xshield_template" "test" {
  template_name        = %q
  template_description = %q
  template_type        = "application-template"

  template_ports = [
    {
      listen_port          = %q
      listen_port_protocol = "tcp"
      listen_port_reviewed = "allow-any"
    },
  ]
}
`, name, description, listenPort))
}

func TestAccTemplateResource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-template")
	replacementName := acctest.RandomWithPrefix("tf-acc-template")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTemplateConfig(name, "created by acceptance test", "8080"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_template.test", tfjsonpath.New("template_name"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue("xshield_template.test", tfjsonpath.New("template_type"), knownvalue.StringExact("application-template")),
					statecheck.ExpectKnownValue("xshield_template.test", tfjsonpath.New("template_ports"), knownvalue.ListSizeExact(1)),
					statecheck.ExpectKnownValue("xshield_template.test", tfjsonpath.New("id"), knownvalue.NotNull()),
				},
			},
			{
				Config: testAccTemplateConfig(replacementName, "updated by acceptance test", "9090"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_template.test", tfjsonpath.New("template_name"), knownvalue.StringExact(replacementName)),
				},
			},
			{
				ResourceName:      "xshield_template.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccTemplateRejectsInvalidEnum pins the enum validators so an out-of-range
// value fails at plan time with a readable message instead of a server error.
func TestAccTemplateRejectsInvalidEnum(t *testing.T) {
	tests := map[string]string{
		"template type": fmt.Sprintf(`
resource "xshield_template" "invalid" {
  template_name = %q
  template_type = "not-a-template-type"
}
`, acctest.RandomWithPrefix("tf-acc-template")),
		"listen port reviewed": fmt.Sprintf(`
resource "xshield_template" "invalid" {
  template_name = %q
  template_type = "application-template"

  template_ports = [
    {
      listen_port          = "8080"
      listen_port_protocol = "tcp"
      listen_port_reviewed = "not-a-review-state"
    },
  ]
}
`, acctest.RandomWithPrefix("tf-acc-template")),
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      testAccConfig(body),
						PlanOnly:    true,
						ExpectError: regexp.MustCompile(`value must be one of`),
					},
				},
			})
		})
	}
}

func TestAccTemplateDataSource(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-template-ds")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTemplateConfig(name, "read by acceptance test", "8080") + fmt.Sprintf(`
data "xshield_template" "by_id" {
  id = xshield_template.test.id
}

data "xshield_template" "by_name" {
  template_name = %q

  depends_on = [xshield_template.test]
}
`, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.CompareValuePairs(
						"xshield_template.test", tfjsonpath.New("id"),
						"data.xshield_template.by_id", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"xshield_template.test", tfjsonpath.New("id"),
						"data.xshield_template.by_name", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}
