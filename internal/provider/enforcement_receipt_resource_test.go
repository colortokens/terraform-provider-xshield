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

// versionPattern is a snapshot version, which Xshield names by its content hash.
var versionPattern = regexp.MustCompile(`^[0-9a-f]{128}$`)

func testAccPublishedEnforcementPoint(t *testing.T) (account, region string) {
	t.Helper()
	return testAccRequireEnv(t, envPublishedCloudAccountID), testAccRequireEnv(t, envPublishedCloudRegion)
}

func testAccEnforcementReceiptConfig(account, region, workspace string) string {
	return testAccConfig(fmt.Sprintf(`
data "xshield_aws_enforcement_snapshot" "test" {
  cloud_account_id = %[1]q
  region           = %[2]q
}

locals {
  snapshot = data.xshield_aws_enforcement_snapshot.test
}

resource "xshield_enforcement_receipt" "test" {
  cloud_account_id = local.snapshot.cloud_account_id
  region           = local.snapshot.region
  workspace        = %[3]q
  snapshot_version = local.snapshot.version

  security_groups = { for key in keys(local.snapshot.security_groups) : key => "sg-${substr(sha1(key), 0, 17)}" }
  rules           = { for key in keys(merge(local.snapshot.ingress_rules, local.snapshot.egress_rules)) : key => "sgr-${substr(sha1(key), 0, 17)}" }
  attachments = {
    for key, attachment in local.snapshot.interface_attachments :
    key => "sg-${substr(sha1(attachment.security_group), 0, 17)}_${attachment.network_interface_id}"
  }
}
`, account, region, workspace))
}

func TestAccEnforcementReceiptResource(t *testing.T) {
	account, region := testAccPublishedEnforcementPoint(t)
	workspace := acctest.RandomWithPrefix("tf-acc-enforcement")
	updatedWorkspace := acctest.RandomWithPrefix("tf-acc-enforcement")
	receiptID := statecheck.CompareValue(compare.ValuesDiffer())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEnforcementReceiptConfig(account, region, workspace),
				ConfigStateChecks: []statecheck.StateCheck{
					receiptID.AddStateValue("xshield_enforcement_receipt.test", tfjsonpath.New("id")),
					statecheck.ExpectKnownValue("xshield_enforcement_receipt.test", tfjsonpath.New("workspace"), knownvalue.StringExact(workspace)),
					statecheck.ExpectKnownValue("xshield_enforcement_receipt.test", tfjsonpath.New("applied_at"), knownvalue.NotNull()),
					statecheck.CompareValuePairs(
						"xshield_enforcement_receipt.test", tfjsonpath.New("snapshot_version"),
						"data.xshield_aws_enforcement_snapshot.test", tfjsonpath.New("version"),
						compare.ValuesSame(),
					),
				},
			},
			{
				Config: testAccEnforcementReceiptConfig(account, region, updatedWorkspace),
				ConfigStateChecks: []statecheck.StateCheck{
					receiptID.AddStateValue("xshield_enforcement_receipt.test", tfjsonpath.New("id")),
					statecheck.ExpectKnownValue("xshield_enforcement_receipt.test", tfjsonpath.New("workspace"), knownvalue.StringExact(updatedWorkspace)),
				},
			},
			{
				ResourceName:      "xshield_enforcement_receipt.test",
				ImportState:       true,
				ImportStateId:     account + "/" + region,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSEnforcementSnapshotDataSource(t *testing.T) {
	account, region := testAccPublishedEnforcementPoint(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(fmt.Sprintf(`
data "xshield_aws_enforcement_snapshot" "expected" {
  cloud_account_id = %[1]q
  region           = %[2]q
}

data "xshield_aws_enforcement_snapshot" "pinned" {
  cloud_account_id = %[1]q
  region           = %[2]q
  version          = data.xshield_aws_enforcement_snapshot.expected.version
}
`, account, region)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.xshield_aws_enforcement_snapshot.expected", tfjsonpath.New("published"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.xshield_aws_enforcement_snapshot.expected", tfjsonpath.New("version"), knownvalue.StringRegexp(versionPattern)),
					statecheck.CompareValuePairs(
						"data.xshield_aws_enforcement_snapshot.expected", tfjsonpath.New("version"),
						"data.xshield_aws_enforcement_snapshot.pinned", tfjsonpath.New("version"),
						compare.ValuesSame(),
					),
					statecheck.CompareValuePairs(
						"data.xshield_aws_enforcement_snapshot.expected", tfjsonpath.New("ingress_rules"),
						"data.xshield_aws_enforcement_snapshot.pinned", tfjsonpath.New("ingress_rules"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccEnforcementStatusDataSource(t *testing.T) {
	account, region := testAccPublishedEnforcementPoint(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(fmt.Sprintf(`
data "xshield_aws_enforcement_snapshot" "test" {
  cloud_account_id = %[1]q
  region           = %[2]q
}

data "xshield_enforcement_status" "test" {
  cloud_account_id = %[1]q
  region           = %[2]q
}
`, account, region)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.xshield_enforcement_status.test", tfjsonpath.New("published"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.xshield_enforcement_status.test", tfjsonpath.New("state"), knownvalue.StringRegexp(regexp.MustCompile(`^(converged|pending|unapplied)$`))),
					statecheck.CompareValuePairs(
						"data.xshield_enforcement_status.test", tfjsonpath.New("expected_version"),
						"data.xshield_aws_enforcement_snapshot.test", tfjsonpath.New("version"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

func TestAccAWSSecurityGroupRulesDataSource(t *testing.T) {
	account, region := testAccPublishedEnforcementPoint(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(fmt.Sprintf(`
data "xshield_aws_security_group_rules" "test" {
  cloud_account_id = %q
  region           = %q
  vpc_id           = "vpc-0123456789abcdef0"
  group_name       = %q

  ingress = {
    https = { ip_protocol = "tcp", from_port = 443, to_port = 443, cidr_ipv4 = "10.0.0.0/8" }
  }
  egress = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }
}
`, account, region, acctest.RandomWithPrefix("tf-acc-group"))),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("published"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("version"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("ingress_rules"), knownvalue.MapExact(map[string]knownvalue.Check{
						"https": knownvalue.ObjectPartial(map[string]knownvalue.Check{
							"ip_protocol": knownvalue.StringExact("tcp"),
							"from_port":   knownvalue.Int64Exact(443),
							"to_port":     knownvalue.Int64Exact(443),
							"cidr_ipv4":   knownvalue.StringExact("10.0.0.0/8"),
						}),
					})),
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("egress_rules"), knownvalue.MapSizeExact(1)),
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("revoked"), knownvalue.ListSizeExact(0)),
					statecheck.ExpectKnownValue("data.xshield_aws_security_group_rules.test", tfjsonpath.New("pending"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
}
