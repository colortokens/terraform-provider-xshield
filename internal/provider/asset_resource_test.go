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
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Assets are registered by the xshield agent, so xshield_asset rejects creation
// outright: the supported flow is import and then update. These tests therefore
// adopt an asset that already exists in the test tenant.
func testAccAssetConfig(assetName, assetType, environmentTag string) string {
	return testAccConfig(fmt.Sprintf(`
resource "xshield_asset" "test" {
  asset_name = %q
  type       = %q

  core_tags = {
    Environment = %q
  }
}
`, assetName, assetType, environmentTag))
}

// TestAccAssetResourceRejectsCreate pins the deliberate refusal to create an
// asset. Without it a regression would silently turn a clear error into a
// confusing API failure.
func TestAccAssetResourceRejectsCreate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAssetConfig(acctest.RandomWithPrefix("tf-acc-asset"), "server", "terraform-acceptance"),
				ExpectError: regexp.MustCompile(`Assets cannot be created through Terraform`),
			},
		},
	})
}

// TestAccAssetResourceImportAndUpdate exercises the supported lifecycle:
// import an existing asset, then manage its tags.
func TestAccAssetResourceImportAndUpdate(t *testing.T) {
	assetID := testAccRequireEnv(t, envExistingAssetID)
	assetName := testAccRequireEnv(t, envExistingAssetName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             testAccAssetConfig(assetName, "server", "terraform-acceptance"),
				ResourceName:       "xshield_asset.test",
				ImportState:        true,
				ImportStateId:      assetID,
				ImportStatePersist: true,
				ImportStateVerify:  false,
			},
			{
				Config: testAccAssetConfig(assetName, "server", "terraform-acceptance-updated"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("xshield_asset.test", tfjsonpath.New("id"), knownvalue.StringExact(assetID)),
					statecheck.ExpectKnownValue("xshield_asset.test", tfjsonpath.New("core_tags"), knownvalue.MapExact(map[string]knownvalue.Check{
						"Environment": knownvalue.StringExact("terraform-acceptance-updated"),
					})),
				},
			},
		},
	})
}

// TestAccAssetResourceImportByName covers the name-based branch of ImportState,
// which resolves a name to an id through a list search.
func TestAccAssetResourceImportByName(t *testing.T) {
	assetID := testAccRequireEnv(t, envExistingAssetID)
	assetName := testAccRequireEnv(t, envExistingAssetName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             testAccAssetConfig(assetName, "server", "terraform-acceptance"),
				ResourceName:       "xshield_asset.test",
				ImportState:        true,
				ImportStateId:      assetName,
				ImportStatePersist: true,
				ImportStateVerify:  false,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected one imported instance, got %d", len(states))
					}
					if got := states[0].Attributes["id"]; got != assetID {
						return fmt.Errorf("imported id = %q, want %q", got, assetID)
					}
					return nil
				},
			},
		},
	})
}

// TestAccAssetResourceImportByUnknownName asserts the name lookup reports a
// clear error rather than importing an empty identifier.
func TestAccAssetResourceImportByUnknownName(t *testing.T) {
	assetName := testAccRequireEnv(t, envExistingAssetName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        testAccAssetConfig(assetName, "server", "terraform-acceptance"),
				ResourceName:  "xshield_asset.test",
				ImportState:   true,
				ImportStateId: acctest.RandomWithPrefix("tf-acc-no-such-asset"),
				ExpectError:   regexp.MustCompile(`No asset found with name`),
			},
		},
	})
}

func TestAccAssetDataSource(t *testing.T) {
	assetID := testAccRequireEnv(t, envExistingAssetID)
	assetName := testAccRequireEnv(t, envExistingAssetName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Both lookup keys must resolve to the same asset. When id was
				// computed-only the by_id read requested the empty identifier
				// and this comparison could not hold.
				Config: testAccConfig(fmt.Sprintf(`
data "xshield_asset" "by_id" {
  id = %q
}

data "xshield_asset" "by_name" {
  asset_name = %q
}
`, assetID, assetName)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.xshield_asset.by_id", tfjsonpath.New("id"), knownvalue.StringExact(assetID)),
					statecheck.ExpectKnownValue("data.xshield_asset.by_id", tfjsonpath.New("asset_name"), knownvalue.StringExact(assetName)),
					statecheck.CompareValuePairs(
						"data.xshield_asset.by_id", tfjsonpath.New("id"),
						"data.xshield_asset.by_name", tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				},
			},
		},
	})
}

// TestAccAssetDataSourceRequiresAnIdentifier covers the branch that reports a
// missing lookup key instead of requesting the empty identifier.
func TestAccAssetDataSourceRequiresAnIdentifier(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(`
data "xshield_asset" "no_identifier" {
}
`),
				ExpectError: regexp.MustCompile(`Either id or asset_name must be provided`),
			},
		},
	})
}
