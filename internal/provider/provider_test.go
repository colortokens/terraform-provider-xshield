package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	envTenancyID      = "XSHIELD_TENANCY_ID"
	envUserID         = "XSHIELD_USER_ID"
	envFingerprint    = "XSHIELD_FINGERPRINT"
	envPrivateKeyPath = "XSHIELD_PRIVATE_KEY_PATH"
	envServerURL      = "XSHIELD_SERVER_URL"

	// envExistingAssetID and envExistingAssetName name an asset that already
	// exists in the test tenant. Assets are registered by the xshield agent and
	// xshield_asset rejects creation, so its tests adopt an existing asset.
	envExistingAssetID   = "XSHIELD_TEST_ASSET_ID"
	envExistingAssetName = "XSHIELD_TEST_ASSET_NAME"
)

// testAccProtoV6ProviderFactories serves the provider under test in-process so
// acceptance tests exercise the same code paths Terraform would over gRPC.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"xshield": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck fails the test when credentials for the acceptance tenant are
// absent. It only runs under TF_ACC, so unit tests remain runnable offline.
func testAccPreCheck(t *testing.T) {
	t.Helper()

	for _, name := range []string{envTenancyID, envUserID, envFingerprint, envPrivateKeyPath} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s must be set for acceptance tests", name)
		}
	}

	if path := os.Getenv(envPrivateKeyPath); path != "" {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s points at an unreadable file: %s", envPrivateKeyPath, err)
		}
	}
}

// testAccRequireEnv skips a test that needs an optional fixture identifier.
func testAccRequireEnv(t *testing.T, name string) string {
	t.Helper()

	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s must be set to run this test", name)
	}

	return value
}

// testAccProviderConfig renders a provider block from the acceptance
// environment. Credentials stay out of the test source this way.
func testAccProviderConfig() string {
	serverURL := ""
	if url := os.Getenv(envServerURL); url != "" {
		serverURL = fmt.Sprintf("  server_url = %q\n", url)
	}

	return fmt.Sprintf(`
provider "xshield" {
%s  tenancy_id       = %q
  user_id          = %q
  fingerprint      = %q
  private_key_path = %q
}
`,
		serverURL,
		os.Getenv(envTenancyID),
		os.Getenv(envUserID),
		os.Getenv(envFingerprint),
		os.Getenv(envPrivateKeyPath),
	)
}

// testAccConfig prefixes a resource configuration with the provider block.
func testAccConfig(body string) string {
	return testAccProviderConfig() + body
}
