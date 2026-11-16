package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func clearXshieldEnv(t *testing.T) {
	for _, name := range []string{"XSHIELD_SERVER_URL", "XSHIELD_TENANCY_ID", "XSHIELD_USER_ID", "XSHIELD_FINGERPRINT", "XSHIELD_PRIVATE_KEY_PATH", "XSHIELD_PRIVATE_KEY"} {
		t.Setenv(name, "")
	}
}

func unsetModel() XshieldProviderModel {
	return XshieldProviderModel{TenancyId: types.StringNull(), PrincipalId: types.StringNull(), FingerPrint: types.StringNull(),
		PrivateKeyLocation: types.StringNull(), PrivateKey: types.StringNull()}
}

func TestCredentialsComeFromTheEnvironmentWhenTheBlockLeavesThemOut(t *testing.T) {
	clearXshieldEnv(t)
	key := testKeyPEM(t)
	t.Setenv("XSHIELD_TENANCY_ID", "tenancy")
	t.Setenv("XSHIELD_USER_ID", "user")
	t.Setenv("XSHIELD_FINGERPRINT", "fp")
	t.Setenv("XSHIELD_PRIVATE_KEY", key)

	var resp provider.ConfigureResponse
	config := buildConfigProvider(unsetModel(), &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if config.TenancyId() != "tenancy" || config.PrincipalId() != "user" || config.FingerPrint() != "fp" {
		t.Errorf("config %+v, want the environment's values", config)
	}
	if _, err := config.KeyLoader().LoadKey(); err != nil {
		t.Errorf("a key given as content in XSHIELD_PRIVATE_KEY did not load: %v", err)
	}
}

func TestTheBlockWinsOverTheEnvironment(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("XSHIELD_TENANCY_ID", "from-env")
	m := unsetModel()
	m.TenancyId = types.StringValue("from-block")
	if got := withEnv(m.TenancyId, "XSHIELD_TENANCY_ID"); got != "from-block" {
		t.Errorf("tenancy %q, want the provider block's", got)
	}
}

func TestMissingCredentialsSayHowToSetThem(t *testing.T) {
	clearXshieldEnv(t)
	var resp provider.ConfigureResponse
	if config := buildConfigProvider(unsetModel(), &resp); config != nil {
		t.Fatal("configured a client with no credentials")
	}
	text := ""
	for _, d := range resp.Diagnostics.Errors() {
		text += d.Summary() + ": " + d.Detail() + "\n"
	}
	for _, phrase := range []string{"XSHIELD_TENANCY_ID", "XSHIELD_USER_ID", "XSHIELD_FINGERPRINT", "Settings > API Keys", "XSHIELD_PRIVATE_KEY_PATH", "XSHIELD_PRIVATE_KEY"} {
		if !strings.Contains(text, phrase) {
			t.Errorf("errors do not mention %s:\n%s", phrase, text)
		}
	}
}

func TestTwoPrivateKeysAreRefused(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("XSHIELD_PRIVATE_KEY", testKeyPEM(t))
	m := unsetModel()
	m.TenancyId, m.PrincipalId, m.FingerPrint = types.StringValue("t"), types.StringValue("u"), types.StringValue("f")
	m.PrivateKeyLocation = types.StringValue("/keys/xshield.pem")
	var resp provider.ConfigureResponse
	buildConfigProvider(m, &resp)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "Set only one") {
		t.Errorf("a key path in the block and a key in the environment were both accepted: %v", resp.Diagnostics)
	}
}

func credentialsInEnvironmentWithoutKey(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("XSHIELD_TENANCY_ID", "tenancy")
	t.Setenv("XSHIELD_USER_ID", "user")
	t.Setenv("XSHIELD_FINGERPRINT", "fp")
}

func configureErrorsAt(t *testing.T, resp provider.ConfigureResponse, attribute string) string {
	t.Helper()
	text := ""
	for _, d := range resp.Diagnostics.Errors() {
		withPath, ok := d.(diag.DiagnosticWithPath)
		if !ok || withPath.Path().String() != attribute {
			t.Errorf("error %q is not on %s", d.Summary(), attribute)
		}
		text += d.Summary() + ": " + d.Detail() + "\n"
	}
	if text == "" {
		t.Fatalf("no error on %s", attribute)
	}
	return text
}

func TestAKeyPutWhereItsPathGoesIsRefusedWithoutPrintingIt(t *testing.T) {
	credentialsInEnvironmentWithoutKey(t)
	key := testKeyPEM(t)
	t.Setenv("XSHIELD_PRIVATE_KEY_PATH", key)

	var resp provider.ConfigureResponse
	if config := buildConfigProvider(unsetModel(), &resp); config != nil {
		t.Fatal("configured a client whose key path holds a key")
	}
	text := configureErrorsAt(t, resp, "private_key_path")
	if !strings.Contains(text, "XSHIELD_PRIVATE_KEY ") && !strings.Contains(text, "XSHIELD_PRIVATE_KEY)") {
		t.Errorf("the error does not say where the key goes:\n%s", text)
	}
	for _, line := range strings.Split(strings.TrimSpace(key), "\n") {
		if strings.Contains(text, line) {
			t.Fatalf("the error prints the key's line %q", line)
		}
	}
}

func TestAKeyThatDoesNotLoadIsRefusedWhenTheProviderIsConfigured(t *testing.T) {
	cases := map[string]struct {
		attribute string
		set       func(t *testing.T) string
	}{
		"a key that is not PEM": {"private_key", func(t *testing.T) string {
			t.Setenv("XSHIELD_PRIVATE_KEY", "MIIEowIBAAKCAQEAsecret")
			return "MIIEowIBAAKCAQEAsecret"
		}},
		"a path to no file": {"private_key_path", func(t *testing.T) string {
			missing := filepath.Join(t.TempDir(), "missing.pem")
			t.Setenv("XSHIELD_PRIVATE_KEY_PATH", missing)
			return missing
		}},
		"a file that holds no key": {"private_key_path", func(t *testing.T) string {
			file := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(file, []byte("MIIEowIBAAKCAQEAsecret"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XSHIELD_PRIVATE_KEY_PATH", file)
			return file
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			credentialsInEnvironmentWithoutKey(t)
			value := c.set(t)

			var resp provider.ConfigureResponse
			if config := buildConfigProvider(unsetModel(), &resp); config != nil {
				t.Fatal("configured a client whose key does not load, so its first request would fail instead")
			}
			if text := configureErrorsAt(t, resp, c.attribute); strings.Contains(text, value) || strings.Contains(text, "endpoint") {
				t.Errorf("the error prints the value or points at the endpoint:\n%s", text)
			}
		})
	}
}

// The environment's value is another key's, so it never stands in for one the configuration will give at apply.
func TestACredentialThePlanDoesNotKnowYetIsRefusedByName(t *testing.T) {
	for _, attribute := range []string{"tenancy_id", "user_id", "fingerprint", "private_key_path", "private_key"} {
		t.Run(attribute, func(t *testing.T) {
			clearXshieldEnv(t)
			t.Setenv("XSHIELD_TENANCY_ID", "tenancy")
			t.Setenv("XSHIELD_USER_ID", "user")
			t.Setenv("XSHIELD_FINGERPRINT", "fp")
			t.Setenv("XSHIELD_PRIVATE_KEY", testKeyPEM(t))
			m := unsetModel()
			unknown := map[string]*types.String{"tenancy_id": &m.TenancyId, "user_id": &m.PrincipalId, "fingerprint": &m.FingerPrint,
				"private_key_path": &m.PrivateKeyLocation, "private_key": &m.PrivateKey}
			*unknown[attribute] = types.StringUnknown()

			var resp provider.ConfigureResponse
			if config := buildConfigProvider(m, &resp); config != nil {
				t.Fatal("configured a client from the environment for a value the plan does not know yet")
			}
			errors := resp.Diagnostics.Errors()
			if len(errors) != 1 || errors[0].Summary() != "Unknown Xshield "+attribute || !strings.Contains(errors[0].Detail(), "not known until apply") {
				t.Errorf("want one error naming %s as not known until apply, got %v", attribute, resp.Diagnostics)
			}
		})
	}
}
