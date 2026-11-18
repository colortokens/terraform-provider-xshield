package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/federation"
	"github.com/colortokens/terraform-provider-xshield/internal/keyservice"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func serviceAccountInEnvironment(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("XSHIELD_TENANCY_ID", "tenant-1")
	t.Setenv("XSHIELD_USER_ID", "111111111111")
}

func errorPaths(resp provider.ConfigureResponse) []string {
	var paths []string
	for _, d := range resp.Diagnostics.Errors() {
		if withPath, ok := d.(diag.DiagnosticWithPath); ok {
			paths = append(paths, withPath.Path().String())
		} else {
			paths = append(paths, "")
		}
	}
	return paths
}

func TestOnlyOneAuthenticationMethodIsAccepted(t *testing.T) {
	cases := map[string]struct {
		set      func(t *testing.T, m *XshieldProviderModel)
		wantPath string
	}{
		"a private key and a key service key": {func(t *testing.T, m *XshieldProviderModel) {
			t.Setenv("XSHIELD_PRIVATE_KEY", testKeyPEM(t))
			m.KMSKey = types.StringValue("awskms:///arn:aws:kms:us-east-1:111122223333:key/x")
		}, "kms_key"},
		"a key service key and oidc": {func(t *testing.T, m *XshieldProviderModel) {
			t.Setenv("XSHIELD_KMS_KEY", "awskms:///arn:aws:kms:us-east-1:111122223333:key/x")
			m.OIDC = &OIDCModel{Source: types.StringValue("kubernetes")}
		}, "oidc"},
		"a private key path and an oidc variable": {func(t *testing.T, m *XshieldProviderModel) {
			m.PrivateKeyLocation = types.StringValue("/keys/xshield.pem")
			t.Setenv("XSHIELD_OIDC_SOURCE", "github-actions")
		}, "oidc"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			serviceAccountInEnvironment(t)
			m := unsetModel()
			c.set(t, &m)
			var resp provider.ConfigureResponse
			config, client := buildAuthentication(context.Background(), m, "https://tenant-1.example.com", http.DefaultClient, &resp)
			if config != nil || client != nil {
				t.Fatal("configured a client with two authentication methods")
			}
			if paths := errorPaths(resp); len(paths) != 1 || paths[0] != c.wantPath {
				t.Fatalf("errors on %v, want one on %s: %v", paths, c.wantPath, resp.Diagnostics)
			}
			if got := resp.Diagnostics.Errors()[0]; got.Summary() != "More than one Xshield authentication method" || !strings.Contains(got.Detail(), "Set only one") {
				t.Errorf("error %q: %q", got.Summary(), got.Detail())
			}
		})
	}
}

func TestAKMSKeyNeedsNoFingerprintOrPrivateKeyButAKeyServiceURI(t *testing.T) {
	serviceAccountInEnvironment(t)
	t.Setenv("XSHIELD_KMS_KEY", "file:///keys/xshield.pem")
	var resp provider.ConfigureResponse
	if config, _ := buildAuthentication(context.Background(), unsetModel(), "https://tenant-1.example.com", http.DefaultClient, &resp); config != nil {
		t.Fatal("configured a client for a key URI no key service serves")
	}
	text := configureErrorsAt(t, resp, "kms_key")
	for _, form := range []string{"awskms:///", "azurekeyvault://", "gcpkms://"} {
		if !strings.Contains(text, form) {
			t.Errorf("the error does not show the %s form:\n%s", form, text)
		}
	}
}

func TestAnUnknownKMSKeyIsRefusedByName(t *testing.T) {
	serviceAccountInEnvironment(t)
	m := unsetModel()
	m.KMSKey = types.StringUnknown()
	var resp provider.ConfigureResponse
	buildAuthentication(context.Background(), m, "https://tenant-1.example.com", http.DefaultClient, &resp)
	if text := configureErrorsAt(t, resp, "kms_key"); !strings.Contains(text, "Unknown Xshield kms_key") {
		t.Errorf("errors:\n%s", text)
	}
}

type remoteKeyStandIn struct{ key *rsa.PrivateKey }

func (r remoteKeyStandIn) SignSHA256Digest(_ context.Context, digest []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, r.key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: sha256.Size})
}

func TestAKeyServiceKeySignsAsItsOwnFingerprintUnlessAnotherIsConfigured(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := keyservice.Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	remote := &keyservice.RemoteKey{Signer: remoteKeyStandIn{key}, PublicKey: &key.PublicKey, Fingerprint: fingerprint}

	for _, configured := range []string{"", fingerprint} {
		var resp provider.ConfigureResponse
		config := keyServiceConfigProvider("tenant-1", "111111111111", configured, remote, &resp)
		if resp.Diagnostics.HasError() || config == nil {
			t.Fatalf("configured fingerprint %q: %v", configured, resp.Diagnostics)
		}
		if config.FingerPrint() != fingerprint || config.TenancyId() != "tenant-1" || config.PrincipalId() != "111111111111" {
			t.Errorf("keyId parts %s::%s::%s, want tenant-1::111111111111::%s", config.TenancyId(), config.PrincipalId(), config.FingerPrint(), fingerprint)
		}
		if _, ok := config.(shared.RemoteSigner); !ok {
			t.Error("the configuration does not sign through the key service")
		}
	}

	var resp provider.ConfigureResponse
	other := strings.Repeat("00:", 15) + "00"
	if config := keyServiceConfigProvider("tenant-1", "111111111111", other, remote, &resp); config != nil {
		t.Fatal("configured a key service key under another key's fingerprint")
	}
	if text := configureErrorsAt(t, resp, "fingerprint"); !strings.Contains(text, other) || !strings.Contains(text, fingerprint) {
		t.Errorf("the error does not show both fingerprints:\n%s", text)
	}
}

// fakeTokenEndpoint is Xshield's token endpoint, issuing access-token for workload-token only.
func fakeTokenEndpoint(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/auth/oauth/token" || r.PostForm.Get("subject_token") != "workload-token" ||
			r.PostForm.Get("tenant_id") != "tenant-1" || r.PostForm.Get("service_account_id") != "111111111111" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "the token was not accepted for this service account"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 900,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestOIDCExchangesTheWorkloadTokenWhenTheProviderIsConfigured(t *testing.T) {
	server := fakeTokenEndpoint(t)
	cases := map[string]func(t *testing.T, m *XshieldProviderModel){
		"from the block": func(t *testing.T, m *XshieldProviderModel) {
			m.OIDC = &OIDCModel{Token: types.StringValue("workload-token")}
		},
		"from the environment": func(t *testing.T, m *XshieldProviderModel) { t.Setenv("XSHIELD_OIDC_TOKEN", "workload-token") },
		"from a named variable": func(t *testing.T, m *XshieldProviderModel) {
			t.Setenv("XSHIELD_OIDC_TOKEN_ENV", "CI_ID_TOKEN")
			t.Setenv("CI_ID_TOKEN", "workload-token")
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			serviceAccountInEnvironment(t)
			m := unsetModel()
			set(t, &m)
			var resp provider.ConfigureResponse
			config, client := buildAuthentication(context.Background(), m, server.URL+"/", server.Client(), &resp)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			federated, ok := config.(shared.AccessTokenSource)
			if !ok {
				t.Fatalf("configuration %T does not send an access token", config)
			}
			if token, err := federated.AccessToken(context.Background()); err != nil || token != "access-token" {
				t.Errorf("access token %q, %v", token, err)
			}
			if _, ok := client.(*federation.ReauthenticatingClient); !ok {
				t.Errorf("client %T does not retry a 401 with a new access token", client)
			}
		})
	}
}

func TestARefusedExchangeFailsTheConfigurationOnOIDC(t *testing.T) {
	server := fakeTokenEndpoint(t)
	serviceAccountInEnvironment(t)
	t.Setenv("XSHIELD_OIDC_TOKEN", "a-token-no-trust-accepts")
	var resp provider.ConfigureResponse
	if config, _ := buildAuthentication(context.Background(), unsetModel(), server.URL, server.Client(), &resp); config != nil {
		t.Fatal("configured a client whose token was refused")
	}
	text := configureErrorsAt(t, resp, "oidc")
	if !strings.Contains(text, "invalid_grant") || strings.Contains(text, "a-token-no-trust-accepts") {
		t.Errorf("the error does not give the refusal, or prints the token:\n%s", text)
	}
}

func TestOIDCSettingErrorsPointAtTheAttribute(t *testing.T) {
	cases := map[string]struct {
		oidc     OIDCModel
		wantPath string
		want     string
	}{
		"a requesting source without audience": {OIDCModel{Source: types.StringValue("github-actions")}, "oidc.audience", "audience"},
		"an unknown source":                    {OIDCModel{Source: types.StringValue("jenkins")}, "oidc.source", "jenkins"},
		"a token not known until apply":        {OIDCModel{Token: types.StringUnknown()}, "oidc.token", "not known until apply"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			serviceAccountInEnvironment(t)
			m := unsetModel()
			m.OIDC = &c.oidc
			var resp provider.ConfigureResponse
			if config, _ := buildAuthentication(context.Background(), m, "https://tenant-1.example.com", http.DefaultClient, &resp); config != nil {
				t.Fatal("configured a client from oidc settings that cannot work")
			}
			if text := configureErrorsAt(t, resp, c.wantPath); !strings.Contains(text, c.want) {
				t.Errorf("errors:\n%s", text)
			}
		})
	}
}

func TestOIDCNeedsTheServiceAccountButNoFingerprintOrKey(t *testing.T) {
	clearXshieldEnv(t)
	t.Setenv("XSHIELD_OIDC_TOKEN", "workload-token")
	var resp provider.ConfigureResponse
	buildAuthentication(context.Background(), unsetModel(), "https://tenant-1.example.com", http.DefaultClient, &resp)
	paths := errorPaths(resp)
	if len(paths) != 2 || paths[0] != "tenancy_id" || paths[1] != "user_id" {
		t.Errorf("errors on %v, want tenancy_id and user_id only: %v", paths, resp.Diagnostics)
	}
	if !strings.Contains(resp.Diagnostics.Errors()[1].Detail(), "service account") {
		t.Errorf("the user_id error does not say it is the service account's: %s", resp.Diagnostics.Errors()[1].Detail())
	}
}
