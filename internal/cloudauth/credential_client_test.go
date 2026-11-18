package cloudauth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// hostRecorder answers every request 400 without reaching the network, and records the hosts it was sent to.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (h *hostRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, req.URL.Hostname())
	h.mu.Unlock()
	return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
}

func (h *hostRecorder) sentTo(host string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sent := range h.hosts {
		if sent == host {
			return true
		}
	}
	return false
}

func TestTheProxyIsNotUsedForEndpointsOnTheMachinesOwnNetwork(t *testing.T) {
	proxy, _ := url.Parse("http://proxy.example.com:3128")
	client := credentialHTTPClient(&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}})
	proxyFor := client.Transport.(*http.Transport).Proxy

	cases := map[string]bool{
		"https://login.microsoftonline.com/tenant/oauth2/v2.0/token": true,
		"https://oauth2.googleapis.com/token":                        true,
		"https://sts.us-east-1.amazonaws.com/":                       true,
		"http://169.254.169.254/metadata/identity/oauth2/token":      false,
		"http://[fd00:ec2::254]/latest/api/token":                    false,
		"http://169.254.170.2/v2/credentials/abc":                    false,
		"http://metadata.google.internal/computeMetadata/v1/":        false,
		"http://127.0.0.1:41000/msi/token":                           false,
		"http://localhost:40342/metadata/identity/oauth2/token":      false,
	}
	for target, proxied := range cases {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		got, err := proxyFor(req)
		if err != nil || (got != nil) != proxied {
			t.Errorf("%s: proxy %v (%v), want proxied %v", target, got, err, proxied)
		}
	}
}

func TestAzureTokenRequestsGoThroughTheConfiguredClient(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	t.Setenv("AZURE_CLIENT_SECRET", "not-a-secret")
	recorder := &hostRecorder{}
	tokens, err := NewDefaultAzureTokens("https://vault.azure.net/.default", &http.Client{Transport: recorder})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tokens.Token(context.Background())
	if !recorder.sentTo("login.microsoftonline.com") {
		t.Errorf("the token request did not go through the configured client; it sent to %v", recorder.hosts)
	}
}

func TestGoogleTokenRequestsGoThroughTheConfiguredClient(t *testing.T) {
	credentials := filepath.Join(t.TempDir(), "application_default_credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"type":"authorized_user","client_id":"id","client_secret":"not-a-secret","refresh_token":"refresh"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentials)
	recorder := &hostRecorder{}
	tokens, err := NewDefaultGoogleTokens("https://www.googleapis.com/auth/cloudkms", &http.Client{Transport: recorder})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tokens.Token(context.Background())
	if !recorder.sentTo("oauth2.googleapis.com") {
		t.Errorf("the token request did not go through the configured client; it sent to %v", recorder.hosts)
	}
}

func TestAWSCredentialRequestsGoThroughTheConfiguredClient(t *testing.T) {
	directory := t.TempDir()
	webIdentityToken := filepath.Join(directory, "token")
	if err := os.WriteFile(webIdentityToken, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"AWS_CONFIG_FILE": filepath.Join(directory, "config"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(directory, "credentials"),
		"AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_SESSION_TOKEN": "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "",
		"AWS_WEB_IDENTITY_TOKEN_FILE": webIdentityToken, "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/terraform",
		"AWS_MAX_ATTEMPTS": "1",
	} {
		t.Setenv(name, value)
	}
	recorder := &hostRecorder{}
	cfg, err := LoadAWSConfig(context.Background(), "us-east-1", &http.Client{Transport: recorder})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cfg.Credentials.Retrieve(context.Background())
	if !recorder.sentTo("sts.us-east-1.amazonaws.com") {
		t.Errorf("the credential request did not go through the configured client; it sent to %v", recorder.hosts)
	}
}
