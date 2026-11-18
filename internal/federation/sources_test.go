package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/colortokens/terraform-provider-xshield/internal/cloudauth"
)

func clearCIEnvironment(t *testing.T) {
	for _, name := range []string{terraformCloudTaggedTokenVariable, terraformCloudTokenVariable, gitHubRequestURLVariable,
		gitHubRequestTokenVariable, azureDevOpsRequestURIVariable, azureDevOpsAccessTokenVariable, azureDevOpsServiceConnectionVariable,
		defaultGitLabTokenVariable, "CUSTOM_ID_TOKEN"} {
		t.Setenv(name, "")
	}
}

func subjectToken(t *testing.T, source SubjectTokenSource) string {
	t.Helper()
	token, err := source.SubjectToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func settingError(t *testing.T, err error) *SettingError {
	t.Helper()
	var setting *SettingError
	if !errors.As(err, &setting) {
		t.Fatalf("error = %v, want a SettingError", err)
	}
	return setting
}

func TestSettingsThatCannotWorkNameTheAttributeToFix(t *testing.T) {
	clearCIEnvironment(t)
	cases := map[string]struct {
		settings  Settings
		attribute string
	}{
		"an unknown source":                {Settings{Source: "jenkins"}, "source"},
		"two explicit tokens":              {Settings{Token: "a", TokenEnv: "B"}, "token"},
		"github-actions without audience":  {Settings{Source: sourceGitHubActions}, "audience"},
		"aws without audience":             {Settings{Source: sourceAWS}, "audience"},
		"azure without audience":           {Settings{Source: sourceAzure}, "audience"},
		"gcp without audience":             {Settings{Source: sourceGCP}, "audience"},
		"a token with a requesting source": {Settings{Source: sourceGCP, Audience: "xshield", Token: "a"}, "source"},
		"a token file with gitlab":         {Settings{Source: sourceGitLab, TokenFile: "/token"}, "token_env"},
		"a token variable with kubernetes": {Settings{Source: sourceKubernetes, TokenEnv: "X"}, "token_file"},
		"auto with nothing to find":        {Settings{}, "source"},
		"github-actions without id-token":  {Settings{Source: sourceGitHubActions, Audience: "xshield"}, "source"},
		"azure-devops without variables":   {Settings{Source: sourceAzureDevOps}, "source"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewSubjectTokenSource(context.Background(), c.settings, http.DefaultClient)
			if got := settingError(t, err); got.Attribute != c.attribute {
				t.Errorf("error on %s (%s), want %s", got.Attribute, got.Detail, c.attribute)
			}
		})
	}
}

func TestAutoNeverReachesForACloudMetadataService(t *testing.T) {
	clearCIEnvironment(t)
	_, err := NewSubjectTokenSource(context.Background(), Settings{Source: sourceAuto, Audience: "xshield"}, http.DefaultClient)
	if detail := settingError(t, err).Detail; !strings.Contains(detail, "auto never calls a cloud metadata service") {
		t.Errorf("detail = %q", detail)
	}
}

func TestAutoTakesTheFirstSourceInOrder(t *testing.T) {
	gitHub := fakeGitHubActions(t)
	cases := map[string]struct {
		environment map[string]string
		settings    Settings
		want        string
	}{
		"an explicit token before the CI variables": {
			map[string]string{terraformCloudTokenVariable: "tfc-token"}, Settings{Token: "explicit-token"}, "explicit-token"},
		"HCP Terraform's tagged token before its default one": {
			map[string]string{terraformCloudTaggedTokenVariable: "tagged-token", terraformCloudTokenVariable: "tfc-token"}, Settings{}, "tagged-token"},
		"HCP Terraform before GitHub Actions": {
			map[string]string{terraformCloudTokenVariable: "tfc-token", gitHubRequestURLVariable: gitHub.URL + "/token", gitHubRequestTokenVariable: "r"},
			Settings{Audience: "xshield"}, "tfc-token"},
		"GitHub Actions before Azure DevOps": {
			map[string]string{gitHubRequestURLVariable: gitHub.URL + "/token?api-version=2.0", gitHubRequestTokenVariable: "request-token", azureDevOpsRequestURIVariable: "https://example.com/oidctoken"},
			Settings{Audience: "xshield"}, "github-token-for-xshield"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			clearCIEnvironment(t)
			for variable, value := range c.environment {
				t.Setenv(variable, value)
			}
			source, err := NewSubjectTokenSource(context.Background(), c.settings, gitHub.Client())
			if err != nil {
				t.Fatal(err)
			}
			if got := subjectToken(t, source); got != c.want {
				t.Errorf("token = %q, want %q", got, c.want)
			}
		})
	}
}

func fakeGitHubActions(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer request-token" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "github-token-for-" + r.URL.Query().Get("audience")})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGitHubActionsIsAskedForTheAudienceOnEveryCall(t *testing.T) {
	clearCIEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "bearer request-token" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "github-token-for-" + r.URL.Query().Get("audience")})
	}))
	t.Cleanup(server.Close)
	t.Setenv(gitHubRequestURLVariable, server.URL+"/token?api-version=2.0")
	t.Setenv(gitHubRequestTokenVariable, "request-token")
	source, err := NewSubjectTokenSource(context.Background(), Settings{Source: sourceGitHubActions, Audience: "api://xshield&x=1"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := subjectToken(t, source); got != "github-token-for-api://xshield&x=1" {
			t.Errorf("token = %q", got)
		}
	}
	if requests.Load() != 2 {
		t.Errorf("%d requests, want one per call so a refresh gets a new token", requests.Load())
	}
}

func TestAzureDevOpsIsAskedForTheServiceConnectionsToken(t *testing.T) {
	clearCIEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if r.Method != http.MethodPost || r.URL.Path != "/org/_apis/oidctoken" || r.Header.Get("Authorization") != "Bearer system-access-token" ||
			query.Get("api-version") != "7.1" || query.Get("serviceConnectionId") != "00000000-0000-0000-0000-000000000000" ||
			r.Header.Get("X-TFS-FedAuthRedirect") != "Suppress" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"oidcToken": "ado-token"})
	}))
	t.Cleanup(server.Close)
	t.Setenv(azureDevOpsRequestURIVariable, server.URL+"/org/_apis/oidctoken")
	t.Setenv(azureDevOpsAccessTokenVariable, "system-access-token")
	t.Setenv(azureDevOpsServiceConnectionVariable, "00000000-0000-0000-0000-000000000000")
	for _, source := range []string{sourceAzureDevOps, sourceAuto} {
		tokens, err := NewSubjectTokenSource(context.Background(), Settings{Source: source}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if got := subjectToken(t, tokens); got != "ado-token" {
			t.Errorf("source %s: token = %q, want ado-token", source, got)
		}
	}
}

func TestAzureDevOpsWithoutTheAccessTokenSaysHowToMapIt(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv(azureDevOpsRequestURIVariable, "https://example.com/oidctoken")
	t.Setenv(azureDevOpsServiceConnectionVariable, "00000000-0000-0000-0000-000000000000")
	_, err := NewSubjectTokenSource(context.Background(), Settings{Source: sourceAzureDevOps}, http.DefaultClient)
	if detail := settingError(t, err).Detail; !strings.Contains(detail, "SYSTEM_ACCESSTOKEN") || !strings.Contains(detail, "$(System.AccessToken)") {
		t.Errorf("detail = %q", detail)
	}
}

func TestGitLabReadsTheJobsIDTokenVariable(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv(defaultGitLabTokenVariable, "gitlab-token")
	t.Setenv("CUSTOM_ID_TOKEN", "custom-token")
	for settings, want := range map[Settings]string{
		{Source: sourceGitLab}:                               "gitlab-token",
		{Source: sourceGitLab, TokenEnv: "CUSTOM_ID_TOKEN"}:  "custom-token",
		{Source: sourceAuto, TokenEnv: "CUSTOM_ID_TOKEN"}:    "custom-token",
		{Source: sourceAuto, Token: "given-in-the-provider"}: "given-in-the-provider",
	} {
		source, err := NewSubjectTokenSource(context.Background(), settings, http.DefaultClient)
		if err != nil {
			t.Fatal(err)
		}
		if got := subjectToken(t, source); got != want {
			t.Errorf("%+v: token = %q, want %q", settings, got, want)
		}
	}
	t.Setenv(defaultGitLabTokenVariable, "")
	source, _ := NewSubjectTokenSource(context.Background(), Settings{Source: sourceGitLab}, http.DefaultClient)
	if _, err := source.SubjectToken(context.Background()); err == nil || !strings.Contains(err.Error(), "id_tokens") {
		t.Errorf("error = %v, want a pointer to the id_tokens keyword", err)
	}
}

func TestKubernetesRereadsTheProjectedTokenOnEveryCall(t *testing.T) {
	clearCIEnvironment(t)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewSubjectTokenSource(context.Background(), Settings{Source: sourceKubernetes, TokenFile: file}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if got := subjectToken(t, source); got != "first-token" {
		t.Errorf("token = %q", got)
	}
	if err := os.WriteFile(file, []byte("rotated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := subjectToken(t, source); got != "rotated-token" {
		t.Errorf("token after the kubelet rotated it = %q, want rotated-token", got)
	}

	defaulted, err := NewSubjectTokenSource(context.Background(), Settings{Source: sourceKubernetes}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if got := defaulted.(fileToken).path; got != "/var/run/secrets/xshield/token" {
		t.Errorf("default token file = %q, want /var/run/secrets/xshield/token", got)
	}
}

func TestAWSSTSIsAskedForAWebIdentityTokenForTheAudience(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=TESTACCESSKEY/") ||
			!strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/sts/aws4_request") ||
			form.Get("Action") != "GetWebIdentityToken" || form.Get("Version") != "2011-06-15" ||
			form.Get("Audience.member.1") != "xshield" || form.Get("SigningAlgorithm") != "RS256" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not allowed to call sts:GetWebIdentityToken</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprint(w, `<GetWebIdentityTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetWebIdentityTokenResult>`+
			`<WebIdentityToken>aws-token</WebIdentityToken><Expiration>2026-01-02T03:09:05Z</Expiration></GetWebIdentityTokenResult>`+
			`<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></GetWebIdentityTokenResponse>`)
	}))
	t.Cleanup(server.Close)
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "TESTACCESSKEY", SecretAccessKey: "secret"}, nil
	})
	source := awsWebIdentityToken{audience: "xshield", region: "eu-west-1", endpoint: server.URL + "/", credentials: credentials, client: server.Client()}
	for range 2 {
		if got := subjectToken(t, source); got != "aws-token" {
			t.Errorf("token = %q", got)
		}
	}
	if requests.Load() != 2 {
		t.Errorf("%d requests, want one per call", requests.Load())
	}

	source.audience = "other"
	if _, err := source.SubjectToken(context.Background()); err == nil || !strings.Contains(err.Error(), "AccessDenied not allowed to call sts:GetWebIdentityToken") {
		t.Errorf("error = %v, want STS's code and message", err)
	}
}

type entraStandIn struct {
	scopes []string
	calls  int
}

func (e *entraStandIn) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	e.calls++
	e.scopes = options.Scopes
	return azcore.AccessToken{Token: "entra-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestAzureAsksEntraForTheAudiencesDefaultScope(t *testing.T) {
	entra := &entraStandIn{}
	source := azureToken{tokens: cloudauth.NewAzureTokens(entra, "api://xshield/.default")}
	for range 2 {
		if got := subjectToken(t, source); got != "entra-token" {
			t.Errorf("token = %q", got)
		}
	}
	if len(entra.scopes) != 1 || entra.scopes[0] != "api://xshield/.default" || entra.calls != 1 {
		t.Errorf("asked %d times for %v, want once for api://xshield/.default", entra.calls, entra.scopes)
	}
}

func TestGoogleCloudMetadataIsAskedForAFullIdentityToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Query().Get("audience") != "https://xshield.example.com" || r.URL.Query().Get("format") != "full" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, "gcp-token")
	}))
	t.Cleanup(server.Close)
	source := gcpIdentityToken{identityURL: server.URL + "/computeMetadata/v1/instance/service-accounts/default/identity", audience: "https://xshield.example.com", client: server.Client()}
	if got := subjectToken(t, source); got != "gcp-token" {
		t.Errorf("token = %q", got)
	}
	if gcpIdentityURL != "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity" {
		t.Errorf("identity URL = %s", gcpIdentityURL)
	}
}
