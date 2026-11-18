// Package federation authenticates the provider as an Xshield service account with workload identity federation:
// it reads or requests an OIDC token from the platform the provider runs on and exchanges it for a short-lived
// Xshield access token.
package federation

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/colortokens/terraform-provider-xshield/internal/cloudauth"
)

const (
	sourceAuto           = "auto"
	sourceTerraformCloud = "terraform-cloud"
	sourceGitHubActions  = "github-actions"
	sourceGitLab         = "gitlab"
	sourceAzureDevOps    = "azure-devops"
	sourceKubernetes     = "kubernetes"
	sourceAWS            = "aws"
	sourceAzure          = "azure"
	sourceGCP            = "gcp"
)

var sources = []string{sourceAuto, sourceTerraformCloud, sourceGitHubActions, sourceGitLab, sourceAzureDevOps, sourceKubernetes, sourceAWS, sourceAzure, sourceGCP}

var sourcesThatRequestAnAudience = []string{sourceGitHubActions, sourceAWS, sourceAzure, sourceGCP}

const (
	defaultGitLabTokenVariable = "XSHIELD_ID_TOKEN"
	defaultKubernetesTokenFile = "/var/run/secrets/xshield/token"

	azureDevOpsServiceConnectionVariable = "XSHIELD_ADO_SERVICE_CONNECTION_ID"

	terraformCloudTaggedTokenVariable = "TFC_WORKLOAD_IDENTITY_TOKEN_XSHIELD"
	terraformCloudTokenVariable       = "TFC_WORKLOAD_IDENTITY_TOKEN"
	gitHubRequestURLVariable          = "ACTIONS_ID_TOKEN_REQUEST_URL"
	gitHubRequestTokenVariable        = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	azureDevOpsRequestURIVariable     = "SYSTEM_OIDCREQUESTURI"
	azureDevOpsAccessTokenVariable    = "SYSTEM_ACCESSTOKEN"

	gcpIdentityURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"

	maxTokenResponseBytes = 1 << 20
)

// Settings is the oidc block, each attribute already merged with its environment variable.
type Settings struct {
	Token     string
	TokenFile string
	TokenEnv  string
	Source    string
	Audience  string
}

// SettingError names the oidc attribute a configuration error is about.
type SettingError struct {
	Attribute string
	Detail    string
}

func (e *SettingError) Error() string { return e.Detail }

// SubjectTokenSource yields the workload's OIDC token. Each call reads or requests it afresh, so a token the
// platform rotates or re-issues is picked up at the next exchange.
type SubjectTokenSource interface {
	SubjectToken(ctx context.Context) (string, error)
}

// NewSubjectTokenSource checks the settings and returns the source they select. With source auto it looks only
// at explicit tokens and CI variables; cloud metadata services are never probed.
func NewSubjectTokenSource(ctx context.Context, settings Settings, client *http.Client) (SubjectTokenSource, error) {
	if settings.Source == "" {
		settings.Source = sourceAuto
	}
	if !slices.Contains(sources, settings.Source) {
		return nil, &SettingError{"source", fmt.Sprintf("source (or XSHIELD_OIDC_SOURCE) is %q. Use one of %s.", settings.Source, strings.Join(sources, ", "))}
	}
	explicit, err := explicitSource(settings)
	if err != nil {
		return nil, err
	}
	if slices.Contains(sourcesThatRequestAnAudience, settings.Source) && settings.Audience == "" {
		return nil, &SettingError{"audience", "Source " + settings.Source + " requests a token for an audience: set audience (or XSHIELD_OIDC_AUDIENCE) " +
			"to the audience of the service account's federation trust."}
	}
	switch settings.Source {
	case sourceAuto:
		return detectSource(settings, explicit, client)
	case sourceGitLab, sourceKubernetes:
		return explicit, nil
	case sourceTerraformCloud:
		return environmentToken{names: []string{terraformCloudTaggedTokenVariable, terraformCloudTokenVariable},
			hint: "Set TFC_WORKLOAD_IDENTITY_AUDIENCE_XSHIELD (or TFC_WORKLOAD_IDENTITY_AUDIENCE) on the workspace."}, nil
	case sourceGitHubActions:
		return newGitHubActionsToken(settings.Audience, client)
	case sourceAzureDevOps:
		return newAzureDevOpsToken(client)
	case sourceAWS:
		return newAWSWebIdentityToken(ctx, settings.Audience, client)
	case sourceAzure:
		tokens, err := cloudauth.NewDefaultAzureTokens(strings.TrimSuffix(settings.Audience, "/") + "/.default")
		if err != nil {
			return nil, err
		}
		return azureToken{tokens: tokens}, nil
	default:
		return gcpIdentityToken{identityURL: gcpIdentityURL, audience: settings.Audience, client: metadataClient()}, nil
	}
}

func explicitSource(settings Settings) (SubjectTokenSource, error) {
	given := 0
	for _, value := range []string{settings.Token, settings.TokenFile, settings.TokenEnv} {
		if value != "" {
			given++
		}
	}
	if given > 1 {
		return nil, &SettingError{"token", "Set only one of token, token_file and token_env (or XSHIELD_OIDC_TOKEN, XSHIELD_OIDC_TOKEN_FILE and XSHIELD_OIDC_TOKEN_ENV)."}
	}
	switch settings.Source {
	case sourceAuto:
	case sourceGitLab:
		if settings.Token != "" || settings.TokenFile != "" {
			return nil, &SettingError{"token_env", "Source gitlab reads the job's ID token from an environment variable: set token_env, not token or token_file."}
		}
		name := settings.TokenEnv
		if name == "" {
			name = defaultGitLabTokenVariable
		}
		return environmentToken{names: []string{name}, hint: "Declare it under the job's id_tokens keyword with the trust's audience as aud."}, nil
	case sourceKubernetes:
		if settings.Token != "" || settings.TokenEnv != "" {
			return nil, &SettingError{"token_file", "Source kubernetes reads a projected service account token from a file: set token_file, not token or token_env."}
		}
		path := settings.TokenFile
		if path == "" {
			path = defaultKubernetesTokenFile
		}
		return fileToken{path: path}, nil
	default:
		if given > 0 {
			return nil, &SettingError{"source", "Source " + settings.Source + " requests its own token, so token, token_file and token_env do not apply. " +
				"Leave them out, or set source to auto to use the token they give."}
		}
	}
	switch {
	case settings.Token != "":
		return staticToken(settings.Token), nil
	case settings.TokenFile != "":
		return fileToken{path: settings.TokenFile}, nil
	case settings.TokenEnv != "":
		return environmentToken{names: []string{settings.TokenEnv}}, nil
	}
	return nil, nil
}

func detectSource(settings Settings, explicit SubjectTokenSource, client *http.Client) (SubjectTokenSource, error) {
	switch {
	case explicit != nil:
		return explicit, nil
	case os.Getenv(terraformCloudTaggedTokenVariable) != "" || os.Getenv(terraformCloudTokenVariable) != "":
		return environmentToken{names: []string{terraformCloudTaggedTokenVariable, terraformCloudTokenVariable}}, nil
	case os.Getenv(gitHubRequestURLVariable) != "":
		if settings.Audience == "" {
			return nil, &SettingError{"audience", "The provider runs in GitHub Actions, which issues a token for a requested audience: set audience " +
				"(or XSHIELD_OIDC_AUDIENCE) to the audience of the service account's federation trust."}
		}
		return newGitHubActionsToken(settings.Audience, client)
	case os.Getenv(azureDevOpsRequestURIVariable) != "":
		return newAzureDevOpsToken(client)
	}
	return nil, &SettingError{"source", "No OIDC token was found. Set token, token_file or token_env, or run in HCP Terraform, GitHub Actions or " +
		"Azure DevOps with an ID token available. On Kubernetes, AWS, Azure or Google Cloud, set source (or XSHIELD_OIDC_SOURCE) to that " +
		"platform: auto never calls a cloud metadata service."}
}

type staticToken string

func (t staticToken) SubjectToken(context.Context) (string, error) { return string(t), nil }

type fileToken struct {
	path string
}

func (f fileToken) SubjectToken(context.Context) (string, error) {
	content, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("reading the OIDC token file %s: %w", f.path, err)
	}
	token := strings.TrimSpace(string(content))
	if token == "" {
		return "", fmt.Errorf("the OIDC token file %s is empty", f.path)
	}
	return token, nil
}

// environmentToken is the first of names that is set.
type environmentToken struct {
	names []string
	hint  string
}

func (e environmentToken) SubjectToken(context.Context) (string, error) {
	for _, name := range e.names {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, nil
		}
	}
	return "", errors.New(strings.TrimSpace(fmt.Sprintf("no OIDC token: %s is not set. %s", strings.Join(e.names, " or "), e.hint)))
}

type gitHubActionsToken struct {
	requestURL   string
	requestToken string
	client       *http.Client
}

func newGitHubActionsToken(audience string, client *http.Client) (SubjectTokenSource, error) {
	requestURL, requestToken := os.Getenv(gitHubRequestURLVariable), os.Getenv(gitHubRequestTokenVariable)
	if requestURL == "" || requestToken == "" {
		return nil, &SettingError{"source", "GitHub Actions gives this job no ID token: add permissions: id-token: write to the workflow or job."}
	}
	withAudience, err := url.Parse(requestURL)
	if err != nil {
		return nil, &SettingError{"source", "ACTIONS_ID_TOKEN_REQUEST_URL is not a URL."}
	}
	query := withAudience.Query()
	query.Set("audience", audience)
	withAudience.RawQuery = query.Encode()
	return gitHubActionsToken{requestURL: withAudience.String(), requestToken: requestToken, client: client}, nil
}

func (g gitHubActionsToken) SubjectToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.requestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+g.requestToken)
	req.Header.Set("Accept", "application/json")
	var response struct {
		Value string `json:"value"`
	}
	if err := doTokenRequest(g.client, req, "GitHub Actions", &response); err != nil {
		return "", err
	}
	return requireToken(response.Value, "GitHub Actions")
}

type azureDevOpsToken struct {
	requestURL  string
	accessToken string
	client      *http.Client
}

func newAzureDevOpsToken(client *http.Client) (SubjectTokenSource, error) {
	requestURI, accessToken, connectionID := os.Getenv(azureDevOpsRequestURIVariable), os.Getenv(azureDevOpsAccessTokenVariable), os.Getenv(azureDevOpsServiceConnectionVariable)
	var missing []string
	for name, value := range map[string]string{azureDevOpsRequestURIVariable: requestURI, azureDevOpsAccessTokenVariable: accessToken, azureDevOpsServiceConnectionVariable: connectionID} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, &SettingError{"source", "Source azure-devops needs " + strings.Join(missing, " and ") + ". Map SYSTEM_ACCESSTOKEN from " +
			"$(System.AccessToken) in the step's env, and set XSHIELD_ADO_SERVICE_CONNECTION_ID to the ID of the service connection whose token Xshield trusts."}
	}
	requestURL, err := url.Parse(requestURI)
	if err != nil {
		return nil, &SettingError{"source", "SYSTEM_OIDCREQUESTURI is not a URL."}
	}
	query := requestURL.Query()
	query.Set("api-version", "7.1")
	query.Set("serviceConnectionId", connectionID)
	requestURL.RawQuery = query.Encode()
	return azureDevOpsToken{requestURL: requestURL.String(), accessToken: accessToken, client: client}, nil
}

func (a azureDevOpsToken) SubjectToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.requestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TFS-FedAuthRedirect", "Suppress")
	var response struct {
		OIDCToken string `json:"oidcToken"`
	}
	if err := doTokenRequest(a.client, req, "Azure DevOps", &response); err != nil {
		return "", err
	}
	return requireToken(response.OIDCToken, "Azure DevOps")
}

type awsWebIdentityToken struct {
	audience    string
	region      string
	endpoint    string
	credentials aws.CredentialsProvider
	client      *http.Client
}

func newAWSWebIdentityToken(ctx context.Context, audience string, client *http.Client) (SubjectTokenSource, error) {
	cfg, err := cloudauth.LoadAWSConfig(ctx, "")
	if err != nil {
		return nil, &SettingError{"source", "Source aws found no AWS region or credentials for the workload: " + err.Error() + ". Set AWS_REGION, " +
			"and run where the default AWS credential chain finds the workload's role."}
	}
	if cfg.Region == "" {
		return nil, &SettingError{"source", "Source aws calls STS in the workload's region, and none was found: set AWS_REGION."}
	}
	return awsWebIdentityToken{audience: audience, region: cfg.Region, endpoint: cloudauth.AWSServiceEndpoint("sts", cfg.Region),
		credentials: cfg.Credentials, client: client}, nil
}

func (a awsWebIdentityToken) SubjectToken(ctx context.Context) (string, error) {
	form := url.Values{"Action": {"GetWebIdentityToken"}, "Version": {"2011-06-15"}, "Audience.member.1": {a.audience}, "SigningAlgorithm": {"RS256"}}
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err = cloudauth.SignAWSRequest(ctx, req, body, a.credentials, "sts", a.region); err != nil {
		return "", fmt.Errorf("AWS STS GetWebIdentityToken: %w", err)
	}
	res, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AWS STS GetWebIdentityToken: %w", err)
	}
	responseBody, err := readLimited(res)
	if err != nil {
		return "", fmt.Errorf("AWS STS GetWebIdentityToken: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		var failure struct {
			Code    string `xml:"Error>Code"`
			Message string `xml:"Error>Message"`
		}
		_ = xml.Unmarshal(responseBody, &failure)
		return "", fmt.Errorf("AWS STS GetWebIdentityToken returned %s: %s %s", res.Status, failure.Code, failure.Message)
	}
	var response struct {
		Token string `xml:"GetWebIdentityTokenResult>WebIdentityToken"`
	}
	if err = xml.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("AWS STS GetWebIdentityToken returned a response that does not parse: %w", err)
	}
	return requireToken(response.Token, "AWS STS")
}

type azureToken struct {
	tokens cloudauth.BearerTokens
}

func (a azureToken) SubjectToken(ctx context.Context) (string, error) {
	return a.tokens.Token(ctx)
}

type gcpIdentityToken struct {
	identityURL string
	audience    string
	client      *http.Client
}

func (g gcpIdentityToken) SubjectToken(ctx context.Context) (string, error) {
	query := url.Values{"audience": {g.audience}, "format": {"full"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.identityURL+"?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	res, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting an identity token from the Google Cloud metadata server: %w", err)
	}
	body, err := readLimited(res)
	if err != nil {
		return "", fmt.Errorf("reading the Google Cloud metadata server's identity token: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the Google Cloud metadata server returned %s for an identity token", res.Status)
	}
	return requireToken(strings.TrimSpace(string(body)), "the Google Cloud metadata server")
}

// metadataClient never goes through a proxy: the metadata server answers only on the instance's own network.
func metadataClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
}

func doTokenRequest(client *http.Client, req *http.Request, issuer string, response any) error {
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting an OIDC token from %s: %w", issuer, err)
	}
	body, err := readLimited(res)
	if err != nil {
		return fmt.Errorf("reading the OIDC token from %s: %w", issuer, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s for an OIDC token", issuer, res.Status)
	}
	if err = json.Unmarshal(body, response); err != nil {
		return fmt.Errorf("%s returned an OIDC token response that does not parse", issuer)
	}
	return nil
}

func requireToken(token, issuer string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("%s returned no OIDC token", issuer)
	}
	return token, nil
}

var errResponseTooLarge = errors.New("the response is larger than 1 MiB")

func readLimited(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTokenResponseBytes {
		return nil, errResponseTooLarge
	}
	return body, nil
}
