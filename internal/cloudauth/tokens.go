package cloudauth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// BearerTokens yields an access token for one audience, reusing it while it stays valid.
type BearerTokens interface {
	Token(ctx context.Context) (string, error)
}

const azureTokenRenewBefore = 5 * time.Minute

// AzureTokens caches the credential's token for one scope, because a developer credential such as the Azure
// CLI starts a process for every token it is asked for.
type AzureTokens struct {
	credential azcore.TokenCredential
	scope      string

	mu      sync.Mutex
	current azcore.AccessToken
}

func NewAzureTokens(credential azcore.TokenCredential, scope string) *AzureTokens {
	return &AzureTokens{credential: credential, scope: scope}
}

// NewDefaultAzureTokens uses DefaultAzureCredential: environment, workload identity, managed identity, then the
// developer tools. Its token requests go through client; the developer tools run as processes that use their own
// proxy settings.
func NewDefaultAzureTokens(scope string, client *http.Client) (*AzureTokens, error) {
	options := &azidentity.DefaultAzureCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: credentialHTTPClient(client)}}
	credential, err := azidentity.NewDefaultAzureCredential(options)
	if err != nil {
		return nil, fmt.Errorf("setting up DefaultAzureCredential: %w", err)
	}
	return NewAzureTokens(credential, scope), nil
}

func (t *AzureTokens) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current.Token != "" && time.Until(t.current.ExpiresOn) > azureTokenRenewBefore {
		return t.current.Token, nil
	}
	token, err := t.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{t.scope}})
	if err != nil {
		return "", fmt.Errorf("getting a Microsoft Entra token for %s: %w", t.scope, err)
	}
	t.current = token
	return token.Token, nil
}

type googleTokens struct {
	source oauth2.TokenSource
}

// NewDefaultGoogleTokens uses Application Default Credentials, with its token requests sent through client. On
// Google Cloud the metadata server is asked for the token directly, never through a proxy.
func NewDefaultGoogleTokens(scope string, client *http.Client) (BearerTokens, error) {
	source, err := google.DefaultTokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, credentialHTTPClient(client)), scope)
	if err != nil {
		return nil, fmt.Errorf("finding Google Application Default Credentials: %w", err)
	}
	return googleTokens{source: source}, nil
}

func (t googleTokens) Token(context.Context) (string, error) {
	token, err := t.source.Token()
	if err != nil {
		return "", fmt.Errorf("getting a Google access token: %w", err)
	}
	return token.AccessToken, nil
}
