package cloudauth

import (
	"context"
	"fmt"
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
// developer tools.
func NewDefaultAzureTokens(scope string) (*AzureTokens, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
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

// NewDefaultGoogleTokens uses Application Default Credentials.
func NewDefaultGoogleTokens(scope string) (BearerTokens, error) {
	source, err := google.DefaultTokenSource(context.Background(), scope)
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
