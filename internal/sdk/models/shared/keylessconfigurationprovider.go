package shared

import (
	"context"
	"crypto/rsa"
	"errors"
)

// RemoteSigner signs the SHA-256 digest of a request's signing string with RSASSA-PSS, using a key held
// outside the provider.
type RemoteSigner interface {
	SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error)
}

// AccessTokenSource yields the bearer token sent in place of a request signature.
type AccessTokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}

var errNoLocalPrivateKey = errors.New("this configuration authenticates without a local private key")

type noLocalPrivateKey struct{}

func (noLocalPrivateKey) LoadKey() (*rsa.PrivateKey, error) { return nil, errNoLocalPrivateKey }

// RemoteKeyConfigProvider signs requests as an API key whose private key stays in a cloud key service.
type RemoteKeyConfigProvider struct {
	tenantId    string
	principalId string
	fingerprint string
	signer      RemoteSigner
}

func NewRemoteKeyConfigProvider(tenancyId, userId, fingerprint string, signer RemoteSigner) RemoteKeyConfigProvider {
	return RemoteKeyConfigProvider{tenantId: tenancyId, principalId: userId, fingerprint: fingerprint, signer: signer}
}

func (p RemoteKeyConfigProvider) TenancyId() string           { return p.tenantId }
func (p RemoteKeyConfigProvider) PrincipalId() string         { return p.principalId }
func (p RemoteKeyConfigProvider) FingerPrint() string         { return p.fingerprint }
func (p RemoteKeyConfigProvider) KeyLoader() PrivateKeyLoader { return noLocalPrivateKey{} }
func (p RemoteKeyConfigProvider) SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error) {
	return p.signer.SignSHA256Digest(ctx, digest)
}

// FederatedConfigProvider authenticates requests with a short-lived Xshield access token for a service account,
// exchanged for the workload's OIDC token.
type FederatedConfigProvider struct {
	tenantId    string
	principalId string
	tokens      AccessTokenSource
}

func NewFederatedConfigProvider(tenancyId, serviceAccountId string, tokens AccessTokenSource) FederatedConfigProvider {
	return FederatedConfigProvider{tenantId: tenancyId, principalId: serviceAccountId, tokens: tokens}
}

func (p FederatedConfigProvider) TenancyId() string           { return p.tenantId }
func (p FederatedConfigProvider) PrincipalId() string         { return p.principalId }
func (p FederatedConfigProvider) FingerPrint() string         { return "" }
func (p FederatedConfigProvider) KeyLoader() PrivateKeyLoader { return noLocalPrivateKey{} }
func (p FederatedConfigProvider) AccessToken(ctx context.Context) (string, error) {
	return p.tokens.AccessToken(ctx)
}
