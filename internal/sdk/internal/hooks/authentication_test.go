package hooks

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// The gateway verifies against "host: <name>" with any port removed, so a server URL with a port
// must be signed the same way or every request is refused.
func TestSignatureVerifiesAsTheGatewayChecksItForAURLWithAPort(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	req, err := http.NewRequest(http.MethodGet, "https://tenant.example.test:8443/api/policies/x?y=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = (&AuthenticationHook{}).signRequest(req, shared.NewDirectConfigProvider("tenant", "user", "fp", keyPEM)); err != nil {
		t.Fatal(err)
	}

	gatewayString := strings.Join([]string{
		"(request-target): get /api/policies/x?y=1",
		"date: " + req.Header.Get("date"),
		"host: tenant.example.test",
		"x-content-sha256: " + req.Header.Get("x-content-sha256"),
	}, "\n")
	auth := req.Header.Get("Authorization")
	sig, err := base64.RawStdEncoding.DecodeString(auth[strings.Index(auth, `signature="`)+len(`signature="`) : len(auth)-1])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(gatewayString))
	if err = rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, nil); err != nil {
		t.Errorf("the gateway would refuse the request: %v", err)
	}
}

// The gateway verifies these exact bytes: the keyId and header list, the signing string's lines and order,
// the body digest, and an unpadded signature made with the largest PSS salt a local key allows.
func TestAPIKeySignatureIsUnchanged(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	config := shared.NewDirectConfigProvider("tenant-1", "111111111111", "aa:bb:cc", keyPEM)
	cases := map[string]struct {
		method, url, body, target, contentDigest string
	}{
		"with a body":    {http.MethodPost, "https://tenant-1.example.com/api/assets?limit=5", `{"name":"web-1"}`, "post /api/assets?limit=5", "OFdQH9y3EN2o1pjQBk8tNV5vO1ahZajqzpA6FuBb3v8="},
		"without a body": {http.MethodGet, "https://tenant-1.example.com/api/assets/1", "", "get /api/assets/1", "Q9XEOfzy9Dmii74Ilukydbc24qHT1ORA/tv3o3zFFuQ="},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			req, err := http.NewRequest(c.method, c.url, body)
			if err != nil {
				t.Fatal(err)
			}
			hookCtx := BeforeRequestContext{HookContext: HookContext{Context: context.Background(),
				SecuritySource: func(context.Context) (interface{}, error) { return config, nil }}}
			if req, err = (&AuthenticationHook{}).BeforeRequest(hookCtx, req); err != nil {
				t.Fatal(err)
			}

			if got := req.Header.Get("x-content-sha256"); got != c.contentDigest {
				t.Errorf("x-content-sha256 = %q, want %q", got, c.contentDigest)
			}
			if got := req.Header.Get("host"); got != "tenant-1.example.com" {
				t.Errorf("host = %q", got)
			}
			date := req.Header.Get("date")
			if sent, err := time.Parse(http.TimeFormat, date); err != nil || time.Since(sent).Abs() > time.Minute {
				t.Errorf("date = %q, want the current time in HTTP format", date)
			}
			const prefix = `Signature version="1",keyId="tenant-1::111111111111::aa:bb:cc",algorithm="rsa-sha256",headers="(request-target) date host x-content-sha256",signature="`
			auth := req.Header.Get("Authorization")
			if !strings.HasPrefix(auth, prefix) || !strings.HasSuffix(auth, `"`) {
				t.Fatalf("Authorization = %q, want the prefix %q", auth, prefix)
			}
			encoded := strings.TrimSuffix(strings.TrimPrefix(auth, prefix), `"`)
			sig, err := base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("signature %q is not unpadded standard base64: %v", encoded, err)
			}
			signingString := "(request-target): " + c.target + "\ndate: " + date + "\nhost: tenant-1.example.com\nx-content-sha256: " + c.contentDigest
			digest := sha256.Sum256([]byte(signingString))
			largestSalt := &rsa.PSSOptions{SaltLength: key.Size() - sha256.Size - 2}
			if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, largestSalt); err != nil {
				t.Errorf("the signature does not verify over the signing string with the largest salt: %v", err)
			}
			if c.body != "" {
				if sent, _ := io.ReadAll(req.Body); string(sent) != c.body {
					t.Errorf("body after signing = %q, want %q", sent, c.body)
				}
			}
		})
	}
}

type keyServiceStandIn struct {
	key        *rsa.PrivateKey
	signedWith context.Context
}

func (k *keyServiceStandIn) SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error) {
	k.signedWith = ctx
	return rsa.SignPSS(rand.Reader, k.key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: sha256.Size})
}

type requestMarker struct{}

// A key held in a key service signs the same signing string, and the header differs from an API key file's only
// in the signature bytes.
func TestAKeyServiceSignsTheSameSigningStringUnderTheSameHeader(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	standIn := &keyServiceStandIn{key: key}
	config := shared.NewRemoteKeyConfigProvider("tenant-1", "111111111111", "aa:bb:cc", standIn)
	ctx := context.WithValue(context.Background(), requestMarker{}, "this request")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://tenant-1.example.com/api/assets?limit=5", strings.NewReader(`{"name":"web-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	hookCtx := BeforeRequestContext{HookContext: HookContext{Context: context.Background(),
		SecuritySource: func(context.Context) (interface{}, error) { return config, nil }}}
	if req, err = (&AuthenticationHook{}).BeforeRequest(hookCtx, req); err != nil {
		t.Fatal(err)
	}

	if standIn.signedWith == nil || standIn.signedWith.Value(requestMarker{}) != "this request" {
		t.Error("the key service was not called with the request's context, so the request's timeout does not bound it")
	}
	const prefix = `Signature version="1",keyId="tenant-1::111111111111::aa:bb:cc",algorithm="rsa-sha256",headers="(request-target) date host x-content-sha256",signature="`
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) || !strings.HasSuffix(auth, `"`) {
		t.Fatalf("Authorization = %q, want the prefix %q", auth, prefix)
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(auth, prefix), `"`))
	if err != nil {
		t.Fatal(err)
	}
	signingString := "(request-target): post /api/assets?limit=5\ndate: " + req.Header.Get("date") +
		"\nhost: tenant-1.example.com\nx-content-sha256: OFdQH9y3EN2o1pjQBk8tNV5vO1ahZajqzpA6FuBb3v8="
	digest := sha256.Sum256([]byte(signingString))
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, nil); err != nil {
		t.Errorf("the gateway would refuse the key service's signature: %v", err)
	}
}

func TestAKeyServiceFailureStopsTheRequest(t *testing.T) {
	config := shared.NewRemoteKeyConfigProvider("tenant-1", "111111111111", "aa:bb:cc", failingSigner{})
	req, _ := http.NewRequest(http.MethodGet, "https://tenant-1.example.com/api/assets", nil)
	hookCtx := BeforeRequestContext{HookContext: HookContext{Context: context.Background(),
		SecuritySource: func(context.Context) (interface{}, error) { return config, nil }}}
	if _, err := (&AuthenticationHook{}).BeforeRequest(hookCtx, req); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("error = %v, want the key service's refusal", err)
	}
}

type failingSigner struct{}

func (failingSigner) SignSHA256Digest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("AccessDeniedException: not allowed to kms:Sign")
}

type fixedAccessToken struct {
	token string
	err   error
}

func (f fixedAccessToken) AccessToken(context.Context) (string, error) { return f.token, f.err }

func TestAFederatedConfigurationSendsItsAccessTokenInsteadOfASignature(t *testing.T) {
	config := shared.NewFederatedConfigProvider("tenant-1", "111111111111", fixedAccessToken{token: "access-token"})
	req, _ := http.NewRequest(http.MethodPost, "https://tenant-1.example.com/api/assets", strings.NewReader(`{"name":"web-1"}`))
	hookCtx := BeforeRequestContext{HookContext: HookContext{Context: context.Background(),
		SecuritySource: func(context.Context) (interface{}, error) { return config, nil }}}
	req, err := (&AuthenticationHook{}).BeforeRequest(hookCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer access-token" {
		t.Errorf("Authorization = %q, want the access token", got)
	}
	if body, _ := io.ReadAll(req.Body); string(body) != `{"name":"web-1"}` {
		t.Errorf("body = %q", body)
	}

	failing := shared.NewFederatedConfigProvider("tenant-1", "111111111111", fixedAccessToken{err: errors.New("invalid_grant")})
	hookCtx.SecuritySource = func(context.Context) (interface{}, error) { return failing, nil }
	req, _ = http.NewRequest(http.MethodGet, "https://tenant-1.example.com/api/assets", nil)
	if _, err := (&AuthenticationHook{}).BeforeRequest(hookCtx, req); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error = %v, want the exchange's refusal", err)
	}
}
