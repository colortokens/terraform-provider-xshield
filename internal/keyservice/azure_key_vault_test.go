package keyservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

var signAndVerify = []string{"sign", "verify"}

// fakeKeyVault serves one key whose current version is v2. It records the path each signature was asked of.
func fakeKeyVault(t *testing.T, keyType string, keyOps []string, signedAt *atomic.Value) *azureKeyVaultKey {
	t.Helper()
	publicKey := keyServiceKey(t).PublicKey
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-version") != "7.4" || r.Header.Get("Authorization") != "Bearer vault-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"Unauthorized","message":"no token"}}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys/api-key":
			_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{
				"kid": server.URL + "/keys/api-key/v2", "kty": keyType, "key_ops": keyOps,
				"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sign"):
			signedAt.Store(r.URL.Path)
			var request struct{ Alg, Value string }
			_ = json.NewDecoder(r.Body).Decode(&request)
			digest, err := base64.RawURLEncoding.DecodeString(request.Value)
			if request.Alg != "PS256" || err != nil || len(digest) != 32 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"BadParameter","message":"bad sign request"}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"kid": server.URL + "/keys/api-key/v2",
				"value": base64.RawURLEncoding.EncodeToString(signLikeAKeyService(t, digest))})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"KeyNotFound","message":"no such key"}}`))
		}
	}))
	t.Cleanup(server.Close)
	return &azureKeyVaultKey{keyID: server.URL + "/keys/api-key", tokens: staticBearerToken("vault-token"), client: server.Client()}
}

func TestAKeyVaultSignatureVerifiesAsXshieldVerifiesIt(t *testing.T) {
	var signedAt atomic.Value
	assertRemoteKeyVerifiesAsXshieldDoes(t, fakeKeyVault(t, "RSA-HSM", signAndVerify, &signedAt))
	if got := signedAt.Load(); got != "/keys/api-key/v2/sign" {
		t.Errorf("signed with %v, want the version whose public key was fingerprinted", got)
	}
}

func TestAKeyVaultKeyThatIsNotRSAIsRefused(t *testing.T) {
	var signedAt atomic.Value
	_, err := openKey(context.Background(), fakeKeyVault(t, "EC", signAndVerify, &signedAt))
	if err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("an EC key was opened: %v", err)
	}
}

func TestAKeyVaultRefusalSaysWhy(t *testing.T) {
	var signedAt atomic.Value
	key := fakeKeyVault(t, "RSA", signAndVerify, &signedAt)
	key.tokens = staticBearerToken("other-token")
	_, err := openKey(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized no token") {
		t.Errorf("error = %v, want the Key Vault error code and message", err)
	}
}

func TestAKeyVaultKeyThatMayNotSignIsRefused(t *testing.T) {
	for name, keyOps := range map[string][]string{"verify only": {"verify", "encrypt"}, "no operations": {}} {
		t.Run(name, func(t *testing.T) {
			var signedAt atomic.Value
			_, err := openKey(context.Background(), fakeKeyVault(t, "RSA", keyOps, &signedAt))
			if err == nil || !strings.Contains(err.Error(), "sign") {
				t.Errorf("a key whose key_ops are %v was opened: %v", keyOps, err)
			}
		})
	}
}
