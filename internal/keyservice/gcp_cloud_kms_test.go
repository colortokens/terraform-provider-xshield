package keyservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKeyVersionName = "projects/example/locations/global/keyRings/xshield/cryptoKeys/api-key/cryptoKeyVersions/1"

func fakeCloudKMS(t *testing.T, algorithm string) *gcpCloudKMSKey {
	t.Helper()
	keyPEM := string(publicKeyPEM(t, &keyServiceKey(t).PublicKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":401,"status":"UNAUTHENTICATED","message":"no token"}}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+testKeyVersionName+"/publicKey":
			_ = json.NewEncoder(w).Encode(map[string]string{"pem": keyPEM, "algorithm": algorithm, "name": testKeyVersionName})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/"+testKeyVersionName+":asymmetricSign":
			var request struct {
				Digest struct {
					SHA256 []byte `json:"sha256"`
				} `json:"digest"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Digest.SHA256) != 32 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"bad digest"}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"signature": signLikeAKeyService(t, request.Digest.SHA256), "name": testKeyVersionName})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"status":"NOT_FOUND","message":"no such key version"}}`))
		}
	}))
	t.Cleanup(server.Close)
	return &gcpCloudKMSKey{versionName: testKeyVersionName, baseURL: server.URL + "/v1/", tokens: staticBearerToken("kms-token"), client: server.Client()}
}

func TestACloudKMSSignatureVerifiesAsXshieldVerifiesIt(t *testing.T) {
	assertRemoteKeyVerifiesAsXshieldDoes(t, fakeCloudKMS(t, "RSA_SIGN_PSS_2048_SHA256"))
}

func TestACloudKMSKeyVersionWithAnotherAlgorithmIsRefused(t *testing.T) {
	for _, algorithm := range []string{"RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PSS_4096_SHA512", "EC_SIGN_P256_SHA256"} {
		_, err := openKey(context.Background(), fakeCloudKMS(t, algorithm))
		if err == nil || !strings.Contains(err.Error(), "fixed per key version") {
			t.Errorf("a %s key version was opened: %v", algorithm, err)
		}
	}
}

func TestACloudKMSRefusalSaysWhy(t *testing.T) {
	key := fakeCloudKMS(t, "RSA_SIGN_PSS_2048_SHA256")
	key.versionName = "projects/example/locations/global/keyRings/xshield/cryptoKeys/api-key/cryptoKeyVersions/9"
	_, err := openKey(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "NOT_FOUND no such key version") {
		t.Errorf("error = %v, want the Cloud KMS status and message", err)
	}
}
