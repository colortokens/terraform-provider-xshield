package keyservice

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const testKeyARN = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"

func fakeAWSKMS(t *testing.T, keyUsage string) *awsKMSKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&keyServiceKey(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=TESTACCESSKEY/") ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/kms/aws4_request") || r.Header.Get("X-Amz-Date") == "" {
			http.Error(w, `{"__type":"IncompleteSignatureException","message":"unsigned"}`, http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var request struct {
			KeyId, MessageType, SigningAlgorithm string
			Message                              []byte
		}
		if err := json.Unmarshal(body, &request); err != nil || request.KeyId != testKeyARN {
			http.Error(w, `{"__type":"com.amazonaws.kms#NotFoundException","message":"no such key"}`, http.StatusBadRequest)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": testKeyARN, "PublicKey": der, "KeySpec": "RSA_2048",
				"KeyUsage": keyUsage, "SigningAlgorithms": []string{"RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"}})
		case "TrentService.Sign":
			if request.MessageType != "DIGEST" || request.SigningAlgorithm != "RSASSA_PSS_SHA_256" || len(request.Message) != 32 {
				http.Error(w, `{"__type":"ValidationException","message":"bad sign request"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": testKeyARN, "SigningAlgorithm": "RSASSA_PSS_SHA_256",
				"Signature": signLikeAKeyService(t, request.Message)})
		default:
			http.Error(w, `{"__type":"UnknownOperationException"}`, http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "TESTACCESSKEY", SecretAccessKey: "secret"}, nil
	})
	return &awsKMSKey{keyARN: testKeyARN, region: "us-east-1", endpoint: server.URL + "/", credentials: credentials, client: server.Client()}
}

func TestAnAWSKMSSignatureVerifiesAsXshieldVerifiesIt(t *testing.T) {
	assertRemoteKeyVerifiesAsXshieldDoes(t, fakeAWSKMS(t, "SIGN_VERIFY"))
}

func TestAnAWSKMSKeyThatCannotSignIsRefused(t *testing.T) {
	_, err := openKey(context.Background(), fakeAWSKMS(t, "ENCRYPT_DECRYPT"))
	if err == nil || !strings.Contains(err.Error(), "SIGN_VERIFY") {
		t.Errorf("an encryption key was opened for signing: %v", err)
	}
}

func TestAnAWSKMSRefusalSaysWhy(t *testing.T) {
	key := fakeAWSKMS(t, "SIGN_VERIFY")
	key.keyARN = "arn:aws:kms:us-east-1:111122223333:key/other"
	_, err := openKey(context.Background(), key)
	if err == nil || !strings.Contains(err.Error(), "NotFoundException no such key") {
		t.Errorf("error = %v, want the KMS error type and message", err)
	}
}
