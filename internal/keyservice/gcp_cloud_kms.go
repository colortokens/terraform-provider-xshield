package keyservice

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"

	"github.com/colortokens/terraform-provider-xshield/internal/cloudauth"
)

const (
	gcpCloudKMSBaseURL = "https://cloudkms.googleapis.com/v1/"
	gcpCloudKMSScope   = "https://www.googleapis.com/auth/cloudkms"
)

var gcpPSSSHA256Algorithms = []string{"RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256", "RSA_SIGN_PSS_4096_SHA256"}

type gcpCloudKMSKey struct {
	versionName string
	baseURL     string
	tokens      cloudauth.BearerTokens
	client      *http.Client
	retry       retryPolicy
}

func newGCPCloudKMSKey(versionName string, client *http.Client) (*gcpCloudKMSKey, error) {
	tokens, err := cloudauth.NewDefaultGoogleTokens(gcpCloudKMSScope)
	if err != nil {
		return nil, err
	}
	return &gcpCloudKMSKey{versionName: versionName, baseURL: gcpCloudKMSBaseURL, tokens: tokens, client: client}, nil
}

func (k *gcpCloudKMSKey) publicKey(ctx context.Context) (*rsa.PublicKey, error) {
	var response struct {
		PEM       string `json:"pem"`
		Algorithm string `json:"algorithm"`
	}
	if err := k.call(ctx, http.MethodGet, k.baseURL+k.versionName+"/publicKey", nil, &response); err != nil {
		return nil, err
	}
	if !slices.Contains(gcpPSSSHA256Algorithms, response.Algorithm) {
		return nil, fmt.Errorf("Cloud KMS key version %s uses %s; Xshield verifies RSASSA-PSS with SHA-256, so the key version's "+
			"algorithm must be one of %v. The algorithm is fixed per key version: create a key with one of these", k.versionName, response.Algorithm, gcpPSSSHA256Algorithms)
	}
	block, _ := pem.Decode([]byte(response.PEM))
	if block == nil {
		return nil, fmt.Errorf("Cloud KMS returned a public key for %s that is not PEM", k.versionName)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Cloud KMS returned a public key for %s that does not parse: %w", k.versionName, err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Cloud KMS key version %s is not an RSA key", k.versionName)
	}
	return publicKey, nil
}

func (k *gcpCloudKMSKey) SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error) {
	request := map[string]map[string][]byte{"digest": {"sha256": digest}}
	var response struct {
		Signature []byte `json:"signature"`
	}
	if err := k.call(ctx, http.MethodPost, k.baseURL+k.versionName+":asymmetricSign", request, &response); err != nil {
		return nil, err
	}
	if len(response.Signature) == 0 {
		return nil, fmt.Errorf("Cloud KMS returned no signature for %s", k.versionName)
	}
	return response.Signature, nil
}

func (k *gcpCloudKMSKey) call(ctx context.Context, method, url string, request, response any) error {
	var body []byte
	if request != nil {
		var err error
		if body, err = json.Marshal(request); err != nil {
			return err
		}
	}
	return k.retry.call(ctx, func() error { return k.callOnce(ctx, method, url, body, response) })
}

func (k *gcpCloudKMSKey) callOnce(ctx context.Context, method, url string, body []byte, response any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token, err := k.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("Cloud KMS key version %s: %w", k.versionName, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := k.client.Do(req)
	if err != nil {
		return transientIfConnectionDropped(fmt.Errorf("Cloud KMS key version %s: %w", k.versionName, err))
	}
	responseBody, err := readResponseBody(res)
	if err != nil {
		return transientIfConnectionDropped(fmt.Errorf("Cloud KMS key version %s: %w", k.versionName, err))
	}
	if res.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		refusal := fmt.Errorf("Cloud KMS key version %s returned %s: %s %s", k.versionName, res.Status, failure.Error.Status, failure.Error.Message)
		if retryableStatus(res.StatusCode) {
			return transientRefusal(refusal, res.Header)
		}
		return refusal
	}
	if err = json.Unmarshal(responseBody, response); err != nil {
		return fmt.Errorf("Cloud KMS returned a response for %s that does not parse: %w", k.versionName, err)
	}
	return nil
}
