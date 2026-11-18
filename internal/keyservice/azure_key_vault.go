package keyservice

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/cloudauth"
)

const (
	azureKeyVaultAPIVersion = "7.4"
	azureKeyVaultScope      = "https://vault.azure.net/.default"
)

// azureKeyVaultKey signs with the key version whose public key was read, so a new version of the key does not
// start signing with a key Xshield does not hold.
type azureKeyVaultKey struct {
	keyID  string
	tokens cloudauth.BearerTokens
	client *http.Client
	retry  retryPolicy
}

func newAzureKeyVaultKey(keyID string, client *http.Client) (*azureKeyVaultKey, error) {
	tokens, err := cloudauth.NewDefaultAzureTokens(azureKeyVaultScope)
	if err != nil {
		return nil, err
	}
	return &azureKeyVaultKey{keyID: keyID, tokens: tokens, client: client}, nil
}

func (k *azureKeyVaultKey) publicKey(ctx context.Context) (*rsa.PublicKey, error) {
	var response struct {
		Key struct {
			KeyID  string   `json:"kid"`
			Type   string   `json:"kty"`
			KeyOps []string `json:"key_ops"`
			N      string   `json:"n"`
			E      string   `json:"e"`
		} `json:"key"`
	}
	if err := k.call(ctx, http.MethodGet, k.keyID, nil, &response); err != nil {
		return nil, err
	}
	if response.Key.Type != "RSA" && response.Key.Type != "RSA-HSM" {
		return nil, fmt.Errorf("Key Vault key %s is %s, not RSA", k.keyID, response.Key.Type)
	}
	if !slices.Contains(response.Key.KeyOps, "sign") {
		return nil, fmt.Errorf("Key Vault key %s permits %v, not sign: add sign to the key's permitted operations", k.keyID, response.Key.KeyOps)
	}
	if !strings.HasPrefix(response.Key.KeyID, versionlessKeyID(k.keyID)+"/") {
		return nil, fmt.Errorf("Key Vault returned key %q for %s", response.Key.KeyID, k.keyID)
	}
	modulus, errN := decodeBase64URL(response.Key.N)
	exponent, errE := decodeBase64URL(response.Key.E)
	if errN != nil || errE != nil || len(modulus) == 0 || len(exponent) == 0 || len(exponent) > 4 {
		return nil, fmt.Errorf("Key Vault returned an RSA key for %s that does not parse", k.keyID)
	}
	k.keyID = response.Key.KeyID
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}, nil
}

func (k *azureKeyVaultKey) SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error) {
	request := map[string]string{"alg": "PS256", "value": base64.RawURLEncoding.EncodeToString(digest)}
	var response struct {
		Value string `json:"value"`
	}
	if err := k.call(ctx, http.MethodPost, k.keyID+"/sign", request, &response); err != nil {
		return nil, err
	}
	signature, err := decodeBase64URL(response.Value)
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("Key Vault returned a signature for %s that does not decode", k.keyID)
	}
	return signature, nil
}

func (k *azureKeyVaultKey) call(ctx context.Context, method, url string, request, response any) error {
	var body []byte
	if request != nil {
		var err error
		if body, err = json.Marshal(request); err != nil {
			return err
		}
	}
	return k.retry.call(ctx, func() error { return k.callOnce(ctx, method, url, body, response) })
}

func (k *azureKeyVaultKey) callOnce(ctx context.Context, method, url string, body []byte, response any) error {
	req, err := http.NewRequestWithContext(ctx, method, url+"?api-version="+azureKeyVaultAPIVersion, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token, err := k.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("Key Vault key %s: %w", k.keyID, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := k.client.Do(req)
	if err != nil {
		return transientIfConnectionDropped(fmt.Errorf("Key Vault key %s: %w", k.keyID, err))
	}
	responseBody, err := readResponseBody(res)
	if err != nil {
		return transientIfConnectionDropped(fmt.Errorf("Key Vault key %s: %w", k.keyID, err))
	}
	if res.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		refusal := fmt.Errorf("Key Vault key %s returned %s: %s %s", k.keyID, res.Status, failure.Error.Code, failure.Error.Message)
		if retryableStatus(res.StatusCode) {
			return transientRefusal(refusal, res.Header)
		}
		return refusal
	}
	if err = json.Unmarshal(responseBody, response); err != nil {
		return fmt.Errorf("Key Vault returned a response for %s that does not parse: %w", k.keyID, err)
	}
	return nil
}

func versionlessKeyID(keyID string) string {
	scheme, rest, _ := strings.Cut(keyID, "://")
	segments := strings.Split(rest, "/")
	if len(segments) > 3 {
		segments = segments[:3]
	}
	return scheme + "://" + strings.Join(segments, "/")
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
}
