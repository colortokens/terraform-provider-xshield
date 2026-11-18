package keyservice

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/colortokens/terraform-provider-xshield/internal/cloudauth"
)

const awsKMSSigningAlgorithm = "RSASSA_PSS_SHA_256"

type awsKMSKey struct {
	keyARN      string
	region      string
	endpoint    string
	credentials aws.CredentialsProvider
	client      *http.Client
}

func newAWSKMSKey(ctx context.Context, keyARN string, client *http.Client) (*awsKMSKey, error) {
	region, err := awsKeyRegion(keyARN)
	if err != nil {
		return nil, err
	}
	cfg, err := cloudauth.LoadAWSConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	return &awsKMSKey{keyARN: keyARN, region: region, endpoint: cloudauth.AWSServiceEndpoint("kms", region),
		credentials: cfg.Credentials, client: client}, nil
}

type awsKMSPublicKeyResponse struct {
	PublicKey         []byte
	KeyUsage          string
	SigningAlgorithms []string
}

func (k *awsKMSKey) publicKey(ctx context.Context) (*rsa.PublicKey, error) {
	var response awsKMSPublicKeyResponse
	if err := k.call(ctx, "GetPublicKey", map[string]string{"KeyId": k.keyARN}, &response); err != nil {
		return nil, err
	}
	if response.KeyUsage != "SIGN_VERIFY" || !slices.Contains(response.SigningAlgorithms, awsKMSSigningAlgorithm) {
		return nil, fmt.Errorf("AWS KMS key %s cannot sign with %s; use an RSA key whose key usage is SIGN_VERIFY", k.keyARN, awsKMSSigningAlgorithm)
	}
	parsed, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS returned a public key for %s that does not parse: %w", k.keyARN, err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("AWS KMS key %s is not an RSA key", k.keyARN)
	}
	return publicKey, nil
}

func (k *awsKMSKey) SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error) {
	request := struct {
		KeyId            string
		Message          []byte
		MessageType      string
		SigningAlgorithm string
	}{KeyId: k.keyARN, Message: digest, MessageType: "DIGEST", SigningAlgorithm: awsKMSSigningAlgorithm}
	var response struct{ Signature []byte }
	if err := k.call(ctx, "Sign", request, &response); err != nil {
		return nil, err
	}
	if len(response.Signature) == 0 {
		return nil, fmt.Errorf("AWS KMS returned no signature for %s", k.keyARN)
	}
	return response.Signature, nil
}

func (k *awsKMSKey) call(ctx context.Context, operation string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+operation)
	if err = cloudauth.SignAWSRequest(ctx, req, body, k.credentials, "kms", k.region); err != nil {
		return fmt.Errorf("AWS KMS %s: %w", operation, err)
	}
	res, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("AWS KMS %s: %w", operation, err)
	}
	responseBody, err := readResponseBody(res)
	if err != nil {
		return fmt.Errorf("AWS KMS %s: %w", operation, err)
	}
	if res.StatusCode != http.StatusOK {
		var failure struct {
			Type         string `json:"__type"`
			Message      string `json:"message"`
			MessageUpper string `json:"Message"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		_, errorType, _ := strings.Cut(failure.Type, "#")
		if errorType == "" {
			errorType = failure.Type
		}
		return fmt.Errorf("AWS KMS %s on %s returned %s: %s %s%s", operation, k.keyARN, res.Status, errorType, failure.Message, failure.MessageUpper)
	}
	if err = json.Unmarshal(responseBody, response); err != nil {
		return fmt.Errorf("AWS KMS %s returned a response that does not parse: %w", operation, err)
	}
	return nil
}
