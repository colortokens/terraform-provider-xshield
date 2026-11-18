// Package keyservice signs Xshield API requests with an API key whose private key is held in AWS KMS, Azure Key
// Vault or Google Cloud KMS, so it never leaves the key service.
package keyservice

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const minimumKeyBytes = 256

const maxResponseBytes = 1 << 20

// Signer signs the SHA-256 digest of a request's signing string with RSASSA-PSS.
type Signer interface {
	SignSHA256Digest(ctx context.Context, digest []byte) ([]byte, error)
}

// RemoteKey is a key service key whose public half has been read and checked.
type RemoteKey struct {
	Signer
	PublicKey   *rsa.PublicKey
	Fingerprint string
}

type remoteKeyClient interface {
	Signer
	publicKey(ctx context.Context) (*rsa.PublicKey, error)
}

// Open reads the public key of the key named by uri, checks Xshield can verify its signatures, and returns a
// signer for it. The key service is called with the cloud's default credentials.
func Open(ctx context.Context, uri string, client *http.Client) (*RemoteKey, error) {
	location, err := parseKeyURI(uri)
	if err != nil {
		return nil, err
	}
	var key remoteKeyClient
	switch location.service {
	case awsKMS:
		key, err = newAWSKMSKey(ctx, location.name, client)
	case azureKeyVault:
		key, err = newAzureKeyVaultKey(location.name, client)
	case gcpCloudKMS:
		key, err = newGCPCloudKMSKey(location.name, client)
	}
	if err != nil {
		return nil, err
	}
	return openKey(ctx, key)
}

func openKey(ctx context.Context, key remoteKeyClient) (*RemoteKey, error) {
	publicKey, err := key.publicKey(ctx)
	if err != nil {
		return nil, err
	}
	if publicKey.Size() < minimumKeyBytes {
		return nil, fmt.Errorf("the key is %d-bit RSA; Xshield needs RSA of 2048 bits or more", publicKey.N.BitLen())
	}
	fingerprint, err := Fingerprint(publicKey)
	if err != nil {
		return nil, err
	}
	return &RemoteKey{Signer: key, PublicKey: publicKey, Fingerprint: fingerprint}, nil
}

// Fingerprint is the API key fingerprint Xshield gives the key: the MD5 of its PKIX DER encoding in lowercase,
// colon-separated hex.
func Fingerprint(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("encoding the public key: %w", err)
	}
	sum := md5.Sum(der)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(pairs, ":"), nil
}

type keyServiceKind int

const (
	awsKMS keyServiceKind = iota
	azureKeyVault
	gcpCloudKMS
)

type keyLocation struct {
	service keyServiceKind
	name    string
}

var errUnrecognisedKeyURI = errors.New("kms_key must be awskms:///<key ARN>, azurekeyvault://<vault>.vault.azure.net/keys/<name>[/<version>] " +
	"or gcpkms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<version>; " +
	"a bare KMS key ARN, Key Vault key ID or Cloud KMS key version name is also accepted")

func parseKeyURI(uri string) (keyLocation, error) {
	switch {
	case strings.HasPrefix(uri, "awskms:///"):
		return parseAWSKeyARN(strings.TrimPrefix(uri, "awskms:///"))
	case strings.HasPrefix(uri, "arn:"):
		return parseAWSKeyARN(uri)
	case strings.HasPrefix(uri, "azurekeyvault://"):
		return parseAzureKeyID("https://" + strings.TrimPrefix(uri, "azurekeyvault://"))
	case strings.HasPrefix(uri, "https://"):
		return parseAzureKeyID(uri)
	case strings.HasPrefix(uri, "gcpkms://"):
		return parseGCPKeyVersionName(strings.TrimPrefix(uri, "gcpkms://"))
	case strings.HasPrefix(uri, "projects/"):
		return parseGCPKeyVersionName(uri)
	}
	return keyLocation{}, errUnrecognisedKeyURI
}

func parseAWSKeyARN(arn string) (keyLocation, error) {
	if _, err := awsKeyRegion(arn); err != nil {
		return keyLocation{}, err
	}
	return keyLocation{service: awsKMS, name: arn}, nil
}

func awsKeyRegion(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" || parts[3] == "" || parts[4] == "" ||
		!(strings.HasPrefix(parts[5], "key/") || strings.HasPrefix(parts[5], "alias/")) || strings.ContainsAny(parts[5], " \t\n") {
		return "", fmt.Errorf("%q is not a KMS key or alias ARN, such as arn:aws:kms:<region>:<account>:key/<key-id>", arn)
	}
	return parts[3], nil
}

const azureKeyVaultHostSuffix = ".vault.azure.net"

func parseAzureKeyID(keyID string) (keyLocation, error) {
	invalid := fmt.Errorf("%q is not a Key Vault key ID, such as https://<vault>.vault.azure.net/keys/<name>[/<version>]", keyID)
	rest := strings.TrimPrefix(keyID, "https://")
	host, keyPath, found := strings.Cut(rest, "/")
	if !found || !strings.HasSuffix(host, azureKeyVaultHostSuffix) || len(host) == len(azureKeyVaultHostSuffix) ||
		strings.ContainsAny(rest, "?#@: ") {
		return keyLocation{}, invalid
	}
	segments := strings.Split(strings.TrimSuffix(keyPath, "/"), "/")
	if len(segments) < 2 || len(segments) > 3 || segments[0] != "keys" {
		return keyLocation{}, invalid
	}
	for _, segment := range segments {
		if segment == "" {
			return keyLocation{}, invalid
		}
	}
	return keyLocation{service: azureKeyVault, name: "https://" + host + "/" + strings.Join(segments, "/")}, nil
}

func parseGCPKeyVersionName(name string) (keyLocation, error) {
	segments := strings.Split(name, "/")
	labels := []string{"projects", "locations", "keyRings", "cryptoKeys", "cryptoKeyVersions"}
	valid := len(segments) == 2*len(labels)
	for i := 0; valid && i < len(labels); i++ {
		valid = segments[2*i] == labels[i] && segments[2*i+1] != "" && !strings.ContainsAny(segments[2*i+1], "?#: ")
	}
	if !valid {
		return keyLocation{}, fmt.Errorf("%q is not a Cloud KMS key version name, such as "+
			"projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<version>", name)
	}
	return keyLocation{service: gcpCloudKMS, name: name}, nil
}

func readResponseBody(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("the response is larger than %d bytes", maxResponseBytes)
	}
	return body, nil
}
