package keyservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"testing"
)

var (
	serviceKeyOnce sync.Once
	serviceKey     *rsa.PrivateKey
)

func keyServiceKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	serviceKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		serviceKey = key
	})
	return serviceKey
}

// signLikeAKeyService signs as the key services do, with a salt as long as the digest, unlike a local key.
func signLikeAKeyService(t *testing.T, digest []byte) []byte {
	t.Helper()
	signature, err := rsa.SignPSS(rand.Reader, keyServiceKey(t), crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: sha256.Size})
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// serverFingerprint is how Xshield fingerprints a registered public key: the MD5 of the PEM block's bytes, in
// colon-separated hex, lowercased.
func serverFingerprint(t *testing.T, publicKeyPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		t.Fatal("not PEM")
	}
	sum := md5.Sum(block.Bytes)
	var buf bytes.Buffer
	for i, b := range sum {
		if i > 0 {
			buf.WriteString(":")
		}
		fmt.Fprintf(&buf, "%02X", b)
	}
	return strings.ToLower(buf.String())
}

func publicKeyPEM(t *testing.T, publicKey *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// assertRemoteKeyVerifiesAsXshieldDoes opens the key, then checks its fingerprint is the one Xshield gives the
// exported public key and that a signature it makes verifies the way the gateway verifies one.
func assertRemoteKeyVerifiesAsXshieldDoes(t *testing.T, key remoteKeyClient) {
	t.Helper()
	opened, err := openKey(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	want := serverFingerprint(t, publicKeyPEM(t, &keyServiceKey(t).PublicKey))
	if opened.Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s", opened.Fingerprint, want)
	}
	digest := sha256.Sum256([]byte("(request-target): get /api/assets\ndate: Mon, 02 Jan 2006 15:04:05 GMT\nhost: tenant-1.example.com\nx-content-sha256: x"))
	signature, err := opened.SignSHA256Digest(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err = rsa.VerifyPSS(opened.PublicKey, crypto.SHA256, digest[:], signature, nil); err != nil {
		t.Errorf("the gateway would refuse the signature: %v", err)
	}
}

func TestFingerprintMatchesOpenSSLForAKnownKey(t *testing.T) {
	const knownPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsAEco+7QahisN7xGiTXK
G9CD8gNtrhsyUMPlMHeRUbukhkB3P0h6jTJtKL35zLcB1g9t/uGcMBlgPYBMhIqq
uyaC27B+LbnWWB0QQq/nfEV+4Jvbms3SICu3SjEU0xk1C4/GGwq4YSUoHrxU0ArK
0S8h9acaN6uOm4Eb2KZkHE2IWLc51OoX2qlz62IaqudUcX8o86X3kXMD60mPvO31
pPREKDBByAx+2iMgOICqTADs23VBThXtdZDw+OsAh3MaSEiP3TNrQ6EEZuujkMYy
D2ihOO6rm9MJF7Am8h6NIbAqbiU4+n4ok3zN8icP0d+YxWVQw9mZnfzEie3cvblx
1wIDAQAB
-----END PUBLIC KEY-----
`
	block, _ := pem.Decode([]byte(knownPEM))
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Fingerprint(parsed.(*rsa.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	const fromOpenSSL = "3a:10:64:9b:87:e3:1a:11:64:7b:ca:06:e2:59:a0:d0"
	if got != fromOpenSSL || got != serverFingerprint(t, []byte(knownPEM)) {
		t.Errorf("fingerprint = %s, want %s (openssl pkey -pubin -outform DER | openssl dgst -md5 -c)", got, fromOpenSSL)
	}
}

func TestKeyURIs(t *testing.T) {
	const keyARN = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
	const versionName = "projects/example/locations/global/keyRings/xshield/cryptoKeys/api-key/cryptoKeyVersions/1"
	valid := map[string]keyLocation{
		"awskms:///" + keyARN: {awsKMS, keyARN},
		keyARN:                {awsKMS, keyARN},
		"awskms:///arn:aws:kms:eu-west-1:111122223333:alias/xshield":         {awsKMS, "arn:aws:kms:eu-west-1:111122223333:alias/xshield"},
		"azurekeyvault://example.vault.azure.net/keys/api-key":               {azureKeyVault, "https://example.vault.azure.net/keys/api-key"},
		"azurekeyvault://example.vault.azure.net/keys/api-key/0123456789abc": {azureKeyVault, "https://example.vault.azure.net/keys/api-key/0123456789abc"},
		"https://example.vault.azure.net/keys/api-key/":                      {azureKeyVault, "https://example.vault.azure.net/keys/api-key"},
		"gcpkms://" + versionName:                                            {gcpCloudKMS, versionName},
		versionName:                                                          {gcpCloudKMS, versionName},
	}
	for uri, want := range valid {
		if got, err := parseKeyURI(uri); err != nil || got != want {
			t.Errorf("parseKeyURI(%q) = %+v, %v; want %+v", uri, got, err, want)
		}
	}
	for _, uri := range []string{
		"", "awskms://arn:aws:kms:us-east-1:111122223333:key/x", "arn:aws:s3:::bucket", "arn:aws:kms::111122223333:key/x",
		"arn:aws:kms:us-east-1:111122223333:grant/x", "azurekeyvault://example.vault.azure.net/secrets/api-key",
		"azurekeyvault://example.example.com/keys/api-key", "https://example.vault.azure.net/keys/a/b/c",
		"azurekeyvault://.vault.azure.net/keys/api-key", "https://example.vault.azure.net/keys/api-key?x=1",
		"gcpkms://projects/example/locations/global/keyRings/xshield/cryptoKeys/api-key",
		"projects/example/locations/global/keyRings/xshield/cryptoKeys/api-key/cryptoKeyVersions/",
		"file:///keys/api-key.pem",
	} {
		if got, err := parseKeyURI(uri); err == nil {
			t.Errorf("parseKeyURI(%q) = %+v, want an error", uri, got)
		}
	}
}

func TestAKeyShorterThan2048BitsIsRefused(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = openKey(context.Background(), fixedPublicKey{&small.PublicKey})
	if err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("a 1024-bit key was opened: %v", err)
	}
}

type fixedPublicKey struct{ key *rsa.PublicKey }

func (f fixedPublicKey) publicKey(context.Context) (*rsa.PublicKey, error) { return f.key, nil }
func (f fixedPublicKey) SignSHA256Digest(context.Context, []byte) ([]byte, error) {
	return nil, fmt.Errorf("not signing")
}

type staticBearerToken string

func (s staticBearerToken) Token(context.Context) (string, error) { return string(s), nil }
