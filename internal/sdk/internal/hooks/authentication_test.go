package hooks

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

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
