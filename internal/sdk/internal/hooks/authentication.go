package hooks

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

type AuthenticationHook struct {
}

func (ah *AuthenticationHook) BeforeRequest(hookCtx BeforeRequestContext, req *http.Request) (*http.Request, error) {

	secSource, err := hookCtx.SecuritySource(hookCtx.Context)
	if err != nil {
		return nil, err
	}

	pkiSigningMaterial, ok := secSource.(shared.ConfigurationProvider)
	if !ok {
		return nil, errors.New("invalid security source configuration")
	}

	err = ah.signRequest(req, pkiSigningMaterial)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (ah *AuthenticationHook) signRequest(req *http.Request, signingMaterial shared.ConfigurationProvider) error {

	signatureHeaders := []string{
		"(request-target)",
		"date",
		"host"}

	prepareBodyForSigningIfPresent(req, &signatureHeaders)

	date := time.Now().UTC().Format(http.TimeFormat)

	signatureMaterial := []string{
		fmt.Sprintf("(request-target): %s %s", strings.ToLower(req.Method), req.URL.RequestURI()),
		fmt.Sprintf("date: %s", date),
		fmt.Sprintf("host: %s", signedHost(req.Host)),
		fmt.Sprintf("x-content-sha256: %s", req.Header.Get("x-content-sha256"))}

	signature, err := calculateSignature(signatureMaterial, signingMaterial)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf(`Signature version="1",keyId="%s::%s::%s",algorithm="rsa-sha256",headers="%s",signature="%s"`, signingMaterial.TenancyId(), signingMaterial.PrincipalId(), signingMaterial.FingerPrint(), strings.Join(signatureHeaders, " "), signature))
	req.Header.Set("date", date)
	req.Header.Set("host", req.Host)

	return nil
}

// signedHost drops any port, because the API gateway checks the signature against the host without it.
func signedHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		return name
	}
	return host
}

func calculateSignature(signatureMaterial []string, signingMaterial shared.ConfigurationProvider) (string, error) {
	privateKey, err := signingMaterial.KeyLoader().LoadKey()
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(strings.Join(signatureMaterial, "\n")))
	hashed := hash.Sum(nil)

	var unencodedSig []byte
	unencodedSig, e := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, nil)
	if e != nil {
		return "", fmt.Errorf("can not compute signature while signing the request %s: ", e.Error())
	}

	return base64.RawStdEncoding.EncodeToString(unencodedSig), nil
}

func prepareBodyForSigningIfPresent(req *http.Request, sigHeaders *[]string) error {
	hash := sha256.New()
	if req.Body == nil || req.ContentLength == 0 {
		hash.Write([]byte(base64.StdEncoding.EncodeToString([]byte("nil"))))
	} else {
		buf := new(bytes.Buffer)
		buf.ReadFrom(req.Body)
		if buf.Len() > 0 {
			bodyB64 := base64.StdEncoding.EncodeToString(buf.Bytes())
			hash.Write([]byte(bodyB64))
			// Rewind the body back to the beginning for further reading
			req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		}
	}

	*sigHeaders = append(*sigHeaders, "x-content-sha256")
	req.Header.Set("x-content-sha256", base64.StdEncoding.EncodeToString(hash.Sum(nil)))
	return nil
}
