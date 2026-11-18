package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const gatewayRefusal = `{"message":"invalid signature"}`

var unauthorizedCauses = []string{"Settings > API Keys", "tenancy_id, user_id and fingerprint", "private_key", "clock", "10 seconds"}

func receiptWithRules(t *testing.T, n int) awsEnforcementReceiptResourceModel {
	t.Helper()
	rules := map[string]string{}
	for i := range n {
		rules[fmt.Sprintf("i-app-%03d/in/tcp/443/10.20.%d.%d/32", i, i/250, i%250)] = fmt.Sprintf("sgr-%017d", i)
	}
	ruleIDs, diags := types.MapValueFrom(context.Background(), types.StringType, rules)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return awsEnforcementReceiptResourceModel{CloudAccountID: types.StringValue("123456789012"),
		Region: types.StringValue("us-east-1"), Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: ruleIDs, Attachments: types.MapNull(types.StringType)}
}

func sendReceipt(t *testing.T, status int, answer string, receipt awsEnforcementReceiptResourceModel) (sentBytes int, refusal string) {
	t.Helper()
	api, recorder, _ := newSnapshotTestAPI(t, status, answer)
	var diags diag.Diagnostics
	(&awsEnforcementReceiptResource{api: api}).send(context.Background(), &receipt, &diags)
	if !diags.HasError() || len(recorder.requests) != 1 {
		t.Fatalf("want one refused request, got %d request(s) and %v", len(recorder.requests), diags)
	}
	return len(recorder.requests[0].body), diags.Errors()[0].Detail()
}

// Xshield's gateway answers 401 "invalid signature" for an inactive key, credentials or a private key that are not
// the key's, a clock running behind and, until it reads buffered bodies, a large body, so "run apply again" alone
// sends a refused request again unchanged. The gateway passed a body of 10,000 bytes and refused one of 12,000, so a
// body over 8 KB is named as a possible cause, not as the cause.
func TestAnUnauthorizedAnswerNamesWhatTheGatewayChecks(t *testing.T) {
	t.Parallel()

	t.Run("a read", func(t *testing.T) {
		t.Parallel()
		api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/expected": {http.StatusUnauthorized, gatewayRefusal}})
		var m awsEnforcementSnapshotDataSourceModel
		ok, errs := readDataSource(t, &awsEnforcementSnapshotDataSource{api: api}, pointArgs(), &m)
		if ok {
			t.Fatal("a refused read planned")
		}
		for _, want := range unauthorizedCauses {
			if !strings.Contains(errs, want) {
				t.Errorf("the error does not mention %q:\n%s", want, errs)
			}
		}
		if strings.Contains(errs, "KB") {
			t.Errorf("a request without a body is blamed on its size:\n%s", errs)
		}
	})

	t.Run("a small receipt", func(t *testing.T) {
		t.Parallel()
		sent, refusal := sendReceipt(t, http.StatusUnauthorized, gatewayRefusal, receiptWithRules(t, 3))
		if sent > 8<<10 {
			t.Fatalf("the receipt is %d bytes, want one under 8 KB", sent)
		}
		for _, want := range append(unauthorizedCauses, "run apply again") {
			if !strings.Contains(refusal, want) {
				t.Errorf("the error does not mention %q:\n%s", want, refusal)
			}
		}
		if strings.Contains(refusal, "KB") {
			t.Errorf("a receipt under 8 KB is blamed on its size:\n%s", refusal)
		}
	})

	t.Run("a receipt over 8 KB", func(t *testing.T) {
		t.Parallel()
		sent, refusal := sendReceipt(t, http.StatusUnauthorized, gatewayRefusal, receiptWithRules(t, 200))
		if sent <= 8<<10 {
			t.Fatalf("the receipt is %d bytes, want one over 8 KB", sent)
		}
		for _, want := range append(unauthorizedCauses, fmt.Sprintf("%d KB", (sent+1023)/1024), "over about 8 KB", "can refuse",
			"may fail the same way") {
			if !strings.Contains(refusal, want) {
				t.Errorf("the error does not mention %q:\n%s", want, refusal)
			}
		}
		for _, certain := range []string{"does not yet check", "sending it again fails the same way"} {
			if strings.Contains(refusal, certain) {
				t.Errorf("the error states the size as the cause, which it may not be: %q\n%s", certain, refusal)
			}
		}
	})
}

type fixedAccessToken string

func (token fixedAccessToken) AccessToken(context.Context) (string, error) { return string(token), nil }

func refusedReadAdvice(t *testing.T, config shared.ConfigurationProvider) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, gatewayRefusal)
	}))
	t.Cleanup(srv.Close)
	api := cloudSnapshotAPI{client: sdk.New(sdk.WithServerURL(srv.URL), sdk.WithConfigProvider(config), sdk.WithClient(srv.Client()))}
	var m awsEnforcementSnapshotDataSourceModel
	ok, errs := readDataSource(t, &awsEnforcementSnapshotDataSource{api: api}, pointArgs(), &m)
	if ok {
		t.Fatal("a refused read planned")
	}
	return errs
}

// Each authentication method fails a request for its own reasons, so a 401 names only those of the method in use.
func TestAnUnauthorizedAnswerNamesTheChecksOfTheAuthenticationMethodInUse(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		config         shared.ConfigurationProvider
		named, unnamed []string
	}{
		"kms_key": {
			config:  shared.NewRemoteKeyConfigProvider("tenancy", "user", "fp", remoteKeyStandIn{key}),
			named:   []string{"kms_key", "tenancy_id and user_id", "clock", "10 seconds"},
			unnamed: []string{"private_key", "fingerprint", "Settings > API Keys"},
		},
		"oidc": {
			config:  shared.NewFederatedConfigProvider("tenancy", "user", fixedAccessToken("access-token")),
			named:   []string{"service account", "tenancy_id and user_id", "access token"},
			unnamed: []string{"private_key", "fingerprint", "clock", "kms_key", "Settings > API Keys"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			errs := refusedReadAdvice(t, tc.config)
			for _, want := range tc.named {
				if !strings.Contains(errs, want) {
					t.Errorf("the error does not mention %q:\n%s", want, errs)
				}
			}
			for _, unrelated := range tc.unnamed {
				if strings.Contains(errs, unrelated) {
					t.Errorf("the error mentions %q, which %s does not use:\n%s", unrelated, name, errs)
				}
			}
		})
	}
}
