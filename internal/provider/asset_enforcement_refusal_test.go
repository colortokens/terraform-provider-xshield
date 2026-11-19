package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func assetSwitchRefusal(code, message string) *shared.ErrorResponse {
	return &shared.ErrorResponse{Message: &message, Details: map[string]any{"code": code}}
}

func TestClassifyAssetSwitchErrorExplainsEachAwsRefusal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		code         string
		message      string
		wantPhrases  []string
		avoidPhrases []string
	}{
		{
			code: "PARTIAL_UNDEPLOY",
			message: "outbound zero trust on web-1 cannot be switched off without inbound TCP:443 on web-2: the rules of customer groups sg-shared " +
				"stay narrowed for what is left, and that change cannot be planned again now; switch them off in one request, or use Rollback on the assets, " +
				"which puts the rules back for every asset of the groups; nothing was written",
			wantPhrases:  []string{"one asset per request", "Rollback", "sg-shared", "on its own"},
			avoidPhrases: []string{"switch fewer", "several assets in one apply"},
		},
		{
			code:        "UNDEPLOY_TOO_LARGE",
			message:     "the switch turns deployment off for 120 assets in one step, as the rules of their customer groups go back together, and one request changes at most 100; switch fewer assets at a time, or use Rollback on them; nothing was written",
			wantPhrases: []string{"Rollback", "120 assets"},
		},
		{
			code:        "NO_CONNECTOR",
			message:     "the switch needs the moved rules of customer groups sg-shared put back for web-1, and account 111122223333 has no active AWS connector; nothing was written",
			wantPhrases: []string{"AWS connector", "active", "apply again"},
		},
	} {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			err := classifyAssetSwitchError(409, assetSwitchRefusal(tc.code, tc.message), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if isRetryableDeploymentError(err) {
				t.Fatalf("%s is refused until the user acts; retrying cannot help", tc.code)
			}
			for _, phrase := range tc.wantPhrases {
				if !strings.Contains(err.Error(), phrase) {
					t.Errorf("message is missing %q:\n%v", phrase, err)
				}
			}
			for _, phrase := range tc.avoidPhrases {
				if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(phrase)) {
					t.Errorf("message must not advise %q:\n%v", phrase, err)
				}
			}
		})
	}
}

func TestClassifyAssetSwitchErrorRetriesALevelChange(t *testing.T) {
	t.Parallel()
	err := classifyAssetSwitchError(409, assetSwitchRefusal("LEVEL_CHANGED", "the AWS protection level changed while the deploy started; nothing was written"), nil)
	if !isRetryableDeploymentError(err) {
		t.Fatalf("LEVEL_CHANGED asks for the request to be sent again, got %v", err)
	}
}

func TestClassifyAssetSwitchErrorKeepsThePlainClassification(t *testing.T) {
	t.Parallel()
	message := "deployment in progress"
	err := classifyAssetSwitchError(400, &shared.ErrorResponse{Message: &message}, nil)
	if !isRetryableDeploymentError(err) {
		t.Fatalf("a busy tenant must still be retried, got %v", err)
	}
}

func newAssetSwitchTestClient(t *testing.T, handler http.HandlerFunc) *sdk.Xshield {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", keyPEM)),
		sdk.WithClient(srv.Client()),
	)
}

func TestApplyAssetEnforcementSendsTheSwitchAgainAfterALevelChange(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	client := newAssetSwitchTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"status":409,"message":"the level changed; nothing was written","details":{"code":"LEVEL_CHANGED"}}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `"accepted"`)
	})

	var diags diag.Diagnostics
	applyAssetEnforcement(context.Background(), client, "a1b2c3d4-0000-0000-0000-000000000000",
		&AssetResourceModel{InboundEnforcement: types.BoolValue(false)},
		&AssetResourceModel{InboundEnforcement: types.BoolValue(true)},
		&diags)

	if diags.HasError() {
		t.Fatalf("a level change should be sent again and then succeed: %v", diags)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d requests, want the refused one and one more", got)
	}
}
