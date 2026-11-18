package sdk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
)

type fixedAccessToken string

func (f fixedAccessToken) AccessToken(context.Context) (string, error) { return string(f), nil }

// Every request path, generated, hand-written and raw, carries the access token and no signature.
func TestAFederatedClientSendsItsAccessTokenOnEveryRequestPath(t *testing.T) {
	var mu sync.Mutex
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, r.Header.Get("Authorization")+" date="+r.Header.Get("date"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/zerotrust") {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`"accepted"`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	client := sdk.New(
		sdk.WithServerURL(server.URL),
		sdk.WithConfigProvider(shared.NewFederatedConfigProvider("tenant-1", "111111111111", fixedAccessToken("access-token"))),
		sdk.WithClient(server.Client()),
	)

	ctx := context.Background()
	if _, err := client.Assets.ConfigureZeroTrust(ctx, operations.ConfigureZeroTrustRequest{AssetID: "a"}); err != nil {
		t.Fatalf("generated operation: %v", err)
	}
	if _, err := client.Tagbasedpolicies.TagBasedPolicyBulkNamedNetworkApply(ctx, operations.TagBasedPolicyBulkNamedNetworkApplyRequest{TagbasedpolicyID: "p"}); err != nil {
		t.Fatalf("hand-written operation: %v", err)
	}
	if _, err := client.DoRaw(ctx, http.MethodGet, server.URL+"/api/raw", nil, 1<<20, retry.Config{}); err != nil {
		t.Fatalf("raw request: %v", err)
	}
	if len(authorizations) != 3 {
		t.Fatalf("%d requests reached the server, want 3", len(authorizations))
	}
	for i, got := range authorizations {
		if got != "Bearer access-token date=" {
			t.Errorf("request %d: Authorization and date %q, want only the bearer token", i, got)
		}
	}
}
