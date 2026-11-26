package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
)

// A cloud connector names its assets by an ID that is not a UUID: a hash of the Azure resource ID, or the AWS ARN in
// URL-safe base64.
const assetIDTheAPIFailsOn = "fedcba9876543210fedcba9876543210"

func newAssetImportClient(t *testing.T, namedAssets map[string]string, assetIDs ...string) *sdk.Xshield {
	t.Helper()
	newLookupClient(t, "{}")
	known := map[string]bool{}
	for _, id := range assetIDs {
		known[id] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/assets/actions/search":
			raw, _ := io.ReadAll(r.Body)
			items := []string{}
			for name, id := range namedAssets {
				if strings.Contains(string(raw), "'"+name+"'") {
					items = append(items, `{"assetId":"`+id+`","assetName":"`+name+`","lastFWSynchronized":""}`)
				}
			}
			_, _ = io.WriteString(w, `{"items":[`+strings.Join(items, ",")+`]}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/assets/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/assets/")
			if id == assetIDTheAPIFailsOn {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"message":"malformed asset id"}`)
				return
			}
			if !known[id] {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"not found"}`)
				return
			}
			_, _ = io.WriteString(w, `{"assetId":"`+id+`","assetName":"vm"}`)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", providerTestKeyPEM)),
		sdk.WithClient(srv.Client()),
	)
}

func TestAssetImportResolvesCloudAssetIDs(t *testing.T) {
	const azureID = "0123456789abcdef0123456789abcdef"
	const awsID = "YXJuOmF3czplYzI6dXMtZWFzdC0xOjExMTExMTExMTExMTppbnN0YW5jZS9pLTBhYmM"
	const uuid = "a1b2c3d4-0000-0000-0000-000000000000"
	client := newAssetImportClient(t, map[string]string{"prod-crm-app": azureID}, azureID, awsID)
	tests := map[string]struct {
		id, want, wantErr string
	}{
		"an Azure asset by its ID": {id: azureID, want: azureID},
		"an AWS asset by its ID":   {id: awsID, want: awsID},
		"an asset by its name":     {id: "prod-crm-app", want: azureID},
		"a UUID as given":          {id: uuid, want: uuid},
		"neither a name nor an ID": {id: "no-such-asset", wantErr: `no asset named or with the ID "no-such-asset"`},
		"an ID the API fails on":   {id: assetIDTheAPIFailsOn, wantErr: "400"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := resolveAssetImportID(context.Background(), client, test.id)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("want an error containing %q, got %v", test.wantErr, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("want %q, got %q (%v)", test.want, got, err)
			}
		})
	}
}
