package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
)

const maxSnapshotResponseBytes = 32 << 20

// snapshotFallbackRetry bounds retries when the provider block sets none: a
// plan against an unavailable Xshield should fail in seconds, not back off for
// the hour the generated operations default to.
var snapshotFallbackRetry = retry.Config{
	Strategy: "backoff",
	Backoff: &retry.BackoffStrategy{
		InitialInterval: 500,
		MaxInterval:     4000,
		Exponent:        2,
		MaxElapsedTime:  15000,
	},
	RetryConnectionErrors: true,
}

type cloudSnapshotAPI struct {
	client *sdk.Xshield
}

func (a cloudSnapshotAPI) endpoint(account, region string, path ...string) string {
	parts := []string{
		strings.TrimRight(a.client.ServerURL(), "/"),
		"api/policies/cloudsnapshots",
		url.PathEscape(account),
		url.PathEscape(region),
	}
	return strings.Join(append(parts, path...), "/")
}

func (a cloudSnapshotAPI) get(ctx context.Context, endpoint string, out any) error {
	return a.do(ctx, http.MethodGet, endpoint, nil, http.StatusOK, out)
}

func (a cloudSnapshotAPI) post(ctx context.Context, endpoint string, in any, wantStatus int, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return a.do(ctx, http.MethodPost, endpoint, body, wantStatus, out)
}

type snapshotAPIError struct {
	Method, Endpoint string
	Status           int
	Detail           string
}

func (e *snapshotAPIError) Error() string {
	return fmt.Sprintf("%s %s -> %d: %s", e.Method, e.Endpoint, e.Status, e.Detail)
}

func (a cloudSnapshotAPI) do(ctx context.Context, method, endpoint string, body []byte, wantStatus int, out any) error {
	res, err := a.client.DoRaw(ctx, method, endpoint, body, maxSnapshotResponseBytes, snapshotFallbackRetry)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, endpoint, err)
	}
	if res.StatusCode != wantStatus {
		return &snapshotAPIError{Method: method, Endpoint: endpoint, Status: res.StatusCode, Detail: describeAPIError(res.Body)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(res.Body, out)
}

func describeAPIError(body []byte) string {
	var apiErr struct {
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(body, &apiErr); err != nil || apiErr.Message == "" {
		return truncate(string(body), 512)
	}
	if len(apiErr.Details) == 0 {
		return apiErr.Message
	}
	details, _ := json.Marshal(apiErr.Details)
	return apiErr.Message + ": " + truncate(string(details), 1024)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
