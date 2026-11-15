package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

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

// cloudAWS is the only cloud whose snapshot this provider applies yet.
const cloudAWS = "aws"

func (a cloudSnapshotAPI) endpoint(cloud, account, region string, path ...string) string {
	parts := []string{
		strings.TrimRight(a.client.ServerURL(), "/"),
		"api/policies/cloudsnapshots",
		url.PathEscape(cloud),
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

// customerGroupChangesReads holds one read per provider configuration, account and region for the run: every
// customer group's data source in a workspace reads the same document, and one read gives them all one version.
var customerGroupChangesReads sync.Map

type customerGroupChangesKey struct {
	client          *sdk.Xshield
	account, region string
}

type customerGroupChangesRead struct {
	once    sync.Once
	changes wireCustomerGroupChanges
	err     error
}

func (a cloudSnapshotAPI) customerGroupChanges(ctx context.Context, account, region string) (wireCustomerGroupChanges, error) {
	value, _ := customerGroupChangesReads.LoadOrStore(customerGroupChangesKey{client: a.client, account: account, region: region}, &customerGroupChangesRead{})
	read := value.(*customerGroupChangesRead)
	read.once.Do(func() {
		endpoint := a.endpoint(cloudAWS, account, region, "customergroupchanges")
		if workspace := a.client.WorkspaceID(); workspace != "" {
			endpoint += "?" + url.Values{"workspace": {workspace}}.Encode()
		}
		read.err = a.get(ctx, endpoint, &read.changes)
	})
	return read.changes, read.err
}

type snapshotAPIError struct {
	Method, Endpoint string
	Status           int
	Code             string
	Detail           string
	Advice           string
}

// Xshield sends this code for an expected absence; a 404 without one, such as
// from a proxy or a platform without the route, stays an error.
const codeNotPublished = "notPublished"

func isAPIRefusal(err error, status int, code string) bool {
	var apiErr *snapshotAPIError
	return errors.As(err, &apiErr) && apiErr.Status == status && apiErr.Code == code
}

func (e *snapshotAPIError) Error() string {
	msg := fmt.Sprintf("%s %s -> %d: %s", e.Method, e.Endpoint, e.Status, e.Detail)
	if e.Advice != "" {
		msg += ". " + e.Advice
	}
	return msg
}

// gatewayBodyLimit is the largest request body whose signature Xshield's gateway checks today.
const gatewayBodyLimit = 8 << 10

// unauthorizedAdvice names what Xshield's gateway checks, because it answers each failed check alike.
func unauthorizedAdvice(bodyBytes int) string {
	advice := "Check that the API key is still active under Settings > API Keys, that tenancy_id, user_id and fingerprint are " +
		"that key's, and that this machine's clock is right: Xshield refuses a request dated more than 10 seconds before it arrives"
	if bodyBytes > gatewayBodyLimit {
		advice += fmt.Sprintf(". This request's body is %d KB, and Xshield's gateway does not yet check the signature of a body "+
			"over about 8 KB, so sending it again fails the same way: report it to ColorTokens support with this message",
			(bodyBytes+1023)/1024)
	}
	return advice
}

func (a cloudSnapshotAPI) do(ctx context.Context, method, endpoint string, body []byte, wantStatus int, out any) error {
	res, err := a.client.DoRaw(ctx, method, endpoint, body, maxSnapshotResponseBytes, snapshotFallbackRetry)
	var tooLarge *sdk.ResponseTooLargeError
	if errors.As(err, &tooLarge) {
		unchanged := ""
		if method == http.MethodGet {
			unchanged = " Nothing was read or changed."
		}
		return fmt.Errorf("%s %s: %w.%s This account and region's policy is larger than one workspace can read; "+
			"report it to ColorTokens support with this message", method, endpoint, err, unchanged)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, endpoint, err)
	}
	if res.StatusCode != wantStatus {
		apiErr := &snapshotAPIError{Method: method, Endpoint: endpoint, Status: res.StatusCode, Code: apiErrorCode(res.Body), Detail: describeAPIError(res.Body)}
		if res.StatusCode == http.StatusUnauthorized {
			apiErr.Advice = unauthorizedAdvice(len(body))
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(res.Body, out)
}

func apiErrorCode(body []byte) string {
	var apiErr struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &apiErr) != nil {
		return ""
	}
	return apiErr.Code
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
