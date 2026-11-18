package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	jwtTokenType           = "urn:ietf:params:oauth:token-type:jwt"
	tokenEndpointPath      = "/api/auth/oauth/token"

	renewBeforeExpiry = 60 * time.Second
)

// Exchanger holds the service account's Xshield access token and exchanges a fresh OIDC token for a new one
// when less than a minute of it remains, or when Xshield stops accepting it.
type Exchanger struct {
	tokenURL         string
	tenancyID        string
	serviceAccountID string
	subjectTokens    SubjectTokenSource
	client           *http.Client
	now              func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewExchanger(serverURL, tenancyID, serviceAccountID string, subjectTokens SubjectTokenSource, client *http.Client) *Exchanger {
	return &Exchanger{
		tokenURL:         strings.TrimRight(serverURL, "/") + tokenEndpointPath,
		tenancyID:        tenancyID,
		serviceAccountID: serviceAccountID,
		subjectTokens:    subjectTokens,
		client:           client,
		now:              time.Now,
	}
}

func (e *Exchanger) AccessToken(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.token != "" && e.now().Add(renewBeforeExpiry).Before(e.expiresAt) {
		return e.token, nil
	}
	return e.exchange(ctx)
}

// Invalidate drops token if it is still the one held, so the next AccessToken exchanges again. A token another
// request already replaced is left alone.
func (e *Exchanger) Invalidate(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.token == token {
		e.token = ""
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *Exchanger) exchange(ctx context.Context) (string, error) {
	e.token = ""
	subjectToken, err := e.subjectTokens.SubjectToken(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {jwtTokenType},
		"tenant_id":          {e.tenancyID},
		"service_account_id": {e.serviceAccountID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchanging the OIDC token for an Xshield access token: %w", err)
	}
	body, err := readLimited(res)
	if err != nil {
		return "", fmt.Errorf("reading Xshield's token response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		var refusal tokenErrorResponse
		_ = json.Unmarshal(body, &refusal)
		reason := strings.TrimSpace(refusal.Error + ": " + refusal.ErrorDescription)
		if refusal.Error == "" {
			reason = res.Status
		}
		return "", fmt.Errorf("Xshield did not exchange the OIDC token for an access token of service account %s (%s). Check that the "+
			"service account is active and that one of its federation trusts names the token's issuer and audience, and matches its "+
			"subject and claims exactly", e.serviceAccountID, reason)
	}
	var issued tokenResponse
	if err = json.Unmarshal(body, &issued); err != nil {
		return "", fmt.Errorf("Xshield's token response does not parse: %w", err)
	}
	if issued.AccessToken == "" || !strings.EqualFold(issued.TokenType, "Bearer") || issued.ExpiresIn <= 0 {
		return "", fmt.Errorf("Xshield's token response has no bearer access token with a lifetime")
	}
	e.token = issued.AccessToken
	e.expiresAt = e.now().Add(time.Duration(issued.ExpiresIn) * time.Second)
	return e.token, nil
}

// HTTPClient is the client the SDK sends API requests through.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ReauthenticatingClient sends a request again, once, with a newly exchanged access token when Xshield answers
// 401 to the access token it carried.
type ReauthenticatingClient struct {
	next   HTTPClient
	tokens *Exchanger
}

func NewReauthenticatingClient(next HTTPClient, tokens *Exchanger) *ReauthenticatingClient {
	return &ReauthenticatingClient{next: next, tokens: tokens}
}

func (c *ReauthenticatingClient) Do(req *http.Request) (*http.Response, error) {
	res, err := c.next.Do(req)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return res, err
	}
	sent, isBearer := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !isBearer {
		return res, nil
	}
	retry := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return res, nil
		}
		if retry.Body, err = req.GetBody(); err != nil {
			return res, nil
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxTokenResponseBytes))
	res.Body.Close()

	c.tokens.Invalidate(sent)
	token, err := c.tokens.AccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	retry.Header.Set("Authorization", "Bearer "+token)
	return c.next.Do(retry)
}
