package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/internal/hooks"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/internal/utils"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
)

type RawResponse struct {
	StatusCode int
	Body       []byte
}

func (s *Xshield) ServerURL() string {
	url, _ := s.sdkConfiguration.GetServerDetails()
	return url
}

// DoRaw calls an endpoint the generated operations do not cover through the
// same client, timeout, retry policy and signing hooks they use, so the
// provider block's proxy, timeout and credentials apply to it unchanged.
// fallbackRetry applies only when the provider block configures no retries.
func (s *Xshield) DoRaw(ctx context.Context, method, url string, body []byte, maxBody int64, fallbackRetry retry.Config) (RawResponse, error) {
	if timeout := s.sdkConfiguration.Timeout; timeout != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	retryConfig := &fallbackRetry
	if s.sdkConfiguration.RetryConfig != nil {
		retryConfig = s.sdkConfiguration.RetryConfig
	}
	hookCtx := hooks.HookContext{
		BaseURL:        s.ServerURL(),
		Context:        ctx,
		OAuth2Scopes:   []string{},
		SecuritySource: s.sdkConfiguration.Security,
	}

	res, err := utils.Retry(ctx, utils.Retries{Config: retryConfig, StatusCodes: []string{"5XX"}}, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, retry.Permanent(err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", s.sdkConfiguration.UserAgent)
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		if req, err = s.sdkConfiguration.Hooks.BeforeRequest(hooks.BeforeRequestContext{HookContext: hookCtx}, req); err != nil {
			return nil, retry.Permanent(err)
		}
		res, err := s.sdkConfiguration.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error sending request: %w", err)
		}
		return res, nil
	})
	if err != nil {
		return RawResponse{}, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return RawResponse{}, fmt.Errorf("reading response: %w", err)
	}
	return RawResponse{StatusCode: res.StatusCode, Body: raw}, nil
}
