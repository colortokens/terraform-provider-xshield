package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/internal/hooks"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/internal/utils"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/retry"
)

// TagBasedPolicyBulkNamedNetworkApply - Apply named networks to a tag-based policy
// Applies the specified named networks to the tag-based policy
func (s *Tagbasedpolicies) TagBasedPolicyBulkNamedNetworkApply(ctx context.Context, request operations.TagBasedPolicyBulkNamedNetworkApplyRequest, opts ...operations.Option) (*operations.TagBasedPolicyBulkNamedNetworkApplyResponse, error) {
	o := operations.Options{}
	supportedOptions := []string{
		operations.SupportedOptionRetries,
		operations.SupportedOptionTimeout,
	}

	for _, opt := range opts {
		if err := opt(&o, supportedOptions...); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	var baseURL string
	if o.ServerURL == nil {
		baseURL = utils.ReplaceParameters(s.sdkConfiguration.GetServerDetails())
	} else {
		baseURL = *o.ServerURL
	}
	opURL, err := utils.GenerateURL(ctx, baseURL, "/api/tagbasedpolicies/{tagbasedpolicyId}/namednetworks", request, nil)
	if err != nil {
		return nil, fmt.Errorf("error generating URL: %w", err)
	}

	bodyReader, reqContentType, err := utils.SerializeRequestBody(ctx, request, false, false, "RequestBody", "json", `request:"mediaType=application/json"`)
	if err != nil {
		return nil, err
	}

	timeout := o.Timeout
	if timeout == nil {
		timeout = s.sdkConfiguration.Timeout
	}

	if timeout != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", opURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.sdkConfiguration.UserAgent)
	if reqContentType != "" {
		req.Header.Set("Content-Type", reqContentType)
	}
	// Add security configuration using hooks (like generated code)
	if s.sdkConfiguration.Security != nil {
		secObj, err := s.sdkConfiguration.Security(ctx)
		if err != nil {
			return nil, err
		}

		if _, ok := secObj.(shared.ConfigurationProvider); ok {
			authHook := &hooks.AuthenticationHook{}
			hookCtx := hooks.BeforeRequestContext{
				HookContext: hooks.HookContext{
					BaseURL:        baseURL,
					Context:        ctx,
					OperationID:    "TagBasedPolicyBulkNamedNetworkApply",
					OAuth2Scopes:   []string{},
					SecuritySource: s.sdkConfiguration.Security,
				},
			}
			req, err = authHook.BeforeRequest(hookCtx, req)
			if err != nil {
				return nil, err
			}
		} else {
		}
	}

	// NEW CODE:
	for k, v := range o.SetHeaders {
		req.Header.Set(k, v)
	}

	client := s.sdkConfiguration.Client

	globalRetryConfig := s.sdkConfiguration.RetryConfig
	retryConfig := o.Retries
	if retryConfig == nil {
		if globalRetryConfig != nil {
			retryConfig = globalRetryConfig
		} else {
			retryConfig = &retry.Config{
				Strategy: "backoff", Backoff: &retry.BackoffStrategy{
					InitialInterval: 500,
					MaxInterval:     60000,
					Exponent:        1.5,
					MaxElapsedTime:  3600000,
				},
				RetryConnectionErrors: true,
			}
		}
	}

	httpRes, err := utils.Retry(ctx, utils.Retries{
		Config:      retryConfig,
		StatusCodes: []string{"5XX"},
	}, func() (*http.Response, error) {
		resp, err := client.Do(req)
		return resp, err
	})

	contentType := httpRes.Header.Get("Content-Type")

	res := &operations.TagBasedPolicyBulkNamedNetworkApplyResponse{
		StatusCode:  httpRes.StatusCode,
		ContentType: contentType,
		RawResponse: httpRes,
	}

	if httpRes.StatusCode >= 400 {
		// Try to read the response body for more details
		if httpRes.Body != nil {
			bodyBytes, readErr := io.ReadAll(httpRes.Body)
			if readErr == nil {
				// Reset the body for further processing
				httpRes.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}
		return nil, fmt.Errorf("unexpected response from API. Got an unexpected response code %v", httpRes.StatusCode)
	}

	return res, nil
}

// TagBasedPolicyBulkNamedNetworkUnApply - Remove named networks from a tag-based policy
// Removes the specified named networks from the tag-based policy
func (s *Tagbasedpolicies) TagBasedPolicyBulkNamedNetworkUnApply(ctx context.Context, request operations.TagBasedPolicyBulkNamedNetworkUnApplyRequest, opts ...operations.Option) (*operations.TagBasedPolicyBulkNamedNetworkUnApplyResponse, error) {
	o := operations.Options{}
	supportedOptions := []string{
		operations.SupportedOptionRetries,
		operations.SupportedOptionTimeout,
	}

	for _, opt := range opts {
		if err := opt(&o, supportedOptions...); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	var baseURL string
	if o.ServerURL == nil {
		baseURL = utils.ReplaceParameters(s.sdkConfiguration.GetServerDetails())
	} else {
		baseURL = *o.ServerURL
	}
	opURL, err := utils.GenerateURL(ctx, baseURL, "/api/tagbasedpolicies/{tagbasedpolicyId}/namednetworks", request, nil)
	if err != nil {
		return nil, fmt.Errorf("error generating URL: %w", err)
	}

	bodyReader, reqContentType, err := utils.SerializeRequestBody(ctx, request, false, false, "RequestBody", "json", "")
	if err != nil {
		return nil, fmt.Errorf("error serializing request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", opURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", reqContentType)
	req.Header.Set("User-Agent", s.sdkConfiguration.UserAgent)

	// Add security configuration using hooks (like generated code)
	if s.sdkConfiguration.Security != nil {
		secObj, err := s.sdkConfiguration.Security(ctx)
		if err != nil {
			return nil, err
		}

		if _, ok := secObj.(shared.ConfigurationProvider); ok {
			authHook := &hooks.AuthenticationHook{}
			hookCtx := hooks.BeforeRequestContext{
				HookContext: hooks.HookContext{
					BaseURL:        baseURL,
					Context:        ctx,
					OperationID:    "TagBasedPolicyBulkNamedNetworkUnApply",
					OAuth2Scopes:   []string{},
					SecuritySource: s.sdkConfiguration.Security,
				},
			}
			req, err = authHook.BeforeRequest(hookCtx, req)
			if err != nil {
				return nil, err
			}
		}
	}

	client := s.sdkConfiguration.Client

	// NEW CODE:
	for k, v := range o.SetHeaders {
		req.Header.Set(k, v)
	}

	globalRetryConfig := s.sdkConfiguration.RetryConfig
	retryConfig := o.Retries
	if retryConfig == nil {
		if globalRetryConfig != nil {
			retryConfig = globalRetryConfig
		} else {
			retryConfig = &retry.Config{
				Strategy: "backoff", Backoff: &retry.BackoffStrategy{
					InitialInterval: 500,
					MaxInterval:     60000,
					Exponent:        1.5,
					MaxElapsedTime:  3600000,
				},
				RetryConnectionErrors: true,
			}
		}
	}

	httpRes, err := utils.Retry(ctx, utils.Retries{
		Config:      retryConfig,
		StatusCodes: []string{"5XX"},
	}, func() (*http.Response, error) {
		return client.Do(req)
	})
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	if httpRes == nil {
		return nil, fmt.Errorf("error sending request: no response")
	}

	contentType := httpRes.Header.Get("Content-Type")

	res := &operations.TagBasedPolicyBulkNamedNetworkUnApplyResponse{
		StatusCode:  httpRes.StatusCode,
		ContentType: contentType,
		RawResponse: httpRes,
	}

	// No need to read the body here for 202 responses

	if httpRes.StatusCode >= 400 {
		// Try to read the response body for more details
		if httpRes.Body != nil {
			bodyBytes, readErr := io.ReadAll(httpRes.Body)
			if readErr == nil {
				// Reset the body for further processing
				httpRes.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}
		return nil, fmt.Errorf("unexpected response from API. Got an unexpected response code %v", httpRes.StatusCode)
	}

	return res, nil
}
