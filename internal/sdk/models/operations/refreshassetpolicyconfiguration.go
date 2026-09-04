// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type RefreshAssetPolicyConfigurationRequest struct {
	// Tag ID
	TagbasedpolicyID string `pathParam:"style=simple,explode=false,name=tagbasedpolicyId"`
}

func (o *RefreshAssetPolicyConfigurationRequest) GetTagbasedpolicyID() string {
	if o == nil {
		return ""
	}
	return o.TagbasedpolicyID
}

type RefreshAssetPolicyConfigurationResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// Bad Request
	ErrorResponse *shared.ErrorResponse
	Headers       map[string][]string
}

func (o *RefreshAssetPolicyConfigurationResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *RefreshAssetPolicyConfigurationResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *RefreshAssetPolicyConfigurationResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *RefreshAssetPolicyConfigurationResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}

func (o *RefreshAssetPolicyConfigurationResponse) GetHeaders() map[string][]string {
	if o == nil {
		return map[string][]string{}
	}
	return o.Headers
}
