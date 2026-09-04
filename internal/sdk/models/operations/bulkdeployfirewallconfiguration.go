// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type BulkDeployFirewallConfigurationResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// Accepted. Async processing in-progress and can be tracked using value in header 'x-ct-workrequest-id'
	TwoHundredAndTwoApplicationJSONString *string
	// Bad Request
	ErrorResponse *shared.ErrorResponse
	Headers       map[string][]string
}

func (o *BulkDeployFirewallConfigurationResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *BulkDeployFirewallConfigurationResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *BulkDeployFirewallConfigurationResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *BulkDeployFirewallConfigurationResponse) GetTwoHundredAndTwoApplicationJSONString() *string {
	if o == nil {
		return nil
	}
	return o.TwoHundredAndTwoApplicationJSONString
}

func (o *BulkDeployFirewallConfigurationResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}

func (o *BulkDeployFirewallConfigurationResponse) GetHeaders() map[string][]string {
	if o == nil {
		return map[string][]string{}
	}
	return o.Headers
}
