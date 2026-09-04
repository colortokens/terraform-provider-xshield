// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type GetTagBasedPolicyAssetsRequest struct {
	// TagBasedPolicy ID
	TagbasedpolicyID string `pathParam:"style=simple,explode=false,name=tagbasedpolicyId"`
}

func (o *GetTagBasedPolicyAssetsRequest) GetTagbasedpolicyID() string {
	if o == nil {
		return ""
	}
	return o.TagbasedpolicyID
}

type GetTagBasedPolicyAssetsResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// OK
	MembershipList *shared.MembershipList
	// Bad Request
	ErrorResponse *shared.ErrorResponse
}

func (o *GetTagBasedPolicyAssetsResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *GetTagBasedPolicyAssetsResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *GetTagBasedPolicyAssetsResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *GetTagBasedPolicyAssetsResponse) GetMembershipList() *shared.MembershipList {
	if o == nil {
		return nil
	}
	return o.MembershipList
}

func (o *GetTagBasedPolicyAssetsResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}
