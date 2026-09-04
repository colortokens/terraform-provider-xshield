// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type GetWorkRequestRequest struct {
	// Work ID
	WorkID string `pathParam:"style=simple,explode=false,name=workId"`
}

func (o *GetWorkRequestRequest) GetWorkID() string {
	if o == nil {
		return ""
	}
	return o.WorkID
}

type GetWorkRequestResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// OK
	WorkrequestWorkRequest *shared.WorkrequestWorkRequest
	// Bad Request
	ErrorResponse *shared.ErrorResponse
}

func (o *GetWorkRequestResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *GetWorkRequestResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *GetWorkRequestResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *GetWorkRequestResponse) GetWorkrequestWorkRequest() *shared.WorkrequestWorkRequest {
	if o == nil {
		return nil
	}
	return o.WorkrequestWorkRequest
}

func (o *GetWorkRequestResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}
