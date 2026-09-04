// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type ListAssetsForPortRequest struct {
	// If true, retrieves only assets with unreviewed ports; otherwise, retrieves all matching assets.
	UnreviewedPort *bool `queryParam:"style=form,explode=true,name=unreviewedPort"`
	// Criteria for filtering assets, such as port number, protocol, asset group, or status.
	AssetsSearchInput shared.AssetsSearchInput `request:"mediaType=application/json"`
}

func (o *ListAssetsForPortRequest) GetUnreviewedPort() *bool {
	if o == nil {
		return nil
	}
	return o.UnreviewedPort
}

func (o *ListAssetsForPortRequest) GetAssetsSearchInput() shared.AssetsSearchInput {
	if o == nil {
		return shared.AssetsSearchInput{}
	}
	return o.AssetsSearchInput
}

type ListAssetsForPortResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// A list of assets affected by the specified port.
	AssetList *shared.AssetList
	// Bad Request
	ErrorResponse *shared.ErrorResponse
}

func (o *ListAssetsForPortResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *ListAssetsForPortResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *ListAssetsForPortResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *ListAssetsForPortResponse) GetAssetList() *shared.AssetList {
	if o == nil {
		return nil
	}
	return o.AssetList
}

func (o *ListAssetsForPortResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}
