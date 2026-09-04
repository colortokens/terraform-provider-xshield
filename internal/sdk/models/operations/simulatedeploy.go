// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package operations

import (
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"net/http"
)

type SimulateDeployRequest struct {
	// Asset ID
	AssetID string `pathParam:"style=simple,explode=false,name=assetId"`
	// the deployment to preview, in the same shape the real deploy takes
	PortDeploymentInput shared.PortDeploymentInput `request:"mediaType=application/json"`
}

func (o *SimulateDeployRequest) GetAssetID() string {
	if o == nil {
		return ""
	}
	return o.AssetID
}

func (o *SimulateDeployRequest) GetPortDeploymentInput() shared.PortDeploymentInput {
	if o == nil {
		return shared.PortDeploymentInput{}
	}
	return o.PortDeploymentInput
}

type SimulateDeployResponse struct {
	// HTTP response content type for this operation
	ContentType string
	// HTTP response status code for this operation
	StatusCode int
	// Raw HTTP response; suitable for custom response parsing
	RawResponse *http.Response
	// The firewall rules before and after the deployment
	FirewallSimulation *shared.FirewallSimulation
	// Bad Request
	ErrorResponse *shared.ErrorResponse
}

func (o *SimulateDeployResponse) GetContentType() string {
	if o == nil {
		return ""
	}
	return o.ContentType
}

func (o *SimulateDeployResponse) GetStatusCode() int {
	if o == nil {
		return 0
	}
	return o.StatusCode
}

func (o *SimulateDeployResponse) GetRawResponse() *http.Response {
	if o == nil {
		return nil
	}
	return o.RawResponse
}

func (o *SimulateDeployResponse) GetFirewallSimulation() *shared.FirewallSimulation {
	if o == nil {
		return nil
	}
	return o.FirewallSimulation
}

func (o *SimulateDeployResponse) GetErrorResponse() *shared.ErrorResponse {
	if o == nil {
		return nil
	}
	return o.ErrorResponse
}
