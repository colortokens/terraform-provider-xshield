package provider

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// Xshield answers an Azure route with this code when the API key's tenant has no cloud connector for the subscription.
const codeAccountUnknown = "accountUnknown"

func isAzureAccountUnknown(err error) bool {
	return isAPIRefusal(err, http.StatusNotFound, codeAccountUnknown)
}

func addAzureAccountUnknownError(diags *diag.Diagnostics, subscription string, err error) {
	diags.AddError("Xshield does not know subscription "+subscription,
		fmt.Sprintf("Xshield does not know subscription %s for this API key's tenant: check the endpoint and API key.\n\n%s", subscription, err))
}
