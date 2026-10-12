package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// The asset service rejects a deployment while another is running for the same
// tenant, and answers 400 rather than 409 or 429. Retrying is the intended
// response, so the text has to be matched.
const deploymentInProgressMessage = "deployment in progress"

// errDeploymentInProgress marks a response worth retrying.
var errDeploymentInProgress = errors.New(deploymentInProgressMessage)

// deploymentRetryDelays paces retries around another tenant deployment. The
// total wait is a little over a minute, which covers a normal deployment
// without holding an apply open indefinitely.
var deploymentRetryDelays = []time.Duration{
	2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second,
}

// retryWhileDeploymentInProgress runs an API call, waiting and retrying while
// the tenant is busy with another deployment.
func retryWhileDeploymentInProgress(ctx context.Context, what string, call func() error) error {
	err := call()
	for attempt, delay := range deploymentRetryDelays {
		if !errors.Is(err, errDeploymentInProgress) {
			return err
		}
		tflog.Info(ctx, "another deployment is running; waiting before retrying", map[string]any{
			"operation": what,
			"attempt":   attempt + 1,
			"delay":     delay.String(),
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		err = call()
	}
	if errors.Is(err, errDeploymentInProgress) {
		return fmt.Errorf(
			"%s: another deployment for this tenant was still running after %d attempts. "+
				"Deployments are serialised per tenant, so re-run the apply once it finishes",
			what, len(deploymentRetryDelays)+1)
	}
	return err
}

// classifyDeploymentError turns a rejection into something a practitioner can
// act on. Every one of these arrives as a plain 400 with the reason in the
// message, so an unclassified error reads as a bad request rather than a
// precondition that has to be met first.
func classifyDeploymentError(status int, detail string) error {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, deploymentInProgressMessage):
		return errDeploymentInProgress
	case strings.Contains(lower, "micro deployment not allowed"):
		return fmt.Errorf(
			"this plan deploys individual ports, which the tenant does not allow. "+
				"Either deploy the whole asset by setting mode instead of plan, or enable micro-deployment "+
				"for the tenant, which is the microDeploymentEnabled integration setting. (%s)", detail)
	case strings.Contains(lower, "no agent installed"):
		return fmt.Errorf(
			"one or more matching assets has no agent installed, so policy cannot be enforced on them. "+
				"Narrow the criteria to assets with an agent. (%s)", detail)
	case strings.Contains(lower, "breach response is active"):
		return fmt.Errorf(
			"enforcement cannot be turned off while breach response is active on the asset. "+
				"Disable breach response first. (%s)", detail)
	case strings.Contains(lower, "edr-managed"):
		return fmt.Errorf(
			"the asset is managed by an EDR integration, which owns its enforcement state. (%s)", detail)
	case strings.Contains(lower, "read-only cloud connector"):
		return fmt.Errorf(
			"the asset belongs to a read-only cloud connector, which cannot receive policy. (%s)", detail)
	case status == 503:
		return fmt.Errorf(
			"the platform is upgrading and is not accepting deployments. Re-run the apply afterwards. (%s)", detail)
	default:
		return fmt.Errorf("the API answered %d: %s", status, detail)
	}
}

// enforcementState converts the boolean a configuration expresses into the
// string the zero-trust endpoint takes.
func enforcementState(v types.Bool) *shared.AssetDeploymentState {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	if v.ValueBool() {
		return shared.AssetDeploymentStateEnabled.ToPointer()
	}
	return shared.AssetDeploymentStateDisabled.ToPointer()
}

// applyAssetEnforcement sends the enforcement change for one asset, if either
// direction actually changed.
//
// The endpoint answers 304 when the asset is already in the requested state,
// which is success rather than a problem to report.
func applyAssetEnforcement(
	ctx context.Context,
	client *sdk.Xshield,
	assetID string,
	plan, state *AssetResourceModel,
	diags *diag.Diagnostics,
) {
	input := shared.AssetStateTransitionInput{}
	if !plan.InboundEnforcement.Equal(state.InboundEnforcement) {
		input.InboundToDeploymentState = enforcementState(plan.InboundEnforcement)
	}
	if !plan.OutboundEnforcement.Equal(state.OutboundEnforcement) {
		input.OutboundToDeploymentState = enforcementState(plan.OutboundEnforcement)
	}
	if input.InboundToDeploymentState == nil && input.OutboundToDeploymentState == nil {
		return
	}

	err := retryWhileDeploymentInProgress(ctx, "changing asset enforcement", func() error {
		res, err := client.Assets.ConfigureZeroTrust(ctx, operations.ConfigureZeroTrustRequest{
			AssetID:                   assetID,
			AssetStateTransitionInput: input,
		})
		if err != nil {
			return err
		}
		switch res.StatusCode {
		case 202, 304:
			// 202 accepted the change; 304 means it was already in this state.
			return nil
		default:
			return classifyDeploymentError(res.StatusCode, apiErrorDetail(res.ErrorResponse, res.RawResponse))
		}
	})
	if err != nil {
		diags.AddError("Cannot change asset enforcement", err.Error())
	}
}
