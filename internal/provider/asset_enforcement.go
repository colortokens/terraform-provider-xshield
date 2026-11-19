package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// errAwsProtectionLevelChanged is the asset switch's LEVEL_CHANGED refusal: the
// tenant's AWS protection level changed while the request ran, nothing was
// written, and the platform asks for the same request to be sent again.
var errAwsProtectionLevelChanged = errors.New("the AWS protection level changed while the request ran")

func isRetryableDeploymentError(err error) bool {
	return errors.Is(err, errDeploymentInProgress) || errors.Is(err, errAwsProtectionLevelChanged)
}

// retryWhileDeploymentInProgress runs an API call, waiting and retrying while
// the tenant is busy with another deployment or its AWS protection level
// changed under the request.
func retryWhileDeploymentInProgress(ctx context.Context, what string, call func() error) error {
	err := call()
	for attempt, delay := range deploymentRetryDelays {
		if !isRetryableDeploymentError(err) {
			return err
		}
		tflog.Info(ctx, "the platform asked for the request to be sent again; waiting before retrying", map[string]any{
			"operation": what,
			"reason":    err.Error(),
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
	switch {
	case errors.Is(err, errDeploymentInProgress):
		return fmt.Errorf(
			"%s: another deployment for this tenant was still running after %d attempts. "+
				"Deployments are serialised per tenant, so re-run the apply once it finishes",
			what, len(deploymentRetryDelays)+1)
	case errors.Is(err, errAwsProtectionLevelChanged):
		return fmt.Errorf(
			"%s: the tenant's AWS protection level was still changing after %d attempts; nothing was written. "+
				"Re-run the apply once the level change in Xshield has finished",
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

// AWS refusals of the asset switch, answered as 409 with the code in details.code.
const (
	awsRefusalLevelChanged     = "LEVEL_CHANGED"
	awsRefusalPartialUndeploy  = "PARTIAL_UNDEPLOY"
	awsRefusalUndeployTooLarge = "UNDEPLOY_TOO_LARGE"
	awsRefusalNoConnector      = "NO_CONNECTOR"
	awsRefusalAcknowledgement  = "ACKNOWLEDGEMENT_REQUIRED"
)

func deploymentRefusalCode(errResp *shared.ErrorResponse) string {
	if errResp == nil {
		return ""
	}
	code, _ := errResp.Details["code"].(string)
	return code
}

// classifyAssetSwitchError classifies a refusal of the asset switch, which this
// resource sends for one asset per request. The platform's own refusal text is
// kept because it names the assets, ports and customer groups involved.
func classifyAssetSwitchError(status int, errResp *shared.ErrorResponse, raw *http.Response, input shared.AssetStateTransitionInput) error {
	detail := apiErrorDetail(errResp, raw)
	if errResp != nil && errResp.Message != nil {
		detail = *errResp.Message
	}
	switch deploymentRefusalCode(errResp) {
	case awsRefusalLevelChanged:
		return fmt.Errorf("%w: %s", errAwsProtectionLevelChanged, detail)
	case awsRefusalPartialUndeploy:
		return fmt.Errorf(
			"switching enforcement off for this asset would leave customer security group rules narrowed for other "+
				"assets, or for a direction this same change switches on, and the platform cannot plan that change again. "+
				"This resource switches one asset per request, so it cannot switch the other assets named below off with it. "+
				"If the refusal names only this asset, switch the direction being turned off on its own first: change only that "+
				"enforcement attribute, apply, then change the other. If it names other assets, use Rollback on them in Xshield, "+
				"which puts the customer group rules back for every asset of the groups, then apply again. (%s)", detail)
	case awsRefusalUndeployTooLarge:
		return fmt.Errorf(
			"switching enforcement off for this asset releases customer group rules that more assets rely on than one "+
				"request may change. Use Rollback on those assets in Xshield, which puts the rules back for every asset of the "+
				"groups, then apply again. (%s)", detail)
	case awsRefusalNoConnector:
		return fmt.Errorf(
			"%s, and the AWS account has no active AWS connector to send that change to; nothing was written. "+
				"Restore the account's AWS connector in Xshield so it is active, then apply again. (%s)", noConnectorNeed(input), detail)
	case awsRefusalAcknowledgement:
		return fmt.Errorf(
			"switching enforcement on for this asset takes moved customer group rules from resources no Xshield group can be "+
				"attached to, named below, and the change must acknowledge that first; nothing was written. The acknowledgedGroupIds "+
				"field the message names is not an attribute of this resource: switch the same enforcement on for this asset in "+
				"Xshield, acknowledging the customer groups named below, then apply again, which finds the asset already enforced. (%s)", detail)
	default:
		return classifyDeploymentError(status, detail)
	}
}

// noConnectorNeed is what the switch needs the AWS connector for, by the directions it turns: turning one on replaces an earlier
// Full control change of the asset's customer groups, which is reverted first, and turning one off puts the moved rules back.
func noConnectorNeed(input shared.AssetStateTransitionInput) string {
	var needs []string
	if turnsEnforcement(input, shared.AssetDeploymentStateEnabled) {
		needs = append(needs, "switching enforcement on replaces an earlier Full control change of the asset's customer groups, "+
			"which has to be reverted first")
	}
	if turnsEnforcement(input, shared.AssetDeploymentStateDisabled) {
		needs = append(needs, "switching enforcement off needs the moved customer group rules put back")
	}
	return strings.Join(needs, "; ")
}

func turnsEnforcement(input shared.AssetStateTransitionInput, to shared.AssetDeploymentState) bool {
	return input.InboundToDeploymentState != nil && *input.InboundToDeploymentState == to ||
		input.OutboundToDeploymentState != nil && *input.OutboundToDeploymentState == to
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
			return classifyAssetSwitchError(res.StatusCode, res.ErrorResponse, res.RawResponse, input)
		}
	})
	if err != nil {
		diags.AddError("Cannot change asset enforcement", err.Error())
	}
}
