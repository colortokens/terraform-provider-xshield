package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestEnforcementState(t *testing.T) {
	t.Parallel()
	// The endpoint takes a string; a configuration expresses a boolean.
	if got := enforcementState(types.BoolValue(true)); got == nil || *got != shared.AssetDeploymentStateEnabled {
		t.Errorf("true should send enabled, got %v", got)
	}
	if got := enforcementState(types.BoolValue(false)); got == nil || *got != shared.AssetDeploymentStateDisabled {
		t.Errorf("false should send disabled, got %v", got)
	}
	// An unset attribute must send nothing, so the current state is left alone.
	if got := enforcementState(types.BoolNull()); got != nil {
		t.Errorf("an unset value should send nothing, got %v", got)
	}
	if got := enforcementState(types.BoolUnknown()); got != nil {
		t.Errorf("an unknown value should send nothing, got %v", got)
	}
}

func TestClassifyDeploymentErrorMarksTheRetryableOne(t *testing.T) {
	t.Parallel()
	// Deployments are serialised per tenant and the refusal arrives as a plain
	// 400, so the text is the only signal that waiting will help.
	err := classifyDeploymentError(400, "deployment in progress")
	if !errors.Is(err, errDeploymentInProgress) {
		t.Fatalf("a busy tenant should be retryable, got %v", err)
	}
}

func TestClassifyDeploymentErrorExplainsEachPrecondition(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		status      int
		detail      string
		wantPhrases []string
	}{
		{
			name:   "micro deployment disabled",
			status: 400,
			detail: "micro deployment not allowed on asset(s)",
			// The message has to say both how to avoid it and what to switch on.
			wantPhrases: []string{"individual ports", "mode instead of plan", "microDeploymentEnabled"},
		},
		{
			name:        "no agent",
			status:      400,
			detail:      "one or more matching assets has no agent installed, unable to enforce policies",
			wantPhrases: []string{"no agent installed", "Narrow the criteria"},
		},
		{
			name:        "breach response active",
			status:      400,
			detail:      "deployment cannot be turned off while breach response is active. Please disable it first.",
			wantPhrases: []string{"breach response", "Disable breach response first"},
		},
		{
			name:        "edr managed",
			status:      400,
			detail:      "operation not permitted on EDR-managed asset(s)",
			wantPhrases: []string{"EDR integration"},
		},
		{
			name:        "read only cloud connector",
			status:      400,
			detail:      "deployment blocked - read-only cloud connector detected",
			wantPhrases: []string{"read-only cloud connector"},
		},
		{
			name:        "platform upgrading",
			status:      503,
			detail:      "system upgrade in progress",
			wantPhrases: []string{"upgrading", "Re-run the apply"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := classifyDeploymentError(tc.status, tc.detail)
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, errDeploymentInProgress) {
				t.Fatal("this is a precondition, not something retrying fixes")
			}
			for _, phrase := range tc.wantPhrases {
				if !strings.Contains(err.Error(), phrase) {
					t.Errorf("message is missing %q:\n%v", phrase, err)
				}
			}
		})
	}
}

func TestClassifyDeploymentErrorFallsBackToTheStatus(t *testing.T) {
	t.Parallel()
	err := classifyDeploymentError(500, "something went wrong")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("an unrecognised failure should still report the status: %v", err)
	}
}

func TestRetryWhileDeploymentInProgressGivesUpWithAdvice(t *testing.T) {
	t.Parallel()
	// Keep the test fast: the real delays are only consulted between attempts,
	// so a context that is already cancelled stops after the first one.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := retryWhileDeploymentInProgress(ctx, "deploying policy", func() error {
		calls++
		return errDeploymentInProgress
	})
	if err == nil {
		t.Fatal("expected an error once retries are exhausted or the context ends")
	}
	if calls == 0 {
		t.Error("the operation should have been attempted at least once")
	}
}

func TestRetryWhileDeploymentInProgressPassesOtherErrorsStraightThrough(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("one or more matching assets has no agent installed")
	calls := 0
	err := retryWhileDeploymentInProgress(context.Background(), "deploying policy", func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want the original error", err)
	}
	if calls != 1 {
		t.Errorf("made %d attempts; a precondition failure must not be retried", calls)
	}
}

func TestRetryWhileDeploymentInProgressSucceedsImmediately(t *testing.T) {
	t.Parallel()
	calls := 0
	err := retryWhileDeploymentInProgress(context.Background(), "deploying policy", func() error {
		calls++
		return nil
	})
	if err != nil || calls != 1 {
		t.Errorf("err=%v calls=%d, want one successful attempt", err, calls)
	}
}

func TestIsWholeAssetDeploy(t *testing.T) {
	t.Parallel()
	entry := deploymentPlanEntryModel{Mode: types.StringValue("enforce")}
	all := map[string]deploymentPlanEntryModel{"*": entry}
	named := map[string]deploymentPlanEntryModel{"TCP:443": entry}

	// The backend only skips the micro-deployment requirements when BOTH maps
	// carry the wildcard; one alone still deploys named ports.
	if !isWholeAssetDeploy(all, all) {
		t.Error("both wildcards should be a whole-asset deploy")
	}
	if isWholeAssetDeploy(all, named) {
		t.Error("a named unreviewed port makes it a micro-deployment")
	}
	if isWholeAssetDeploy(named, all) {
		t.Error("a named reviewed port makes it a micro-deployment")
	}
	if isWholeAssetDeploy(nil, nil) {
		t.Error("an empty plan is not a whole-asset deploy")
	}
}

func TestBuildInputExpandsTheWholeAssetShorthand(t *testing.T) {
	t.Parallel()
	r := &PolicyDeploymentResource{}
	input := r.buildInput(&PolicyDeploymentResourceModel{
		Criteria:  types.StringValue("application = 'payroll'"),
		Direction: types.StringValue("inbound"),
		Mode:      types.StringValue("enforce"),
	})

	if input.DeploymentCriteria.Criteria != "application = 'payroll'" {
		t.Errorf("criteria = %q", input.DeploymentCriteria.Criteria)
	}
	// mode has to become both wildcard keys, because that shape is what tells
	// the backend to deploy the whole asset rather than named ports.
	for name, entries := range map[string]map[string]shared.DeploymentConfig{
		"reviewed":   input.DeploymentPlan.Reviewed,
		"unreviewed": input.DeploymentPlan.Unreviewed,
	} {
		entry, ok := entries["*"]
		if !ok {
			t.Fatalf("%s is missing the \"*\" key: %v", name, entries)
		}
		if entry.DeploymentMode != shared.DeploymentModeEnforce {
			t.Errorf("%s mode = %q, want enforce", name, entry.DeploymentMode)
		}
	}
}

func TestBuildInputPassesAPerPortPlanThrough(t *testing.T) {
	t.Parallel()
	r := &PolicyDeploymentResource{}
	input := r.buildInput(&PolicyDeploymentResourceModel{
		Criteria:  types.StringValue("*"),
		Direction: types.StringValue("outbound"),
		Reviewed: map[string]deploymentPlanEntryModel{
			"TCP:443": {Mode: types.StringValue("enforce"), TargetAssets: types.StringValue("affected")},
		},
		Unreviewed: map[string]deploymentPlanEntryModel{
			"*": {Mode: types.StringValue("test")},
		},
	})

	entry, ok := input.DeploymentPlan.Reviewed["TCP:443"]
	if !ok {
		t.Fatalf("reviewed plan = %v", input.DeploymentPlan.Reviewed)
	}
	if entry.DeploymentMode != shared.DeploymentModeEnforce {
		t.Errorf("mode = %q", entry.DeploymentMode)
	}
	if entry.TargetAssets == nil || *entry.TargetAssets != shared.TargetAssetsAffected {
		t.Errorf("target = %v, want affected", entry.TargetAssets)
	}
	if input.DeploymentCriteria.Direction == nil || *input.DeploymentCriteria.Direction != "outbound" {
		t.Errorf("direction = %v", input.DeploymentCriteria.Direction)
	}
}

func TestDeploymentIDIsStableForTheSameTarget(t *testing.T) {
	t.Parallel()
	a := &PolicyDeploymentResourceModel{
		Criteria: types.StringValue("application = 'payroll'"), Direction: types.StringValue("inbound")}
	b := &PolicyDeploymentResourceModel{
		Criteria: types.StringValue("application = 'payroll'"), Direction: types.StringValue("outbound")}

	if deploymentID(a) == deploymentID(b) {
		t.Error("the two directions are separate deployments and must not share an id")
	}

	// Stability means two equal models agree, not that one call equals itself.
	// Comparing deploymentID(a) to deploymentID(a) passes even if the id is
	// derived from the pointer rather than the content.
	sameAsA := &PolicyDeploymentResourceModel{
		Criteria: types.StringValue("application = 'payroll'"), Direction: types.StringValue("inbound")}
	if deploymentID(a) != deploymentID(sameAsA) {
		t.Errorf("the id must depend only on the target: %q vs %q",
			deploymentID(a), deploymentID(sameAsA))
	}
}
