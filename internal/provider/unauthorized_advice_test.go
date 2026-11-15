package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const gatewayRefusal = `{"message":"invalid signature"}`

var unauthorizedCauses = []string{"Settings > API Keys", "tenancy_id, user_id and fingerprint", "clock", "10 seconds"}

func receiptWithRules(t *testing.T, n int) enforcementReceiptResourceModel {
	t.Helper()
	rules := map[string]string{}
	for i := range n {
		rules[fmt.Sprintf("i-app-%03d/in/tcp/443/10.20.%d.%d/32", i, i/250, i%250)] = fmt.Sprintf("sgr-%017d", i)
	}
	ruleIDs, diags := types.MapValueFrom(context.Background(), types.StringType, rules)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return enforcementReceiptResourceModel{Cloud: types.StringValue(cloudAWS), CloudAccountID: types.StringValue("123456789012"),
		Region: types.StringValue("us-east-1"), Workspace: types.StringValue("ws"), SnapshotVersion: types.StringValue(testVersion),
		SecurityGroups: types.MapNull(types.StringType), Rules: ruleIDs, Attachments: types.MapNull(types.StringType)}
}

func sendReceipt(t *testing.T, receipt enforcementReceiptResourceModel) (sentBytes int, refusal string) {
	t.Helper()
	api, recorder, _ := newSnapshotTestAPI(t, http.StatusUnauthorized, gatewayRefusal)
	var diags diag.Diagnostics
	(&enforcementReceiptResource{api: api}).send(context.Background(), &receipt, &diags)
	if !diags.HasError() || len(recorder.requests) != 1 {
		t.Fatalf("want one refused request, got %d request(s) and %v", len(recorder.requests), diags)
	}
	return len(recorder.requests[0].body), diags.Errors()[0].Detail()
}

// Xshield's gateway answers 401 "invalid signature" for an inactive key, a clock running behind and, until it reads
// buffered bodies, a body over its buffer, so "run apply again" alone sends a refused request again unchanged.
func TestAnUnauthorizedAnswerNamesWhatTheGatewayChecks(t *testing.T) {
	t.Parallel()

	t.Run("a read", func(t *testing.T) {
		t.Parallel()
		api, _ := newRoutedSnapshotAPI(t, map[string]cannedResponse{"/expected": {http.StatusUnauthorized, gatewayRefusal}})
		var m awsEnforcementSnapshotDataSourceModel
		ok, errs := readDataSource(t, &awsEnforcementSnapshotDataSource{api: api}, pointArgs(), &m)
		if ok {
			t.Fatal("a refused read planned")
		}
		for _, want := range unauthorizedCauses {
			if !strings.Contains(errs, want) {
				t.Errorf("the error does not mention %q:\n%s", want, errs)
			}
		}
		if strings.Contains(errs, "KB") {
			t.Errorf("a request without a body is blamed on its size:\n%s", errs)
		}
	})

	t.Run("a small receipt", func(t *testing.T) {
		t.Parallel()
		sent, refusal := sendReceipt(t, receiptWithRules(t, 3))
		if sent > 8<<10 {
			t.Fatalf("the receipt is %d bytes, want one under 8 KB", sent)
		}
		for _, want := range append(unauthorizedCauses, "run apply again") {
			if !strings.Contains(refusal, want) {
				t.Errorf("the error does not mention %q:\n%s", want, refusal)
			}
		}
		if strings.Contains(refusal, "KB") {
			t.Errorf("a receipt under 8 KB is blamed on its size:\n%s", refusal)
		}
	})

	t.Run("a receipt over 8 KB", func(t *testing.T) {
		t.Parallel()
		sent, refusal := sendReceipt(t, receiptWithRules(t, 200))
		if sent <= 8<<10 {
			t.Fatalf("the receipt is %d bytes, want one over 8 KB", sent)
		}
		for _, want := range append(unauthorizedCauses, fmt.Sprintf("%d KB", (sent+1023)/1024), "over about 8 KB", "fails the same way") {
			if !strings.Contains(refusal, want) {
				t.Errorf("the error does not mention %q:\n%s", want, refusal)
			}
		}
	})
}
