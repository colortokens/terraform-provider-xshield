package provider

import (
	"net/http"
	"strings"
	"testing"
)

const handedOverRefusal = `{"status":409,"code":"handedOver","message":"Xshield handed this account and region to the cloud connector, ` +
	`which keeps the groups, rules and attachments your pipeline created: replace the enforcement module with removed blocks ` +
	`that keep them (lifecycle { destroy = false }), and stop running it"}`

// Once the account is handed back to its connector, Xshield refuses every receipt for it, so sending one again can never
// succeed and applying again would change groups the connector now keeps.
func TestAReceiptRefusedAsHandedOverSaysToStopApplying(t *testing.T) {
	t.Parallel()
	_, refusal := sendReceipt(t, http.StatusConflict, handedOverRefusal, receiptWithRules(t, 3))
	for _, want := range []string{"handed back to the cloud connector", "no longer delivers", "stop applying it",
		"enforcement-snapshot/leave", "stop running this workspace"} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the error does not say %q:\n%s", want, refusal)
		}
	}
	if strings.Contains(refusal, "apply again") {
		t.Errorf("the error says to apply again, which Xshield refuses the same way:\n%s", refusal)
	}
}

// A conflict without the handedOver code, such as from a proxy or a platform that refuses for another reason, says
// nothing of a hand-over the platform never made: telling the team to stop applying would leave the account unenforced.
func TestAConflictThatIsNotAHandOverGetsTheGenericAdvice(t *testing.T) {
	t.Parallel()
	for name, answer := range map[string]string{
		"without a code":      `{"message":"conflict"}`,
		"with another code":   `{"status":409,"code":"versionSuperseded","message":"conflict"}`,
		"from a proxy (HTML)": `<html><body>409 Conflict</body></html>`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, refusal := sendReceipt(t, http.StatusConflict, answer, receiptWithRules(t, 3))
			for _, notSaid := range []string{"handed back", "stop applying", "enforcement-snapshot/leave"} {
				if strings.Contains(refusal, notSaid) {
					t.Errorf("the error says %q of a conflict that is not a hand-over:\n%s", notSaid, refusal)
				}
			}
			if !strings.Contains(refusal, "run apply again to send the receipt") {
				t.Errorf("the error does not give the generic advice:\n%s", refusal)
			}
		})
	}
}
