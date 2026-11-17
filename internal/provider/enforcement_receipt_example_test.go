package provider

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// Xshield refuses a receipt that leaves out a resource the snapshot asks for, so a receipt written from the registry
// example must set every map of resource IDs the schema has.
func TestTheReceiptExampleSetsEveryMapOfResourceIDs(t *testing.T) {
	t.Parallel()
	example, err := os.ReadFile("../../examples/resources/xshield_enforcement_receipt/resource.tf")
	if err != nil {
		t.Fatal(err)
	}
	for name, attribute := range receiptSchema(context.Background()).Attributes {
		if _, isMap := attribute.(schema.MapAttribute); !isMap {
			continue
		}
		if !regexp.MustCompile(`(?m)^\s*` + name + `\s*=`).Match(example) {
			t.Errorf("the receipt example does not set %s", name)
		}
	}
}
