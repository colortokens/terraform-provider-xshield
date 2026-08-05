package objectvalidators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.Object = atLeastOneOfValidator{}

// atLeastOneOfValidator ensures that when an object is non-null, at least one
// of the listed child attributes is also non-null.
type atLeastOneOfValidator struct {
	attrNames []string
}

func (v atLeastOneOfValidator) Description(_ context.Context) string {
	return fmt.Sprintf("at least one of %s must be configured", strings.Join(v.attrNames, ", "))
}

func (v atLeastOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v atLeastOneOfValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	attrs := req.ConfigValue.Attributes()
	for _, name := range v.attrNames {
		val, ok := attrs[name]
		if ok && !val.IsNull() {
			return
		}
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Missing Required Attribute",
		fmt.Sprintf("at least one of %s must be configured in %s", strings.Join(v.attrNames, ", "), req.Path),
	)
}

// AtLeastOneOf returns a validator that ensures at least one of the given
// child attributes is non-null whenever the containing object is non-null.
func AtLeastOneOf(attrNames ...string) validator.Object {
	return atLeastOneOfValidator{attrNames: attrNames}
}
