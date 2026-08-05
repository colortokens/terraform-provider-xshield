package objectvalidators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.Object = requiredAttributesValidator{}

// requiredAttributesValidator ensures that when an object is non-null, the
// listed child attributes are also non-null. This is the workaround for the
// framework's prohibition of Required+Computed on the same attribute: the
// parent NestedObject stays Optional+Computed while business-critical children
// are enforced here.
type requiredAttributesValidator struct {
	attrNames []string
}

func (v requiredAttributesValidator) Description(_ context.Context) string {
	return fmt.Sprintf("attributes %s must be configured", strings.Join(v.attrNames, ", "))
}

func (v requiredAttributesValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v requiredAttributesValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	attrs := req.ConfigValue.Attributes()
	for _, name := range v.attrNames {
		val, ok := attrs[name]
		if !ok || val.IsNull() {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Missing Required Attribute",
				fmt.Sprintf("%q must be configured in %s", name, req.Path),
			)
		}
	}
}

// RequiredAttributes returns a validator that ensures the given child
// attributes are non-null whenever the containing object is non-null. Compose
// with NotNull() on the same NestedObject to also reject null objects.
func RequiredAttributes(attrNames ...string) validator.Object {
	return requiredAttributesValidator{attrNames: attrNames}
}
