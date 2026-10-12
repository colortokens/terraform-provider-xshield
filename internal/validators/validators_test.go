package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func runStringValidator(v validator.String, value types.String) validator.StringResponse {
	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		ConfigValue:    value,
	}
	resp := validator.StringResponse{}
	v.ValidateString(context.Background(), req, &resp)

	return resp
}

func testStringValidator(t *testing.T, v validator.String, cases map[string]struct {
	value     types.String
	wantError bool
}) {
	t.Helper()

	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}

	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			resp := runStringValidator(v, test.value)

			if got := resp.Diagnostics.HasError(); got != test.wantError {
				t.Fatalf("HasError() = %t, want %t (diagnostics: %s)", got, test.wantError, resp.Diagnostics)
			}
		})
	}
}

func TestJSONParseValidator(t *testing.T) {
	t.Parallel()

	testStringValidator(t, IsValidJSON(), map[string]struct {
		value     types.String
		wantError bool
	}{
		"null is skipped":      {value: types.StringNull()},
		"unknown is skipped":   {value: types.StringUnknown()},
		"object":               {value: types.StringValue(`{"a":1}`)},
		"array":                {value: types.StringValue(`[1,2,3]`)},
		"bare string":          {value: types.StringValue(`"a"`)},
		"empty string":         {value: types.StringValue(""), wantError: true},
		"trailing comma":       {value: types.StringValue(`{"a":1,}`), wantError: true},
		"unquoted identifier":  {value: types.StringValue(`{a:1}`), wantError: true},
		"truncated object":     {value: types.StringValue(`{"a":`), wantError: true},
		"single quoted string": {value: types.StringValue(`'a'`), wantError: true},
	})
}

func TestRFC3339TimeValidator(t *testing.T) {
	t.Parallel()

	testStringValidator(t, IsRFC3339(), map[string]struct {
		value     types.String
		wantError bool
	}{
		"null is skipped":    {value: types.StringNull()},
		"unknown is skipped": {value: types.StringUnknown()},
		"utc":                {value: types.StringValue("2026-08-10T12:30:00Z")},
		"offset":             {value: types.StringValue("2026-08-10T12:30:00+05:30")},
		"nanoseconds":        {value: types.StringValue("2026-08-10T12:30:00.123456789Z")},
		"date only":          {value: types.StringValue("2026-08-10"), wantError: true},
		"no timezone":        {value: types.StringValue("2026-08-10T12:30:00"), wantError: true},
		"space separator":    {value: types.StringValue("2026-08-10 12:30:00Z"), wantError: true},
		"empty string":       {value: types.StringValue(""), wantError: true},
		"not a time":         {value: types.StringValue("yesterday"), wantError: true},
	})
}

func TestDateValidator(t *testing.T) {
	t.Parallel()

	testStringValidator(t, IsValidDate(), map[string]struct {
		value     types.String
		wantError bool
	}{
		"null is skipped":    {value: types.StringNull()},
		"unknown is skipped": {value: types.StringUnknown()},
		"date":               {value: types.StringValue("2026-08-10")},
		"leap day":           {value: types.StringValue("2024-02-29")},
		"non leap day":       {value: types.StringValue("2025-02-29"), wantError: true},
		"month out of range": {value: types.StringValue("2026-13-01"), wantError: true},
		"rfc3339 timestamp":  {value: types.StringValue("2026-08-10T12:30:00Z"), wantError: true},
		"slash separators":   {value: types.StringValue("2026/08/10"), wantError: true},
		"empty string":       {value: types.StringValue(""), wantError: true},
	})
}

func TestExactlyOneChild(t *testing.T) {
	t.Parallel()

	attributeTypes := map[string]attr.Type{
		"a": types.StringType,
		"b": types.StringType,
	}

	object := func(a, b attr.Value) types.Object {
		return types.ObjectValueMust(attributeTypes, map[string]attr.Value{"a": a, "b": b})
	}

	tests := map[string]struct {
		value     types.Object
		wantError bool
	}{
		"null is skipped":    {value: types.ObjectNull(attributeTypes)},
		"unknown is skipped": {value: types.ObjectUnknown(attributeTypes)},
		"only a": {
			value: object(types.StringValue("set"), types.StringNull()),
		},
		"only b": {
			value: object(types.StringNull(), types.StringValue("set")),
		},
		"unknown sibling counts as unset": {
			value: object(types.StringValue("set"), types.StringUnknown()),
		},
		"both set": {
			value:     object(types.StringValue("set"), types.StringValue("also set")),
			wantError: true,
		},
		"none set": {
			value:     object(types.StringNull(), types.StringNull()),
			wantError: true,
		},
		"empty string still counts as set": {
			value:     object(types.StringValue(""), types.StringValue("")),
			wantError: true,
		},
	}

	v := ExactlyOneChild()

	if v.Description(context.Background()) == "" {
		t.Error("Description is empty")
	}

	if v.MarkdownDescription(context.Background()) == "" {
		t.Error("MarkdownDescription is empty")
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := validator.ObjectRequest{
				Path:           path.Root("test"),
				PathExpression: path.MatchRoot("test"),
				ConfigValue:    test.value,
			}
			resp := validator.ObjectResponse{}
			v.ValidateObject(context.Background(), req, &resp)

			if got := resp.Diagnostics.HasError(); got != test.wantError {
				t.Fatalf("HasError() = %t, want %t (diagnostics: %s)", got, test.wantError, resp.Diagnostics)
			}
		})
	}
}
