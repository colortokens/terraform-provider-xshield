package provider

import (
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// xshieldNamesChangedForTerraform is every place an attribute that mirrors a field of Xshield's API is not that
// field's name in snake case. Xshield and its cloud connector keep their own names, so this is the whole of the
// mapping between the two, and each entry keeps Xshield's word and adds only the noun Terraform's naming asks for.
var xshieldNamesChangedForTerraform = map[string]map[string]string{
	"the snapshot":           {"directory": "directory_entries", "withdrawing": "withdrawing_security_groups"},
	"a notice of the status": {"group": "security_group"},
}

func snakeCase(camel string) string {
	var out strings.Builder
	for i, r := range camel {
		if unicode.IsUpper(r) && i > 0 {
			out.WriteByte('_')
		}
		out.WriteRune(unicode.ToLower(r))
	}
	return out.String()
}

func jsonFieldNames(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumField(); i++ {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func attributeNames[A any](attributes map[string]A) map[string]attr.Type {
	names := map[string]attr.Type{}
	for name := range attributes {
		names[name] = nil
	}
	return names
}

// fieldType is the struct, or the struct a pointer, map or list holds, that the named field of t is declared with.
func fieldType(t reflect.Type, name string) reflect.Type {
	field, ok := t.FieldByName(name)
	if !ok {
		panic(t.String() + " has no field " + name)
	}
	held := field.Type
	for held.Kind() != reflect.Struct {
		held = held.Elem()
	}
	return held
}

// A field Xshield adds to what it publishes takes its own name here, in snake case, unless Terraform's naming rules
// ask for another, and then the difference is written down in one place.
func TestAttributesTakeXshieldsFieldNamesExceptWhereListed(t *testing.T) {
	schemas := dataSourceSchemas(t)
	attributesOf := func(typeName string) map[string]dsschema.Attribute {
		s, ok := schemas[typeName]
		if !ok {
			t.Fatalf("%s is not registered", typeName)
		}
		return s.Schema.Attributes
	}
	snapshot, status, rules := attributesOf("xshield_aws_enforcement_snapshot"), attributesOf("xshield_enforcement_status"),
		attributesOf("xshield_aws_security_group_rules")
	published := fieldType(reflect.TypeOf(wireSnapshot{}), "AWS")

	for _, mirrored := range []struct {
		what      string
		xshield   reflect.Type
		terraform map[string]attr.Type
	}{
		{"the snapshot", published, attributeNames(snapshot)},
		{"a security group of the snapshot", fieldType(published, "SecurityGroups"), objectFields(snapshot["security_groups"].GetType())},
		{"a rule of the snapshot", reflect.TypeOf(wireRule{}), objectFields(snapshot["ingress_rules"].GetType())},
		{"an interface attachment of the snapshot", fieldType(published, "InterfaceAttachments"), objectFields(snapshot["interface_attachments"].GetType())},
		{"a directory entry of the snapshot", fieldType(published, "Directory"), objectFields(snapshot["directory_entries"].GetType())},
		{"an asset of the snapshot", fieldType(published, "Assets"), objectFields(snapshot["assets"].GetType())},
		{"a notice of the status", reflect.TypeOf(wireNotice{}), objectFields(status["notices"].GetType())},
		{"a drift finding of the status", fieldType(reflect.TypeOf(wireDrift{}), "Findings"), objectFields(status["drift_findings"].GetType())},
		{"a rule a change moves", reflect.TypeOf(wireRuleMatch{}), objectFields(rules["undeclared_pending_rules"].GetType())},
	} {
		changed := xshieldNamesChangedForTerraform[mirrored.what]
		used := map[string]bool{}
		for _, field := range jsonFieldNames(mirrored.xshield) {
			want := snakeCase(field)
			if other, listed := changed[field]; listed {
				want, used[field] = other, true
				if _, plain := mirrored.terraform[snakeCase(field)]; plain {
					t.Errorf("%s: `%s` is listed as renamed to `%s`, yet `%s` exists too", mirrored.what, field, other, snakeCase(field))
				}
			}
			if _, ok := mirrored.terraform[want]; !ok {
				t.Errorf("%s: Xshield's `%s` should be the attribute `%s`, which does not exist; name it so, or list the difference in xshieldNamesChangedForTerraform",
					mirrored.what, field, want)
			}
		}
		for field := range changed {
			if !used[field] {
				t.Errorf("%s: `%s` is listed in xshieldNamesChangedForTerraform and Xshield publishes no such field", mirrored.what, field)
			}
		}
	}
}
