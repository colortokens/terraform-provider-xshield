package provider

import (
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type schemaAttribute interface {
	GetType() attr.Type
	GetDescription() string
	GetMarkdownDescription() string
	IsComputed() bool
}

type attributeAt struct {
	typeName  string
	path      string
	attribute schemaAttribute
	nested    bool
}

func (a attributeAt) description() string {
	return a.attribute.GetMarkdownDescription() + a.attribute.GetDescription()
}

func dataSourceAttributes(typeName, prefix string, attributes map[string]dsschema.Attribute) []attributeAt {
	var found []attributeAt
	for name, a := range attributes {
		path := prefix + "." + name
		var inner map[string]dsschema.Attribute
		switch n := a.(type) {
		case dsschema.ListNestedAttribute:
			inner = n.NestedObject.Attributes
		case dsschema.MapNestedAttribute:
			inner = n.NestedObject.Attributes
		case dsschema.SetNestedAttribute:
			inner = n.NestedObject.Attributes
		case dsschema.SingleNestedAttribute:
			inner = n.Attributes
		}
		found = append(found, attributeAt{typeName, path, a, inner != nil})
		found = append(found, dataSourceAttributes(typeName, path, inner)...)
	}
	return found
}

func resourceAttributes(typeName, prefix string, attributes map[string]rschema.Attribute) []attributeAt {
	var found []attributeAt
	for name, a := range attributes {
		path := prefix + "." + name
		var inner map[string]rschema.Attribute
		switch n := a.(type) {
		case rschema.ListNestedAttribute:
			inner = n.NestedObject.Attributes
		case rschema.MapNestedAttribute:
			inner = n.NestedObject.Attributes
		case rschema.SetNestedAttribute:
			inner = n.NestedObject.Attributes
		case rschema.SingleNestedAttribute:
			inner = n.Attributes
		}
		found = append(found, attributeAt{typeName, path, a, inner != nil})
		found = append(found, resourceAttributes(typeName, path, inner)...)
	}
	return found
}

// everyAttribute walks each registered type's schema, nested attributes included. A data source's type name
// carries the data. prefix a configuration addresses it by.
func everyAttribute(t *testing.T) []attributeAt {
	t.Helper()
	var found []attributeAt
	for typeName, s := range dataSourceSchemas(t) {
		found = append(found, dataSourceAttributes("data."+typeName, "data."+typeName, s.Schema.Attributes)...)
	}
	for typeName, s := range resourceSchemas(t) {
		found = append(found, resourceAttributes(typeName, typeName, s.Schema.Attributes)...)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	return found
}

// objectFields is the fields of the objects a plain attribute holds, or nil when it holds none.
func objectFields(t attr.Type) map[string]attr.Type {
	element := t
	switch collection := t.(type) {
	case types.ListType:
		element = collection.ElemType
	case types.MapType:
		element = collection.ElemType
	case types.SetType:
		element = collection.ElemType
	}
	object, ok := element.(types.ObjectType)
	if !ok {
		return nil
	}
	return object.AttrTypes
}

// undescribedWhenTheRuleCame counts, per type released before the rule, the attributes that have no description
// yet. A type not listed has none. A count here only goes down.
var undescribedWhenTheRuleCame = map[string]int{
	"data.xshield_asset":          222,
	"data.xshield_assets":         3,
	"data.xshield_named_networks": 10,
	"data.xshield_open_ports":     5,
	"data.xshield_paths":          12,
	"data.xshield_policy_changes": 6,
	"data.xshield_segment":        3,
	"data.xshield_segments":       7,
	"data.xshield_tag_rules":      4,
	"data.xshield_template":       3,
	"data.xshield_templates":      7,
	"data.xshield_work_request":   2,
	"xshield_asset":               5,
	"xshield_template":            2,
}

// The registry page, `terraform providers schema -json` and an editor's hover all show an attribute's own description.
func TestEveryAttributeIsDescribed(t *testing.T) {
	undescribed := map[string][]string{}
	for _, a := range everyAttribute(t) {
		if a.description() == "" {
			undescribed[a.typeName] = append(undescribed[a.typeName], a.path)
		}
	}
	for typeName, paths := range undescribed {
		allowed, known := undescribedWhenTheRuleCame[typeName]
		if !known {
			t.Errorf("%s: %d attributes have no description: %s", typeName, len(paths), strings.Join(paths, ", "))
		} else if len(paths) > allowed {
			t.Errorf("%s: %d attributes have no description, up from %d; describe the new ones", typeName, len(paths), allowed)
		}
	}
	for typeName, allowed := range undescribedWhenTheRuleCame {
		if len(undescribed[typeName]) < allowed {
			t.Errorf("%s: %d attributes have no description, down from %d; lower its count in undescribedWhenTheRuleCame",
				typeName, len(undescribed[typeName]), allowed)
		}
	}
}

// The fields of an object in a plain collection attribute cannot carry a description of their own, so the
// attribute's description is the only place a reader learns of them.
func TestAnObjectsFieldsAreNamedInItsAttributesDescription(t *testing.T) {
	for _, a := range everyAttribute(t) {
		if a.nested {
			continue
		}
		for field := range objectFields(a.attribute.GetType()) {
			if !strings.Contains(a.description(), "`"+field+"`") {
				t.Errorf("%s: its description does not name the field `%s`", a.path, field)
			}
		}
	}
}

// pipelineDataSources are read by the modules shipped with the provider, and by the tests of the teams that call them.
var pipelineDataSources = []string{
	"data.xshield_aws_enforcement_snapshot",
	"data.xshield_aws_security_group_changes",
	"data.xshield_aws_security_group_rules",
	"data.xshield_enforcement_status",
}

// `terraform test` cannot set a computed nested attribute from mock_data: the mocked value comes back empty, as
// Terraform 1.17 still does. A module's tests mock these data sources, so what they return stays in plain
// collection attributes, where a mock can set every field.
func TestPipelineDataSourcesReturnNothingAMockCannotSet(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range everyAttribute(t) {
		seen[a.typeName] = true
		isPipeline := false
		for _, name := range pipelineDataSources {
			isPipeline = isPipeline || name == a.typeName
		}
		if isPipeline && a.nested && a.attribute.IsComputed() {
			t.Errorf("%s is a computed nested attribute, which terraform test cannot mock; declare it as a collection of objects", a.path)
		}
	}
	for _, name := range pipelineDataSources {
		if !seen[name] {
			t.Errorf("%s is not registered", name)
		}
	}
}
