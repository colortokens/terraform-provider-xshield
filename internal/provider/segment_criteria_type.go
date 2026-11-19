package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// SegmentCriteriaType is the type of a segment's criteria. Terraform refuses a
// plan that differs from a configured value, so the backend's managedby rewrite
// cannot be applied at plan time. Semantic equality instead lets Create, Read
// and Update keep the configured text whenever the stored criteria is that text
// plus the clause the backend appends, while any other difference is drift.
type SegmentCriteriaType struct {
	basetypes.StringType
}

var _ basetypes.StringTypable = SegmentCriteriaType{}

func (t SegmentCriteriaType) Equal(o attr.Type) bool {
	other, ok := o.(SegmentCriteriaType)
	if !ok {
		return false
	}
	return t.StringType.Equal(other.StringType)
}

func (t SegmentCriteriaType) String() string {
	return "SegmentCriteriaType"
}

func (t SegmentCriteriaType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return SegmentCriteriaValue{StringValue: in}, nil
}

func (t SegmentCriteriaType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := attrValue.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}
	value, diags := t.ValueFromString(ctx, stringValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting StringValue to SegmentCriteriaValue: %v", diags)
	}
	return value, nil
}

func (t SegmentCriteriaType) ValueType(_ context.Context) attr.Value {
	return SegmentCriteriaValue{}
}

type SegmentCriteriaValue struct {
	basetypes.StringValue
}

var _ basetypes.StringValuableWithSemanticEquals = SegmentCriteriaValue{}

func NewSegmentCriteriaValue(criteria string) SegmentCriteriaValue {
	return SegmentCriteriaValue{StringValue: types.StringValue(criteria)}
}

func NewSegmentCriteriaNull() SegmentCriteriaValue {
	return SegmentCriteriaValue{StringValue: types.StringNull()}
}

func (v SegmentCriteriaValue) Equal(o attr.Value) bool {
	other, ok := o.(SegmentCriteriaValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(other.StringValue)
}

func (v SegmentCriteriaValue) Type(_ context.Context) attr.Type {
	return SegmentCriteriaType{}
}

func (v SegmentCriteriaValue) StringSemanticEquals(_ context.Context, newValuable basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	newValue, ok := newValuable.(SegmentCriteriaValue)
	if !ok {
		diags.AddError("Semantic Equality Check Error",
			fmt.Sprintf("Expected value type %T but got value type %T. Please report this to the provider developers.", v, newValuable))
		return false, diags
	}
	return canonicalSegmentCriteria(v.ValueString()) == canonicalSegmentCriteria(newValue.ValueString()), diags
}
