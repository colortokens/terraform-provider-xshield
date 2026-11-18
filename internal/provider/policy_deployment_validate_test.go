package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func policyDeploymentConfig(t *testing.T, set map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	r := &PolicyDeploymentResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	objectType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, attrType := range objectType.AttributeTypes {
		if value, ok := set[name]; ok {
			values[name] = value
			continue
		}
		values[name] = tftypes.NewValue(attrType, nil)
	}
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: tftypes.NewValue(objectType, values)}
}

func planEntriesValue(t *testing.T, entries map[string]string) tftypes.Value {
	t.Helper()
	ctx := context.Background()
	r := &PolicyDeploymentResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	mapType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object).AttributeTypes["reviewed"].(tftypes.Map)
	entryType := mapType.ElementType.(tftypes.Object)
	if entries == nil {
		return tftypes.NewValue(mapType, tftypes.UnknownValue)
	}
	elements := map[string]tftypes.Value{}
	for key, mode := range entries {
		elements[key] = tftypes.NewValue(entryType, map[string]tftypes.Value{
			"mode":            tftypes.NewValue(tftypes.String, mode),
			"target_assets":   tftypes.NewValue(tftypes.String, nil),
			"bypass_warnings": tftypes.NewValue(tftypes.Bool, nil),
		})
	}
	return tftypes.NewValue(mapType, elements)
}

func TestPolicyDeploymentValidateConfigWaitsForValuesFromVariables(t *testing.T) {
	unknownMode := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	tests := map[string]struct {
		set     map[string]tftypes.Value
		wantErr string
	}{
		"mode from a variable": {
			set: map[string]tftypes.Value{"mode": unknownMode},
		},
		"reviewed ports from a variable": {
			set: map[string]tftypes.Value{"reviewed": planEntriesValue(t, nil)},
		},
		"unreviewed ports from a variable": {
			set: map[string]tftypes.Value{"unreviewed": planEntriesValue(t, nil)},
		},
		"mode from a variable beside port maps": {
			set: map[string]tftypes.Value{"mode": unknownMode, "reviewed": planEntriesValue(t, map[string]string{"TCP:22": "test"})},
		},
		"mode given": {
			set: map[string]tftypes.Value{"mode": tftypes.NewValue(tftypes.String, "test")},
		},
		"nothing given": {
			wantErr: "Nothing to deploy",
		},
		"mode and port maps given": {
			set: map[string]tftypes.Value{
				"mode":     tftypes.NewValue(tftypes.String, "enforce"),
				"reviewed": planEntriesValue(t, map[string]string{"TCP:22": "test"}),
			},
			wantErr: "Set either mode or the port maps, not both",
		},
		"an unreviewed key other than the wildcard": {
			set:     map[string]tftypes.Value{"unreviewed": planEntriesValue(t, map[string]string{"TCP:22": "test"})},
			wantErr: "Only the \"*\" key is honoured for unreviewed ports",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := &PolicyDeploymentResource{}
			resp := &resource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: policyDeploymentConfig(t, test.set)}, resp)
			var summaries []string
			for _, d := range resp.Diagnostics.Errors() {
				summaries = append(summaries, d.Summary())
			}
			got := strings.Join(summaries, "; ")
			if test.wantErr == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if test.wantErr != "" && !strings.Contains(got, test.wantErr) {
				t.Fatalf("want an error containing %q, got %q", test.wantErr, got)
			}
		})
	}
}
