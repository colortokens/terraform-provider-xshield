package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// templateConfigWithPaths renders an xshield_template config whose
// template_paths is the given value, every other attribute null.
func templateConfigWithPaths(t *testing.T, paths func(path tftypes.Object) tftypes.Value) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	var schemaResp resource.SchemaResponse
	(&TemplateResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	s := schemaResp.Schema
	root := s.Type().TerraformType(ctx).(tftypes.Object)
	pathsType := root.AttributeTypes["template_paths"].(tftypes.List)
	values := nullAttributes(root)
	values["template_name"] = tftypes.NewValue(tftypes.String, "db")
	values["template_type"] = tftypes.NewValue(tftypes.String, "application-template")
	values["template_paths"] = paths(pathsType.ElementType.(tftypes.Object))
	return tfsdk.Config{Schema: s, Raw: tftypes.NewValue(root, values)}
}

func nullAttributes(typ tftypes.Object) map[string]tftypes.Value {
	values := map[string]tftypes.Value{}
	for name, attrType := range typ.AttributeTypes {
		values[name] = tftypes.NewValue(attrType, nil)
	}
	return values
}

// templatePathObject is one template_paths element: the given attributes, the
// rest null. A nested object attribute given as a map is built with its own type.
func templatePathObject(typ tftypes.Object, attrs map[string]any) tftypes.Value {
	values := nullAttributes(typ)
	for name, v := range attrs {
		switch v := v.(type) {
		case tftypes.Value:
			values[name] = v
		case string:
			values[name] = tftypes.NewValue(tftypes.String, v)
		case map[string]any:
			values[name] = templatePathObject(typ.AttributeTypes[name].(tftypes.Object), v)
		}
	}
	return tftypes.NewValue(typ, values)
}

func pathList(paths ...map[string]any) func(tftypes.Object) tftypes.Value {
	return func(typ tftypes.Object) tftypes.Value {
		elements := make([]tftypes.Value, len(paths))
		for i, attrs := range paths {
			elements[i] = templatePathObject(typ, attrs)
		}
		return tftypes.NewValue(tftypes.List{ElementType: typ}, elements)
	}
}

func unknownOf(typ tftypes.Object, name string) tftypes.Value {
	return tftypes.NewValue(typ.AttributeTypes[name], tftypes.UnknownValue)
}

var unknownString = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)

func validateTemplateConfig(t *testing.T, config tfsdk.Config) []string {
	t.Helper()
	var resp resource.ValidateConfigResponse
	(&TemplateResource{}).ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: config}, &resp)
	var errs []string
	for _, d := range resp.Diagnostics.Errors() {
		errs = append(errs, d.Summary()+": "+d.Detail())
	}
	return errs
}

func inbound(attrs map[string]any) map[string]any {
	attrs["direction"], attrs["port"], attrs["protocol"] = "inbound", "3306", "TCP"
	return attrs
}

func outbound(attrs map[string]any) map[string]any {
	attrs["direction"], attrs["port"], attrs["protocol"] = "outbound", "443", "TCP"
	return attrs
}

// A selector from a variable, a data source or another resource is unknown
// during validate and plan; the path must not be rejected for it.
func TestTemplatePathSelectorsKnownOnlyAtApplyPassValidateConfig(t *testing.T) {
	cases := map[string]func(tftypes.Object) tftypes.Value{
		"inbound source_asset_id from a variable":       pathList(inbound(map[string]any{"source_asset_id": unknownString})),
		"inbound src_ip from a variable":                pathList(inbound(map[string]any{"src_ip": unknownString})),
		"outbound destination_asset_id from a resource": pathList(outbound(map[string]any{"destination_asset_id": unknownString})),
		"outbound dst_ip from a resource":               pathList(outbound(map[string]any{"dst_ip": unknownString})),
		"outbound domain from a variable":               pathList(outbound(map[string]any{"domain": unknownString})),
		"outbound destination_named_network object from a variable": func(typ tftypes.Object) tftypes.Value {
			return pathList(outbound(map[string]any{"destination_named_network": unknownOf(typ, "destination_named_network")}))(typ)
		},
		"outbound destination_tag_based_policy object from a conditional": func(typ tftypes.Object) tftypes.Value {
			return pathList(outbound(map[string]any{"destination_tag_based_policy": unknownOf(typ, "destination_tag_based_policy")}))(typ)
		},
		"inbound source_named_network object from a variable": func(typ tftypes.Object) tftypes.Value {
			return pathList(inbound(map[string]any{"source_named_network": unknownOf(typ, "source_named_network")}))(typ)
		},
		"inbound source_tag_based_policy object from a variable": func(typ tftypes.Object) tftypes.Value {
			return pathList(inbound(map[string]any{"source_tag_based_policy": unknownOf(typ, "source_tag_based_policy")}))(typ)
		},
		"inbound source_named_network whose id comes from a resource": pathList(inbound(map[string]any{
			"source_named_network": map[string]any{"named_network_id": unknownString}})),
		"outbound destination_tag_based_policy whose id comes from a resource": pathList(outbound(map[string]any{
			"destination_tag_based_policy": map[string]any{"tag_based_policy_id": unknownString}})),
		"a literal selector beside one that may resolve to null": pathList(inbound(map[string]any{
			"src_ip": "10.0.0.1", "source_asset_id": unknownString})),
		"direction from a variable": pathList(map[string]any{"direction": unknownString, "port": "443", "protocol": "TCP"}),
		"template_paths built by a for expression over a variable": func(typ tftypes.Object) tftypes.Value {
			return tftypes.NewValue(tftypes.List{ElementType: typ}, tftypes.UnknownValue)
		},
		"one path element from a variable": func(typ tftypes.Object) tftypes.Value {
			return tftypes.NewValue(tftypes.List{ElementType: typ}, []tftypes.Value{
				tftypes.NewValue(typ, tftypes.UnknownValue),
				templatePathObject(typ, inbound(map[string]any{"src_ip": "10.0.0.1"})),
			})
		},
	}
	for name, paths := range cases {
		t.Run(name, func(t *testing.T) {
			if errs := validateTemplateConfig(t, templateConfigWithPaths(t, paths)); len(errs) > 0 {
				t.Errorf("rejected at validate/plan although the value is only known at apply: %v", errs)
			}
		})
	}
}

// templateAPIThatMustNotBeCalled records every request; validation must stop
// an invalid path before any reaches the API.
func templateAPIThatMustNotBeCalled(t *testing.T) (*sdk.Xshield, *[]string) {
	t.Helper()
	newLookupClient(t, "{}")
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	return sdk.New(
		sdk.WithServerURL(srv.URL),
		sdk.WithConfigProvider(shared.NewDirectConfigProvider("tenancy", "user", "fp", providerTestKeyPEM)),
		sdk.WithClient(srv.Client()),
	), &requests
}

// A selector that was unknown at plan and resolves to null at apply leaves the
// path with no selector. The plan cannot show this, since an unset Optional and
// Computed selector is unknown there, so create and update check the config,
// which is fully known at apply.
func TestTemplateApplyRejectsAPathWhoseDeferredSelectorResolvedToNull(t *testing.T) {
	ctx := context.Background()
	config := templateConfigWithPaths(t, pathList(inbound(map[string]any{})))
	plan := templateConfigWithPaths(t, pathList(inbound(map[string]any{
		"src_ip": unknownString, "source_asset_id": unknownString})))
	const want = "Invalid inbound template path configuration - selector fields"

	t.Run("create", func(t *testing.T) {
		client, requests := templateAPIThatMustNotBeCalled(t)
		resp := resource.CreateResponse{State: tfsdk.State{Schema: config.Schema, Raw: tftypes.NewValue(config.Raw.Type(), nil)}}
		(&TemplateResource{client: client}).Create(ctx, resource.CreateRequest{
			Config: config, Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, &resp)
		if !strings.Contains(fmt.Sprint(resp.Diagnostics), want) || len(*requests) > 0 {
			t.Errorf("create diagnostics = %v, API requests = %v; want %q and no request", resp.Diagnostics, *requests, want)
		}
	})
	t.Run("update", func(t *testing.T) {
		client, requests := templateAPIThatMustNotBeCalled(t)
		state := templateConfigWithPaths(t, pathList(inbound(map[string]any{"src_ip": "10.0.0.1"})))
		resp := resource.UpdateResponse{State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}
		(&TemplateResource{client: client}).Update(ctx, resource.UpdateRequest{
			Config: config, Plan: tfsdk.Plan{Schema: config.Schema, Raw: config.Raw}, State: tfsdk.State{Schema: state.Schema, Raw: state.Raw}}, &resp)
		if !strings.Contains(fmt.Sprint(resp.Diagnostics), want) || len(*requests) > 0 {
			t.Errorf("update diagnostics = %v, API requests = %v; want %q and no request", resp.Diagnostics, *requests, want)
		}
	})
}

// Literal configs keep the errors they have always had.
func TestTemplatePathLiteralMistakesStillFailValidateConfig(t *testing.T) {
	cases := map[string]struct {
		paths func(tftypes.Object) tftypes.Value
		want  string
	}{
		"inbound path naming no source": {
			pathList(inbound(map[string]any{})),
			"Invalid inbound template path configuration - selector fields: For inbound template_paths elements, exactly one of src_ip, source_asset_id, source_named_network, or source_tag_based_policy must be set.",
		},
		"outbound path naming no destination": {
			pathList(outbound(map[string]any{})),
			"Invalid outbound template path configuration - selector fields: For outbound template_paths elements, exactly one of dst_ip, destination_asset_id, destination_named_network, destination_tag_based_policy, or domain must be set.",
		},
		"inbound path naming two literal sources": {
			pathList(inbound(map[string]any{"src_ip": "10.0.0.1", "source_asset_id": "client-asset"})),
			"Currently set selector fields: [src_ip source_asset_id].",
		},
		"inbound path whose only pending selector is a destination": {
			func(typ tftypes.Object) tftypes.Value {
				return pathList(inbound(map[string]any{"destination_named_network": unknownOf(typ, "destination_named_network")}))(typ)
			},
			"Invalid inbound template path configuration - selector fields",
		},
		"outbound path with a literal source": {
			pathList(outbound(map[string]any{"dst_ip": "10.0.0.2", "src_ip": "10.0.0.1"})),
			"Invalid outbound template path configuration - direction: For outbound template_paths elements, source-side fields must not be set. The following source-side fields are set: [src_ip].",
		},
		"inbound path with a literal domain": {
			pathList(inbound(map[string]any{"src_ip": "10.0.0.1", "domain": "db.example.internal"})),
			"Invalid inbound template path configuration - direction: For inbound template_paths elements, destination-side fields must not be set. The following forbidden fields are set: [domain].",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			errs := validateTemplateConfig(t, templateConfigWithPaths(t, c.paths))
			if len(errs) != 1 || !strings.Contains(errs[0], c.want) {
				t.Errorf("errors = %q, want one containing %q", errs, c.want)
			}
		})
	}
}
