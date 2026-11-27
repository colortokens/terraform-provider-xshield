package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func templateSchemaForTest(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	(&TemplateResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	return resp
}

func templateConfigOf(t *testing.T, paths ...tfTypes.MetadataPath) tfsdk.Config {
	t.Helper()
	s := templateSchemaForTest(t).Schema
	model := templateWithPaths(paths...)
	model.ID = types.StringNull()
	return tfsdk.Config{Schema: s, Raw: templateValue(t, s, model)}
}

func pathWithDirection(direction string) tfTypes.MetadataPath {
	p := inboundMySQLPath("")
	p.ID = types.StringNull()
	p.Direction = types.StringValue(direction)
	return p
}

func namedNetwork(id, name types.String) *tfTypes.MetadataNamedNetworkReference {
	return &tfTypes.MetadataNamedNetworkReference{NamedNetworkID: id, NamedNetworkName: name}
}

func tagBasedPolicy(id, name, criteria types.String) *tfTypes.MetadataTagBasedPolicyReference {
	return &tfTypes.MetadataTagBasedPolicyReference{TagBasedPolicyID: id, TagBasedPolicyName: name, Criteria: criteria}
}

var noValue = types.StringNull()

// errorsAt lists each error as "<attribute path>: <detail>".
func errorsAt(diags diag.Diagnostics) []string {
	var out []string
	for _, d := range diags.Errors() {
		at := ""
		if d, ok := d.(diag.DiagnosticWithPath); ok {
			at = d.Path().String()
		}
		out = append(out, at+": "+d.Detail())
	}
	return out
}

// A selector object that names no network or segment selects nothing, and the
// API rejects the path, so validate reports it at the object, naming the path.
func TestTemplatePathSelectorObjectWithNoIDFailsValidateConfig(t *testing.T) {
	srcIP := pathWithDirection("inbound")
	srcIP.SrcIP = types.StringValue("10.0.0.1")
	cases := map[string]struct {
		path func(p *tfTypes.MetadataPath)
		at   string
		want string
	}{
		"inbound source_named_network = {}": {
			func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(noValue, noValue) },
			"template_paths[1].source_named_network",
			"template_paths[1].source_named_network must set named_network_id.",
		},
		"inbound source_named_network with only a name": {
			func(p *tfTypes.MetadataPath) {
				p.SourceNamedNetwork = namedNetwork(noValue, types.StringValue("office"))
			},
			"template_paths[1].source_named_network",
			"template_paths[1].source_named_network must set named_network_id.",
		},
		"inbound source_named_network with an empty id": {
			func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(types.StringValue(""), noValue) },
			"template_paths[1].source_named_network",
			"template_paths[1].source_named_network must set named_network_id.",
		},
		"inbound source_tag_based_policy = {}": {
			func(p *tfTypes.MetadataPath) { p.SourceTagBasedPolicy = tagBasedPolicy(noValue, noValue, noValue) },
			"template_paths[1].source_tag_based_policy",
			"template_paths[1].source_tag_based_policy must set tag_based_policy_id.",
		},
		"inbound source_tag_based_policy with only a name and criteria": {
			func(p *tfTypes.MetadataPath) {
				p.SourceTagBasedPolicy = tagBasedPolicy(noValue, types.StringValue("web"), types.StringValue("role = web"))
			},
			"template_paths[1].source_tag_based_policy",
			"template_paths[1].source_tag_based_policy must set tag_based_policy_id.",
		},
		"outbound destination_named_network = {}": {
			func(p *tfTypes.MetadataPath) {
				p.Direction = types.StringValue("outbound")
				p.DestinationNamedNetwork = namedNetwork(noValue, noValue)
			},
			"template_paths[1].destination_named_network",
			"template_paths[1].destination_named_network must set named_network_id.",
		},
		"outbound destination_tag_based_policy = {}": {
			func(p *tfTypes.MetadataPath) {
				p.Direction = types.StringValue("outbound")
				p.DestinationTagBasedPolicy = tagBasedPolicy(noValue, noValue, noValue)
			},
			"template_paths[1].destination_tag_based_policy",
			"template_paths[1].destination_tag_based_policy must set tag_based_policy_id.",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := pathWithDirection("inbound")
			c.path(&p)
			var resp resource.ValidateConfigResponse
			(&TemplateResource{}).ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: templateConfigOf(t, srcIP, p)}, &resp)
			errs := errorsAt(resp.Diagnostics)
			if len(errs) != 1 || !strings.HasPrefix(errs[0], c.at+": "+c.want) {
				t.Errorf("errors = %q, want one at %s starting %q", errs, c.at, c.want)
			}
		})
	}
}

// An object that names its network or segment, or whose ID is only known at
// apply, is a selector.
func TestTemplatePathSelectorObjectWithAnIDPassesValidateConfig(t *testing.T) {
	unknown := types.StringUnknown()
	id := types.StringValue("6f1c2b8e-0d4a-4c1e-9a7b-3e5f2d1c0b9a")
	cases := map[string]func(p *tfTypes.MetadataPath){
		"source_named_network with an id":          func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(id, noValue) },
		"source_named_network with an id and name": func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(id, types.StringValue("office")) },
		"source_named_network id from a resource":  func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(unknown, noValue) },
		"source_tag_based_policy with an id":       func(p *tfTypes.MetadataPath) { p.SourceTagBasedPolicy = tagBasedPolicy(id, noValue, noValue) },
		"source_tag_based_policy id from a resource": func(p *tfTypes.MetadataPath) {
			p.SourceTagBasedPolicy = tagBasedPolicy(unknown, noValue, noValue)
		},
		"outbound destination_named_network id from a resource": func(p *tfTypes.MetadataPath) {
			p.Direction = types.StringValue("outbound")
			p.DestinationNamedNetwork = namedNetwork(unknown, noValue)
		},
		"outbound destination_tag_based_policy with an id": func(p *tfTypes.MetadataPath) {
			p.Direction = types.StringValue("outbound")
			p.DestinationTagBasedPolicy = tagBasedPolicy(id, noValue, noValue)
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			p := pathWithDirection("inbound")
			set(&p)
			var resp resource.ValidateConfigResponse
			(&TemplateResource{}).ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: templateConfigOf(t, p)}, &resp)
			if errs := errorsAt(resp.Diagnostics); len(errs) > 0 {
				t.Errorf("rejected a selector that names its target: %q", errs)
			}
		})
	}
}

// templateAPIRecordingRequests answers every request with an error and records it.
func templateAPIRecordingRequests(t *testing.T) (*sdk.Xshield, *[]string) {
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

// An ID from a resource or variable is unknown at plan; if it resolves to null
// at apply, the plan still holds it as unknown (it is Optional and Computed),
// so create and update check the configuration, which is fully known by then.
func TestTemplateApplyRejectsASelectorObjectWhoseIDResolvedToNull(t *testing.T) {
	ctx := context.Background()
	s := templateSchemaForTest(t).Schema
	selectors := map[string]struct {
		configured, planned func(p *tfTypes.MetadataPath)
		want                string
	}{
		"source_named_network": {
			func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(noValue, noValue) },
			func(p *tfTypes.MetadataPath) {
				p.SourceNamedNetwork = namedNetwork(types.StringUnknown(), types.StringUnknown())
			},
			"template_paths[0].source_named_network: template_paths[0].source_named_network must set named_network_id.",
		},
		"source_tag_based_policy": {
			func(p *tfTypes.MetadataPath) { p.SourceTagBasedPolicy = tagBasedPolicy(noValue, noValue, noValue) },
			func(p *tfTypes.MetadataPath) {
				p.SourceTagBasedPolicy = tagBasedPolicy(types.StringUnknown(), types.StringUnknown(), types.StringUnknown())
			},
			"template_paths[0].source_tag_based_policy: template_paths[0].source_tag_based_policy must set tag_based_policy_id.",
		},
	}
	for name, sel := range selectors {
		configured, planned := pathWithDirection("inbound"), pathWithDirection("inbound")
		sel.configured(&configured)
		sel.planned(&planned)
		planModel := templateWithPaths(planned)
		planModel.ID = types.StringUnknown()
		config := templateConfigOf(t, configured)
		plan := tfsdk.Plan{Schema: s, Raw: templateValue(t, s, planModel)}

		t.Run(name+"/create", func(t *testing.T) {
			client, requests := templateAPIRecordingRequests(t)
			resp := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: plan.Raw.Copy()}}
			(&TemplateResource{client: client}).Create(ctx, resource.CreateRequest{Config: config, Plan: plan}, &resp)
			if errs := errorsAt(resp.Diagnostics); !strings.Contains(fmt.Sprint(errs), sel.want) || len(*requests) > 0 {
				t.Errorf("create errors = %q, API requests = %v; want %q and no request", errs, *requests, sel.want)
			}
		})
		t.Run(name+"/update", func(t *testing.T) {
			client, requests := templateAPIRecordingRequests(t)
			held := inboundMySQLPath("h-old")
			held.SrcIP = types.StringValue("10.0.0.1")
			state := tfsdk.State{Schema: s, Raw: templateValue(t, s, templateWithPaths(held))}
			updatePlan := tfsdk.Plan{Schema: s, Raw: templateValue(t, s, templateWithPaths(planned))}
			resp := resource.UpdateResponse{State: state}
			(&TemplateResource{client: client}).Update(ctx, resource.UpdateRequest{Config: config, Plan: updatePlan, State: state}, &resp)
			if errs := errorsAt(resp.Diagnostics); !strings.Contains(fmt.Sprint(errs), sel.want) || len(*requests) > 0 {
				t.Errorf("update errors = %q, API requests = %v; want %q and no request", errs, *requests, sel.want)
			}
		})
	}
}
