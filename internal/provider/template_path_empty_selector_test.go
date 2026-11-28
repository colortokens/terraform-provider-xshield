package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
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

// An object that names its network or segment, or whose ID is only known at
// apply, is a selector.
func TestTemplatePathSelectorObjectWithAnIDPassesValidateAndPlan(t *testing.T) {
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
			config := templateWithPaths(p)
			config.ID = types.StringNull()
			proposed := config
			validateErrs, planErrs, _ := templatePlan{nil, &config, &proposed}.run(t)
			if len(validateErrs) > 0 || len(planErrs) > 0 {
				t.Errorf("rejected a selector that names its target: validate %q, plan %q", validateErrs, planErrs)
			}
		})
	}
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
			client, requests := templateAPIThatMustNotBeCalled(t)
			resp := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: plan.Raw.Copy()}}
			(&TemplateResource{client: client}).Create(ctx, resource.CreateRequest{Config: config, Plan: plan}, &resp)
			if errs := errorsAt(resp.Diagnostics); !strings.Contains(fmt.Sprint(errs), sel.want) || len(*requests) > 0 {
				t.Errorf("create errors = %q, API requests = %v; want %q and no request", errs, *requests, sel.want)
			}
		})
		t.Run(name+"/update", func(t *testing.T) {
			client, requests := templateAPIThatMustNotBeCalled(t)
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

// On update, a selector the configuration names only by name is sent with the
// ID the plan carries from state, so apply does not reject it.
func TestTemplateUpdateAcceptsASelectorIDCarriedFromState(t *testing.T) {
	ctx := context.Background()
	s := templateSchemaForTest(t).Schema
	for selector, sel := range importedSelectors {
		t.Run(selector, func(t *testing.T) {
			held := inboundMySQLPath("h-imported")
			sel.held(&held)
			prior := templateWithPaths(held)
			prior.TemplateDescription = types.StringValue("before")
			planned := prior
			planned.TemplateDescription = types.StringValue("after")
			configured := pathWithDirection("inbound")
			sel.nameOnly(&configured)
			config := templateWithPaths(configured)
			config.ID = types.StringNull()
			config.TemplateDescription = planned.TemplateDescription

			client, requests := templateAPIThatMustNotBeCalled(t)
			state := tfsdk.State{Schema: s, Raw: templateValue(t, s, prior)}
			resp := resource.UpdateResponse{State: state}
			(&TemplateResource{client: client}).Update(ctx, resource.UpdateRequest{
				Config: tfsdk.Config{Schema: s, Raw: templateValue(t, s, config)},
				Plan:   tfsdk.Plan{Schema: s, Raw: templateValue(t, s, planned)},
				State:  state,
			}, &resp)
			if errs := errorsAt(resp.Diagnostics); strings.Contains(fmt.Sprint(errs), "empty selector") || len(*requests) == 0 {
				t.Errorf("update errors = %q, API requests = %v; want the update sent", errs, *requests)
			}
		})
	}
}
