package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tfTypes "github.com/colortokens/terraform-provider-xshield/internal/provider/types"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// templatePlan is what Terraform sends the provider for one plan of an
// xshield_template: validate the configuration, then plan the change.
type templatePlan struct {
	prior, config, proposed *TemplateResourceModel
}

// run returns the errors from validate and from plan, as "<path>: <detail>",
// and the planned value.
func (p templatePlan) run(t *testing.T) (validateErrs, planErrs []string, planned tftypes.Value) {
	t.Helper()
	ctx := context.Background()
	s := templateSchemaForTest(t).Schema
	typ := s.Type().TerraformType(ctx)
	dynamic := func(model *TemplateResourceModel) *tfprotov6.DynamicValue {
		v := tftypes.NewValue(typ, nil)
		if model != nil {
			v = templateValue(t, s, *model)
		}
		d, err := tfprotov6.NewDynamicValue(typ, v)
		if err != nil {
			t.Fatal(err)
		}
		return &d
	}
	errorsOf := func(diags []*tfprotov6.Diagnostic) []string {
		var out []string
		for _, d := range diags {
			if d.Severity == tfprotov6.DiagnosticSeverityError {
				out = append(out, fmt.Sprintf("%v: %s", d.Attribute, d.Detail))
			}
		}
		return out
	}

	server := providerserver.NewProtocol6(New("test")())()
	validated, err := server.ValidateResourceConfig(ctx, &tfprotov6.ValidateResourceConfigRequest{
		TypeName: "xshield_template", Config: dynamic(p.config)})
	if err != nil {
		t.Fatal(err)
	}
	plannedResp, err := server.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
		TypeName:         "xshield_template",
		PriorState:       dynamic(p.prior),
		ProposedNewState: dynamic(p.proposed),
		Config:           dynamic(p.config),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plannedResp.PlannedState != nil {
		if planned, err = plannedResp.PlannedState.Unmarshal(typ); err != nil {
			t.Fatal(err)
		}
	}
	return errorsOf(validated.Diagnostics), errorsOf(plannedResp.Diagnostics), planned
}

// plannedSelectorID is the planned ID of template_paths[i].<selector>.
func plannedSelectorID(t *testing.T, planned tftypes.Value, i int, selector, idAttribute string) tftypes.Value {
	t.Helper()
	v, _, err := tftypes.WalkAttributePath(planned, tftypes.NewAttributePath().
		WithAttributeName("template_paths").WithElementKeyInt(i).WithAttributeName(selector).WithAttributeName(idAttribute))
	if err != nil {
		t.Fatal(err)
	}
	return v.(tftypes.Value)
}

const (
	importedNamedNetworkID = "0b5e1f0c-7d2a-4f3e-9c61-2a8d4b7e9f10"
	importedSegmentID      = "6f1c2b8e-0d4a-4c1e-9a7b-3e5f2d1c0b9a"
)

// importedSelectors are the path selectors of a template that Read filled
// from the API: each holds its ID and name.
var importedSelectors = map[string]struct {
	idAttribute string
	held        func(p *tfTypes.MetadataPath)
	configured  map[string]func(p *tfTypes.MetadataPath)
}{
	"source_named_network": {
		idAttribute: "named_network_id",
		held: func(p *tfTypes.MetadataPath) {
			p.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), types.StringValue("corp-networks"))
		},
		configured: map[string]func(p *tfTypes.MetadataPath){
			"only a name": func(p *tfTypes.MetadataPath) {
				p.SourceNamedNetwork = namedNetwork(noValue, types.StringValue("corp-networks"))
			},
			"{}": func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(noValue, noValue) },
		},
	},
	"source_tag_based_policy": {
		idAttribute: "tag_based_policy_id",
		held: func(p *tfTypes.MetadataPath) {
			p.SourceTagBasedPolicy = tagBasedPolicy(types.StringValue(importedSegmentID), types.StringValue("payroll-app"), types.StringValue("app = payroll"))
		},
		configured: map[string]func(p *tfTypes.MetadataPath){
			"only a name": func(p *tfTypes.MetadataPath) {
				p.SourceTagBasedPolicy = tagBasedPolicy(noValue, types.StringValue("payroll-app"), noValue)
			},
			"{}": func(p *tfTypes.MetadataPath) { p.SourceTagBasedPolicy = tagBasedPolicy(noValue, noValue, noValue) },
		},
	},
}

// An imported template whose configuration names a selector only by name, or
// as {}, plans with the ID Read put in state, so an unrelated edit applies.
func TestTemplatePathSelectorWithItsIDInStatePlansCleanly(t *testing.T) {
	for selector, sel := range importedSelectors {
		for written, configure := range sel.configured {
			t.Run(selector+" as "+written, func(t *testing.T) {
				held := inboundMySQLPath("h-imported")
				sel.held(&held)
				heldIP := inboundMySQLPath("h-ip")
				heldIP.SrcIP = types.StringValue("10.0.0.1")
				prior := templateWithPaths(held, heldIP)
				prior.TemplateDescription = types.StringValue("before")

				configured := pathWithDirection("inbound")
				configure(&configured)
				configuredIP := pathWithDirection("inbound")
				configuredIP.SrcIP = heldIP.SrcIP
				config := templateWithPaths(configured, configuredIP)
				config.ID = types.StringNull()
				config.TemplateDescription = types.StringValue("after")

				// Terraform proposes the prior value for every Optional and
				// Computed attribute the configuration leaves null.
				proposed := prior
				proposed.TemplateDescription = config.TemplateDescription

				validateErrs, planErrs, planned := templatePlan{&prior, &config, &proposed}.run(t)
				if len(validateErrs) > 0 || len(planErrs) > 0 {
					t.Fatalf("validate errors = %q, plan errors = %q; want none", validateErrs, planErrs)
				}
				want := map[string]string{"source_named_network": importedNamedNetworkID, "source_tag_based_policy": importedSegmentID}[selector]
				if got := plannedSelectorID(t, planned, 0, selector, sel.idAttribute); !got.Equal(tftypes.NewValue(tftypes.String, want)) {
					t.Errorf("planned %s = %v, want the ID from state %q", sel.idAttribute, got, want)
				}
			})
		}
	}
}

// A selector with no ID that would reach the API with none, on create or as a
// path new to the template, fails the plan at the selector.
func TestTemplatePathSelectorWithNoIDFailsThePlan(t *testing.T) {
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
		p := pathWithDirection("inbound")
		c.path(&p)
		config := templateWithPaths(srcIP, p)
		config.ID = types.StringNull()
		check := func(t *testing.T, validateErrs, planErrs []string) {
			t.Helper()
			if len(validateErrs) > 0 {
				t.Errorf("validate errors = %q; the plan reports this, once it can see state", validateErrs)
			}
			if len(planErrs) != 1 || !strings.HasPrefix(planErrs[0], `AttributeName("template_paths").ElementKeyInt(1).AttributeName("`) ||
				!strings.Contains(planErrs[0], c.want) {
				t.Errorf("plan errors = %q, want one at %s containing %q", planErrs, c.at, c.want)
			}
		}
		t.Run(name+"/create", func(t *testing.T) {
			proposed := config
			validateErrs, planErrs, _ := templatePlan{nil, &config, &proposed}.run(t)
			check(t, validateErrs, planErrs)
		})
		t.Run(name+"/added on update", func(t *testing.T) {
			held := srcIP
			held.ID = types.StringValue("h-1")
			prior := templateWithPaths(held)
			proposed := templateWithPaths(held, p)
			validateErrs, planErrs, _ := templatePlan{&prior, &config, &proposed}.run(t)
			check(t, validateErrs, planErrs)
		})
	}
}
