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
	nameOnly    func(p *tfTypes.MetadataPath)
	empty       func(p *tfTypes.MetadataPath)
}{
	"source_named_network": {
		idAttribute: "named_network_id",
		held: func(p *tfTypes.MetadataPath) {
			p.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), types.StringValue("corp-networks"))
		},
		nameOnly: func(p *tfTypes.MetadataPath) {
			p.SourceNamedNetwork = namedNetwork(noValue, types.StringValue("corp-networks"))
		},
		empty: func(p *tfTypes.MetadataPath) { p.SourceNamedNetwork = namedNetwork(noValue, noValue) },
	},
	"source_tag_based_policy": {
		idAttribute: "tag_based_policy_id",
		held: func(p *tfTypes.MetadataPath) {
			p.SourceTagBasedPolicy = tagBasedPolicy(types.StringValue(importedSegmentID), types.StringValue("payroll-app"), types.StringValue("app = payroll"))
		},
		nameOnly: func(p *tfTypes.MetadataPath) {
			p.SourceTagBasedPolicy = tagBasedPolicy(noValue, types.StringValue("payroll-app"), noValue)
		},
		empty: func(p *tfTypes.MetadataPath) { p.SourceTagBasedPolicy = tagBasedPolicy(noValue, noValue, noValue) },
	},
}

// An imported template whose configuration names a selector only by name plans
// with the ID Read put in state, so an unrelated edit applies. A selector
// written as {} names nothing to match in state, so it fails the plan.
func TestTemplatePathSelectorWithItsIDInStatePlansCleanly(t *testing.T) {
	for selector, sel := range importedSelectors {
		for written, configure := range map[string]func(p *tfTypes.MetadataPath){"only a name": sel.nameOnly, "{}": sel.empty} {
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
				if written == "{}" {
					want := "template_paths[0]." + selector + " must set " + sel.idAttribute
					if len(validateErrs) > 0 || len(planErrs) != 1 || !strings.Contains(planErrs[0], want) {
						t.Errorf("validate errors = %q, plan errors = %q; want one plan error containing %q", validateErrs, planErrs, want)
					}
					return
				}
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

// A name-only selector on a path inserted ahead of existing ones must not plan
// with the ID of the state path that used to hold its position.
func TestTemplatePathSelectorDoesNotTakeAnotherSelectorsIDFromState(t *testing.T) {
	for selector, sel := range importedSelectors {
		t.Run(selector, func(t *testing.T) {
			held := inboundMySQLPath("h-imported")
			sel.held(&held)
			prior := templateWithPaths(held)

			inserted := pathWithDirection("inbound")
			kept := pathWithDirection("inbound")
			switch selector {
			case "source_named_network":
				inserted.SourceNamedNetwork = namedNetwork(noValue, types.StringValue("branch-offices"))
				kept.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), noValue)
			case "source_tag_based_policy":
				inserted.SourceTagBasedPolicy = tagBasedPolicy(noValue, types.StringValue("payroll-batch"), noValue)
				kept.SourceTagBasedPolicy = tagBasedPolicy(types.StringValue(importedSegmentID), noValue, noValue)
			}
			config := templateWithPaths(inserted, kept)
			config.ID = types.StringNull()

			// Terraform proposes the prior value by position: the inserted path
			// gets the ID of the path that was first.
			proposedInserted, proposedKept := held, kept
			proposedInserted.ID = types.StringNull()
			switch selector {
			case "source_named_network":
				proposedInserted.SourceNamedNetwork = namedNetwork(held.SourceNamedNetwork.NamedNetworkID, inserted.SourceNamedNetwork.NamedNetworkName)
			case "source_tag_based_policy":
				proposedInserted.SourceTagBasedPolicy = tagBasedPolicy(held.SourceTagBasedPolicy.TagBasedPolicyID, inserted.SourceTagBasedPolicy.TagBasedPolicyName, held.SourceTagBasedPolicy.Criteria)
			}
			proposed := templateWithPaths(proposedInserted, proposedKept)

			_, planErrs, _ := templatePlan{&prior, &config, &proposed}.run(t)
			want := `AttributeName("template_paths").ElementKeyInt(0).AttributeName("` + selector + `"): template_paths[0].` + selector + " must set " + sel.idAttribute
			if len(planErrs) != 1 || !strings.HasPrefix(planErrs[0], want) {
				t.Errorf("plan errors = %q, want one starting %q", planErrs, want)
			}
		})
	}
}

// A name-only selector on a path that moved takes the ID of the state path
// whose selector has that name, not of the path now at its position.
func TestTemplatePathSelectorTakesTheIDOfTheStateSelectorWithItsName(t *testing.T) {
	for selector, sel := range importedSelectors {
		t.Run(selector, func(t *testing.T) {
			held := inboundMySQLPath("h-imported")
			sel.held(&held)
			heldIP := inboundMySQLPath("h-ip")
			heldIP.SrcIP = types.StringValue("10.0.0.1")
			prior := templateWithPaths(held, heldIP)

			configuredIP := pathWithDirection("inbound")
			configuredIP.SrcIP = heldIP.SrcIP
			moved := pathWithDirection("inbound")
			sel.nameOnly(&moved)
			config := templateWithPaths(configuredIP, moved)
			config.ID = types.StringNull()

			// By position, the moved path has no prior selector to take an ID from.
			proposedIP := heldIP
			proposed := templateWithPaths(proposedIP, moved)
			proposed.TemplatePaths[1].ID = types.StringNull()

			validateErrs, planErrs, planned := templatePlan{&prior, &config, &proposed}.run(t)
			if len(validateErrs) > 0 || len(planErrs) > 0 {
				t.Fatalf("validate errors = %q, plan errors = %q; want none", validateErrs, planErrs)
			}
			want := map[string]string{"source_named_network": importedNamedNetworkID, "source_tag_based_policy": importedSegmentID}[selector]
			if got := plannedSelectorID(t, planned, 1, selector, sel.idAttribute); !got.Equal(tftypes.NewValue(tftypes.String, want)) {
				t.Errorf("planned %s = %v, want %q, the ID of the state selector with that name", sel.idAttribute, got, want)
			}
		})
	}
}

// Paths that set their selector IDs keep them when reordered.
func TestTemplatePathSelectorsWithIDsKeepThemWhenReordered(t *testing.T) {
	const secondNetworkID = "3c9d2e71-5a4b-4c8f-b0e6-7f1a2d3b4c5e"
	first, second := inboundMySQLPath("h-1"), inboundMySQLPath("h-2")
	first.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), types.StringValue("corp-networks"))
	second.SourceNamedNetwork = namedNetwork(types.StringValue(secondNetworkID), types.StringValue("branch-offices"))
	prior := templateWithPaths(first, second)

	configuredSecond, configuredFirst := pathWithDirection("inbound"), pathWithDirection("inbound")
	configuredSecond.SourceNamedNetwork = namedNetwork(types.StringValue(secondNetworkID), noValue)
	configuredFirst.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), noValue)
	config := templateWithPaths(configuredSecond, configuredFirst)
	config.ID = types.StringNull()

	proposedSecond, proposedFirst := first, second
	proposedSecond.SourceNamedNetwork = namedNetwork(types.StringValue(secondNetworkID), first.SourceNamedNetwork.NamedNetworkName)
	proposedFirst.SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), second.SourceNamedNetwork.NamedNetworkName)
	proposed := templateWithPaths(proposedSecond, proposedFirst)

	validateErrs, planErrs, planned := templatePlan{&prior, &config, &proposed}.run(t)
	if len(validateErrs) > 0 || len(planErrs) > 0 {
		t.Fatalf("validate errors = %q, plan errors = %q; want none", validateErrs, planErrs)
	}
	for i, want := range []string{secondNetworkID, importedNamedNetworkID} {
		if got := plannedSelectorID(t, planned, i, "source_named_network", "named_network_id"); !got.Equal(tftypes.NewValue(tftypes.String, want)) {
			t.Errorf("planned template_paths[%d] named_network_id = %v, want %q", i, got, want)
		}
	}
}

// The state selector a name-only selector takes its ID from must be of the same
// kind and must name a single ID; source and destination share one pool.
func TestTemplatePathSelectorNameMatchesOnlyOneIDOfItsKind(t *testing.T) {
	const otherID = "3c9d2e71-5a4b-4c8f-b0e6-7f1a2d3b4c5e"
	outbound := func(id string, set func(p *tfTypes.MetadataPath)) tfTypes.MetadataPath {
		p := inboundMySQLPath(id)
		p.Direction = types.StringValue("outbound")
		set(&p)
		return p
	}
	corpNetwork := func(id types.String) func(p *tfTypes.MetadataPath) {
		return func(p *tfTypes.MetadataPath) {
			p.DestinationNamedNetwork = namedNetwork(id, types.StringValue("corp-networks"))
		}
	}
	cases := map[string]struct {
		held    []tfTypes.MetadataPath
		wantID  string
		wantErr bool
	}{
		"a source selector with the name": {
			held: []tfTypes.MetadataPath{func() tfTypes.MetadataPath {
				p := inboundMySQLPath("h-1")
				importedSelectors["source_named_network"].held(&p)
				return p
			}()},
			wantID: importedNamedNetworkID,
		},
		"a destination selector with the name": {
			held:   []tfTypes.MetadataPath{outbound("h-1", corpNetwork(types.StringValue(otherID)))},
			wantID: otherID,
		},
		"two selectors with the name and different IDs": {
			held: []tfTypes.MetadataPath{
				outbound("h-1", corpNetwork(types.StringValue(otherID))),
				outbound("h-2", corpNetwork(types.StringValue(importedNamedNetworkID))),
			},
			wantErr: true,
		},
		"only a segment with the name": {
			held: []tfTypes.MetadataPath{outbound("h-1", func(p *tfTypes.MetadataPath) {
				p.DestinationTagBasedPolicy = tagBasedPolicy(types.StringValue(importedSegmentID), types.StringValue("corp-networks"), noValue)
			})},
			wantErr: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			prior := templateWithPaths(c.held...)
			var configured []tfTypes.MetadataPath
			for _, h := range c.held {
				p := h
				p.ID = types.StringNull()
				configured = append(configured, p)
			}
			added := pathWithDirection("outbound")
			added.DestinationNamedNetwork = namedNetwork(noValue, types.StringValue("corp-networks"))
			config := templateWithPaths(append(configured, added)...)
			config.ID = types.StringNull()
			proposed := templateWithPaths(append(append([]tfTypes.MetadataPath{}, c.held...), added)...)

			_, planErrs, planned := templatePlan{&prior, &config, &proposed}.run(t)
			at := len(c.held)
			if c.wantErr {
				want := fmt.Sprintf("template_paths[%d].destination_named_network must set named_network_id", at)
				if len(planErrs) != 1 || !strings.Contains(planErrs[0], want) {
					t.Errorf("plan errors = %q, want one containing %q", planErrs, want)
				}
				return
			}
			if len(planErrs) > 0 {
				t.Fatalf("plan errors = %q; want none", planErrs)
			}
			if got := plannedSelectorID(t, planned, at, "destination_named_network", "named_network_id"); !got.Equal(tftypes.NewValue(tftypes.String, c.wantID)) {
				t.Errorf("planned named_network_id = %v, want %q", got, c.wantID)
			}
		})
	}
}

// A name known only at apply leaves the ID unknown at plan; apply checks it.
func TestTemplatePathSelectorNameKnownOnlyAtApplyPassesThePlan(t *testing.T) {
	held := inboundMySQLPath("h-1")
	importedSelectors["source_named_network"].held(&held)
	prior := templateWithPaths(held)
	configured := pathWithDirection("inbound")
	configured.SourceNamedNetwork = namedNetwork(noValue, types.StringUnknown())
	config := templateWithPaths(configured)
	config.ID = types.StringNull()
	proposed := templateWithPaths(held)
	proposed.TemplatePaths[0].SourceNamedNetwork = namedNetwork(types.StringValue(importedNamedNetworkID), types.StringUnknown())

	validateErrs, planErrs, planned := templatePlan{&prior, &config, &proposed}.run(t)
	if len(validateErrs) > 0 || len(planErrs) > 0 {
		t.Fatalf("validate errors = %q, plan errors = %q; want none", validateErrs, planErrs)
	}
	if got := plannedSelectorID(t, planned, 0, "source_named_network", "named_network_id"); got.IsKnown() {
		t.Errorf("planned named_network_id = %v, want unknown until the name is known", got)
	}
}
