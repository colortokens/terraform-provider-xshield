package provider

import (
	"context"
	"strings"
	"testing"

	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
)

// resourceSchemas returns every registered resource keyed by its Terraform type
// name, so schema assertions cover the provider as a whole rather than a
// hand-maintained subset.
func resourceSchemas(t *testing.T) map[string]fwresource.SchemaResponse {
	t.Helper()

	ctx := context.Background()
	schemas := make(map[string]fwresource.SchemaResponse)

	for _, newResource := range New("test")().(*XshieldProvider).Resources(ctx) {
		r := newResource()

		metadataResp := &fwresource.MetadataResponse{}
		r.Metadata(ctx, fwresource.MetadataRequest{ProviderTypeName: "xshield"}, metadataResp)

		schemaResp := &fwresource.SchemaResponse{}
		r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)

		if _, duplicate := schemas[metadataResp.TypeName]; duplicate {
			t.Fatalf("resource type name %q is registered twice", metadataResp.TypeName)
		}

		schemas[metadataResp.TypeName] = *schemaResp
	}

	return schemas
}

func dataSourceSchemas(t *testing.T) map[string]fwdatasource.SchemaResponse {
	t.Helper()

	ctx := context.Background()
	schemas := make(map[string]fwdatasource.SchemaResponse)

	for _, newDataSource := range New("test")().(*XshieldProvider).DataSources(ctx) {
		d := newDataSource()

		metadataResp := &fwdatasource.MetadataResponse{}
		d.Metadata(ctx, fwdatasource.MetadataRequest{ProviderTypeName: "xshield"}, metadataResp)

		schemaResp := &fwdatasource.SchemaResponse{}
		d.Schema(ctx, fwdatasource.SchemaRequest{}, schemaResp)

		if _, duplicate := schemas[metadataResp.TypeName]; duplicate {
			t.Fatalf("data source type name %q is registered twice", metadataResp.TypeName)
		}

		schemas[metadataResp.TypeName] = *schemaResp
	}

	return schemas
}

func TestResourceSchemasValidateImplementation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for typeName, schemaResp := range resourceSchemas(t) {
		t.Run(typeName, func(t *testing.T) {
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("schema produced errors: %s", schemaResp.Diagnostics)
			}

			if diags := schemaResp.Schema.ValidateImplementation(ctx); diags.HasError() {
				t.Fatalf("schema is not a valid implementation: %s", diags)
			}
		})
	}
}

func TestDataSourceSchemasValidateImplementation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for typeName, schemaResp := range dataSourceSchemas(t) {
		t.Run(typeName, func(t *testing.T) {
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("schema produced errors: %s", schemaResp.Diagnostics)
			}

			if diags := schemaResp.Schema.ValidateImplementation(ctx); diags.HasError() {
				t.Fatalf("schema is not a valid implementation: %s", diags)
			}
		})
	}
}

func TestTypeNamesArePrefixed(t *testing.T) {
	t.Parallel()

	for typeName := range resourceSchemas(t) {
		if !strings.HasPrefix(typeName, "xshield_") {
			t.Errorf("resource type name %q is not prefixed with the provider type name", typeName)
		}
	}

	for typeName := range dataSourceSchemas(t) {
		if !strings.HasPrefix(typeName, "xshield_") {
			t.Errorf("data source type name %q is not prefixed with the provider type name", typeName)
		}
	}
}

// dataSourceLookupAttributes names, per data source, the attributes its Read
// accepts as a lookup key. Each must be settable in configuration, otherwise
// the read requests the empty identifier no matter what the practitioner wrote.
var dataSourceLookupAttributes = map[string][]string{
	// Single-object lookups: either key identifies one record.
	"xshield_asset":         {"id", "asset_name"},
	"xshield_named_network": {"id", "named_network_name"},
	"xshield_segment":       {"id", "tag_based_policy_name"},
	"xshield_tag_rule":      {"id", "rule_name"},
	"xshield_template":      {"id", "template_name"},
	"xshield_work_request":  {"id"},

	// Searches: the criteria is what selects the rows. max_results bounds the
	// page and is deliberately not a lookup key.
	"xshield_assets":         {"criteria"},
	"xshield_named_networks": {"criteria"},
	"xshield_segments":       {"criteria"},
	"xshield_tag_rules":      {"criteria"},
	"xshield_templates":      {"criteria"},
	"xshield_open_ports":     {"criteria"},
	"xshield_paths":          {"criteria"},

	// Scoped metadata reads.
	"xshield_fields":       {"scope"},
	"xshield_field_values": {"scope", "field"},

	// Deployment inspection: the target is a criteria or an asset plus direction.
	"xshield_criteria":              {"criteria"},
	"xshield_policy_changes":        {"criteria", "direction"},
	"xshield_deployment_simulation": {"asset_id", "direction"},

	// Enforcement point: the account and region select the snapshot. version is
	// an optional pin and deliberately not a lookup key, since omitting it is
	// what makes the read converge on the expected version.
	"xshield_enforcement_snapshot": {"cloud_account_id", "region"},
	"xshield_enforcement_status":   {"cloud_account_id", "region"},
}

func TestDataSourceLookupKeysAreConfigurable(t *testing.T) {
	t.Parallel()

	schemas := dataSourceSchemas(t)

	for typeName, lookupAttributes := range dataSourceLookupAttributes {
		t.Run(typeName, func(t *testing.T) {
			schemaResp, ok := schemas[typeName]
			if !ok {
				t.Fatalf("data source %s is not registered", typeName)
			}

			for _, name := range lookupAttributes {
				attribute, ok := schemaResp.Schema.Attributes[name]
				if !ok {
					t.Errorf("lookup attribute %q is missing from the schema", name)
					continue
				}

				if !attribute.IsRequired() && !attribute.IsOptional() {
					t.Errorf("%q is a lookup key but is not configurable, so reads cannot select by it", name)
				}
			}
		})
	}
}

// TestDataSourcesCoverEveryLookupAttribute keeps the table above honest when a
// data source is added.
func TestDataSourcesCoverEveryLookupAttribute(t *testing.T) {
	t.Parallel()

	for typeName := range dataSourceSchemas(t) {
		if _, ok := dataSourceLookupAttributes[typeName]; !ok {
			t.Errorf("data source %s has no entry in dataSourceLookupAttributes", typeName)
		}
	}
}

// TestResourcesSupportImport keeps the documented import.sh examples honest:
// each resource claims importability and imports by "id", so "id" must exist in
// the schema for ImportState to write to.
func TestResourcesSupportImport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemas := resourceSchemas(t)

	for _, newResource := range New("test")().(*XshieldProvider).Resources(ctx) {
		r := newResource()

		metadataResp := &fwresource.MetadataResponse{}
		r.Metadata(ctx, fwresource.MetadataRequest{ProviderTypeName: "xshield"}, metadataResp)

		t.Run(metadataResp.TypeName, func(t *testing.T) {
			if _, ok := r.(fwresource.ResourceWithImportState); !ok {
				t.Fatal("resource does not implement ResourceWithImportState")
			}

			if _, ok := schemas[metadataResp.TypeName].Schema.Attributes["id"]; !ok {
				t.Error(`resource imports by "id" but has no "id" attribute`)
			}
		})
	}
}

// TestResourcesAreConfigurable asserts every resource and data source accepts
// the SDK client handed to it by the provider. One missing Configure silently
// keeps a nil client and panics on first use.
func TestResourcesAreConfigurable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, newResource := range New("test")().(*XshieldProvider).Resources(ctx) {
		r := newResource()

		metadataResp := &fwresource.MetadataResponse{}
		r.Metadata(ctx, fwresource.MetadataRequest{ProviderTypeName: "xshield"}, metadataResp)

		if _, ok := r.(fwresource.ResourceWithConfigure); !ok {
			t.Errorf("%s does not implement ResourceWithConfigure", metadataResp.TypeName)
		}
	}

	for _, newDataSource := range New("test")().(*XshieldProvider).DataSources(ctx) {
		d := newDataSource()

		metadataResp := &fwdatasource.MetadataResponse{}
		d.Metadata(ctx, fwdatasource.MetadataRequest{ProviderTypeName: "xshield"}, metadataResp)

		if _, ok := d.(fwdatasource.DataSourceWithConfigure); !ok {
			t.Errorf("%s does not implement DataSourceWithConfigure", metadataResp.TypeName)
		}
	}
}

// resourcesWithoutDataSource records the resources that deliberately have no
// same-named data source, with the reason. Anything not listed here still fails,
// so a genuinely dropped registration is still caught.
var resourcesWithoutDataSource = map[string]string{
	"xshield_policy_deployment": "a deployment is an action, not a stored object: " +
		"the API has no read-by-id for one. xshield_policy_changes and " +
		"xshield_deployment_simulation are its read-only counterparts.",
	"xshield_enforcement_receipt": "a receipt reports an apply rather than storing an " +
		"object Terraform reads back. xshield_enforcement_status is its read-only counterpart.",
}

// TestEveryResourceHasADataSource keeps the two registrations in step; a
// resource without its read-only counterpart is the usual sign a registration
// was dropped.
func TestEveryResourceHasADataSource(t *testing.T) {
	t.Parallel()

	dataSources := dataSourceSchemas(t)

	for typeName := range resourceSchemas(t) {
		if _, ok := dataSources[typeName]; ok {
			continue
		}
		if _, exempt := resourcesWithoutDataSource[typeName]; exempt {
			continue
		}
		t.Errorf("resource %s has no matching data source", typeName)
	}
}

// TestExemptionsFromTheDataSourceRuleStillApply stops the list above outliving
// the resources it excuses, or excusing one that has since grown a data source.
func TestExemptionsFromTheDataSourceRuleStillApply(t *testing.T) {
	t.Parallel()

	resources := resourceSchemas(t)
	dataSources := dataSourceSchemas(t)

	for typeName := range resourcesWithoutDataSource {
		if _, ok := resources[typeName]; !ok {
			t.Errorf("%s is exempted but is no longer a registered resource", typeName)
		}
		if _, ok := dataSources[typeName]; ok {
			t.Errorf("%s now has a data source, so its exemption should be removed", typeName)
		}
	}
}
