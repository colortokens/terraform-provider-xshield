package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestProviderSchemaValidateImplementation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resp := &fwprovider.SchemaResponse{}
	New("test")().Schema(ctx, fwprovider.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema produced errors: %s", resp.Diagnostics)
	}

	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("provider schema is not a valid implementation: %s", diags)
	}
}

func TestProviderMetadata(t *testing.T) {
	t.Parallel()

	resp := &fwprovider.MetadataResponse{}
	New("1.2.3")().Metadata(context.Background(), fwprovider.MetadataRequest{}, resp)

	if resp.TypeName != "xshield" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "xshield")
	}

	if resp.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", resp.Version, "1.2.3")
	}
}

func completeProviderModel() XshieldProviderModel {
	return XshieldProviderModel{
		ServerURL:          types.StringValue("https://example.invalid"),
		TenancyId:          types.StringValue("tenancy"),
		PrincipalId:        types.StringValue("user"),
		FingerPrint:        types.StringValue("fingerprint"),
		PrivateKeyLocation: types.StringValue("/tmp/key.pem"),
	}
}

func TestBuildConfigProvider(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate            func(*XshieldProviderModel)
		wantAttributePath string
	}{
		"complete": {
			mutate: func(*XshieldProviderModel) {},
		},
		"empty tenancy id": {
			mutate:            func(m *XshieldProviderModel) { m.TenancyId = types.StringValue("") },
			wantAttributePath: "tenancy_id",
		},
		"null tenancy id": {
			mutate:            func(m *XshieldProviderModel) { m.TenancyId = types.StringNull() },
			wantAttributePath: "tenancy_id",
		},
		"empty user id": {
			mutate:            func(m *XshieldProviderModel) { m.PrincipalId = types.StringValue("") },
			wantAttributePath: "user_id",
		},
		"empty fingerprint": {
			mutate:            func(m *XshieldProviderModel) { m.FingerPrint = types.StringValue("") },
			wantAttributePath: "fingerprint",
		},
		"empty private key path": {
			mutate:            func(m *XshieldProviderModel) { m.PrivateKeyLocation = types.StringValue("") },
			wantAttributePath: "private_key_path",
		},
	}

	// Every attribute the diagnostics can point at must exist in the schema,
	// otherwise Terraform renders the error against an unknown path.
	schemaResp := &fwprovider.SchemaResponse{}
	New("test")().Schema(context.Background(), fwprovider.SchemaRequest{}, schemaResp)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			model := completeProviderModel()
			test.mutate(&model)

			resp := &fwprovider.ConfigureResponse{}
			config := buildConfigProvider(model, resp)

			if test.wantAttributePath == "" {
				if resp.Diagnostics.HasError() {
					t.Fatalf("unexpected diagnostics: %s", resp.Diagnostics)
				}
				if config == nil {
					t.Fatal("expected a configuration provider for a complete model")
				}
				return
			}

			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error diagnostic")
			}

			if config != nil {
				t.Error("expected a nil configuration provider when validation fails")
			}

			var paths []string
			for _, d := range resp.Diagnostics.Errors() {
				withPath, ok := d.(diag.DiagnosticWithPath)
				if !ok {
					t.Fatalf("diagnostic %q is not attached to an attribute path", d.Summary())
				}
				paths = append(paths, withPath.Path().String())
			}

			if len(paths) != 1 || paths[0] != test.wantAttributePath {
				t.Fatalf("diagnostic paths = %v, want [%s]", paths, test.wantAttributePath)
			}

			if _, ok := schemaResp.Schema.Attributes[test.wantAttributePath]; !ok {
				t.Fatalf("diagnostic points at %q, which is not a provider schema attribute", test.wantAttributePath)
			}
		})
	}
}
