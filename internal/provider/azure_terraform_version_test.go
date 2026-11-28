package provider

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// An import block with for_each needs Terraform 1.7. handover.tf and recovery.tf are copied into a workspace on their own,
// so each Azure configuration that imports says so itself, and an older Terraform stops at init naming the version
// rather than failing on the block.
func TestEveryAzureConfigurationThatImportsRequiresTerraform17(t *testing.T) {
	t.Parallel()
	dirs, err := filepath.Glob("../../examples/enforcement-snapshot/*-azure")
	if err != nil {
		t.Fatal(err)
	}
	dirs = append(dirs, "../../modules/azure")
	importing := 0
	for _, dir := range dirs {
		paths, err := filepath.Glob(filepath.Join(dir, "*.tf"))
		if err != nil || len(paths) == 0 {
			t.Fatalf("no Terraform files in %s: %v", dir, err)
		}
		imports, versions := false, []string{}
		parser := hclparse.NewParser()
		for _, path := range paths {
			file, diags := parser.ParseHCLFile(path)
			if diags.HasErrors() {
				t.Fatalf("%s: %s", path, diags.Error())
			}
			for _, block := range file.Body.(*hclsyntax.Body).Blocks {
				switch block.Type {
				case "import":
					imports = true
				case "terraform":
					if attr, ok := block.Body.Attributes["required_version"]; ok {
						value, diags := attr.Expr.Value(nil)
						if diags.HasErrors() {
							t.Fatalf("%s: required_version: %s", path, diags.Error())
						}
						versions = append(versions, value.AsString())
					}
				}
			}
		}
		if !imports {
			continue
		}
		importing++
		if !slices.Contains(versions, ">= 1.7.0") {
			t.Errorf("%s has an import block but requires Terraform %q, want \">= 1.7.0\"", dir, versions)
		}
	}
	if importing == 0 {
		t.Fatal("no Azure configuration imports anything, so nothing was checked")
	}
}
