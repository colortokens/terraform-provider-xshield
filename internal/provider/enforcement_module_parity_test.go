package provider

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// A customer who runs the aws module learns the azure one by its inputs and outputs, so the two keep the same ones,
// with the same types and defaults, wherever the clouds allow. Each way they differ is listed here with its reason.
var enforcementModuleDifferences = map[string]string{
	"variable region default":  "The aws module defaults to the AWS provider's region. The azurerm provider has no region, so the azure module needs one.",
	"variable region nullable": "The azure module's region has no default, and null would name no region.",
	"output security_group_ids": "The aws module's map from asset to its one security group. The azure module's network_security_group_ids " +
		"lists a group for each of an asset's network interfaces.",
	"output network_security_group_ids": "See security_group_ids: Azure calls the group a network security group, and an asset can have several.",
	"output attachment_keys":            "Azure associates a group with a network interface, and the azure module's interface_association_keys names those.",
	"output interface_association_keys": "See attachment_keys.",
	"output network_acl_entry_keys": "The aws module blocks malicious addresses in network ACLs. The azure module blocks them with deny rules " +
		"in the group itself, ahead of its allows.",
	"output directory_entries": "On AWS the workspace that owns a database attaches its group, through a directory parameter. On Azure a " +
		"database or function is reached through its subnet, which the azure module associates itself.",
	"variable customer_network_security_groups_in_code": "On AWS Xshield's rules reach a group of yours only through " +
		"xshield_aws_security_group_rules in that group's own configuration. On Azure the module writes them into a group of yours as " +
		"rules of their own, except in a group whose configuration declares its rules inline, which this lists.",
}

type moduleInterface struct {
	variables map[string]map[string]string
	outputs   map[string]bool
}

func readModuleInterface(t *testing.T, dir string) moduleInterface {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no Terraform files in %s: %v", dir, err)
	}
	module := moduleInterface{variables: map[string]map[string]string{}, outputs: map[string]bool{}}
	parser := hclparse.NewParser()
	for _, path := range paths {
		file, diags := parser.ParseHCLFile(path)
		if diags.HasErrors() {
			t.Fatalf("%s: %s", path, diags.Error())
		}
		for _, block := range file.Body.(*hclsyntax.Body).Blocks {
			switch block.Type {
			case "variable":
				arguments := map[string]string{}
				for _, name := range []string{"type", "default", "nullable", "sensitive"} {
					if attribute, ok := block.Body.Attributes[name]; ok {
						arguments[name] = string(attribute.Expr.Range().SliceBytes(file.Bytes))
					}
				}
				module.variables[block.Labels[0]] = arguments
			case "output":
				module.outputs[block.Labels[0]] = true
			}
		}
	}
	return module
}

func enforcementModuleDifferencesBetween(aws, azure moduleInterface) []string {
	differences := []string{}
	for name := range maps.Keys(aws.variables) {
		if _, ok := azure.variables[name]; !ok {
			differences = append(differences, "variable "+name)
		}
	}
	for name, azureArguments := range azure.variables {
		awsArguments, ok := aws.variables[name]
		if !ok {
			differences = append(differences, "variable "+name)
			continue
		}
		for _, argument := range []string{"type", "default", "nullable", "sensitive"} {
			if awsArguments[argument] != azureArguments[argument] {
				differences = append(differences, "variable "+name+" "+argument)
			}
		}
	}
	for name := range aws.outputs {
		if !azure.outputs[name] {
			differences = append(differences, "output "+name)
		}
	}
	for name := range azure.outputs {
		if !aws.outputs[name] {
			differences = append(differences, "output "+name)
		}
	}
	slices.Sort(differences)
	return differences
}

func TestAWSAndAzureModulesDifferOnlyWhereTheCloudsDo(t *testing.T) {
	modules := filepath.Join("..", "..", "modules")
	differences := enforcementModuleDifferencesBetween(readModuleInterface(t, filepath.Join(modules, "aws")), readModuleInterface(t, filepath.Join(modules, "azure")))

	for _, difference := range differences {
		if enforcementModuleDifferences[difference] == "" {
			t.Errorf("the aws and azure modules differ in %s: make them the same, or give the reason in enforcementModuleDifferences", difference)
		}
	}
	for difference := range enforcementModuleDifferences {
		if !slices.Contains(differences, difference) {
			t.Errorf("the aws and azure modules no longer differ in %s: remove it from enforcementModuleDifferences", difference)
		}
	}
}
