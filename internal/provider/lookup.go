package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/operations"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// isXshieldUUID reports whether an import identifier is an object id rather than
// a name. Every resource used to carry its own copy of this check.
func isXshieldUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// criteriaNameEquals builds a `<field> = '<name>'` search criteria.
//
// The criteria grammar has no escape sequence inside a quoted literal, so a name
// containing a quote has to use the other quote character, and a name containing
// both cannot be expressed at all. Interpolating blindly produced a criteria the
// backend rejected as a syntax error, with no hint about the cause.
func criteriaNameEquals(field, name string) (string, error) {
	switch {
	case !strings.Contains(name, "'"):
		return fmt.Sprintf("%s = '%s'", field, name), nil
	case !strings.Contains(name, `"`):
		return fmt.Sprintf(`%s = "%s"`, field, name), nil
	default:
		return "", fmt.Errorf(
			"%q contains both a single and a double quote, which the search criteria grammar cannot express; look the object up by id instead",
			name)
	}
}

// uniqueMatch returns the single id whose name matches exactly.
//
// The list endpoints match loosely, so the caller has to filter, and names are
// not unique for every object type. Returning the first hit silently bound the
// configuration to an arbitrary object.
func uniqueMatch(kind, name string, ids []string) (string, error) {
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", fmt.Errorf("no %s named %q", kind, name)
	default:
		return "", fmt.Errorf("%d %ss are named %q; use the id instead of the name", len(ids), kind, name)
	}
}

func findAssetIDByName(ctx context.Context, client *sdk.Xshield, name string) (string, error) {
	criteria, err := criteriaNameEquals("assetName", name)
	if err != nil {
		return "", err
	}
	res, err := client.Assets.ListAssets(ctx,
		operations.ListAssetsRequest{SearchInput: shared.SearchInput{Criteria: criteria}},
		operations.WithAcceptHeaderOverride(operations.AcceptHeaderEnumApplicationJson))
	if err != nil {
		return "", fmt.Errorf("listing assets: %w", err)
	}
	var ids []string
	if res.AssetSearchResults != nil {
		for _, item := range res.AssetSearchResults.Items {
			if item.AssetName == name && item.AssetID != nil {
				ids = append(ids, *item.AssetID)
			}
		}
	}
	return uniqueMatch("asset", name, ids)
}

func findSegmentIDByName(ctx context.Context, client *sdk.Xshield, name string) (string, error) {
	criteria, err := criteriaNameEquals("tagBasedPolicyName", name)
	if err != nil {
		return "", err
	}
	res, err := client.Tagbasedpolicies.ListTagBasedPolicies(ctx,
		operations.ListTagBasedPoliciesRequest{SearchInput: shared.SearchInput{Criteria: criteria}})
	if err != nil {
		return "", fmt.Errorf("listing segments: %w", err)
	}
	var ids []string
	if res.TagBasedPolicies != nil {
		for _, item := range res.TagBasedPolicies.Items {
			if item.TagBasedPolicyName != nil && *item.TagBasedPolicyName == name && item.TagBasedPolicyID != nil {
				ids = append(ids, *item.TagBasedPolicyID)
			}
		}
	}
	return uniqueMatch("segment", name, ids)
}

func findTemplateIDByName(ctx context.Context, client *sdk.Xshield, name string) (string, error) {
	criteria, err := criteriaNameEquals("templateName", name)
	if err != nil {
		return "", err
	}
	res, err := client.Templates.ListTemplates(ctx,
		operations.ListTemplatesRequest{SearchInput: shared.SearchInput{Criteria: criteria}})
	if err != nil {
		return "", fmt.Errorf("listing templates: %w", err)
	}
	var ids []string
	if res.Templates != nil {
		for _, item := range res.Templates.Items {
			if item.TemplateName != nil && *item.TemplateName == name && item.TemplateID != nil {
				ids = append(ids, *item.TemplateID)
			}
		}
	}
	return uniqueMatch("template", name, ids)
}

func findNamedNetworkIDByName(ctx context.Context, client *sdk.Xshield, name string) (string, error) {
	criteria, err := criteriaNameEquals("namedNetworkName", name)
	if err != nil {
		return "", err
	}
	res, err := client.Namednetworks.ListNamedNetworks(ctx,
		operations.ListNamedNetworksRequest{SearchInput: shared.SearchInput{Criteria: criteria}})
	if err != nil {
		return "", fmt.Errorf("listing named networks: %w", err)
	}
	var ids []string
	if res.NamedNetworks != nil {
		for _, item := range res.NamedNetworks.Items {
			if item.NamedNetworkName != nil && *item.NamedNetworkName == name && item.ID != nil {
				ids = append(ids, *item.ID)
			}
		}
	}
	return uniqueMatch("named network", name, ids)
}

func findTagRuleIDByName(ctx context.Context, client *sdk.Xshield, name string) (string, error) {
	criteria, err := criteriaNameEquals("ruleName", name)
	if err != nil {
		return "", err
	}
	res, err := client.Tagrules.ListTagRules(ctx,
		operations.ListTagRulesRequest{SearchInput: shared.SearchInput{Criteria: criteria}})
	if err != nil {
		return "", fmt.Errorf("listing tag rules: %w", err)
	}
	var ids []string
	if res.TagRules != nil {
		for _, item := range res.TagRules.Items {
			if item.RuleName != nil && *item.RuleName == name && item.ID != nil {
				ids = append(ids, *item.ID)
			}
		}
	}
	return uniqueMatch("tag rule", name, ids)
}

// resolveAssetLookup turns whichever of id or asset_name was configured into an
// asset id. Names are resolved through the asset search, so a practitioner who
// has never opened the portal can still address an asset.
func resolveAssetLookup(ctx context.Context, client *sdk.Xshield, data *AssetDataSourceModel, diags *diag.Diagnostics) (string, bool) {
	id := strings.TrimSpace(data.ID.ValueString())
	name := strings.TrimSpace(data.AssetName.ValueString())

	switch {
	case id != "" && name != "":
		diags.AddError("Specify either id or asset_name, not both",
			"Both identify the same asset, and supplying both leaves it ambiguous which one wins "+
				"if they disagree. Remove whichever is not the one you meant.")
		return "", false
	case id != "":
		return id, true
	case name != "":
		found, err := findAssetIDByName(ctx, client, name)
		if err != nil {
			diags.AddAttributeError(path.Root("asset_name"), "Cannot find that asset", err.Error())
			return "", false
		}
		return found, true
	default:
		diags.AddError("An asset must be identified",
			"Set id to the asset's UUID, or asset_name to its name.")
		return "", false
	}
}
