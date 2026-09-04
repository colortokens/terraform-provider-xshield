package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The asset service rewrites a segment criteria that does not already constrain
// managedby, storing "(<criteria>) AND 'managedby' in ('colortokens')" and
// returning that on every later read. Mirroring the rewrite here keeps config,
// plan, state and the API on the same string, so a diff means real drift.
const (
	managedByField      = "managedby"
	defaultManagedByLoV = "colortokens"
)

func canonicalSegmentCriteria(criteria string) string {
	if strings.TrimSpace(criteria) == "" || criteriaReferencesManagedBy(criteria) {
		return criteria
	}
	return fmt.Sprintf("(%s) AND '%s' in ('%s')", criteria, managedByField, defaultManagedByLoV)
}

type criteriaToken struct {
	text  string
	field bool // a bare or quoted word, so a candidate field name
}

// scanCriteria splits a criteria into the few token classes needed to tell a
// field name from a value. It deliberately does not validate the criteria; the
// backend parser owns that.
func scanCriteria(criteria string) []criteriaToken {
	var tokens []criteriaToken
	runes := []rune(criteria)
	for i := 0; i < len(runes); {
		c := runes[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"':
			// CTQL has no escape sequence inside a quoted literal.
			quote := c
			j := i + 1
			for j < len(runes) && runes[j] != quote {
				j++
			}
			tokens = append(tokens, criteriaToken{text: string(runes[i+1 : min(j, len(runes))]), field: true})
			i = min(j+1, len(runes))
		case isCriteriaWordStart(c):
			j := i
			for j < len(runes) && isCriteriaWordPart(runes[j]) {
				j++
			}
			tokens = append(tokens, criteriaToken{text: string(runes[i:j]), field: true})
			i = j
		case c == '!' || c == '<' || c == '>' || c == '=':
			j := i + 1
			if j < len(runes) && runes[j] == '=' {
				j++
			}
			tokens = append(tokens, criteriaToken{text: string(runes[i:j])})
			i = j
		default:
			tokens = append(tokens, criteriaToken{text: string(c)})
			i++
		}
	}
	return tokens
}

func isCriteriaWordStart(c rune) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isCriteriaWordPart(c rune) bool {
	return isCriteriaWordStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '/'
}

// criteriaOperators are the tokens that can follow a field name. A word that is
// not followed by one of these is a value, not a field.
var criteriaOperators = map[string]bool{
	"=": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"in": true, "not": true, "like": true, "ilike": true, "between": true,
}

func criteriaReferencesManagedBy(criteria string) bool {
	tokens := scanCriteria(criteria)
	for i, tok := range tokens {
		if !tok.field || !strings.EqualFold(tok.text, managedByField) {
			continue
		}
		if i+1 < len(tokens) && criteriaOperators[strings.ToLower(tokens[i+1].text)] {
			return true
		}
	}
	return false
}

// The automation endpoint accepts test / enforce / disable but reads back
// under-test / enforced / disabled for the same setting. Terraform shows one
// vocabulary, the one you write.
var autoSyncReadToWrite = map[string]string{
	"under-test": "test",
	"enforced":   "enforce",
	"disabled":   "disable",
}

func normalizeAutoSyncDeploymentMode(mode *string) types.String {
	if mode == nil {
		return types.StringNull()
	}
	if write, ok := autoSyncReadToWrite[strings.ToLower(*mode)]; ok {
		return types.StringValue(write)
	}
	return types.StringValue(*mode)
}

// The backend stores -1 for an interval or threshold that does not apply,
// which it does whenever auto-sync is disabled or under test. Surfacing that
// sentinel as a number invites a plan that tries to "correct" it.
func autoSyncSentinelToNull(v *int64) types.Int64 {
	if v == nil || *v == -1 {
		return types.Int64Null()
	}
	return types.Int64Value(*v)
}

// resolveSegmentReferences fills in the id of any template or named network the
// practitioner referenced by name.
//
// The schema accepts either an id or a name, but every write path keys on the id:
// the create payload only carries ids, and the update diff maps by id. A name-only
// entry therefore used to be dropped on create and to collide under the empty-string
// key on update, so it silently never reconciled.
func resolveSegmentReferences(ctx context.Context, client *sdk.Xshield, data *SegmentResourceModel, diags *diag.Diagnostics) {
	for i := range data.Templates {
		ref := &data.Templates[i]
		if ref.TemplateID.ValueString() != "" || ref.TemplateName.ValueString() == "" {
			continue
		}
		name := ref.TemplateName.ValueString()
		id, err := findTemplateIDByName(ctx, client, name)
		if err != nil {
			diags.AddAttributeError(
				path.Root("templates").AtListIndex(i).AtName("template_name"),
				"Cannot resolve template name", err.Error())
			continue
		}
		ref.TemplateID = types.StringValue(id)
	}

	for i := range data.Namednetworks {
		ref := &data.Namednetworks[i]
		if ref.NamedNetworkID.ValueString() != "" || ref.NamedNetworkName.ValueString() == "" {
			continue
		}
		name := ref.NamedNetworkName.ValueString()
		id, err := findNamedNetworkIDByName(ctx, client, name)
		if err != nil {
			diags.AddAttributeError(
				path.Root("namednetworks").AtListIndex(i).AtName("named_network_name"),
				"Cannot resolve named network name", err.Error())
			continue
		}
		ref.NamedNetworkID = types.StringValue(id)
	}
}
