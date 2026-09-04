#!/usr/bin/env python3
"""Regenerates the asset resource/data-source model, schema and refresh mapping
from shared.AssetDetails, so every declared attribute is one the backend returns.

Splices the model struct and schema attribute map into the existing resource and
data source files (leaving CRUD untouched) and rewrites both *_sdk.go mappings.
"""
import os
import re
import sys

ROOT = sys.argv[1]
PROV = os.path.join(ROOT, "internal", "provider")
SHARED_GO = os.path.join(ROOT, "internal", "sdk", "models", "shared", "assetdetails.go")

# ---------------------------------------------------------------- field parsing
FIELD_RE = re.compile(r"^\t(\w+)\s+([\w\.\*\[\]]+)\s+`json:\"([^\",]+)")


def parse_fields():
    fields = []
    inside = False
    for line in open(SHARED_GO):
        if line.startswith("type AssetDetails struct {"):
            inside = True
            continue
        if inside:
            if line.startswith("}"):
                break
            m = FIELD_RE.match(line)
            if m:
                fields.append((m.group(1), m.group(2), m.group(3)))
    return fields


def snake(json_name):
    if json_name == "assetId":
        return "id"
    out = []
    for i, ch in enumerate(json_name):
        if ch.isupper():
            prev = json_name[i - 1] if i else ""
            nxt = json_name[i + 1] if i + 1 < len(json_name) else ""
            if i and (prev.islower() or prev.isdigit() or (prev.isupper() and nxt.islower())):
                out.append("_")
        out.append(ch.lower())
    return "".join(out)


# Nested object shapes: tf type name -> list of (TfField, tf_kind, SdkField, sdk_kind)
NESTED = {
    "Tag": [("ID", "string_ptr", "ID", None), ("IsCloudTag", "bool_ptr", "IsCloudTag", None),
            ("Key", "string_val", "Key", None), ("Value", "string_val", "Value", None)],
    "NetworkInterface": [("Flags", "string_list", "Flags", None), ("Ipaddresses", "string_list", "Ipaddresses", None),
                         ("Macaddress", "string_ptr", "Macaddress", None), ("Name", "string_val", "Name", None)],
    "Program": [("Image", "string_ptr", "Image", None), ("Name", "string_val", "Name", None),
                ("Path", "string_ptr", "Path", None)],
    "ReviewCoverage": [("Allowed", "int_ptr", "Allowed", None), ("AllowedPorts", "int_ptr", "AllowedPorts", None),
                       ("Reviewed", "int_ptr", "Reviewed", None), ("Total", "int_ptr", "Total", None),
                       ("Unreviewed", "int_ptr", "Unreviewed", None)],
    "MetadataNamedNetworkReference": [("NamedNetworkID", "string_ptr", "NamedNetworkID", None),
                                      ("NamedNetworkName", "string_ptr", "NamedNetworkName", None)],
    "TemplateReference": [("TemplateID", "string_ptr", "TemplateID", None),
                          ("TemplateName", "string_ptr", "TemplateName", None)],
    "AssetGroup": [("Groupid", "string_ptr", "Groupid", None)],
    "AssetUser": [("Assetid", "string_val", "Assetid", None), ("Domainname", "string_val", "Domainname", None),
                  ("Email", "string_ptr", "Email", None), ("Logincount", "int_ptr", "Logincount", None),
                  ("Name", "string_val", "Name", None), ("Scimuserid", "string_ptr", "Scimuserid", None),
                  ("Signedin", "bool_ptr", "Signedin", None)],
    "PendingChanges": [("AllowTemplates", "string_list", "AllowTemplates", None),
                       ("AssetPolicySyncPending", "bool_ptr", "AssetPolicySyncPending", None),
                       ("BlockTemplates", "string_list", "BlockTemplates", None),
                       ("InternetPaths", "int_ptr", "InternetPaths", None),
                       ("InternetPorts", "int_ptr", "InternetPorts", None),
                       ("IntranetPaths", "int_ptr", "IntranetPaths", None),
                       ("IntranetPorts", "int_ptr", "IntranetPorts", None),
                       ("NamednetworkChange", "string_list", "NamednetworkChange", None),
                       ("PeerChange", "bool_ptr", "PeerChange", None),
                       ("UnassignedAllowTemplates", "string_list", "UnassignedAllowTemplates", None),
                       ("UnassignedBlockTemplates", "string_list", "UnassignedBlockTemplates", None)],
    "FWConfigPendingChanges": [("FwCoexistenceCfgUpdatePending", "bool_ptr", "FwCoexistenceCfgUpdatePending", None),
                               ("IntranetChange", "bool_ptr", "IntranetChange", None),
                               ("IPV6BlanketAllow", "bool_ptr", "IPV6BlanketAllow", None)],
    "AppControlPendingChanges": [("AllowTemplates", "string_list", "AllowTemplates", None),
                                 ("BlockTemplates", "string_list", "BlockTemplates", None),
                                 ("ChangedApplications", "int_ptr", "ChangedApplications", None)],
}

NESTED_TFSDK = {
    "Tag": {"ID": "id", "IsCloudTag": "is_cloud_tag", "Key": "key", "Value": "value"},
    "NetworkInterface": {"Flags": "flags", "Ipaddresses": "ipaddresses", "Macaddress": "macaddress", "Name": "name"},
    "Program": {"Image": "image", "Name": "name", "Path": "path"},
    "ReviewCoverage": {"Allowed": "allowed", "AllowedPorts": "allowed_ports", "Reviewed": "reviewed",
                       "Total": "total", "Unreviewed": "unreviewed"},
    "MetadataNamedNetworkReference": {"NamedNetworkID": "named_network_id", "NamedNetworkName": "named_network_name"},
    "TemplateReference": {"TemplateID": "template_id", "TemplateName": "template_name"},
    "AssetGroup": {"Groupid": "groupid"},
    "AssetUser": {"Assetid": "assetid", "Domainname": "domainname", "Email": "email", "Logincount": "logincount",
                  "Name": "name", "Scimuserid": "scimuserid", "Signedin": "signedin"},
    "PendingChanges": {"AllowTemplates": "allow_templates", "AssetPolicySyncPending": "asset_policy_sync_pending",
                       "BlockTemplates": "block_templates", "InternetPaths": "internet_paths",
                       "InternetPorts": "internet_ports", "IntranetPaths": "intranet_paths",
                       "IntranetPorts": "intranet_ports", "NamednetworkChange": "namednetwork_change",
                       "PeerChange": "peer_change", "UnassignedAllowTemplates": "unassigned_allow_templates",
                       "UnassignedBlockTemplates": "unassigned_block_templates"},
    "FWConfigPendingChanges": {"FwCoexistenceCfgUpdatePending": "fw_coexistence_cfg_update_pending",
                               "IntranetChange": "intranet_change", "IPV6BlanketAllow": "ipv6_blanket_allow"},
    "AppControlPendingChanges": {"AllowTemplates": "allow_templates", "BlockTemplates": "block_templates",
                                 "ChangedApplications": "changed_applications"},
}

KIND_TF_TYPE = {"string_ptr": "types.String", "string_val": "types.String", "bool_ptr": "types.Bool",
                "int_ptr": "types.Int64", "string_list": "[]types.String"}
KIND_SCHEMA = {"string_ptr": "schema.StringAttribute", "string_val": "schema.StringAttribute",
               "bool_ptr": "schema.BoolAttribute", "int_ptr": "schema.Int64Attribute",
               "string_list": "schema.ListAttribute"}


def classify(go_type):
    """Returns (category, detail)."""
    if go_type == "*string":
        return "string_ptr", None
    if go_type == "string":
        return "string_val", None
    if go_type == "*bool":
        return "bool_ptr", None
    if go_type == "*int64":
        return "int_ptr", None
    if go_type == "*SafeTime":
        return "time", None
    if go_type == "map[string]string":
        return "string_map", None
    if go_type == "*CurrentTrafficConfiguration":
        return "enum_string", None
    if go_type.startswith("[]"):
        return "object_list", go_type[2:]
    if go_type.startswith("*"):
        return "object", go_type[1:]
    raise SystemExit("unmapped Go type: " + go_type)


TRAFFIC_VALUES = ["disabled", "enable-all", "enable-inbound-only", "enable-outbound-only"]


def tf_type(cat, detail):
    if cat in ("string_ptr", "string_val", "time", "enum_string"):
        return "types.String"
    if cat == "bool_ptr":
        return "types.Bool"
    if cat == "int_ptr":
        return "types.Int64"
    if cat == "string_map":
        return "map[string]types.String"
    if cat == "object":
        return "*tfTypes." + detail
    if cat == "object_list":
        return "[]tfTypes." + detail
    raise SystemExit(cat)


def indent(text, n):
    pad = "\t" * n
    return "".join(pad + l + "\n" if l else "\n" for l in text.split("\n"))


def nested_schema(type_name, level):
    lines = []
    for tf_field, kind, _sdk, _ in NESTED[type_name]:
        name = NESTED_TFSDK[type_name][tf_field]
        attr = KIND_SCHEMA[kind]
        if kind == "string_list":
            lines.append('"%s": %s{\n\tComputed:    true,\n\tElementType: types.StringType,\n},' % (name, attr))
        else:
            lines.append('"%s": %s{\n\tComputed: true,\n},' % (name, attr))
    return indent("\n".join(lines), level)


# Prose for the attributes a practitioner actually writes. `id` needs one for a
# second reason: tfplugindocs substitutes "The ID of this resource." and files a
# description-less `id` under Read-Only, which would misdocument it as unsettable.
# Prose for the attributes a practitioner actually writes. The two lookup
# arguments need one for a second reason: tfplugindocs substitutes "The ID of this
# resource." for a description-less `id` and files it under Read-Only, which would
# misdocument the data source's id as unsettable.
# The text is embedded in a Go raw string, so it must not contain backticks.
DATASOURCE_DESCRIPTIONS = {
    "id": "The asset's UUID. Set this or asset_name, not both.",
    "asset_name": "The asset's name. Set this or id, not both. Resolving by name "
                  "avoids needing a UUID from the portal, and fails if the name is not unique.",
}
RESOURCE_DESCRIPTIONS = {
    "id": "The asset's UUID, assigned by the platform. Either this or the asset's "
          "name works as the terraform import identifier.",
    "asset_name": "The asset's name.",
}


def schema_attr(name, cat, detail, mode, descriptions):
    """mode: 'computed', 'required', 'optional'."""
    header = {"computed": "Computed: true,", "required": "Required: true,", "optional": "Optional:    true,"}[mode]
    if name in descriptions and cat in ("string_ptr", "string_val"):
        return '"%s": schema.StringAttribute{\n\t%s\n\tDescription: `%s`,\n},' % (
            name, header, descriptions[name])
    if cat == "string_map":
        if mode == "optional":
            return '"%s": schema.MapAttribute{\n\tOptional:    true,\n\tElementType: types.StringType,\n},' % name
        return '"%s": schema.MapAttribute{\n\tComputed:    true,\n\tElementType: types.StringType,\n},' % name
    if cat == "enum_string":
        vals = "".join('\n\t\t\t"%s",' % v for v in TRAFFIC_VALUES)
        return ('"%s": schema.StringAttribute{\n\tComputed:    true,\n\tDescription: `must be one of %s`,\n'
                '\tValidators: []validator.String{\n\t\tstringvalidator.OneOf(%s\n\t\t),\n\t},\n},'
                % (name, str(TRAFFIC_VALUES).replace("'", '"'), vals))
    if cat == "object":
        return '"%s": schema.SingleNestedAttribute{\n\tComputed: true,\n\tAttributes: map[string]schema.Attribute{\n%s\t},\n},' % (name, nested_schema(detail, 2))
    if cat == "object_list":
        return '"%s": schema.ListNestedAttribute{\n\tComputed: true,\n\tNestedObject: schema.NestedAttributeObject{\n\t\tAttributes: map[string]schema.Attribute{\n%s\t\t},\n\t},\n},' % (name, nested_schema(detail, 3))
    attr = {"string_ptr": "schema.StringAttribute", "string_val": "schema.StringAttribute",
            "time": "schema.StringAttribute", "bool_ptr": "schema.BoolAttribute",
            "int_ptr": "schema.Int64Attribute"}[cat]
    return '"%s": %s{\n\t%s\n},' % (name, attr, header)


def refresh_scalar(kind, dst, src):
    return {
        "string_ptr": "%s = types.StringPointerValue(%s)" % (dst, src),
        "string_val": "%s = types.StringValue(%s)" % (dst, src),
        "bool_ptr": "%s = types.BoolPointerValue(%s)" % (dst, src),
        "int_ptr": "%s = types.Int64PointerValue(%s)" % (dst, src),
    }[kind]


def refresh_string_list(dst, src):
    return ("%s = make([]types.String, 0, len(%s))\nfor _, v := range %s {\n"
            "\t%s = append(%s, types.StringValue(v))\n}") % (dst, src, src, dst, dst)


def nested_body(type_name, dst, src):
    out = []
    for tf_field, kind, sdk_field, _ in NESTED[type_name]:
        d, s = "%s.%s" % (dst, tf_field), "%s.%s" % (src, sdk_field)
        out.append(refresh_string_list(d, s) if kind == "string_list" else refresh_scalar(kind, d, s))
    return "\n".join(out)


def refresh_field(go_name, cat, detail):
    dst, src = "r." + go_name, "resp." + go_name
    if cat in ("string_ptr", "string_val", "bool_ptr", "int_ptr"):
        return refresh_scalar(cat, dst, src)
    if cat == "time":
        return ("if %s != nil && !%s.Time.IsZero() {\n\t%s = types.StringValue(%s.Time.Format(time.RFC3339))\n"
                "} else {\n\t%s = types.StringNull()\n}") % (src, src, dst, src, dst)
    if cat == "enum_string":
        return ("if %s != nil {\n\t%s = types.StringValue(string(*%s))\n} else {\n\t%s = types.StringNull()\n}"
                % (src, dst, src, dst))
    if cat == "string_map":
        return ("if len(%s) > 0 {\n\t%s = make(map[string]types.String, len(%s))\n\tfor k, v := range %s {\n"
                "\t\t%s[k] = types.StringValue(v)\n\t}\n} else {\n\t%s = nil\n}") % (src, dst, src, src, dst, dst)
    if cat == "object":
        body = indent(nested_body(detail, dst, src), 1)
        return "if %s == nil {\n\t%s = nil\n} else {\n\t%s = &tfTypes.%s{}\n%s}" % (src, dst, dst, detail, body)
    if cat == "object_list":
        body = indent(nested_body(detail, "item", "v"), 1)
        return ("%s = []tfTypes.%s{}\nfor _, v := range %s {\n\tvar item tfTypes.%s\n%s\t%s = append(%s, item)\n}"
                % (dst, detail, src, detail, body, dst, dst))
    raise SystemExit(cat)


# Attributes with no direct AssetDetails field. Enforcement is reported as
# "enabled"/"disabled" on inboundAssetDeploymentState and its outbound twin;
# a boolean is the honest way to express it in a configuration.
ENFORCEMENT_ATTRS = [
    ("InboundEnforcement", "inbound_enforcement", "InboundAssetDeploymentState", "inbound"),
    ("OutboundEnforcement", "outbound_enforcement", "OutboundAssetDeploymentState", "outbound"),
]


def enforcement_model():
    return "\n".join(
        '%s types.Bool `tfsdk:"%s"`' % (go, name) for go, name, _, _ in ENFORCEMENT_ATTRS)


def enforcement_schema(resource):
    out = []
    for _, name, state_field, direction in ENFORCEMENT_ATTRS:
        state_attr = snake(state_field[0].lower() + state_field[1:])
        if resource:
            description = (
                "Whether %s policy is enforced on this asset. Setting it calls the zero-trust "
                "endpoint; the deployed rules themselves come from templates and a deployment. "
                "Leave unset to leave the current state alone. Reported back from %s."
                % (direction, state_attr))
            out.append('"%s": schema.BoolAttribute{\n\tOptional:    true,\n\tComputed:    true,\n\tDescription: `%s`,\n},' % (name, description))
        else:
            out.append('"%s": schema.BoolAttribute{\n\tComputed:    true,\n\tDescription: `True when %s policy is enforced on this asset.`,\n},' % (name, direction))
    return "\n".join(out)


def enforcement_refresh():
    out = []
    for go, _, state_field, _ in ENFORCEMENT_ATTRS:
        out.append(
            'if resp.%s != nil {\n'
            '\tr.%s = types.BoolValue(*resp.%s == "enabled")\n'
            '} else {\n\tr.%s = types.BoolNull()\n}' % (state_field, go, state_field, go))
    return "\n".join(out)


FIELDS = parse_fields()

# Attributes the practitioner sets. Everything else is read from the API.
RESOURCE_MODES = {"assetName": "required", "type": "required", "coreTags": "optional"}
# Either identifies the asset. Requiring the id would mean needing the portal to
# find a UUID before Terraform could read anything, which defeats the point.
DATASOURCE_MODES = {"assetId": "optional", "assetName": "optional"}

# The asset resource is import-only: Create is refused outright, and Update sends
# exactly these seven fields plus the enforcement toggles. Every other field in
# AssetDetails is reported by the agent or derived by the backend, so it moves with
# no Terraform action behind it. Holding those in resource state buys nothing that
# converges and makes refresh report drift on every plan. The xshield_asset and
# xshield_assets data sources still expose the whole of AssetDetails.
RESOURCE_FIELDS = {
    "assetId", "assetName", "type", "coreTags",
    "agentId", "deterministicId", "vendorInfo",
}


def build(mode_map, resource):
    descriptions = RESOURCE_DESCRIPTIONS if resource else DATASOURCE_DESCRIPTIONS
    model, schema_lines, refresh = [], [], []
    for go_name, go_type, json_name in FIELDS:
        if resource and json_name not in RESOURCE_FIELDS:
            continue
        cat, detail = classify(go_type)
        name = snake(json_name)
        mode = mode_map.get(json_name, "computed")
        model.append("%s %s `tfsdk:\"%s\"`" % (go_name, tf_type(cat, detail), name))
        schema_lines.append(schema_attr(name, cat, detail, mode, descriptions))
        refresh.append(refresh_field(go_name, cat, detail))
    model.append(enforcement_model())
    schema_lines.append(enforcement_schema(resource))
    refresh.append(enforcement_refresh())
    return "\n".join(model), "\n".join(schema_lines), "\n".join(refresh)


def splice(path, struct_name, model_body, schema_body):
    lines = open(path).read().split("\n")
    # model struct
    start = next(i for i, l in enumerate(lines) if l.startswith("type %s struct {" % struct_name))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    lines[start + 1:end] = indent(model_body, 1).rstrip("\n").split("\n")
    # schema attribute map
    start = next(i for i, l in enumerate(lines) if l.strip() == "Attributes: map[string]schema.Attribute{")
    depth, end = 0, None
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0:
            end = i
            break
    assert end is not None, "unbalanced schema block in " + path
    lines[start + 1:end] = indent(schema_body, 3).rstrip("\n").split("\n")
    open(path, "w").write("\n".join(lines))
    print("spliced", os.path.relpath(path, ROOT))


HEADER = ("// Code generated by scripts/gen_asset_provider.py from shared.AssetDetails.\n"
          "// Re-run that script rather than editing by hand; see scripts/README.md.\n\npackage provider\n\n")
TF_TYPES_IMPORT = "\ttfTypes \"github.com/colortokens/terraform-provider-xshield/internal/provider/types\"\n"
SHARED_IMPORT = "\t\"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared\"\n"
TYPES_IMPORT = "\t\"github.com/hashicorp/terraform-plugin-framework/types\"\n"


def imports_for(body):
    """Only the imports the generated body actually uses.

    Which packages are needed depends on which fields survive RESOURCE_FIELDS, so
    deriving this from the body keeps the output compiling however that set changes.
    """
    stdlib = "\t\"time\"\n\n" if "time." in body else ""
    third = ""
    if "tfTypes." in body:
        third += TF_TYPES_IMPORT
    if "shared." in body:
        third += SHARED_IMPORT
    if "types." in body:
        third += TYPES_IMPORT
    return "import (\n" + stdlib + third + ")\n\n"

TO_SHARED = '''
func (r *AssetResourceModel) ToSharedCreateAssetDetails() *shared.CreateAssetDetails {
\tagentID := new(string)
\tif !r.AgentID.IsUnknown() && !r.AgentID.IsNull() {
\t\t*agentID = r.AgentID.ValueString()
\t} else {
\t\tagentID = nil
\t}
\tid := new(string)
\tif !r.ID.IsUnknown() && !r.ID.IsNull() {
\t\t*id = r.ID.ValueString()
\t} else {
\t\tid = nil
\t}
\tvar assetName string
\tassetName = r.AssetName.ValueString()

\tvar typeVar string
\ttypeVar = r.Type.ValueString()

\tcoreTags := make(map[string]string)
\tfor coreTagsKey, coreTagsValue := range r.CoreTags {
\t\tvar coreTagsInst string
\t\tcoreTagsInst = coreTagsValue.ValueString()

\t\tcoreTags[coreTagsKey] = coreTagsInst
\t}
\tdeterministicID := new(string)
\tif !r.DeterministicID.IsUnknown() && !r.DeterministicID.IsNull() {
\t\t*deterministicID = r.DeterministicID.ValueString()
\t} else {
\t\tdeterministicID = nil
\t}
\tvendorInfo := new(string)
\tif !r.VendorInfo.IsUnknown() && !r.VendorInfo.IsNull() {
\t\t*vendorInfo = r.VendorInfo.ValueString()
\t} else {
\t\tvendorInfo = nil
\t}
\tout := shared.CreateAssetDetails{
\t\tAgentID:         agentID,
\t\tID:              id,
\t\tAssetName:       assetName,
\t\tType:            typeVar,
\t\tCoreTags:        coreTags,
\t\tDeterministicID: deterministicID,
\t\tVendorInfo:      vendorInfo,
\t}
\treturn &out
}
'''


def write_sdk(path, model_name, refresh_body, extra=""):
    body = indent(refresh_body, 2).rstrip("\n")
    code = "func (r *%s) RefreshFromSharedAssetDetails(resp *shared.AssetDetails) {\n\tif resp != nil {\n%s\n\t}\n}\n" % (model_name, body)
    code += extra
    out = HEADER + imports_for(code) + code
    open(path, "w").write(out)
    print("wrote", os.path.relpath(path, ROOT))


res_model, res_schema, res_refresh = build(RESOURCE_MODES, resource=True)
ds_model, ds_schema, ds_refresh = build(DATASOURCE_MODES, resource=False)

splice(os.path.join(PROV, "asset_resource.go"), "AssetResourceModel", res_model, res_schema)
splice(os.path.join(PROV, "asset_data_source.go"), "AssetDataSourceModel", ds_model, ds_schema)
write_sdk(os.path.join(PROV, "asset_resource_sdk.go"), "AssetResourceModel", res_refresh, TO_SHARED)
write_sdk(os.path.join(PROV, "asset_data_source_sdk.go"), "AssetDataSourceModel", ds_refresh)
print("fields mapped:", len(FIELDS))
