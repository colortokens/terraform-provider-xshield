package provider

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/colortokens/terraform-provider-xshield/internal/federation"
	"github.com/colortokens/terraform-provider-xshield/internal/keyservice"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk"
	"github.com/colortokens/terraform-provider-xshield/internal/sdk/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var oidcEnvironmentVariables = []string{"XSHIELD_OIDC_TOKEN", "XSHIELD_OIDC_TOKEN_FILE", "XSHIELD_OIDC_TOKEN_ENV", "XSHIELD_OIDC_SOURCE", "XSHIELD_OIDC_AUDIENCE"}

// buildAuthentication picks the one authentication method the provider block and the environment configure: an
// API key's private key, a key held in a cloud key service, or workload identity federation.
func buildAuthentication(ctx context.Context, data XshieldProviderModel, serverURL string, httpClient *http.Client,
	resp *provider.ConfigureResponse) (shared.ConfigurationProvider, sdk.HTTPClient) {
	usesPrivateKey := withEnv(data.PrivateKeyLocation, "XSHIELD_PRIVATE_KEY_PATH") != "" || withEnv(data.PrivateKey, "XSHIELD_PRIVATE_KEY") != "" ||
		data.PrivateKeyLocation.IsUnknown() || data.PrivateKey.IsUnknown()
	usesKeyService := withEnv(data.KMSKey, "XSHIELD_KMS_KEY") != "" || data.KMSKey.IsUnknown()
	usesFederation := data.OIDC != nil
	for _, name := range oidcEnvironmentVariables {
		usesFederation = usesFederation || os.Getenv(name) != ""
	}

	var methods []string
	conflictAt := path.Root("kms_key")
	if usesPrivateKey {
		methods = append(methods, "a private key (private_key or private_key_path)")
	}
	if usesKeyService {
		methods = append(methods, "a key service key (kms_key)")
	}
	if usesFederation {
		methods = append(methods, "workload identity federation (oidc)")
		conflictAt = path.Root("oidc")
	}
	if len(methods) > 1 {
		resp.Diagnostics.AddAttributeError(conflictAt, "More than one Xshield authentication method",
			"The provider block and the environment set "+strings.Join(methods, " and ")+". Set only one: an API key's private_key or "+
				"private_key_path, a kms_key, or oidc, with the matching XSHIELD_* environment variables.")
		return nil, nil
	}

	switch {
	case usesKeyService:
		return buildKeyServiceConfigProvider(ctx, data, httpClient, resp), httpClient
	case usesFederation:
		return buildFederatedConfigProvider(ctx, data, serverURL, httpClient, resp)
	default:
		return buildConfigProvider(data, resp), httpClient
	}
}

func buildKeyServiceConfigProvider(ctx context.Context, data XshieldProviderModel, httpClient *http.Client,
	resp *provider.ConfigureResponse) shared.ConfigurationProvider {
	const fromKey = "It is shown with the API key the key service's public key was registered as."
	if refuseUnknown(resp, "kms_key", "XSHIELD_KMS_KEY", data.KMSKey) {
		return nil
	}
	tenancy := requireCredential(resp, "tenancy_id", "XSHIELD_TENANCY_ID", data.TenancyId, fromKey)
	user := requireCredential(resp, "user_id", "XSHIELD_USER_ID", data.PrincipalId, fromKey)
	if refuseUnknown(resp, "fingerprint", "XSHIELD_FINGERPRINT", data.FingerPrint) || resp.Diagnostics.HasError() {
		return nil
	}
	key, err := keyservice.Open(ctx, withEnv(data.KMSKey, "XSHIELD_KMS_KEY"), httpClient)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("kms_key"), "Xshield kms_key cannot sign", err.Error())
		return nil
	}
	return keyServiceConfigProvider(tenancy, user, withEnv(data.FingerPrint, "XSHIELD_FINGERPRINT"), key, resp)
}

// keyServiceConfigProvider signs as the key's own fingerprint, after checking it against a configured one.
func keyServiceConfigProvider(tenancy, user, configuredFingerprint string, key *keyservice.RemoteKey,
	resp *provider.ConfigureResponse) shared.ConfigurationProvider {
	if configuredFingerprint != "" && configuredFingerprint != key.Fingerprint {
		resp.Diagnostics.AddAttributeError(path.Root("fingerprint"), "Xshield fingerprint does not match kms_key",
			"fingerprint (or XSHIELD_FINGERPRINT) is "+configuredFingerprint+", but the public key of kms_key has the fingerprint "+
				key.Fingerprint+". Point kms_key at the key registered as this API key, or leave fingerprint out to use the key's own.")
		return nil
	}
	return shared.NewRemoteKeyConfigProvider(tenancy, user, key.Fingerprint, key)
}

func buildFederatedConfigProvider(ctx context.Context, data XshieldProviderModel, serverURL string, httpClient *http.Client,
	resp *provider.ConfigureResponse) (shared.ConfigurationProvider, sdk.HTTPClient) {
	const ofServiceAccount = "With oidc it is the tenancy ID and user ID of the service account whose federation trust accepts the workload's token."
	tenancy := requireCredential(resp, "tenancy_id", "XSHIELD_TENANCY_ID", data.TenancyId, ofServiceAccount)
	user := requireCredential(resp, "user_id", "XSHIELD_USER_ID", data.PrincipalId, ofServiceAccount)
	settings := readOIDCSettings(data.OIDC, resp)
	if resp.Diagnostics.HasError() {
		return nil, nil
	}
	subjectTokens, err := federation.NewSubjectTokenSource(ctx, settings, httpClient)
	if err != nil {
		var setting *federation.SettingError
		if errors.As(err, &setting) {
			resp.Diagnostics.AddAttributeError(path.Root("oidc").AtName(setting.Attribute), "Xshield oidc "+setting.Attribute+" does not work", setting.Detail)
		} else {
			resp.Diagnostics.AddAttributeError(path.Root("oidc"), "Xshield OIDC token source does not work", err.Error())
		}
		return nil, nil
	}
	exchanger := federation.NewExchanger(serverURL, tenancy, user, subjectTokens, httpClient)
	if _, err := exchanger.AccessToken(ctx); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("oidc"), "Xshield workload identity federation failed", err.Error())
		return nil, nil
	}
	return shared.NewFederatedConfigProvider(tenancy, user, exchanger), federation.NewReauthenticatingClient(httpClient, exchanger)
}

func readOIDCSettings(block *OIDCModel, resp *provider.ConfigureResponse) federation.Settings {
	var fields OIDCModel
	if block != nil {
		fields = *block
	}
	read := func(attr, env string, v types.String) string {
		if refuseUnknownAt(resp, path.Root("oidc").AtName(attr), "oidc."+attr, env, v) {
			return ""
		}
		return withEnv(v, env)
	}
	return federation.Settings{
		Token:     read("token", "XSHIELD_OIDC_TOKEN", fields.Token),
		TokenFile: read("token_file", "XSHIELD_OIDC_TOKEN_FILE", fields.TokenFile),
		TokenEnv:  read("token_env", "XSHIELD_OIDC_TOKEN_ENV", fields.TokenEnv),
		Source:    read("source", "XSHIELD_OIDC_SOURCE", fields.Source),
		Audience:  read("audience", "XSHIELD_OIDC_AUDIENCE", fields.Audience),
	}
}
