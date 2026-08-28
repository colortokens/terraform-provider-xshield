package sdk

import "context"

// ServerURL exposes the configured server URL to hand-written data sources that
// call endpoints not covered by the generated SDK (e.g. the cloud enforcement
// snapshot API).
func (s *Xshield) ServerURL() string {
	url, _ := s.sdkConfiguration.GetServerDetails()
	return url
}

// SecuritySource exposes the configured security/signing source so a custom
// request can be signed with the same RSA material the SDK uses.
func (s *Xshield) SecuritySource() func(context.Context) (interface{}, error) {
	return s.sdkConfiguration.Security
}
