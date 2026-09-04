// Derived from xshield_oas3.yaml. Keep this file in sync with that document.
// Maintained in-tree; the Speakeasy pipeline was retired. See scripts/README.md.

package shared

// FirewallSimulation is the before and after of a deployment, rendered as the
// firewall rule text the agent would run. Served by the policy-generator
// service, which is exposed on the same host under /api/policysimulation.
type FirewallSimulation struct {
	CurrentRules   string `json:"currentRules"`
	CandidateRules string `json:"candidateRules"`
}

func (o *FirewallSimulation) GetCurrentRules() string {
	if o == nil {
		return ""
	}
	return o.CurrentRules
}

func (o *FirewallSimulation) GetCandidateRules() string {
	if o == nil {
		return ""
	}
	return o.CandidateRules
}
