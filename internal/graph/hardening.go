package graph

import "strings"

// This file reads the hardening settings of the org a path ends in. It is
// context only: nothing in reach, scoring, ranking or fix suggestion calls
// it, so evidence levels, counts, scores and rank order never depend on it.

// HardeningUnknown is the value of a hardening setting the token could not
// read or gop did not collect. It never stands for off or none.
const HardeningUnknown = "unknown"

// OrgHardening is the hardening context of a path's target org: its SSO and
// IP allow list settings as gop recorded them, "unknown" when not visible or
// not collected.
type OrgHardening struct {
	Org         string `json:"org"`           // org node ID, e.g. org:acme-app
	SSO         string `json:"sso"`           // enforced | configured | none | unknown
	IPAllowList string `json:"ip_allow_list"` // on | off | unknown
}

// Weak is true when the org's SSO is not enforced or its IP allow list is not
// on, including when either is unknown.
func (h OrgHardening) Weak() bool {
	return h.SSO != "enforced" || h.IPAllowList != "on"
}

// Line is the human note for a path: "target org acme-app: SSO not enforced
// (configured), IP allow list off". Unknown reads "unknown", never "off".
func (h OrgHardening) Line() string {
	var sso string
	switch h.SSO {
	case "enforced":
		sso = "SSO enforced"
	case "configured":
		sso = "SSO not enforced (configured)"
	case "none":
		sso = "SSO not enforced (none)"
	default:
		sso = "SSO unknown"
	}
	ip := "IP allow list " + h.IPAllowList
	if h.IPAllowList != "on" && h.IPAllowList != "off" {
		ip = "IP allow list unknown"
	}
	return "target org " + strings.TrimPrefix(h.Org, "org:") + ": " + sso + ", " + ip
}

// OrgSetting returns an org node attribute, or "unknown" when the attribute
// is not_visible, has the value "unknown", or was not collected.
func OrgSetting(n Node, key string) string {
	ev := n.Evidence
	if e, ok := n.AttrEvidence[key]; ok {
		ev = e
	}
	v := n.Attrs[key]
	if ev == NotVisible || v == "" || v == HardeningUnknown {
		return HardeningUnknown
	}
	return v
}

// OrgHardening returns the hardening settings of the org node orgID. ok is
// false when the graph has no such org node (gop makes no claim about it).
func (ix *Index) OrgHardening(orgID string) (OrgHardening, bool) {
	n, ok := ix.Node(orgID)
	if !ok || n.Kind != KindOrg {
		return OrgHardening{}, false
	}
	return OrgHardening{Org: orgID, SSO: OrgSetting(n, AttrSSO), IPAllowList: OrgSetting(n, AttrIPAllowList)}, true
}

// TargetRepo is the repo a path ends in: the repo of its target when that is
// a repo, workflow, secret, OIDC or runner scope, else the last such node on
// the path (the repo whose workflow assumes a cloud target). "" when none.
func TargetRepo(p Path) string {
	ids := []string{p.To}
	for i := len(p.Hops) - 1; i >= 0; i-- {
		ids = append(ids, p.Hops[i].To, p.Hops[i].From)
	}
	for _, id := range ids {
		prefix, rest, ok := strings.Cut(id, ":")
		if !ok {
			continue
		}
		switch prefix {
		case "repo", "workflow", "secret", "oidc", "runner":
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return "repo:" + parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}

// TargetOrgHardening is the hardening context of p's target repo's org when
// that org is weak or unknown (Weak), else nil. It is nil too when the path
// ends in no repo or the graph has no node for the org.
func (ix *Index) TargetOrgHardening(p Path) *OrgHardening {
	repo := TargetRepo(p)
	if repo == "" {
		return nil
	}
	h, ok := ix.OrgHardening(OrgOf(repo))
	if !ok || !h.Weak() {
		return nil
	}
	return &h
}
