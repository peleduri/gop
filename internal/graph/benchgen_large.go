package graph

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// LargeSpec sizes SyntheticLarge.
type LargeSpec struct {
	Orgs, Repos, Actions, Principals int
	// Agents is how many workflows run an AI agent.
	Agents int
	// Owners is how many accounts own OwnedOrgs orgs each: an org owner
	// pushes to every repo of each org it owns, the edges that make a big
	// enterprise graph big.
	Owners, OwnedOrgs int
	// ExtraMemberships is how many more orgs each org member also belongs
	// to: an identity in a default-write org reaches all of its repos.
	ExtraMemberships int
}

// LargeEnterprise is the shape of the report scale benchmark: tens of orgs,
// thousands of repos, a few hundred agent workflows and accounts that own
// many orgs (about 1.5 million edges).
var LargeEnterprise = LargeSpec{Orgs: 40, Repos: 8000, Actions: 1500, Principals: 20000,
	Agents: 264, Owners: 300, OwnedOrgs: 12, ExtraMemberships: 2}

// SyntheticLarge is SyntheticEnterprise grown into a large enterprise for the
// report scale benchmarks (never for product output): it adds Agents agent
// workflows with a mix of exposures, Owners accounts that own OwnedOrgs
// orgs each, and branch protection and secret scanning facts on every repo.
// Deterministic for a seed; synthetic names only (acme-oN, identity:uN).
func SyntheticLarge(seed uint64, s LargeSpec) *Graph {
	g := SyntheticEnterprise(seed, s.Orgs, s.Repos, s.Actions, s.Principals)
	r := rand.New(rand.NewPCG(seed, 0x6c617267))
	orgs := max(s.Orgs, 2)
	idx := map[string]int{}
	for i := range g.Nodes {
		idx[g.Nodes[i].ID] = i
	}
	set := func(id string, attrs map[string]string) {
		n := &g.Nodes[idx[id]]
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		for k, v := range attrs {
			n.Attrs[k] = v
		}
	}
	add := func(e Edge) {
		e.SourceAPI = "bench:" + string(e.Kind)
		e.ObservedAt = syntheticTime
		if e.Evidence == "" {
			e.Evidence = Live
		}
		g.Edges = append(g.Edges, e)
	}

	var workflows []string
	reposOf := map[string][]string{} // org -> repo IDs
	for _, n := range g.Nodes {
		switch n.Kind {
		case KindWorkflow:
			workflows = append(workflows, n.ID)
		case KindRepo:
			o := strings.TrimPrefix(OrgOf(n.ID), "org:")
			reposOf[o] = append(reposOf[o], n.ID)
		}
	}

	// Repo hardening facts, so the hardening sections have rows.
	for _, n := range g.Nodes {
		if n.Kind != KindRepo {
			continue
		}
		prot := []string{"true", "true", "false", "unknown"}[r.IntN(4)]
		set(n.ID, map[string]string{AttrBranchProtected: prot, AttrBranchReviews: fmt.Sprint(r.IntN(3)),
			AttrCodeownersWorkflows: []string{"true", "false"}[r.IntN(2)],
			AttrSecretScanning:      []string{"on", "off"}[r.IntN(2)], AttrSecretPushProtection: []string{"on", "off", "unknown"}[r.IntN(3)],
			AttrVisibility: []string{"private", "internal", "public"}[r.IntN(3)]})
	}

	// Agent workflows: every k-th workflow, so they spread over orgs.
	step := max(1, len(workflows)/max(1, s.Agents))
	exposures := []string{ExposureOutsiders, ExposureOutsiders, ExposureOutsiders, ExposureListed, ExposureForkRO,
		ExposureMaintainer, ExposureMaintainer, ExposureMaintainer, ExposureMaintainer, ExposureMaintainer}
	kinds := []string{"claude-code-action", "codex-cli", "gemini-cli", "copilot-swe-agent"}
	for i := 0; i < s.Agents && i*step < len(workflows); i++ {
		wf := workflows[i*step]
		exp := exposures[r.IntN(len(exposures))]
		gate := GateWriteAccess
		trig := "push"
		switch exp {
		case ExposureOutsiders:
			gate, trig = []string{GateAnyone, GateNone, GateUnknown}[r.IntN(3)], "issue_comment"
		case ExposureListed:
			gate, trig = GateListed, "issues"
		case ExposureForkRO:
			gate, trig = GateNone, "pull_request"
		}
		perms := []string{"contents:read", "contents:write,pull-requests:write", "contents:write,id-token:write", "pull-requests:write"}[r.IntN(4)]
		tools := ""
		if r.IntN(5) == 0 {
			tools = "dangerously_skip_permissions"
		}
		attrs := map[string]string{AttrAgent: kinds[r.IntN(len(kinds))], AttrAgentSource: "uses", AttrAgentConfidence: AgentAction,
			AttrAgentJobs: "agent", AttrAgentGate: gate, AttrAgentExposure: exp, AttrAgentPerms: perms,
			AttrAgentSecrets: fmt.Sprint(r.IntN(3)), AttrAgentRunner: "hosted", AttrAgentRefKind: []string{"sha", "tag", "branch"}[r.IntN(3)],
			"risky_triggers": trig}
		if tools != "" {
			attrs[AttrAgentTools] = tools
		}
		if exp != ExposureMaintainer && r.IntN(2) == 0 {
			attrs[AttrAgentPrompt] = "github.event.comment.body"
		}
		set(wf, attrs)
		if exp == ExposureOutsiders {
			add(Edge{From: "external:anyone", To: wf, Kind: CanTrigger, Attrs: map[string]string{"trigger": trig, "exec": "agent"}})
		}
	}

	// More org memberships for every identity that is a member somewhere.
	var members []string
	for _, e := range g.Edges {
		if e.Kind == MemberOf && strings.HasPrefix(e.From, "identity:") {
			members = append(members, e.From)
		}
	}
	for _, id := range members {
		for k := 0; k < s.ExtraMemberships; k++ {
			add(Edge{From: id, To: fmt.Sprintf("org:acme-o%d", 1+r.IntN(orgs-1)), Kind: MemberOf})
		}
	}

	// Accounts that own many orgs: the bulk of a large enterprise's edges.
	for i := 0; i < s.Owners; i++ {
		id := fmt.Sprintf("identity:owner%d", i)
		g.Nodes = append(g.Nodes, Node{ID: id, Kind: KindIdentity, Name: id, Evidence: Live})
		start := r.IntN(orgs - 1)
		for k := 0; k < min(s.OwnedOrgs, orgs-1); k++ {
			o := fmt.Sprintf("acme-o%d", 1+(start+k)%(orgs-1))
			add(Edge{From: id, To: "org:" + o, Kind: MemberOf})
			for _, repo := range reposOf[o] {
				add(Edge{From: id, To: repo, Kind: CanPush, Evidence: Inferred,
					Attrs: map[string]string{AttrVia: ViaOrgOwner, AttrRule: RuleOrgOwner, "permission": "admin"}})
			}
		}
	}
	return g
}
