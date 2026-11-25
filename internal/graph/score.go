package graph

import (
	"slices"
	"sort"
)

// Counts are headline numbers for one reach set.
type Counts struct {
	Repos     int `json:"repos"`
	Orgs      int `json:"orgs"`
	Workflows int `json:"workflows"`
	Secrets   int `json:"secrets"`
	OIDC      int `json:"oidc"`
	Runners   int `json:"runners"`
	// CloudTargets counts cloud roles reached through supplied trust files.
	CloudTargets int `json:"cloud_targets,omitempty"`
}

func (c *Counts) add(o Counts) {
	c.Repos += o.Repos
	c.Orgs += o.Orgs
	c.Workflows += o.Workflows
	c.Secrets += o.Secrets
	c.OIDC += o.OIDC
	c.Runners += o.Runners
	c.CloudTargets += o.CloudTargets
}

func countsOf(r Reached) Counts {
	return Counts{Repos: len(r.Repos), Orgs: len(r.Orgs), Workflows: len(r.Workflows),
		Secrets: len(r.Secrets), OIDC: len(r.OIDC), Runners: len(r.Runners), CloudTargets: len(r.CloudTargets)}
}

// Score is a principal's blast radius. Score is computed from Confirmed only;
// PossibleScore is the same formula over Possible only (reach that depends on at
// least one not_visible hop). They are never summed into the headline.
type Score struct {
	Principal     string  `json:"principal"`
	Confirmed     Counts  `json:"confirmed"`
	Possible      Counts  `json:"possible"`
	Multiplier    float64 `json:"multiplier"`
	Score         float64 `json:"score"`
	PossibleScore float64 `json:"possible_score"`
	// PoutineInjectable counts the confirmed-reached workflows that carry an
	// injection-class poutine finding (see PoutineInjectable). It is a
	// separate rank factor cited from poutine: it never changes Score, the
	// counts or any evidence. 0 when no poutine report was imported.
	PoutineInjectable int `json:"poutine_injectable,omitempty"`
	// Advisories lists the actions with a known-compromise or vulnerability
	// advisory that a confirmed path runs through (for an advisory action ranked by
	// TopPaths, the action itself first). Any entry here ranks first.
	Advisories []string `json:"advisories,omitempty"`
	// AgentExposed counts the confirmed-reached AI agent workflows the
	// principal starts through its own CAN_TRIGGER edge (without push
	// access) and that hold write, secrets or OIDC (see AgentExposed). A
	// separate rank factor like PoutineInjectable: it never changes Score,
	// the counts or any evidence. 0 when the graph has no such workflow.
	AgentExposed int `json:"agent_exposed,omitempty"`
	// BotSelfMerge counts the confirmed-reached repos the principal lands
	// code on through its own CAN_MERGE_VIA_BOT edge: a bot approves and
	// merges its pull request with no human review. Context for the
	// [bot_self_merge] marker: the repos are already in the counts and the
	// score, and it is not a rank factor.
	BotSelfMerge int `json:"bot_self_merge,omitempty"`
	// EnvGated counts the confirmed-reached secrets, OIDC tokens and cloud
	// targets that every confirmed-reached workflow reaches only through a
	// deployment environment with required reviewers (env_gate). They stay
	// in Confirmed and in the score, weighted at half: a human must approve
	// the run first, which slows an attacker but does not stop one who is,
	// or can fool, a reviewer.
	EnvGated int `json:"env_gated,omitempty"`
}

// Blast radius weights. Terminal impact (cloud roles, OIDC to cloud, secrets,
// self-hosted runners) outweighs plain CI on a repo.
const (
	wRepo     = 1.0
	wWorkflow = 0.5
	wOrg      = 2.0
	wRunner   = 3.0
	wSecret   = 5.0
	wOIDC     = 8.0
	// wCloud is per cloud role reached through a supplied trust file: the
	// OIDC token turned into a concrete cloud identity.
	wCloud = 13.0
	// Each weak org control multiplies the score by this factor.
	weakOrgFactor = 1.5
)

// rawScore is the formula:
//
//	base       = 1*repos + 0.5*workflows + 2*orgs + 3*runners + 5*secrets + 8*oidc
//	             + 13*cloud_targets
//	             - 0.5 * (the weights of the gated secrets, oidc and cloud_targets:
//	               those reached only through a required-reviewer environment)
//	multiplier = 1.0
//	             x1.5 if the principal's org has two_factor = not_required
//	             x1.5 if the principal's org has sso != enforced (configured or none)
//	score      = base * multiplier
//
// The org is org:X for members:X, and every MEMBER_OF org for an identity (the
// weakest one wins; MEMBER_OF targets that are not orgs, such as teams, are ignored). Attrs are read from the org node, falling back to the
// principal's CAN_PUSH edge attrs. A missing attr adds no multiplier: unknown is
// not treated as weak or as strong.
func rawScore(c Counts) float64 {
	return wRepo*float64(c.Repos) + wWorkflow*float64(c.Workflows) + wOrg*float64(c.Orgs) +
		wRunner*float64(c.Runners) + wSecret*float64(c.Secrets) + wOIDC*float64(c.OIDC) +
		wCloud*float64(c.CloudTargets)
}

func (ix *Index) orgAttr(org, principal, key string) string {
	if n, ok := ix.nodes[org]; ok && n.Attrs[key] != "" {
		return n.Attrs[key]
	}
	for _, e := range ix.out[principal] {
		if e.Kind == CanPush && e.Attrs[key] != "" {
			return e.Attrs[key]
		}
	}
	return ""
}

func (ix *Index) multiplier(principal string) float64 {
	var orgs []string
	switch ix.Kind(principal) {
	case KindExternal:
		return 1.0 // no org controls apply to anyone on the internet
	case KindOrgMembers:
		orgs = []string{OrgOf(principal)}
	case KindIdentity:
		// A team belongs to exactly one org, which its ID names.
		if o := OrgOf(principal); o != "" {
			orgs = append(orgs, o)
		}
		for _, e := range ix.out[principal] {
			if e.Kind != MemberOf {
				continue
			}
			// Only org memberships carry org controls; a MEMBER_OF a team is not an org.
			if o := OrgOf(e.To); o != "" && ix.Kind(e.To) == KindOrg {
				orgs = append(orgs, o)
			}
		}
	}
	best := 1.0
	for _, o := range orgs {
		m := 1.0
		if ix.orgAttr(o, principal, AttrTwoFactor) == "not_required" {
			m *= weakOrgFactor
		}
		if s := ix.orgAttr(o, principal, AttrSSO); s != "" && s != "enforced" {
			m *= weakOrgFactor
		}
		if m > best {
			best = m
		}
	}
	return best
}

func (ix *Index) score(cg *controlGraph, principal string) Score {
	return ix.scoreOf(principal, ix.reach(cg, principal))
}

// scoreOf scores a reach result r of principal.
func (ix *Index) scoreOf(principal string, r Result) Score {
	s := Score{Principal: principal, Confirmed: countsOf(r.Confirmed), Possible: countsOf(r.Possible), Multiplier: ix.multiplier(principal)}
	confG, possG := ix.envGatedOn(r)
	s.Score = (rawScore(s.Confirmed) - (1-gatedFactor)*rawScore(confG)) * s.Multiplier
	s.PossibleScore = (rawScore(s.Possible) - (1-gatedFactor)*rawScore(possG)) * s.Multiplier
	s.EnvGated = confG.Secrets + confG.OIDC + confG.CloudTargets
	for _, w := range r.Confirmed.Workflows {
		if PoutineInjectable(ix.nodes[w]) {
			s.PoutineInjectable++
		}
	}
	s.Advisories = ix.advisoriesOn(r)
	s.AgentExposed = ix.agentExposedOn(r)
	s.BotSelfMerge = ix.botMergeOn(r)
	return s
}

// BlastRadius scores what a principal can reach. See rawScore for the formula.
func BlastRadius(g *Graph, principal string) Score {
	ix := NewIndex(g)
	return ix.score(ix.base, principal)
}

// BlastRadius on a prebuilt index.
func (ix *Index) BlastRadius(principal string) Score { return ix.score(ix.base, principal) }

// TopPaths ranks the scoring principals (see ScoringPrincipals), plus every
// action with an advisory and confirmed reach (see advisoryScores), with
// RanksAbove and returns the first n (all when n <= 0).
func TopPaths(g *Graph, n int) []Score { return NewIndex(g).TopPaths(n) }

// TopPaths on a prebuilt index.
func (ix *Index) TopPaths(n int) []Score {
	out := append(slices.Clone(ix.baseScores()), ix.advisoryScores(ix.base)...)
	sort.SliceStable(out, func(i, j int) bool { return RanksAbove(out[i], out[j]) })
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

// RanksAbove is the top_risks order. Rank factors, in order:
//
//  1. known advisory: an entry with confirmed reach through an action with
//     a known-compromise or vulnerability advisory (rankAdvisory) first;
//  2. poutine injectable: more confirmed-reached workflows with an
//     injection-class poutine finding (Score.PoutineInjectable) first, so a
//     confirmed path into a workflow poutine found injectable ranks above
//     the same reach without one;
//  3. agent exposed: more confirmed-reached AI agent workflows the
//     principal can start without push access while they hold write,
//     secrets or OIDC (Score.AgentExposed) first;
//  4. confirmed Score (desc);
//  5. PossibleScore (desc);
//  6. principal ID.
func RanksAbove(a, b Score) bool {
	if ra, rb := rankAdvisory(a), rankAdvisory(b); ra != rb {
		return ra > rb
	}
	if a.PoutineInjectable != b.PoutineInjectable {
		return a.PoutineInjectable > b.PoutineInjectable
	}
	if a.AgentExposed != b.AgentExposed {
		return a.AgentExposed > b.AgentExposed
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.PossibleScore != b.PossibleScore {
		return a.PossibleScore > b.PossibleScore
	}
	return a.Principal < b.Principal
}

// allScores scores every principal in ScoringPrincipals. The walks run on
// a worker pool; each score is written at its principal's index, so the
// result does not depend on scheduling.
func (ix *Index) allScores(cg *controlGraph) []Score {
	ps := ix.ScoringPrincipals()
	out := make([]Score, len(ps))
	parallelFor(len(ps), workers(), func(_, i int) { out[i] = ix.score(cg, ps[i]) })
	return out
}

// scoresAndPairs returns allScores(cg) and, in the same order, what each
// scoring principal adds to the pair totals: its score over pairReach (see
// Totals). The pair score is the full score unless the full walk entered an
// org_members population other than the principal itself.
func (ix *Index) scoresAndPairs(cg *controlGraph) (full, pair []Score) {
	ps := ix.ScoringPrincipals()
	full, pair = make([]Score, len(ps)), make([]Score, len(ps))
	parallelFor(len(ps), workers(), func(_, i int) {
		p := ps[i]
		r := ix.reach(cg, p)
		s := ix.scoreOf(p, r)
		full[i] = s
		if ix.entersPopulation(p, r) {
			s = ix.scoreOf(p, ix.pairReach(cg, p))
		}
		pair[i] = s
	})
	return full, pair
}

// entersPopulation reports whether reach result r of p went through an
// org_members population other than p.
func (ix *Index) entersPopulation(p string, r Result) bool {
	for id := range r.Paths {
		if id != p && ix.Kind(id) == KindOrgMembers {
			return true
		}
	}
	return false
}
