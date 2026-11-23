package graph

import "sort"

// Counts are headline numbers for one reach set.
type Counts struct {
	Repos     int `json:"repos"`
	Orgs      int `json:"orgs"`
	Workflows int `json:"workflows"`
	Secrets   int `json:"secrets"`
	OIDC      int `json:"oidc"`
	Runners   int `json:"runners"`
}

func (c *Counts) add(o Counts) {
	c.Repos += o.Repos
	c.Orgs += o.Orgs
	c.Workflows += o.Workflows
	c.Secrets += o.Secrets
	c.OIDC += o.OIDC
	c.Runners += o.Runners
}

func countsOf(r Reached) Counts {
	return Counts{Repos: len(r.Repos), Orgs: len(r.Orgs), Workflows: len(r.Workflows),
		Secrets: len(r.Secrets), OIDC: len(r.OIDC), Runners: len(r.Runners)}
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
}

// Blast radius weights. Terminal impact (OIDC to cloud, secrets, self-hosted
// runners) outweighs plain CI on a repo.
const (
	wRepo     = 1.0
	wWorkflow = 0.5
	wOrg      = 2.0
	wRunner   = 3.0
	wSecret   = 5.0
	wOIDC     = 8.0
	// Each weak org control multiplies the score by this factor.
	weakOrgFactor = 1.5
)

// rawScore is the formula:
//
//	base       = 1*repos + 0.5*workflows + 2*orgs + 3*runners + 5*secrets + 8*oidc
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
		wRunner*float64(c.Runners) + wSecret*float64(c.Secrets) + wOIDC*float64(c.OIDC)
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
	r := ix.reach(cg, principal)
	s := Score{Principal: principal, Confirmed: countsOf(r.Confirmed), Possible: countsOf(r.Possible), Multiplier: ix.multiplier(principal)}
	s.Score = rawScore(s.Confirmed) * s.Multiplier
	s.PossibleScore = rawScore(s.Possible) * s.Multiplier
	return s
}

// BlastRadius scores what a principal can reach. See rawScore for the formula.
func BlastRadius(g *Graph, principal string) Score {
	ix := NewIndex(g)
	return ix.score(ix.base, principal)
}

// BlastRadius on a prebuilt index.
func (ix *Index) BlastRadius(principal string) Score { return ix.score(ix.base, principal) }

// TopPaths ranks the scoring principals (see ScoringPrincipals) by confirmed Score (desc), then PossibleScore
// (desc), then ID, and returns the first n (all when n <= 0).
func TopPaths(g *Graph, n int) []Score { return NewIndex(g).TopPaths(n) }

// TopPaths on a prebuilt index.
func (ix *Index) TopPaths(n int) []Score {
	out := ix.allScores(ix.base)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].PossibleScore != out[j].PossibleScore {
			return out[i].PossibleScore > out[j].PossibleScore
		}
		return out[i].Principal < out[j].Principal
	})
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out
}

// allScores scores every principal in ScoringPrincipals.
func (ix *Index) allScores(cg *controlGraph) []Score {
	ps := ix.ScoringPrincipals()
	out := make([]Score, 0, len(ps))
	for _, p := range ps {
		out = append(out, ix.score(cg, p))
	}
	return out
}
