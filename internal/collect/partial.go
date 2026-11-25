package collect

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// Steps of run that a stopped run reports per org, after the progress
// phases they extend. The progress phases (PhaseOrgs ... PhaseProtection)
// keep their names.
const (
	phaseActionsAccess = "actions_access"
	phaseRefs          = "refs"
	phaseTags          = "tag_immutability"
	phaseIndirect      = "indirect"
	phaseBotScripts    = "bot_scripts"
	phaseActionsApprov = "actions_approve"
	phasePolicyFiles   = "policy_files"
	phaseRefProtection = "ref_protection"
	phaseEnvironments  = "environments"
)

// runPhases is the order run goes through; a run stopped in one phase did
// not start the ones after it.
var runPhases = []string{
	PhaseOrgs, PhaseSettings, PhaseMembers, PhaseRepos, PhaseWorkflows, PhaseNested,
	phaseActionsAccess, phaseRefs, phaseTags, PhaseProtection, phaseIndirect, phaseBotScripts, phaseActionsApprov, phasePolicyFiles, phaseRefProtection,
	phaseEnvironments,
}

// enter records that run started phase, for the coverage of a stopped run.
func (k *collector) enter(phase string) {
	k.phase, k.phaseOrg = phase, 0
}

// orderOrgs sorts the orgs to collect so a budgeted or interrupted run
// covers the ones that matter most: Config.Priority first, in the order
// given, then, when bySize is set, by member count (the size known before
// repositories are listed, largest first), then the rest in their listed
// order.
func (k *collector) orderOrgs(bySize bool) {
	rank := map[string]int{}
	for i, p := range k.cfg.Priority {
		if _, ok := rank[strings.ToLower(p)]; !ok {
			rank[strings.ToLower(p)] = i
		}
	}
	size := func(o *orgState) int {
		if !bySize || o.node.AttrEvidence[graph.AttrMembers] == graph.NotVisible {
			return -1
		}
		n, err := strconv.Atoi(o.node.Attrs[graph.AttrMembers])
		if err != nil {
			return -1
		}
		return n
	}
	sort.SliceStable(k.orgs, func(i, j int) bool {
		a, b := k.orgs[i], k.orgs[j]
		ra, aok := rank[strings.ToLower(a.login)]
		rb, bok := rank[strings.ToLower(b.login)]
		if aok != bok {
			return aok
		}
		if aok {
			return ra < rb
		}
		return size(a) > size(b)
	})
}

// warnPriority logs the --priority orgs that are not collected.
func (k *collector) warnPriority() {
	for _, p := range k.cfg.Priority {
		if _, ok := k.byLower[strings.ToLower(p)]; !ok {
			k.logf("collect: --priority %s: not among the organizations to collect", p)
		}
	}
}

// stoppedFix is the access-or-action note of a stopped run's coverage.
func stoppedFix(reason string) string {
	fix := "re-run gop collect with the same --cache-dir and --resume to complete it"
	switch reason {
	case graph.PartialMaxRequests:
		fix += ", with a larger --max-requests"
	case graph.PartialReserve:
		fix += " after the rate limit resets, or with a smaller --reserve"
	case graph.PartialRateLimit:
		fix += " after the rate limit resets"
	}
	return fix
}

// markStopped records what a run stopped in k.phase did not read: one
// coverage entry per org (or the enterprise) and phase not run, and
// not_visible for the org facts those phases would have set. Then it runs
// the offline steps the run did not reach that keep unread facts unknown
// rather than absent (stub repos get their not_visible push edges).
func (k *collector) markStopped(reason string) {
	cur := slices.Index(runPhases, k.phase)
	if cur < 0 {
		cur = 0
	}
	fix := stoppedFix(reason)
	ent := "enterprise:" + k.enterprise
	for i, ph := range runPhases[cur:] {
		why := graph.CoverageNotCollected + " (" + reason + ") before the " + ph + " phase"
		if i == 0 {
			why = graph.CoverageNotCollected + " (" + reason + ") during the " + ph + " phase; partly collected"
		}
		fact := "phase:" + ph
		switch ph {
		case PhaseOrgs:
			k.cover(ent, fact, why, fix)
			setAttr(k.node(ent, graph.KindEnterprise, k.enterprise), "orgs", "unknown", graph.NotVisible)
			continue
		case PhaseSettings:
			for _, o := range k.orgs {
				for _, spec := range settingSpecs {
					if _, ok := o.node.Attrs[spec.attr]; !ok {
						setAttr(o.node, spec.attr, "unknown", graph.NotVisible)
					}
				}
			}
		case PhaseMembers:
			for _, o := range k.orgs {
				if _, ok := o.node.Attrs[graph.AttrMembers]; !ok {
					setAttr(o.node, graph.AttrMembers, "unknown", graph.NotVisible)
				}
			}
		}
		for j, o := range k.orgs {
			if o.archived {
				continue
			}
			if ph == PhaseRepos {
				if i == 0 && j < k.phaseOrg {
					continue // collected before the stop
				}
				if i == 0 && j > k.phaseOrg {
					why = graph.CoverageNotCollected + " (" + reason + ") before this organization's turn in the repos phase"
				}
				if _, ok := o.node.Attrs[attrRepositories]; !ok {
					setAttr(o.node, attrRepositories, "unknown", graph.NotVisible)
				}
			}
			k.cover(o.node.ID, fact, why, fix)
		}
	}
	// Offline steps that come after the nested phase and that a run stopped
	// before or in it did not reach.
	if cur <= slices.Index(runPhases, PhaseNested) {
		k.applyActionsLocks()
		k.linkJobWorkflowRefs()
		k.coverUnknownOwners()
		k.pushToStubs()
	}
}

// partialGraph is graph() for a run stopped for reason.
func (k *collector) partialGraph(reason string) *graph.Graph {
	k.markStopped(reason)
	g := k.graph()
	g.Partial, g.PartialReason = true, reason
	return g
}
