package collect

import (
	"slices"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

const (
	webRepo    = "repo:acme-app/web"
	deployCI   = "workflow:acme-actions/deploy/.github/workflows/ci.yml"
	vaultCI    = "workflow:acme-secure/vault-proxy/.github/workflows/ci.yml"
	legacyCI   = "workflow:acme-legacy/old-site/.github/workflows/ci.yml"
	apiRelease = "workflow:acme-app/api/.github/workflows/release.yml"
)

func TestTokenWrite(t *testing.T) {
	f := newFakeGitHub(t)
	ix := collectFake(t, f)

	// No permissions block, org default write: the token can push.
	e := ix.mustEdge(t, webCI, webRepo, graph.CanPush)
	if e.Evidence != graph.Live || e.Attrs[graph.AttrVia] != graph.ViaTokenWrite || e.Attrs[attrJobs] != "build" ||
		e.SourceAPI != srcRepoWorkflowPerms {
		t.Errorf("web token edge = %+v", e)
	}
	if n := ix.node(t, webCI); n.Attrs[attrTokenWrite] != "true" || n.AttrEvidence[attrTokenWrite] != "" {
		t.Errorf("web ci token_write = %q (%q)", n.Attrs[attrTokenWrite], n.AttrEvidence[attrTokenWrite])
	}

	// contents: write in the file decides, even where the repo default is read.
	if e := ix.mustEdge(t, apiRelease, "repo:acme-app/api", graph.CanPush); e.SourceAPI != srcWorkflow || e.Evidence != graph.Live {
		t.Errorf("api release edge = %+v", e)
	}
	// Repo default read (overriding the org's write).
	ix.noEdge(t, "workflow:acme-app/api/.github/workflows/deploy.yml", "repo:acme-app/api", graph.CanPush)
	// contents: read in the file, or contents omitted next to id-token: write.
	ix.noEdge(t, "workflow:acme-app/billing/.github/workflows/deploy.yml", "repo:acme-app/billing", graph.CanPush)
	ix.noEdge(t, "workflow:acme-app/search/.github/workflows/index.yaml", "repo:acme-app/search", graph.CanPush)
	ix.noEdge(t, deployCI, deployRepo, graph.CanPush)

	// The repo setting is refused, the org default is read: read is proven.
	if n := ix.node(t, vaultCI); n.Attrs[attrTokenWrite] != "false" || n.AttrEvidence[attrTokenWrite] != "" {
		t.Errorf("vault-proxy token_write = %q (%q)", n.Attrs[attrTokenWrite], n.AttrEvidence[attrTokenWrite])
	}
	ix.noEdge(t, vaultCI, "repo:acme-secure/vault-proxy", graph.CanPush)

	// Neither setting is readable (not an org owner): possible, with coverage.
	if e := ix.mustEdge(t, legacyCI, "repo:acme-legacy/old-site", graph.CanPush); e.Evidence != graph.NotVisible {
		t.Errorf("legacy token edge = %+v", e)
	}
	if _, ok := hasCoverage(ix.g, "repo:acme-legacy/old-site", factWorkflowDef); !ok {
		t.Error("missing default_workflow_permissions coverage for acme-legacy/old-site")
	}

	// Each org setting is read at most once.
	if n := f.hitCount("/orgs/acme-legacy/actions/permissions/workflow"); n != 1 {
		t.Errorf("org setting read %d times, want 1", n)
	}
	// Repos whose workflows all declare permissions never ask.
	if n := f.hitCount("/repos/acme-app/billing/actions/permissions/workflow"); n != 0 {
		t.Errorf("billing setting read %d times, want 0", n)
	}
}

func TestTokenWriteNotVisible(t *testing.T) {
	f := newFakeGitHub(t)
	f.forbidWorkflowPerms = true
	ix := collectFake(t, f)
	e := ix.mustEdge(t, webCI, webRepo, graph.CanPush)
	if e.Evidence != graph.NotVisible || e.Attrs[graph.AttrVia] != graph.ViaTokenWrite {
		t.Errorf("web token edge = %+v", e)
	}
	if n := ix.node(t, webCI); n.Attrs[attrTokenWrite] != "unknown" || n.AttrEvidence[attrTokenWrite] != graph.NotVisible {
		t.Errorf("web ci token_write = %q (%q)", n.Attrs[attrTokenWrite], n.AttrEvidence[attrTokenWrite])
	}
	c, ok := hasCoverage(ix.g, webRepo, factWorkflowDef)
	if !ok || c.NeedsFix != "admin on acme-app/web (or org owner)" {
		t.Errorf("coverage = %+v ok=%v", c, ok)
	}
	// The file still decides where it can.
	if e := ix.mustEdge(t, apiRelease, "repo:acme-app/api", graph.CanPush); e.Evidence != graph.Live {
		t.Errorf("api release edge = %+v", e)
	}
	// Confirmed reach of web is CI reach only; control is possible.
	r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
	if p := r.Paths[webRepo]; len(p.Hops) == 0 || p.Hops[len(p.Hops)-1].Kind != graph.DefinedIn {
		t.Errorf("confirmed path to web = %+v, want CI reach (a final DEFINED_IN)", p.Hops)
	}
}

// TestTokenWriteOrgWrite: a refused repo setting under an org default of write
// stays unknown: the repo may restrict it to read.
func TestTokenWriteOrgWrite(t *testing.T) {
	f := newFakeGitHub(t)
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login == "acme-secure" {
			f.fx.Orgs[i].WorkflowPerms = "write"
		}
	}
	ix := collectFake(t, f)
	if e := ix.mustEdge(t, vaultCI, "repo:acme-secure/vault-proxy", graph.CanPush); e.Evidence != graph.NotVisible {
		t.Errorf("vault-proxy token edge = %+v", e)
	}
	if c, ok := hasCoverage(ix.g, "repo:acme-secure/vault-proxy", factWorkflowDef); !ok || c.Reason == "" {
		t.Errorf("coverage = %+v ok=%v", c, ok)
	}
}

// TestTokenWriteReach: members of acme-actions control acme-app/web through
// deploy@main and web's write token, not just its CI.
func TestTokenWriteReach(t *testing.T) {
	ix := collectFake(t, newFakeGitHub(t))
	r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
	if !slices.Contains(r.Confirmed.Repos, webRepo) {
		t.Fatalf("web not confirmed: %v", r.Confirmed.Repos)
	}
	p := r.Paths[webRepo]
	last := p.Hops[len(p.Hops)-1]
	if last.Kind != graph.CanPush || last.From != webCI {
		t.Errorf("path to web = %+v, want a final CAN_PUSH from %s", p.Hops, webCI)
	}
	// Control of a repo is not a principal: no workflow ID among principals.
	for _, pr := range graph.NewIndex(ix.g).Principals() {
		if graph.KindFromID(pr) == graph.KindWorkflow {
			t.Errorf("principal %s", pr)
		}
	}
}

// TestTokenWriteBranchProtection: a GITHUB_TOKEN push is a push like any
// other, so branch protection on an action's ref gates the repo -> action hop
// for a token-controlled host repo too.
func TestTokenWriteBranchProtection(t *testing.T) {
	f := newFakeGitHub(t)
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login == "acme-actions" {
			f.fx.Orgs[i].WorkflowPerms = "write"
		}
	}
	ix := collectFake(t, f)
	ix.mustEdge(t, deployCI, deployRepo, graph.CanPush)
	if p, ok := graph.Reach(ix.g, deployCI, graph.Options{}).Paths[deployMain]; !ok || !usesHop(p, deployRepo, deployMain) {
		t.Fatalf("unprotected: path to %s = %+v ok=%v", deployMain, p, ok)
	}

	f.rules["acme-actions/deploy@main"] = raws(t, prRule(7, 1, true, false))
	ix = collectFake(t, f)
	for id, p := range graph.Reach(ix.g, deployCI, graph.Options{}).Paths {
		if usesHop(p, deployRepo, deployMain) {
			t.Errorf("protected: path to %s still uses %s -> %s", id, deployRepo, deployMain)
		}
	}
}
