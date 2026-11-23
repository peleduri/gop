package oidc

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

const (
	acmeGraph = "../../testdata/acme/graph.json"
	acmeTrust = "../../testdata/acme/trust"
	awsDeploy = "cloud:aws:arn:aws:iam::111111111111:role/deploy"
	azureWeb  = "cloud:azure:app:11111111-1111-1111-1111-111111111111"
	webCI     = "workflow:acme-app/web/.github/workflows/ci.yml"
	vaultRel  = "workflow:acme-secure/vault/.github/workflows/release.yml"
)

func enrichAcme(t *testing.T, paths ...string) (*graph.Graph, EnrichStats) {
	t.Helper()
	g, err := graph.LoadFile(acmeGraph)
	if err != nil {
		t.Fatal(err)
	}
	files, err := TrustFiles(paths...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(Options{}, paths...)
	if err != nil {
		t.Fatal(err)
	}
	return g, Enrich(g, res.Trusts, files, res.Warnings)
}

func findEdge(g *graph.Graph, from, to string) (graph.Edge, bool) {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Kind == graph.CanAssume {
			return e, true
		}
	}
	return graph.Edge{}, false
}

func findNode(g *graph.Graph, id string) (graph.Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return graph.Node{}, false
}

func TestEnrichAcme(t *testing.T) {
	g, st := enrichAcme(t, acmeTrust)
	if st.Confirmed != 1 || st.Unmatched != 1 {
		t.Errorf("stats = %+v", st)
	}

	// Environment-scoped AWS trust: the prod release workflow assumes it, supplied.
	e, ok := findEdge(g, webRelease, awsDeploy)
	if !ok || e.Evidence != graph.Supplied || e.Attrs[graph.AttrMatchedSub] != "repo:acme-app/web:environment:prod" ||
		e.Attrs[graph.AttrFile] != "../../testdata/acme/trust/aws/deploy.json" || e.SourceAPI != "supplied:../../testdata/acme/trust/aws/deploy.json" ||
		e.Attrs[graph.AttrProvider] != "aws" || e.Attrs[graph.AttrOIDC] != "oidc:acme-app/web" || e.Attrs[graph.AttrClaims] != "sub" ||
		e.Attrs[graph.AttrPointer] == "" || !e.ObservedAt.Equal(g.CollectedAt) {
		t.Errorf("release -> aws = %+v (found %v)", e, ok)
	}
	// ci.yml has no environment: the env-scoped trust does not match it.
	if _, ok := findEdge(g, webCI, awsDeploy); ok {
		t.Error("ci.yml (no environment) must not assume the prod-scoped role")
	}
	n, ok := findNode(g, awsDeploy)
	if !ok || n.Kind != graph.KindCloudTarget || n.Evidence != graph.Supplied || n.Attrs[graph.AttrAccount] != "111111111111" ||
		n.Attrs[graph.AttrRole] != "deploy" || n.Attrs[graph.AttrProvider] != "aws" {
		t.Errorf("aws node = %+v", n)
	}

	// Branch-scoped Azure trust, triggers unknown: possible, with a reason.
	e, ok = findEdge(g, webCI, azureWeb)
	if !ok || e.Evidence != graph.NotVisible || !strings.Contains(e.Attrs[graph.AttrReason], "triggers") ||
		e.Attrs[graph.AttrTrust] != "app:11111111-1111-1111-1111-111111111111/fic:web-main" {
		t.Errorf("ci -> azure = %+v (found %v)", e, ok)
	}
	if _, ok := findEdge(g, webRelease, azureWeb); ok {
		t.Error("release.yml (single prod job) must not match a branch-scoped sub")
	}

	// Unparsed GCP CEL: possible, never dropped or confirmed.
	sa := "cloud:gcp:serviceAccount:deploy@acme-prod.iam.gserviceaccount.com"
	for _, w := range []string{webCI, webRelease} {
		e, ok = findEdge(g, w, sa)
		if !ok || e.Evidence != graph.NotVisible || !strings.Contains(e.Attrs[graph.AttrReason], "not understood") {
			t.Errorf("%s -> gcp sa = %+v (found %v)", w, e, ok)
		}
	}
	if n, _ := findNode(g, sa); n.Attrs[graph.AttrAccount] != "acme-prod" || !strings.Contains(n.Attrs[graph.AttrWarnings], CodeUnparsed) {
		t.Errorf("gcp node = %+v", n)
	}

	// vault matches nothing: coverage, not a guess.
	var cov []graph.Coverage
	for _, c := range g.Coverage {
		if c.Fact == FactCloudTrust {
			cov = append(cov, c)
		}
	}
	if len(cov) != 1 || cov[0].Scope != "oidc:acme-secure/vault" || cov[0].NeedsFix != NeedsFixCloudTrust {
		t.Errorf("cloud_trust coverage = %+v", cov)
	}

	// Reach: confirmed and supplied through the release workflow.
	r := graph.Reach(g, "members:acme-actions", graph.Options{})
	p, ok := r.Paths[awsDeploy]
	if !ok || p.Unverified || !p.Supplied || p.Evidence != graph.Supplied || len(r.Confirmed.CloudTargets) != 1 {
		t.Fatalf("path to aws = %+v, confirmed clouds %v", p, r.Confirmed.CloudTargets)
	}
	if want := "cloud hop from supplied trust file ../../testdata/acme/trust/aws/deploy.json, not read from the cloud"; p.SuppliedNote() != want {
		t.Errorf("note = %q", p.SuppliedNote())
	}
	if p, ok := r.Paths[azureWeb]; !ok || !p.Unverified || !p.Supplied || p.Hops[len(p.Hops)-1].Reason == "" {
		t.Errorf("path to azure = %+v", p)
	}
}

func TestEnrichNoSubMatchesEveryOIDCNode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "open.json")
	doc := `{"Role": {"RoleName": "open", "Arn": "arn:aws:iam::111111111111:role/open", "AssumeRolePolicyDocument": {"Statement": [
	  {"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
	   "Action": "sts:AssumeRoleWithWebIdentity",
	   "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}]}}}`
	if err := os.WriteFile(f, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	g, st := enrichAcme(t, f)
	open := "cloud:aws:arn:aws:iam::111111111111:role/open"
	for _, w := range []string{webCI, webRelease, vaultRel} {
		if e, ok := findEdge(g, w, open); !ok || e.Evidence != graph.Supplied {
			t.Errorf("%s -> open role: %+v (found %v)", w, e, ok)
		}
	}
	n, _ := findNode(g, open)
	if n.Attrs[graph.AttrWarnings] != CodeNoSub {
		t.Errorf("warnings = %q, want %s", n.Attrs[graph.AttrWarnings], CodeNoSub)
	}
	if st.Unmatched != 0 {
		t.Errorf("unmatched = %d", st.Unmatched)
	}
}

func TestEnrichIdempotent(t *testing.T) {
	g, _ := enrichAcme(t, acmeTrust)
	var once bytes.Buffer
	if err := json.NewEncoder(&once).Encode(g); err != nil {
		t.Fatal(err)
	}
	files, _ := TrustFiles(acmeTrust)
	res, _ := Parse(Options{}, acmeTrust)
	Enrich(g, res.Trusts, files, res.Warnings)
	var twice bytes.Buffer
	if err := json.NewEncoder(&twice).Encode(g); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(once.Bytes(), twice.Bytes()) {
		t.Error("enriching an enriched graph with the same files changed it")
	}
	g2, _ := enrichAcme(t, acmeTrust)
	var again bytes.Buffer
	if err := json.NewEncoder(&again).Encode(g2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(once.Bytes(), again.Bytes()) {
		t.Error("two runs on the same inputs differ")
	}

	// Enriching with no trusts from the same files removes what they added.
	Enrich(g, nil, files, nil)
	for _, n := range g.Nodes {
		if n.Kind == graph.KindCloudTarget {
			t.Errorf("stale cloud node %s", n.ID)
		}
	}
	for _, e := range g.Edges {
		if e.Kind == graph.CanAssume {
			t.Errorf("stale edge %s -> %s", e.From, e.To)
		}
	}
}

func TestEnrichDenyStatementDowngrades(t *testing.T) {
	g, err := graph.LoadFile(acmeGraph)
	if err != nil {
		t.Fatal(err)
	}
	tr := Trust{Provider: AWS, Target: "arn:aws:iam::111111111111:role/deploy", File: "trust/deploy.json",
		Subjects: []Pattern{{Raw: "repo:acme-app/web:environment:prod", Op: OpEquals}}}
	Enrich(g, []Trust{tr}, []string{"trust/deploy.json"}, []string{"trust/deploy.json: /Statement/1: Deny statement for sts:AssumeRoleWithWebIdentity ignored; the real trust may be narrower"})
	e, ok := findEdge(g, webRelease, awsDeploy)
	if !ok || e.Evidence != graph.NotVisible || !strings.Contains(e.Attrs[graph.AttrReason], "Deny") {
		t.Errorf("edge = %+v (found %v)", e, ok)
	}
}

func TestCloudID(t *testing.T) {
	for _, c := range []struct {
		t    Trust
		want string
	}{
		{Trust{Provider: AWS, Target: "arn:aws:iam::111111111111:role/deploy"}, awsDeploy},
		{Trust{Provider: GCP, Target: "projects/acme-prod/x+serviceAccount:a@acme-prod.iam.gserviceaccount.com", ServiceAccount: "a@acme-prod.iam.gserviceaccount.com"},
			"cloud:gcp:serviceAccount:a@acme-prod.iam.gserviceaccount.com"},
		{Trust{Provider: Azure, Target: "app:11111111-1111-1111-1111-111111111111/fic:web-main"}, azureWeb},
		{Trust{Provider: Azure, Target: "identity:/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/acme-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deployer/fic:web-prod"},
			"cloud:azure:identity:/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/acme-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deployer"},
	} {
		if got := CloudID(c.t); got != c.want {
			t.Errorf("CloudID(%s) = %s, want %s", c.t.Target, got, c.want)
		}
	}
	n := cloudNode(Trust{Provider: Azure, Target: "identity:/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/acme-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deployer/fic:web-prod"})
	if n.Attrs[graph.AttrAccount] != "00000000-0000-0000-0000-000000000000" || n.Attrs[graph.AttrRole] != "deployer" {
		t.Errorf("azure identity node attrs = %v", n.Attrs)
	}
}

// setHost records host on the graph's enterprise node.
func setHost(g *graph.Graph, host string) {
	for i := range g.Nodes {
		if g.Nodes[i].Kind == graph.KindEnterprise {
			if g.Nodes[i].Attrs == nil {
				g.Nodes[i].Attrs = map[string]string{}
			}
			g.Nodes[i].Attrs[graph.AttrHost] = host
		}
	}
}

// ghesTrust copies the acme trust files with the GHES issuer
// https://github.acme.example/_services/token in place of github.com's.
func ghesTrust(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(acmeTrust, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(acmeTrust, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out := strings.ReplaceAll(string(b), "token.actions.githubusercontent.com", "github.acme.example/_services/token")
		if err := os.MkdirAll(filepath.Join(dst, filepath.Dir(rel)), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), []byte(out), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func enrichWithHost(t *testing.T, host, trustDir string) (*graph.Graph, EnrichStats) {
	t.Helper()
	g, err := graph.LoadFile(acmeGraph)
	if err != nil {
		t.Fatal(err)
	}
	setHost(g, host)
	files, err := TrustFiles(trustDir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(Options{}, trustDir)
	if err != nil {
		t.Fatal(err)
	}
	return g, Enrich(g, res.Trusts, files, res.Warnings)
}

// TestEnrichMatchesIssuerOfHost: a GHES graph matches trusts for its own
// issuer (https://HOST/_services/token) and none for github.com's, and the
// reverse for a github.com graph.
func TestEnrichMatchesIssuerOfHost(t *testing.T) {
	_, base := enrichAcme(t, acmeTrust)
	if base.Confirmed == 0 {
		t.Fatal("baseline has no confirmed match")
	}
	ghes := ghesTrust(t)
	for _, tc := range []struct {
		host, trust string
		match       bool
	}{
		{"github.acme.example", ghes, true},
		{"github.acme.example", acmeTrust, false},
		{"github.com", acmeTrust, true},
		{"github.com", ghes, false},
		{"", ghes, true}, // a graph without host matches any GitHub issuer
	} {
		g, st := enrichWithHost(t, tc.host, tc.trust)
		assumes := 0
		for _, e := range g.Edges {
			if e.Kind == graph.CanAssume {
				assumes++
			}
		}
		if tc.match && st != base {
			t.Errorf("host %q trust %s: %+v, want %+v", tc.host, tc.trust, st, base)
		}
		if !tc.match && (st.Confirmed+st.Possible != 0 || assumes != 0) {
			t.Errorf("host %q trust %s: %+v (%d CAN_ASSUME edges), want no match", tc.host, tc.trust, st, assumes)
		}
	}
}

func TestIssuerFor(t *testing.T) {
	for host, want := range map[string]string{
		"":                    "https://token.actions.githubusercontent.com",
		"github.com":          "https://token.actions.githubusercontent.com",
		"GitHub.Acme.Example": "https://github.acme.example/_services/token",
	} {
		if got := IssuerFor(host); got != want {
			t.Errorf("IssuerFor(%q) = %q, want %q", host, got, want)
		}
		if !IssuerMatchesHost(want, host) {
			t.Errorf("IssuerMatchesHost(%q, %q) = false", want, host)
		}
	}
	for _, tc := range []struct {
		iss, host string
		want      bool
	}{
		{"https://token.actions.githubusercontent.com/acme", "github.com", true},
		{"https://token.actions.githubusercontent.com/", "github.com", true},
		{"https://github.acme.example/_services/token/", "github.acme.example", true},
		{"https://github.acme.example/_services/token", "github.com", false},
		{"https://token.actions.githubusercontent.com", "github.acme.example", false},
		{"https://other.example/_services/token", "github.acme.example", false},
		{"https://github.acme.example/other", "github.acme.example", false},
		{"", "github.acme.example", true},
	} {
		if got := IssuerMatchesHost(tc.iss, tc.host); got != tc.want {
			t.Errorf("IssuerMatchesHost(%q, %q) = %v, want %v", tc.iss, tc.host, got, tc.want)
		}
	}
}
