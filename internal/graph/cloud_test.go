package graph

import (
	"strings"
	"testing"
)

const (
	cloudDeploy = "cloud:aws:arn:aws:iam::111111111111:role/deploy"
	cloudAzure  = "cloud:azure:app:11111111-1111-1111-1111-111111111111"
	webRelease  = "workflow:acme-app/web/.github/workflows/release.yml"
	webCI       = "workflow:acme-app/web/.github/workflows/ci.yml"
)

// acmeWithCloud is the acme fixture plus what gop enrich adds for one
// matched and one undecided trust.
func acmeWithCloud(t *testing.T) *Graph {
	t.Helper()
	g := loadAcme(t)
	g.Nodes = append(g.Nodes,
		Node{ID: cloudDeploy, Kind: KindCloudTarget, Name: "deploy", Evidence: Supplied},
		Node{ID: cloudAzure, Kind: KindCloudTarget, Name: "web-main", Evidence: Supplied})
	g.Edges = append(g.Edges,
		Edge{From: webRelease, To: cloudDeploy, Kind: CanAssume, Evidence: Supplied, SourceAPI: SourceSupplied + "trust/aws/deploy.json",
			Attrs: map[string]string{AttrFile: "trust/aws/deploy.json"}},
		Edge{From: webCI, To: cloudAzure, Kind: CanAssume, Evidence: NotVisible, SourceAPI: SourceSupplied + "trust/azure/web-main.json",
			Attrs: map[string]string{AttrFile: "trust/azure/web-main.json", AttrReason: "triggers unknown"}})
	return g
}

func TestLoadAcceptsSupplied(t *testing.T) {
	in := `{"schema":"gop.graph/v1","edges":[{"from":"workflow:a/b/w.yml","to":"cloud:aws:x","kind":"CAN_ASSUME","evidence":"supplied"}]}`
	if _, err := Load(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	if !Verified(Supplied) || evRank(Supplied) <= evRank(NotVisible) || evRank(Supplied) >= evRank(Audit) {
		t.Error("supplied must be verified and rank between not_visible and audit")
	}
	if weakest(Live, Supplied) != Supplied || weakest(Supplied, NotVisible) != NotVisible || weakest(Audit, Supplied) != Supplied {
		t.Error("weakest must order not_visible < supplied < audit < live")
	}
	if KindFromID(cloudDeploy) != KindCloudTarget {
		t.Error("cloud: prefix must infer cloud_target")
	}
}

func TestReachThroughCanAssume(t *testing.T) {
	g := acmeWithCloud(t)
	r := Reach(g, "members:acme-actions", Options{})
	if len(r.Confirmed.CloudTargets) != 1 || r.Confirmed.CloudTargets[0] != cloudDeploy {
		t.Fatalf("confirmed clouds = %v", r.Confirmed.CloudTargets)
	}
	if len(r.Possible.CloudTargets) != 1 || r.Possible.CloudTargets[0] != cloudAzure {
		t.Fatalf("possible clouds = %v", r.Possible.CloudTargets)
	}
	p := r.Paths[cloudDeploy]
	want := []string{"members:acme-actions", "repo:acme-actions/deploy", "action:acme-actions/deploy@main", webRelease, cloudDeploy}
	var got []string
	for i, h := range p.Hops {
		if i == 0 {
			got = append(got, h.From)
		}
		got = append(got, h.To)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") || p.Unverified || !p.Supplied || p.Evidence != Supplied {
		t.Errorf("path = %+v", p)
	}
	if p.SuppliedNote() != "cloud hop from supplied trust file trust/aws/deploy.json, not read from the cloud" {
		t.Errorf("note = %q", p.SuppliedNote())
	}
	pa := r.Paths[cloudAzure]
	if !pa.Unverified || !pa.Supplied || pa.Hops[len(pa.Hops)-1].Reason != "triggers unknown" {
		t.Errorf("azure path = %+v", pa)
	}
	// A path with no supplied hop is not flagged.
	if q := r.Paths["oidc:acme-app/web"]; q.Supplied || q.SuppliedNote() != "" {
		t.Errorf("oidc path flagged supplied: %+v", q)
	}
	// alice reaches neither: CAN_ASSUME starts at the workflow, not the shared oidc node.
	if a := Reach(g, "identity:alice", Options{}); len(a.Confirmed.CloudTargets)+len(a.Possible.CloudTargets) != 0 {
		t.Errorf("alice clouds = %+v", a)
	}
}

func TestWhoCanReachCloud(t *testing.T) {
	g := acmeWithCloud(t)
	ws := WhoCanReach(g, cloudDeploy)
	var from []string
	for _, p := range ws {
		if p.Unverified || !p.Supplied {
			t.Errorf("who path %+v", p)
		}
		from = append(from, p.From)
	}
	if strings.Join(from, ",") != "identity:bob,members:acme-actions" {
		t.Errorf("who can reach aws = %v", from)
	}
	for _, p := range WhoCanReach(g, cloudAzure) {
		if !p.Unverified {
			t.Errorf("azure path must stay possible: %+v", p)
		}
	}
}

func TestCloudScoreWeight(t *testing.T) {
	base := BlastRadius(loadAcme(t), "members:acme-actions")
	s := BlastRadius(acmeWithCloud(t), "members:acme-actions")
	if s.Confirmed.CloudTargets != 1 || s.Possible.CloudTargets != 1 {
		t.Fatalf("counts = %+v / %+v", s.Confirmed, s.Possible)
	}
	if got, want := s.Score-base.Score, wCloud*s.Multiplier; got != want {
		t.Errorf("score delta = %v, want %v (wCloud=13 x multiplier)", got, want)
	}
	if s.PossibleScore != wCloud*s.Multiplier {
		t.Errorf("possible score = %v", s.PossibleScore)
	}
}
