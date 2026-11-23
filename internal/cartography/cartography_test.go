package cartography

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/oidc"
)

const (
	fixture    = "../../testdata/cartography/oidc-trusts.json"
	deployOnly = "../../testdata/cartography/deploy-only.json"
	trustFile  = "../../testdata/acme/trust/aws/deploy.json"
	acmeGraph  = "../../testdata/acme/graph.json"
	deployARN  = "arn:aws:iam::111111111111:role/deploy"
	githubFed  = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
)

// stripSource clears what necessarily differs between a trust read from a
// trust file and from an export: the file and the pointer inside it.
func stripSource(ts []oidc.Trust) []oidc.Trust {
	out := make([]oidc.Trust, len(ts))
	for i, t := range ts {
		t.File, t.Pointer = "", ""
		out[i] = t
	}
	return out
}

func TestTrustRowEqualsTrustFile(t *testing.T) {
	want, err := oidc.ParseFile(trustFile)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadFile(deployOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings: %q", r.Warnings)
	}
	if !reflect.DeepEqual(stripSource(r.Trusts), stripSource(want)) {
		t.Errorf("export trusts\n%+v\nwant (from %s)\n%+v", r.Trusts, trustFile, want)
	}
	if r.Trusts[0].File != "../../testdata/cartography/deploy-only.json" || r.Trusts[0].Pointer != "/0/conditions/0" {
		t.Errorf("file %q pointer %q", r.Trusts[0].File, r.Trusts[0].Pointer)
	}
}

func TestFixture(t *testing.T) {
	r, err := ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	byTarget := map[string][]oidc.Trust{}
	for _, tr := range r.Trusts {
		role := strings.TrimPrefix(tr.Target, "arn:aws:iam::111111111111:role/")
		byTarget[role] = append(byTarget[role], tr)
	}
	if len(byTarget["deploy"]) != 1 || len(byTarget["ci-open"]) != 1 || len(byTarget["vault-release"]) != 2 ||
		len(byTarget["legacy"]) != 1 || len(byTarget["broken"]) != 1 || len(byTarget) != 5 {
		t.Fatalf("trusts by role: %+v", byTarget)
	}
	if r.TrustRows != 5 {
		t.Errorf("TrustRows = %d", r.TrustRows)
	}
	open := byTarget["ci-open"][0]
	if len(open.Subjects) != 0 || !contains(open.Warnings, oidc.WarnNoSub) || open.Pointer != "/1" {
		t.Errorf("unconditional trust: %+v", open)
	}
	vr := byTarget["vault-release"]
	if vr[0].Pointer != "/2/conditions/0" || vr[1].Pointer != "/2/conditions/1" ||
		vr[0].Subjects[0] != (oidc.Pattern{Raw: "repo:acme-secure/vault:environment:*", Op: oidc.OpGlob}) ||
		vr[1].Subjects[0] != (oidc.Pattern{Raw: "repo:acme-app/web:environment:staging", Op: oidc.OpEquals}) {
		t.Errorf("one trust per condition block: %+v", vr)
	}
	legacy := byTarget["legacy"][0]
	if len(legacy.Subjects) != 1 || legacy.Subjects[0].Op != oidc.OpCEL || contains(legacy.Warnings, oidc.WarnNoSub) ||
		!contains(legacy.Warnings, warnUnknownConditions) {
		t.Errorf("unknown conditions must be possible, not open: %+v", legacy)
	}
	if len(r.Observations) != 2 {
		t.Fatalf("observations: %+v", r.Observations)
	}
	if o := r.Observations[0]; o != (Observation{Row: 7, Repo: "acme-app/web", RoleARN: deployARN, TimesUsed: 42,
		FirstSeen: "2026-11-01T09:00:00Z", LastUsed: "2026-11-20T08:00:00Z"}) {
		t.Errorf("observation: %+v", o)
	}
	for _, want := range []string{
		"row 4: skipped: role_arn \"not-an-arn\"",
		"row 5: conditions is not JSON: conditions unknown",
		"row 3: has_condition and conditions are missing",
		"row 6: skipped: kind \"bogus\"",
		"row 9: skipped: repo \"nope\"",
		"row 10: skipped: kind \"\"",
	} {
		if !anyContains(r.Warnings, want) {
			t.Errorf("no warning %q in %q", want, r.Warnings)
		}
	}
	// Conditions that exist but cannot be read: possible, never dropped.
	if b := byTarget["broken"][0]; len(b.Subjects) != 1 || b.Subjects[0].Op != oidc.OpCEL || b.Pointer != "/5" {
		t.Errorf("unreadable conditions: %+v", b)
	}
}

// TestShapes: the same rows from every accepted export shape parse alike.
func TestShapes(t *testing.T) {
	cond := `[{"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme-app/web:environment:prod", "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}]`
	condJSON, _ := json.Marshal(cond)
	plainArray := `[{"kind":"trust","role_arn":"` + deployARN + `","role_name":"deploy","principal_arn":"` + githubFed + `","has_condition":true,"conditions":` + string(condJSON) + `},
 {"kind":"observed","role_arn":"` + deployARN + `","repo":"acme-app/web","times_used":42,"last_used":"2026-11-20T08:00:00Z"}]`
	records := `[{"keys":["kind","role_arn","role_name","principal_arn","has_condition","conditions","repo","times_used","last_used"],"length":9,
  "_fields":["trust","` + deployARN + `","deploy","` + githubFed + `",true,` + string(condJSON) + `,null,null,null],"_fieldLookup":{}},
 {"keys":["kind","role_arn","role_name","principal_arn","has_condition","conditions","repo","times_used","last_used"],"length":9,
  "_fields":["observed","` + deployARN + `","deploy",null,null,null,"acme-app/web",{"low":42,"high":0},"2026-11-20T08:00:00Z"],"_fieldLookup":{}}]`
	httpAPI := `{"results":[{"columns":["kind","role_arn","role_name","principal_arn","has_condition","conditions","repo","times_used","last_used"],
  "data":[{"row":["trust","` + deployARN + `","deploy","` + githubFed + `",true,` + string(condJSON) + `,null,null,null]},
          {"row":["observed","` + deployARN + `","deploy",null,null,null,"acme-app/web",42,"2026-11-20T08:00:00Z"]}]}],"errors":[]}`
	shellCond := strings.ReplaceAll(cond, `"`, `\"`)
	plain := "kind, role_arn, role_name, principal_arn, has_condition, conditions, repo, times_used, last_used\n" +
		`"trust", "` + deployARN + `", "deploy", "` + githubFed + `", TRUE, "` + shellCond + `", NULL, NULL, NULL` + "\n" +
		`"observed", "` + deployARN + `", "deploy", NULL, NULL, NULL, "acme-app/web", 42, "2026-11-20T08:00:00Z"` + "\n"

	want, err := Parse("export.json", []byte(plainArray))
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Trusts) != 1 || len(want.Observations) != 1 || len(want.Warnings) != 0 || want.Observations[0].TimesUsed != 42 {
		t.Fatalf("plain array: %+v", want)
	}
	for name, in := range map[string]string{"browser records": records, "http api": httpAPI, "cypher-shell plain": plain} {
		got, err := Parse("export.json", []byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n%+v\nwant\n%+v", name, got, want)
		}
	}
}

func TestFormatErrors(t *testing.T) {
	for _, in := range []string{`{`, `"x"`, `[] []`, "not a header!\n1, 2", "42"} {
		if _, err := Parse("x.json", []byte(in)); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: err = %v, want ErrFormat", in, err)
		}
	}
	for _, in := range []string{"", "  \n", "[]", "kind, role_arn\n"} {
		r, err := Parse("x.json", []byte(in))
		if err != nil || len(r.Trusts) != 0 || len(r.Warnings) != 0 {
			t.Errorf("%q: %+v %v", in, r, err)
		}
	}
	// A broken cypher-shell line is a warning, not an error.
	r, err := Parse("x.txt", []byte("kind, role_arn\n\"trust\", \"unterminated\n\"observed\"\n"))
	if err != nil || len(r.Warnings) != 2 {
		t.Errorf("broken lines: %+v %v", r, err)
	}
}

func TestAnnotate(t *testing.T) {
	g, err := graph.LoadFile(acmeGraph)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	oidc.Enrich(g, r.Trusts, []string{r.File}, nil)
	warns, st := Annotate(g, r)
	if st.Observed != 1 || st.Orphans != 1 || len(warns) != 1 ||
		!strings.Contains(warns[0], "row 8: CloudTrail shows acme-app/api assumed "+deployARN+" 3 times (last 2026-11-03T10:00:00Z), but no CAN_ASSUME edge") {
		t.Fatalf("stats %+v warnings %q", st, warns)
	}
	deploy := "cloud:aws:" + deployARN
	release := "workflow:acme-app/web/.github/workflows/release.yml"
	observed := 0
	for _, e := range g.Edges {
		if e.Kind != graph.CanAssume {
			continue
		}
		if e.Attrs[graph.AttrSource] != graph.SourceCartography || e.SourceAPI != graph.SourceSupplied+r.File {
			t.Errorf("edge %s -> %s: source %q source_api %q", e.From, e.To, e.Attrs[graph.AttrSource], e.SourceAPI)
		}
		if e.Attrs[graph.AttrObservedUse] == "true" {
			observed++
			if e.From != release || e.To != deploy || e.Attrs[graph.AttrTimesUsed] != "42" ||
				e.Attrs[graph.AttrLastUsed] != "2026-11-20T08:00:00Z" || e.Evidence != graph.Supplied {
				t.Errorf("observed edge: %+v", e)
			}
		}
	}
	if observed != 1 {
		t.Errorf("%d observed edges, want 1", observed)
	}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindCloudTarget && n.Attrs[graph.AttrSource] != graph.SourceCartography {
			t.Errorf("cloud node %s: source %q", n.ID, n.Attrs[graph.AttrSource])
		}
	}

	// Running again with no observations clears the attrs.
	r.Observations = nil
	oidc.Enrich(g, r.Trusts, []string{r.File}, nil)
	if _, st := Annotate(g, r); st.Observed != 0 {
		t.Errorf("stats %+v", st)
	}
	for _, e := range g.Edges {
		if e.Attrs[graph.AttrObservedUse] != "" || e.Attrs[graph.AttrTimesUsed] != "" {
			t.Errorf("stale observed attrs on %s -> %s", e.From, e.To)
		}
	}
}

func TestEdgeRepo(t *testing.T) {
	cases := []struct {
		e    graph.Edge
		want string
	}{
		{graph.Edge{From: "workflow:acme-app/web/.github/workflows/x.yml", Attrs: map[string]string{graph.AttrOIDC: "oidc:acme-app/web"}}, "acme-app/web"},
		{graph.Edge{From: "workflow:acme-app/api/.github/workflows/x.yml"}, "acme-app/api"},
		{graph.Edge{From: "repo:acme-app/api"}, ""},
		{graph.Edge{From: "workflow:acme"}, ""},
	}
	for _, c := range cases {
		if got := edgeRepo(c.e); got != c.want {
			t.Errorf("edgeRepo(%+v) = %q, want %q", c.e, got, c.want)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, e := range ss {
		if e == s {
			return true
		}
	}
	return false
}

func anyContains(ss []string, sub string) bool {
	for _, e := range ss {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
