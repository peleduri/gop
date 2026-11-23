package collect

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Workflow files and composite actions are attacker-controlled input: any repo
// in the enterprise can commit one. These fuzz targets check that the parsers
// never panic and that what they return keeps its invariants. `go test` runs
// only the seed corpus; CI runs each target with -fuzztime.

// fuzzSeeds returns the testdata workflow and action files plus hand-written
// edge cases: alias bombs, deep nesting, every shape of `on:`, non-UTF-8.
func fuzzSeeds(t testing.TB) [][]byte {
	var out [][]byte
	for _, dir := range []string{"testdata/workflows", "testdata/actions", "testdata/oidc"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out = append(out, b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return append(out,
		[]byte(""),
		[]byte("on: push\n"),
		[]byte("on: [push, pull_request]\njobs: {}\n"),
		[]byte("on:\n  push:\n    branches: [main]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme-actions/setup@v1\n"),
		[]byte("on: push\njobs:\n  a:\n    uses: acme-actions/deploy/.github/workflows/release.yml@"+testSHA+"\n    secrets: inherit\n"),
		[]byte("jobs:\n  a:\n    steps:\n      - run: echo ${{ secrets.github_token }} ${{ secrets.API_KEY }} ${{ secrets[format('X')] }}\n"),
		[]byte("permissions: write-all\njobs:\n  a:\n    permissions: {id-token: write}\n    runs-on: [self-hosted, linux]\n"),
		[]byte("runs:\n  using: composite\n  steps:\n    - uses: acme-actions/setup@main\n    - uses: ./local\n    - uses: docker://alpine:3\n"),
		[]byte("runs:\n  using: node20\n  main: index.js\n"),
		[]byte("jobs:\n  a:\n    steps:\n      - uses: [not, a, scalar]\n      - uses: {a: b}\n      - uses: a/b@c@d\n"),
		aliasBomb(9),
		deepNesting(500),
		[]byte("jobs:\n  a:\n    steps:\n      - uses: acme\xff\xfe/x@main\n"),
		[]byte("\xef\xbb\xbfon: push\n\x00\x01\x02"),
		[]byte("&a [*a]"),
		[]byte("a: &a\n  b: *a\n"),
	)
}

// aliasBomb is a "billion laughs" document: each level is a list of ten
// aliases to the previous level.
func aliasBomb(levels int) []byte {
	var b strings.Builder
	b.WriteString("x0: &x0 [\"lol\"]\n")
	for i := 1; i <= levels; i++ {
		b.WriteString("x")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(": &x")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(" [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*x")
			b.WriteString(strconv.Itoa(i - 1))
		}
		b.WriteString("]\n")
	}
	b.WriteString("jobs:\n  a:\n    runs-on: *x")
	b.WriteString(strconv.Itoa(levels))
	b.WriteString("\n    steps: *x")
	b.WriteString(strconv.Itoa(levels))
	b.WriteString("\n")
	return []byte(b.String())
}

func deepNesting(depth int) []byte {
	return []byte("jobs: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n")
}

func checkUses(t *testing.T, uses []ActionUse) {
	t.Helper()
	for _, u := range uses {
		if u.Owner == "" || u.Repo == "" || u.Ref == "" {
			t.Fatalf("use with empty owner/repo/ref: %+v", u)
		}
		v, ok := ParseUses(u.Raw)
		if !ok || v.Owner != u.Owner || v.Repo != u.Repo || v.Path != u.Path || v.Ref != u.Ref {
			t.Fatalf("ParseUses(%q) does not round-trip: got %+v ok=%v, want %+v", u.Raw, v, ok, u)
		}
		checkRefKind(t, u.Ref, u.RefKind)
	}
}

func checkRefKind(t *testing.T, ref, kind string) {
	t.Helper()
	switch kind {
	case "sha", "tag", "branch":
	default:
		t.Fatalf("RefKind(%q) = %q, want sha, tag or branch", ref, kind)
	}
}

func FuzzParseWorkflow(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		facts, err := ParseWorkflow(data)
		if err != nil {
			return
		}
		checkUses(t, facts.Uses)
		if !sort.StringsAreSorted(facts.Secrets) {
			t.Fatalf("secrets not sorted: %q", facts.Secrets)
		}
		switch facts.TokenContentsWrite {
		case TokenWrite:
			if len(facts.TokenWriteJobs) == 0 {
				t.Fatalf("token write with no write jobs")
			}
		case TokenDefault:
			if len(facts.TokenWriteJobs) > 0 || len(facts.TokenDefaultJobs) == 0 {
				t.Fatalf("token default with write jobs %q, default jobs %q", facts.TokenWriteJobs, facts.TokenDefaultJobs)
			}
		case TokenRead:
			if len(facts.TokenWriteJobs) > 0 || len(facts.TokenDefaultJobs) > 0 {
				t.Fatalf("token read with write jobs %q, default jobs %q", facts.TokenWriteJobs, facts.TokenDefaultJobs)
			}
		default:
			t.Fatalf("token contents %q", facts.TokenContentsWrite)
		}
		for _, l := range [][]string{facts.TokenWriteJobs, facts.TokenDefaultJobs, facts.TokenScopes} {
			if !sort.StringsAreSorted(l) {
				t.Fatalf("not sorted: %q", l)
			}
		}
		checkIDTokenJobs(t, facts)
		for i, s := range facts.Secrets {
			if i > 0 && facts.Secrets[i-1] == s {
				t.Fatalf("duplicate secret %q in %q", s, facts.Secrets)
			}
			if strings.EqualFold(s, "GITHUB_TOKEN") {
				t.Fatalf("secrets include %q", s)
			}
		}
	})
}

// checkIDTokenJobs checks that the id-token jobs are a sorted subset of the
// workflow's jobs and agree with IDTokenWrite, scopes and lines.
func checkIDTokenJobs(t *testing.T, facts *WorkflowFacts) {
	t.Helper()
	if !sort.StringsAreSorted(facts.Jobs) {
		t.Fatalf("jobs not sorted: %q", facts.Jobs)
	}
	jobs := map[string]bool{}
	for _, j := range facts.Jobs {
		if jobs[j] {
			t.Fatalf("duplicate job %q", j)
		}
		jobs[j] = true
	}
	if facts.IDTokenWrite != (len(facts.IDTokenJobs) > 0) {
		t.Fatalf("IDTokenWrite %v with id-token jobs %+v", facts.IDTokenWrite, facts.IDTokenJobs)
	}
	ids := facts.IDTokenJobIDs()
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("id-token jobs not sorted: %q", ids)
	}
	for i, j := range facts.IDTokenJobs {
		if !jobs[j.Job] || (i > 0 && ids[i-1] == j.Job) {
			t.Fatalf("id-token job %q is not a distinct job of %q", j.Job, facts.Jobs)
		}
		if j.Line < 1 {
			t.Fatalf("id-token job %q has line %d", j.Job, j.Line)
		}
		if j.EnvironmentDynamic != strings.Contains(j.Environment, "${{") {
			t.Fatalf("id-token job %q environment %q dynamic=%v", j.Job, j.Environment, j.EnvironmentDynamic)
		}
	}
	if (len(facts.IDTokenJobs) == 0) != (len(facts.IDTokenScopes) == 0) {
		t.Fatalf("id-token scopes %q with jobs %+v", facts.IDTokenScopes, facts.IDTokenJobs)
	}
	for _, s := range facts.IDTokenScopes {
		if facts.IDTokenLines[s] < 1 {
			t.Fatalf("id-token scope %q has no line in %v", s, facts.IDTokenLines)
		}
	}
}

func FuzzParseCompositeAction(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		uses, using, err := ParseCompositeAction(data)
		if err != nil {
			return
		}
		if using != "composite" && len(uses) > 0 {
			t.Fatalf("runs.using %q returned %d uses", using, len(uses))
		}
		checkUses(t, uses)
	})
}

func FuzzParseUses(f *testing.F) {
	for _, s := range []string{
		"acme-actions/deploy@main", "acme-actions/setup/.github/workflows/build.yml@v1",
		"acme-actions/deploy@" + testSHA, " acme/x@v1.2.3 ", "a/b@c@d", "./local", "docker://alpine:3",
		"acme@main", "acme/x@", "/x@y", "a//b@c", "${{ matrix.uses }}", "a/b@\xff", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, ok := ParseUses(s)
		if !ok {
			return
		}
		checkUses(t, []ActionUse{u})
	})
}

func FuzzRefKind(f *testing.F) {
	for _, s := range []string{testSHA, strings.ToUpper(testSHA), "v1", "v4.1.0", "1.2.3", "2.0", "main", "release/v1", "", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		checkRefKind(t, ref, RefKind(ref))
	})
}

func TestFuzzSeedsParse(t *testing.T) {
	// Guard against the seed walk silently finding nothing.
	if n := len(fuzzSeeds(t)); n < 20 {
		t.Fatalf("only %d fuzz seeds", n)
	}
}

// maxFileBytes is the largest file the contents API returns inline (base64).
const maxFileBytes = 1 << 20

// fill pads a document to just under maxFileBytes with copies of line.
func fill(head, line string, i0 int, n func(i int) string) []byte {
	var b strings.Builder
	b.WriteString(head)
	for i := i0; b.Len()+len(line)+16 < maxFileBytes; i++ {
		b.WriteString(strings.ReplaceAll(line, "N", n(i)))
	}
	return []byte(b.String())
}

// TestParseResourceBound: 1 MiB of hostile YAML (alias fan-out, or tens of
// thousands of flat keys, which made yaml.v3's quadratic duplicate-key check
// take about 20 s) must parse or fail in well under 2 s.
func TestParseResourceBound(t *testing.T) {
	bomb := string(aliasBomb(12))
	cases := map[string][]byte{
		"alias fan-out":        fill(bomb, "kN: [*x12, *x12, *x12, *x12, *x12, *x12, *x12, *x12]\n", 0, strconv.Itoa),
		"aliased steps":        fill("s: &s\n"+strings.Repeat("  - uses: acme/x@main\n", 2000)+"jobs:\n", "  jN: {steps: *s}\n", 0, strconv.Itoa),
		"flat top-level keys":  fill("", "kN: 1\n", 0, strconv.Itoa),
		"flat job keys":        fill("jobs:\n", "  jN: {}\n", 0, strconv.Itoa),
		"flat keys in one job": fill("jobs:\n  a:\n", "    kN: 1\n", 0, strconv.Itoa),
		"flat runs keys":       fill("runs:\n  using: composite\n", "  kN: 1\n", 0, strconv.Itoa),
		"many permission keys, many jobs": func() []byte {
			var b strings.Builder
			b.WriteString("permissions:\n")
			for i := 0; i < 15000; i++ {
				b.WriteString("  s" + strconv.Itoa(i) + ": write\n")
			}
			b.WriteString("jobs:\n")
			for i := 0; b.Len() < maxFileBytes-64; i++ {
				b.WriteString("  j" + strconv.Itoa(i) + ": {}\n")
			}
			return []byte(b.String())
		}(),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// The bound is about complexity, not speed: the quadratic parser this
			// replaced took about 20s on these inputs, the linear one about 0.1s.
			// 10s leaves room for parallel subtests on small CI runners (and for
			// goreleaser's hook running tests while it builds). The race detector
			// slows yaml parsing by an order of magnitude, so scale it there.
			limit := 10 * time.Second
			if raceEnabled {
				limit *= 10
			}
			done := make(chan error, 2)
			start := time.Now()
			go func() {
				_, err := ParseWorkflow(data)
				if err == nil {
					_, _, err = ParseCompositeAction(data)
				}
				done <- err
			}()
			select {
			case err := <-done:
				t.Logf("%d bytes: %v (err: %v)", len(data), time.Since(start), err)
			case <-time.After(limit):
				t.Fatalf("parsing %d bytes did not finish in %v", len(data), limit)
			}
		})
	}
}
