package collect

import (
	"strings"
	"testing"
	"time"
)

func TestRefPatternMatch(t *testing.T) {
	cases := []struct {
		pattern, ref string
		want         bool
	}{
		{"refs/tags/v*", "refs/tags/v3", true},
		{"refs/tags/v*", "refs/tags/v3.1.0", true},
		{"refs/tags/v*", "refs/tags/release-2026", false},
		{"refs/tags/v*", "refs/tags/v3/hotfix", false}, // * stops at /
		{"refs/tags/**", "refs/tags/v3/hotfix", true},
		{"refs/tags/**/v*", "refs/tags/v3", true}, // **/ matches nothing too
		{"refs/tags/**/v*", "refs/tags/a/b/v3", true},
		{"refs/tags/**/v*", "refs/tags/a/b/x3", false},
		{"refs/tags/v?", "refs/tags/v3", true},
		{"refs/tags/v?", "refs/tags/v10", false},
		{"refs/tags/v[0-9]", "refs/tags/v3", true},
		{"refs/tags/v[!0-9]", "refs/tags/v3", false},
		{"refs/tags/v[^0-9]", "refs/tags/vx", true},
		{"refs/tags/v[]", "refs/tags/v[]", true}, // unterminated class is literal
		{`refs/tags/v\*`, "refs/tags/v*", true},
		{`refs/tags/v\*`, "refs/tags/v3", false},
		{"refs/tags/v3", "refs/tags/v3", true},
		{"refs/tags/v3", "refs/heads/v3", false},
		{"v*", "refs/tags/v3", false}, // patterns name full refs
		{"~ALL", "refs/tags/anything", true},
		{"~DEFAULT_BRANCH", "refs/tags/main", false},
		{"", "refs/tags/v3", false},
	}
	for _, tc := range cases {
		if got := refPatternMatch(tc.pattern, tc.ref); got != tc.want {
			t.Errorf("refPatternMatch(%q, %q) = %v, want %v", tc.pattern, tc.ref, got, tc.want)
		}
	}
}

// A pattern with many stars against a long attacker-chosen ref must not
// backtrack exponentially.
func TestRefPatternMatchLinear(t *testing.T) {
	pattern := "refs/tags/" + strings.Repeat("*a", 30) + "b"
	ref := "refs/tags/" + strings.Repeat("a", 4000)
	start := time.Now()
	if refPatternMatch(pattern, ref) {
		t.Error("unexpected match")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("match took %s", d)
	}
}

func TestRefBatchQueryUsesVariables(t *testing.T) {
	q := refBatchQuery(2)
	for _, want := range []string{"$o0: String!", "$h1: String!", "r1: repository(owner: $o1, name: $n1)", "ref(qualifiedName: $t0)"} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
}

func TestRefLookupKind(t *testing.T) {
	cases := []struct {
		l                RefLookup
		kind             string
		ambiguous, found bool
	}{
		{RefLookup{Tag: true}, "tag", false, true},
		{RefLookup{Branch: true}, "branch", false, true},
		{RefLookup{Tag: true, Branch: true}, "branch", true, true},
		{RefLookup{}, "", false, false},
	}
	for _, tc := range cases {
		k, a, f := tc.l.Kind()
		if k != tc.kind || a != tc.ambiguous || f != tc.found {
			t.Errorf("%+v.Kind() = %q %v %v", tc.l, k, a, f)
		}
	}
}
