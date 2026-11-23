package fixplan

import (
	"strings"
	"testing"
)

const sha = "1111111111111111111111111111111111111111"

func TestPinLine(t *testing.T) {
	uses := "acme-actions/deploy@main"
	for _, tc := range []struct{ in, want string }{
		{"      - uses: acme-actions/deploy@main", "      - uses: acme-actions/deploy@" + sha + " # main"},
		{"    uses: acme-actions/deploy@main", "    uses: acme-actions/deploy@" + sha + " # main"},
		{`      - uses: "acme-actions/deploy@main" # deploy`, `      - uses: "acme-actions/deploy@` + sha + `" # main # deploy`},
		{"      - uses: 'acme-actions/deploy@main'\r", "      - uses: 'acme-actions/deploy@" + sha + "' # main\r"},
		{"  - {uses: acme-actions/deploy@main}", ""},
		{"      - uses: acme-actions/deploy@main-2", ""},
		{"      - uses: acme-actions/deploy@mainline", ""},
		{"      - uses: other/acme-actions/deploy@main", ""},
		{"      # uses acme-actions/deploy@main", ""},
		{"", ""},
	} {
		got, ok := PinLine(tc.in, uses, sha)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("PinLine(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
	got, ok := PinLine("      - uses: acme-actions/tools/.github/workflows/build.yml@v1", "acme-actions/tools/.github/workflows/build.yml@v1", sha)
	if !ok || got != "      - uses: acme-actions/tools/.github/workflows/build.yml@"+sha+" # v1" {
		t.Errorf("reusable workflow: %q %v", got, ok)
	}
}

func TestFileDiffMergesHunks(t *testing.T) {
	var lines []string
	for i := 1; i <= 20; i++ {
		lines = append(lines, "l"+string(rune('a'+i-1)))
	}
	content := []byte(strings.Join(lines, "\n") + "\n")
	got := FileDiff("f.yml", content, []Edit{{Line: 2, New: "X"}, {Line: 7, New: "Y"}, {Line: 18, New: "Z"}, {Line: 30, New: "ignored"}})
	want := `diff --git a/f.yml b/f.yml
--- a/f.yml
+++ b/f.yml
@@ -1,10 +1,10 @@
 la
-lb
+X
 lc
 ld
 le
 lf
-lg
+Y
 lh
 li
 lj
@@ -15,6 +15,6 @@
 lo
 lp
 lq
-lr
+Z
 ls
 lt
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if FileDiff("f.yml", content, []Edit{{Line: 1, New: "la"}}) != "" {
		t.Error("an edit that changes nothing should give no diff")
	}
}

func TestFileDiffNoTrailingNewline(t *testing.T) {
	got := FileDiff("f.yml", []byte("a\nb"), []Edit{{Line: 2, New: "c"}})
	want := "diff --git a/f.yml b/f.yml\n--- a/f.yml\n+++ b/f.yml\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestPinFileDiffMissing(t *testing.T) {
	content := []byte("steps:\n  - uses: acme-actions/deploy@main\n")
	diff, missing := PinFileDiff("w.yml", content, []int{1, 2, 9}, "acme-actions/deploy@main", sha)
	if len(missing) != 2 || missing[0] != 1 || missing[1] != 9 {
		t.Errorf("missing = %v", missing)
	}
	if !strings.Contains(diff, "+  - uses: acme-actions/deploy@"+sha+" # main\n") {
		t.Errorf("diff:\n%s", diff)
	}
}

func TestPinDiffMatchesPinnedUses(t *testing.T) {
	d := PinDiff("w.yml", 4, "acme-actions/deploy@main", sha)
	v, c := PinnedUses("acme-actions/deploy@main", sha)
	if !strings.Contains(d, "+uses: "+v+" "+c+"\n") {
		t.Errorf("PinDiff = %q", d)
	}
}
