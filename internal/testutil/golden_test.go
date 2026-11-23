package testutil

import (
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n11\n"
	got := UnifiedDiff(a, b)
	want := "--- want\n+++ got\n@@ -2,9 +2,10 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n 9\n 10\n+11\n"
	if got != want {
		t.Errorf("UnifiedDiff:\n%s\nwant:\n%s", got, want)
	}
	if d := UnifiedDiff("x", "x\n"); !strings.Contains(d, "trailing newline") {
		t.Errorf("trailing newline diff: %q", d)
	}
}

func TestNormalize(t *testing.T) {
	got := string(Normalize([]byte("gop v1.2.3\r\nok\r\n"), "v1.2.3", ""))
	if got != "gop vTEST\nok\n" {
		t.Errorf("Normalize = %q", got)
	}
}
