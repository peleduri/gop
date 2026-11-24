package mcpserver

import (
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/demo"
)

func TestTopRisksAdvisoryFirst(t *testing.T) {
	out, err := NewEngine(demo.Generate(demo.Options{Seed: 1})).TopRisks(TopRisksInput{N: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.Risks[0].Principal != demo.CheckoutIsh || len(out.Risks[0].Advisories) == 0 {
		t.Fatalf("top risk %+v", out.Risks[0])
	}
	if out.Risks[1].Score <= out.Risks[0].Score {
		t.Errorf("the advisory ranks first despite a lower score: %+v", out.Risks[:2])
	}
	if !strings.Contains(out.Summary, "known advisory") {
		t.Errorf("summary %q", out.Summary)
	}
}
