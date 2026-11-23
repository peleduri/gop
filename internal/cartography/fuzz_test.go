package cartography

import (
	"os"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/oidc"
)

// Exports come from users and from tools gop does not control. FuzzParse
// checks that Parse never panics and that what it returns keeps its
// invariants: AWS trusts on IAM role ARNs recorded under the export's file,
// and observations of owner/repo. `go test` runs only the seed corpus.
func FuzzParse(f *testing.F) {
	for _, p := range []string{fixture, deployOnly} {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"results":[{"columns":["kind","role_arn","times_used"],"data":[{"row":["observed","arn:aws:iam::1:role/r",{"low":1,"high":1}]}]}]}`))
	f.Add([]byte(`[{"keys":["kind","role_arn"],"_fields":["trust"]}]`))
	f.Add([]byte("kind, role_arn, principal_arn, conditions\n\"trust\", \"arn:aws:iam::1:role/r\", \"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com\", [{StringLike: {`token.actions.githubusercontent.com:sub`: 'repo:acme-app/*'}}]\n"))
	f.Add([]byte(`[{"kind":"trust","role_arn":"arn:aws:iam::1:role/r","principal_arn":"x","has_condition":"true","conditions":"[1]"}]`))
	f.Add([]byte("a\n" + strings.Repeat("[", 200)))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse("export.json", data)
		if err != nil {
			return
		}
		for _, tr := range r.Trusts {
			if tr.Provider != oidc.AWS || !isRoleARN(tr.Target) || tr.File != "export.json" || !strings.HasPrefix(tr.Pointer, "/") {
				t.Fatalf("bad trust %+v", tr)
			}
			for _, p := range tr.Subjects {
				if p.Op == oidc.OpCEL && len(tr.Warnings) == 0 {
					t.Fatalf("possible condition without a warning: %+v", tr)
				}
			}
		}
		for _, o := range r.Observations {
			if strings.Count(o.Repo, "/") != 1 || !isRoleARN(o.RoleARN) || o.TimesUsed < 0 {
				t.Fatalf("bad observation %+v", o)
			}
		}
	})
}
