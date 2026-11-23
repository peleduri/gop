package oidc

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	gcpPool  = "projects/acme-prod/locations/global/workloadIdentityPools/github/providers/"
	gcpAud   = "https://iam.googleapis.com/" + gcpPool
	azureApp = "app:22222222-2222-2222-2222-222222222222/fic:"
	azAud    = " aud=api://AzureADTokenExchange"
	stsAud   = " aud=sts.amazonaws.com"
	noSub    = "\n  ! " + WarnNoSub
	noAud    = "\n  ! " + WarnNoAud
)

func wildOwner(key, raw string) string {
	return "\n  ! wildcard owner: " + key + " " + strconv.Quote(raw) + " does not pin the repository owner; repositories of other GitHub users can match"
}

type fileCase struct {
	file string
	opts Options
	want []string // summary() of each trust, in order
}

func runFileCases(t *testing.T, cases []fileCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			r, err := Parse(c.opts, filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, tr := range r.Trusts {
				got = append(got, summary(tr))
				checkTrust(t, tr)
			}
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

func TestParseAWS(t *testing.T) {
	runFileCases(t, []fileCase{
		{file: "aws/exact-sub.json", want: []string{
			"aws arn:aws:iam::111111111111:role/deploy" + stsAud + " sub=[equals:repo:acme-app/web:ref:refs/heads/main]",
		}},
		{file: "aws/wildcard-branch.json", want: []string{
			"aws unknown:testdata/aws/wildcard-branch.json" + stsAud + " sub=[glob:repo:acme-app/web:ref:refs/heads/*]" +
				"\n  ! role ARN unknown: supply the aws iam get-role output or a target override",
		}},
		{file: "aws/wildcard-branch.json", opts: Options{Target: "arn:aws:iam::111111111111:role/deploy"}, want: []string{
			"aws arn:aws:iam::111111111111:role/deploy" + stsAud + " sub=[glob:repo:acme-app/web:ref:refs/heads/*]",
		}},
		{file: "aws/environment-only.json", want: []string{
			"aws arn:aws:iam::111111111111:role/ci/deploy-prod" + stsAud + " sub=[equals:repo:acme-app/web:environment:prod]",
		}},
		{file: "aws/missing-sub.json", want: []string{
			"aws arn:aws:iam::111111111111:role/ci-readonly" + stsAud + noSub,
		}},
		{file: "aws/wildcard-owner.json", want: []string{
			"aws arn:aws:iam::111111111111:role/artifacts" + stsAud + " sub=[glob:repo:acme* | glob:repo:*/web:ref:refs/heads/main]" +
				wildOwner("sub", "repo:acme*") + wildOwner("sub", "repo:*/web:ref:refs/heads/main"),
		}},
		{file: "aws/list-roles.json", want: []string{
			"aws arn:aws:iam::111111111111:role/release sub=[glob:repo:acme-app/*:ref:refs/tags/v*]" +
				"\n  ! negative condition StringNotEquals on sub ignored, treated as possible" + noAud,
		}},
	})
}

func TestParseGCP(t *testing.T) {
	runFileCases(t, []fileCase{
		{file: "gcp/exact-sub.json", want: []string{
			"gcp " + gcpPool + "github-main aud=" + gcpAud + "github-main sub=[equals:repo:acme-app/web:ref:refs/heads/main]",
		}},
		{file: "gcp/wildcard-branch.json", want: []string{
			"gcp " + gcpPool + "github-branches aud=" + gcpAud + "github-branches ref=[like:refs/heads/] repository=[equals:acme-app/web]",
		}},
		{file: "gcp/environment-only.json", want: []string{
			"gcp " + gcpPool + "github-prod aud=" + gcpAud + "github-prod environment=[equals:prod] repository_owner=[equals:acme-app]",
		}},
		{file: "gcp/missing-sub.json", want: []string{
			"gcp " + gcpPool + "github-open aud=" + gcpAud + "github-open" + noSub,
		}},
		{file: "gcp/unparsed-cel.json", want: []string{
			"gcp " + gcpPool + "github-regex aud=" + gcpAud + "github-regex repository_owner=[equals:acme-app] workflow_ref=[cel:assertion.workflow_ref.matches('^acme-app/[a-z]+/')]" +
				"\n  ! condition not fully understood, treated as possible: assertion.workflow_ref.matches('^acme-app/[a-z]+/')",
		}},
		{file: "gcp/or-branches.json", want: []string{
			"gcp " + gcpPool + "github-either aud=" + gcpAud + "github-either repository=[equals:acme-app/web | equals:acme-app/api]",
			"gcp " + gcpPool + "github-either aud=" + gcpAud + "github-either ref=[equals:refs/heads/main] repository_owner=[equals:acme-actions]",
		}},
		{file: "gcp/bound", want: []string{
			"gcp projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github aud=https://iam.googleapis.com/projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github repository_owner=[equals:acme-app]",
			"gcp projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github+serviceAccount:deploy@acme-prod.iam.gserviceaccount.com aud=https://iam.googleapis.com/projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github repository=[equals:acme-app/web] repository_owner=[equals:acme-app]",
			"gcp projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github+serviceAccount:deploy@acme-prod.iam.gserviceaccount.com aud=https://iam.googleapis.com/projects/acme-prod/locations/global/workloadIdentityPools/deploy/providers/github sub=[equals:repo:acme-app/api:environment:prod] repository_owner=[equals:acme-app]",
		}},
	})
}

func TestParseAzure(t *testing.T) {
	runFileCases(t, []fileCase{
		{file: "azure/exact-sub.json", want: []string{
			"azure unknown:testdata/azure/exact-sub.json#/0/fic:web-main" + azAud + " sub=[equals:repo:acme-app/web:ref:refs/heads/main]" +
				"\n  ! application (client) ID unknown: pass it as the target or wrap the list as {\"appId\": ..., \"federatedCredentials\": [...]}",
		}},
		{file: "azure/exact-sub.json", opts: Options{Target: "22222222-2222-2222-2222-222222222222"}, want: []string{
			"azure " + azureApp + "web-main" + azAud + " sub=[equals:repo:acme-app/web:ref:refs/heads/main]",
		}},
		{file: "azure/wildcard-branch.json", want: []string{
			"azure " + azureApp + "web-branches" + azAud + " sub=[glob:repo:acme-app/web:ref:refs/heads/*]",
		}},
		{file: "azure/environment-only.json", want: []string{
			"azure " + azureApp + "web-prod" + azAud + " sub=[equals:repo:acme-app/web:environment:prod]",
		}},
		{file: "azure/missing-sub.json", want: []string{
			"azure " + azureApp + "any-main" + azAud + " ref=[equals:refs/heads/main]" + noSub,
		}},
		{file: "azure/wildcard-owner.json", want: []string{
			"azure " + azureApp + "any-prod" + azAud + " sub=[glob:repo:*:environment:prod]" + wildOwner("sub", "repo:*:environment:prod"),
			"azure " + azureApp + "any-prod" + azAud + " sub=[equals:repo:acme-app/api:ref:refs/heads/main | cel:claims['sub'].startsWith('repo:acme')]" +
				"\n  ! condition not fully understood, treated as possible: claims['sub'].startsWith('repo:acme')" +
				"\n  ! 2 conditions on sub must all hold; treated as any one of them",
		}},
		{file: "azure/managed-identity.json", want: []string{
			"azure identity:/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/acme-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/deployer/fic:web-prod" + azAud + " sub=[equals:repo:acme-app/web:environment:prod]",
		}},
	})
}

// checkTrust asserts the invariants every parsed trust keeps.
func checkTrust(t *testing.T, tr Trust) {
	t.Helper()
	switch tr.Provider {
	case AWS, GCP, Azure:
	default:
		t.Fatalf("provider %q", tr.Provider)
	}
	if tr.Target == "" || tr.File == "" {
		t.Fatalf("empty target or file: %+v", tr)
	}
	if !isGitHubIssuer(tr.Issuer) {
		t.Fatalf("issuer %q is not GitHub", tr.Issuer)
	}
	cel := false
	check := func(ps []Pattern) {
		for _, p := range ps {
			switch p.Op {
			case OpEquals, OpLike, OpGlob:
			case OpCEL:
				cel = true
			default:
				t.Fatalf("pattern op %q", p.Op)
			}
		}
	}
	check(tr.Subjects)
	for k, ps := range tr.Claims {
		if k == "" || k == "sub" || len(ps) == 0 {
			t.Fatalf("bad claims key %q with %d patterns", k, len(ps))
		}
		check(ps)
	}
	if cel && !hasWarning(tr, "treated as possible") {
		t.Fatalf("cel pattern without a warning: %s", summary(tr))
	}
}

func hasWarning(tr Trust, substr string) bool {
	for _, w := range tr.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestEveryProviderHasFourFixtures(t *testing.T) {
	for _, p := range []string{"aws", "gcp", "azure"} {
		for _, f := range []string{"exact-sub", "wildcard-branch", "environment-only", "missing-sub"} {
			if _, err := os.Stat(filepath.Join("testdata", p, f+".json")); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	for name, data := range map[string]string{
		"not json":       "resource \"aws_iam_role\" \"deploy\" {}",
		"empty":          "",
		"number":         "42",
		"null":           "null",
		"other object":   `{"kind": "Deployment"}`,
		"list of string": `["a"]`,
		"mixed list":     `[{"issuer":"https://token.actions.githubusercontent.com","subject":"x"}, 1]`,
		"two values":     `{} {}`,
		"bad statement":  `{"Statement": "x"}`,
		"string doc":     `{"Role":{"AssumeRolePolicyDocument":"%zz"}}`,
		"bad value list": `{"value":[{"name":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBytes("x.json", []byte(data), Options{})
			if !errors.Is(err, ErrUnknownFormat) {
				t.Fatalf("err = %v, want ErrUnknownFormat", err)
			}
		})
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(p, []byte(`{"kind":"Deployment"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(p); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("ParseFile err = %v, want ErrUnknownFormat", err)
	}
}

func TestDirectorySkipsUnknown(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile("testdata/aws/exact-sub.json")
	if err != nil {
		t.Fatal(err)
	}
	write("roles/deploy.json", string(b))
	write("package.json", `{"name":"acme-web"}`)
	write("notes.txt", "not json and not .json")
	write("broken.json", "{")
	r, err := Parse(Options{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Trusts) != 1 || r.Trusts[0].Target != "arn:aws:iam::111111111111:role/deploy" {
		t.Fatalf("trusts = %+v", r.Trusts)
	}
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "broken.json: skipped") || !strings.Contains(r.Warnings[1], "package.json: skipped") {
		t.Fatalf("warnings = %q", r.Warnings)
	}
	if _, err := Parse(Options{}, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path: no error")
	}
}

func TestAWSURLEncodedDocument(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme-app/web:ref:refs/heads/main","token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`
	in := `{"Role":{"RoleName":"deploy","Arn":"arn:aws:iam::111111111111:role/deploy","AssumeRolePolicyDocument":"` + url.QueryEscape(doc) + `"}}`
	r, err := ParseBytes("get-role.json", []byte(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := "aws arn:aws:iam::111111111111:role/deploy" + stsAud + " sub=[equals:repo:acme-app/web:ref:refs/heads/main]"
	if len(r.Trusts) != 1 || summary(r.Trusts[0]) != want {
		t.Fatalf("got %+v", r.Trusts)
	}
}

func TestAWSStatements(t *testing.T) {
	const fed = `"Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"}`
	cases := []struct {
		name, stmt string
		want       []string
	}{
		{"deny ignored", `{"Effect":"Deny",` + fed + `,"Action":"sts:AssumeRoleWithWebIdentity"}`, nil},
		{"other action", `{"Effect":"Allow",` + fed + `,"Action":"sts:AssumeRole"}`, nil},
		{"action wildcard", `{"Effect":"Allow",` + fed + `,"Action":"sts:*","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"*"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[equals:*]"}},
		{"sub star glob", `{"Effect":"Allow",` + fed + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"*"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[glob:*]" + wildOwner("sub", "*")}},
		{"repo star", `{"Effect":"Allow",` + fed + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[glob:repo:*]" + wildOwner("sub", "repo:*")}},
		{"owner pinned by another claim", `{"Effect":"Allow",` + fed + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:repository_owner":"acme-app"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[glob:repo:*] repository_owner=[equals:acme-app]"}},
		{"unknown operator and IfExists", `{"Effect":"Allow",` + fed + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLikeIfExists":{"token.actions.githubusercontent.com:sub":"repo:acme-app/web:*"},"Null":{"token.actions.githubusercontent.com:sub":"false"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[cel:Null false | glob:repo:acme-app/web:*]" +
				"\n  ! condition not fully understood, treated as possible: Null false on sub" +
				"\n  ! StringLikeIfExists on sub: a token without this claim also matches" +
				"\n  ! 2 conditions on sub must all hold; treated as any one of them"}},
		{"ghes issuer", `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/ghes.acme.example/_services/token"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"ghes.acme.example/_services/token:aud":"sts.amazonaws.com","ghes.acme.example/_services/token:sub":"repo:acme-app/web:ref:refs/heads/main","token.actions.githubusercontent.com:sub":"ignored"}}}`,
			[]string{"aws arn:aws:iam::111111111111:role/x" + stsAud + " sub=[equals:repo:acme-app/web:ref:refs/heads/main]"}},
		{"cognito skipped", `{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ParseBytes("x.json", []byte(`{"Statement":[`+c.stmt+`]}`), Options{Target: "arn:aws:iam::111111111111:role/x"})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, tr := range r.Trusts {
				checkTrust(t, tr)
				got = append(got, summary(tr))
			}
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

func TestCEL(t *testing.T) {
	m := &gcpProvider{mapping: map[string]string{
		"google.subject":       "assertion.sub",
		"attribute.repo":       "assertion.repository",
		"attribute.complex":    "assertion.repository + '@' + assertion.ref",
		"attribute.repo_owner": "assertion.repository_owner",
	}}
	cases := []struct{ expr, want string }{
		{`assertion.sub == 'repo:acme-app/web:ref:refs/heads/main'`, `sub=[equals:repo:acme-app/web:ref:refs/heads/main]`},
		{`'acme-app' == attribute.repo_owner`, `repository_owner=[equals:acme-app]`},
		{`google.subject.startsWith("repo:acme-app/")`, `sub=[like:repo:acme-app/]`},
		{`attribute.repo in ["acme-app/web", 'acme-app/api']`, `repository=[equals:acme-app/web | equals:acme-app/api]`},
		{`(assertion.repository_owner == 'acme-app') && (assertion.ref == 'refs/heads/main' || assertion.ref == 'refs/heads/release')`,
			"ref=[equals:refs/heads/main] repository_owner=[equals:acme-app] ; ref=[equals:refs/heads/release] repository_owner=[equals:acme-app]"},
		{`assertion.repository_owner == 'acme-app' && !(assertion.ref == 'refs/heads/dev')`, "ref=[cel:!(assertion.ref == 'refs/heads/dev')] repository_owner=[equals:acme-app]"},
		{`assertion.repository != 'acme-app/web'`, "repository=[cel:assertion.repository != 'acme-app/web']"},
		{`attribute.complex == 'acme-app/web@refs/heads/main'`, "cel=[cel:attribute.complex == 'acme-app/web@refs/heads/main']"},
		{`assertion.repository_owner == 'acme-app' && size(assertion.x) > 0`, "cel=[cel:size(assertion.x) > 0] repository_owner=[equals:acme-app]"},
		{`assertion.repository == 'a\'b'`, `repository=[equals:a'b]`},
		{`assertion.repository ==`, "repository=[cel:assertion.repository ==]"},
		{`assertion.repository == 'acme-app/web`, "cel=[cel:assertion.repository == 'acme-app/web]"},
		{`(assertion.repository == 'acme-app/web'`, "cel=[cel:(assertion.repository == 'acme-app/web']"},
		{`assertion.repository == 'acme-app/web')`, "cel=[cel:assertion.repository == 'acme-app/web')]"},
		{`&&`, "cel=[cel:&&]"},
		{strings.Repeat("(", 200) + "assertion.ref == 'x'" + strings.Repeat(")", 200), "cel=[cel:" + strings.Repeat("(", 200) + "assertion.ref == 'x'" + strings.Repeat(")", 200) + "]"},
		{strings.Repeat("(assertion.ref == 'a' || assertion.ref == 'b') && ", 7) + "assertion.ref == 'c'", "cel=[cel:" + strings.Repeat("(assertion.ref == 'a' || assertion.ref == 'b') && ", 7) + "assertion.ref == 'c']"},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			var got []string
			for _, conj := range parseExpr(c.expr, celDialect, m.resolver()) {
				tr := Trust{Provider: GCP, Target: "x", File: "x", Issuer: "https://token.actions.githubusercontent.com", Audiences: []string{"a"}}
				tr.applyConj(conj)
				checkTrust(t, tr)
				s := summary(tr)
				s = strings.TrimPrefix(s[:strings.IndexByte(s+"\n", '\n')], "gcp x aud=a ")
				got = append(got, s)
			}
			if g := strings.Join(got, " ; "); g != c.want {
				t.Errorf("got  %s\nwant %s", g, c.want)
			}
		})
	}
}

func TestIssuer(t *testing.T) {
	for iss, want := range map[string]bool{
		"https://token.actions.githubusercontent.com":      true,
		"https://token.actions.githubusercontent.com/":     true,
		"https://token.actions.githubusercontent.com/acme": true,
		"https://ghes.acme.example/_services/token":        true,
		"https://oidc.eks.us-east-1.amazonaws.com/id/X":    false,
		"https://gitlab.acme.example":                      false,
		"https://login.microsoftonline.com/00000000/v2.0":  false,
		"":                         false,
		"https:///_services/token": false,
		"https://token.actions.githubusercontent.com.evil/": false,
	} {
		if got := isGitHubIssuer(iss); got != want {
			t.Errorf("isGitHubIssuer(%q) = %v, want %v", iss, got, want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"sts:*", "sts:assumerolewithwebidentity", true},
		{"*", "", true},
		{"s?s:*", "sts:x", true},
		{"sts:assume*identity", "sts:assumerolewithwebidentity", true},
		{"sts:assumerole", "sts:assumerolewithwebidentity", false},
		{"iam:*", "sts:x", false},
		{"*a*a*a*a*b", strings.Repeat("a", 64), false},
	} {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.pat, c.s, got)
		}
	}
}

func TestGCPBindings(t *testing.T) {
	provider, err := os.ReadFile("testdata/gcp/bound/provider.json")
	if err != nil {
		t.Fatal(err)
	}
	policy := `{"bindings":[{"role":"roles/iam.workloadIdentityUser","members":[
		"principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/deploy/*",
		"principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/deploy/group/admins",
		"principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/deploy/attribute.actor/alice",
		"principalSet://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/other/*"]}]}`
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pp := write("provider.json", string(provider))
	sp := write("ci@acme-prod.iam.gserviceaccount.com.json", policy)
	r, err := Parse(Options{}, pp, sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Trusts) != 4 {
		t.Fatalf("got %d trusts", len(r.Trusts))
	}
	for _, tr := range r.Trusts[1:] {
		checkTrust(t, tr)
		if tr.ServiceAccount != "ci@acme-prod.iam.gserviceaccount.com" {
			t.Fatalf("service account %q", tr.ServiceAccount)
		}
	}
	if len(r.Trusts[1].Claims[CELKey]) != 0 {
		t.Errorf("pool-wide member added a condition: %s", summary(r.Trusts[1]))
	}
	if !hasWarning(r.Trusts[2], "group/admins") || !hasWarning(r.Trusts[3], "attribute.actor == 'alice'") {
		t.Errorf("unresolvable members need warnings:\n%s\n%s", summary(r.Trusts[2]), summary(r.Trusts[3]))
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "no workload identity provider") {
		t.Errorf("warnings = %q", r.Warnings)
	}

	// Without a name hint the service account is unknown, with a warning;
	// Options.ServiceAccount fills it in.
	np := write("policy.json", policy)
	r, err = Parse(Options{}, pp, np)
	if err != nil {
		t.Fatal(err)
	}
	if r.Trusts[1].ServiceAccount != "unknown" || !hasWarning(r.Trusts[1], "service account unknown") {
		t.Errorf("got %+v", r.Trusts[1])
	}
	r, err = Parse(Options{ServiceAccount: "ci@acme-prod.iam.gserviceaccount.com"}, pp, np)
	if err != nil {
		t.Fatal(err)
	}
	if r.Trusts[1].ServiceAccount != "ci@acme-prod.iam.gserviceaccount.com" {
		t.Errorf("got %+v", r.Trusts[1])
	}
}

func TestSkippedProviders(t *testing.T) {
	for name, in := range map[string]string{
		"gcp gitlab":    `{"name":"projects/acme-prod/locations/global/workloadIdentityPools/p/providers/gitlab","oidc":{"issuerUri":"https://gitlab.acme.example"}}`,
		"gcp aws":       `{"name":"projects/acme-prod/locations/global/workloadIdentityPools/p/providers/aws","aws":{"accountId":"111111111111"},"attributeMapping":{}}`,
		"azure entra":   `[{"name":"x","issuer":"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0","subject":"y","audiences":["z"]}]`,
		"azure empty":   `[]`,
		"aws no oidc":   `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		"gcp no member": `{"bindings":[{"role":"roles/viewer","members":["user:alice@acme.example"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			r, err := ParseBytes("x.json", []byte(in), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Trusts) != 0 {
				t.Fatalf("got %d trusts", len(r.Trusts))
			}
		})
	}
}
