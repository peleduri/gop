package oidc

import (
	"strings"
	"testing"
)

const webRelease = "workflow:acme-app/web/.github/workflows/release.yml"

// claims builds the WorkflowClaims of an acme-app/web workflow.
func claims(jobs, envs, jwr string) WorkflowClaims {
	return WorkflowClaims{
		Workflow:        webRelease,
		Repository:      "acme-app/web",
		RepositoryOwner: "acme-app",
		Jobs:            splitList(jobs),
		Environments:    splitList(envs),
		JobWorkflowRefs: splitList(jwr),
		Known:           jobs != "",
	}
}

func sub(op, raw string) Trust {
	return Trust{Provider: AWS, Target: "arn:aws:iam::111111111111:role/deploy", Subjects: []Pattern{{Raw: raw, Op: op}}}
}

func withClaim(t Trust, key, op, raw string) Trust {
	t = t.clone()
	t.addCond(key, Pattern{Raw: raw, Op: op})
	return t
}

func TestMatch(t *testing.T) {
	prod := claims("deploy", "prod", "")
	noEnv := claims("build", "", "")
	twoJobs := claims("build,deploy", "prod", "")
	dynamic := claims("deploy", "*dynamic*", "")
	called := claims("deploy", "", "acme-actions/deploy/.github/workflows/release.yml@refs/heads/main")
	legacy := WorkflowClaims{Workflow: webRelease, Repository: "acme-app/web"} // no claim inputs

	cases := []struct {
		name   string
		trust  Trust
		w      WorkflowClaims
		want   MatchResult
		reason string // substring of the reason for Uncertain
	}{
		{"exact env sub", sub(OpEquals, "repo:acme-app/web:environment:prod"), prod, Matched, ""},
		{"exact env sub, other env", sub(OpEquals, "repo:acme-app/web:environment:staging"), prod, NoMatch, ""},
		{"exact env sub, other repo", sub(OpEquals, "repo:acme-app/api:environment:prod"), prod, NoMatch, ""},
		{"env sub, no env jobs", sub(OpEquals, "repo:acme-app/web:environment:prod"), noEnv, NoMatch, ""},
		{"env sub, one of two jobs has it", sub(OpEquals, "repo:acme-app/web:environment:prod"), twoJobs, Matched, ""},
		{"glob any env", sub(OpGlob, "repo:acme-app/web:environment:*"), prod, Matched, ""},
		{"glob whole repo", sub(OpGlob, "repo:acme-app/web:*"), noEnv, Matched, ""},
		{"glob owner", sub(OpGlob, "repo:acme-app/*"), noEnv, Matched, ""},
		{"glob other owner", sub(OpGlob, "repo:acme-actions/*"), noEnv, NoMatch, ""},
		{"like prefix", sub(OpLike, "repo:acme-app/"), prod, Matched, ""},
		{"branch sub, triggers unknown", sub(OpEquals, "repo:acme-app/web:ref:refs/heads/main"), noEnv, Uncertain, "triggers"},
		{"branch glob, triggers unknown", sub(OpGlob, "repo:acme-app/web:ref:refs/heads/*"), noEnv, Uncertain, "triggers"},
		{"branch sub, single env job", sub(OpEquals, "repo:acme-app/web:ref:refs/heads/main"), prod, NoMatch, ""},
		{"branch sub, a job may lack an env", sub(OpEquals, "repo:acme-app/web:ref:refs/heads/main"), twoJobs, Uncertain, "without an environment"},
		{"pull_request sub", sub(OpEquals, "repo:acme-app/web:pull_request"), noEnv, Uncertain, "triggers"},
		{"dynamic env, env sub", sub(OpEquals, "repo:acme-app/web:environment:prod"), dynamic, Uncertain, "expression"},
		{"dynamic env, other repo", sub(OpEquals, "repo:acme-app/api:environment:prod"), dynamic, NoMatch, ""},
		{"dynamic env, any env glob", sub(OpGlob, "repo:acme-app/web:environment:*"), dynamic, Uncertain, "expression"},
		{"legacy edge, env sub", sub(OpEquals, "repo:acme-app/web:environment:prod"), legacy, Uncertain, "claim inputs"},
		{"legacy edge, other repo", sub(OpEquals, "repo:acme-app/api:environment:prod"), legacy, NoMatch, ""},
		{"no sub condition", Trust{Provider: AWS, Target: "arn:aws:iam::111111111111:role/open"}, noEnv, Matched, ""},
		{"no sub condition, legacy edge", Trust{Provider: AWS, Target: "arn:aws:iam::111111111111:role/open"}, legacy, Matched, ""},
		{"repository claim", withClaim(Trust{Provider: GCP}, "repository", OpEquals, "acme-app/web"), noEnv, Matched, ""},
		{"repository claim, other repo", withClaim(Trust{Provider: GCP}, "repository", OpEquals, "acme-app/api"), noEnv, NoMatch, ""},
		{"owner claim", withClaim(Trust{Provider: GCP}, "repository_owner", OpEquals, "acme-app"), dynamic, Matched, ""},
		{"environment claim", withClaim(Trust{Provider: GCP}, "environment", OpEquals, "prod"), prod, Matched, ""},
		{"environment claim, no env", withClaim(Trust{Provider: GCP}, "environment", OpEquals, "prod"), noEnv, NoMatch, ""},
		{"job_workflow_ref of a called workflow", withClaim(Trust{Provider: GCP}, "job_workflow_ref", OpEquals,
			"acme-actions/deploy/.github/workflows/release.yml@refs/heads/main"), called, Uncertain, "job_workflow_ref"},
		{"job_workflow_ref glob over both", withClaim(Trust{Provider: GCP}, "job_workflow_ref", OpGlob, "acme-*"), called, Matched, ""},
		{"job_workflow_ref of the workflow itself", withClaim(Trust{Provider: GCP}, "job_workflow_ref", OpGlob,
			"acme-app/web/.github/workflows/release.yml@*"), prod, Matched, ""},
		{"job_workflow_ref own file, branch pinned", withClaim(Trust{Provider: GCP}, "job_workflow_ref", OpEquals,
			"acme-app/web/.github/workflows/release.yml@refs/heads/main"), prod, Uncertain, "job_workflow_ref"},
		{"job_workflow_ref other repo", withClaim(Trust{Provider: GCP}, "job_workflow_ref", OpEquals,
			"acme-app/api/.github/workflows/release.yml@refs/heads/main"), prod, NoMatch, ""},
		{"unparsed CEL", withClaim(Trust{Provider: GCP}, CELKey, OpCEL, "assertion.workflow_ref.matches('x')"), prod, Uncertain, "not understood"},
		{"unparsed CEL, other repo pinned", withClaim(withClaim(Trust{Provider: GCP}, CELKey, OpCEL, "x"), "repository", OpEquals, "acme-app/api"), prod, NoMatch, ""},
		{"claim not known before the run", withClaim(Trust{Provider: GCP}, "actor", OpEquals, "alice"), prod, Uncertain, "actor"},
		{"ANDed sub conditions kept as any-of", func() Trust {
			tr := sub(OpGlob, "repo:acme-app/*")
			tr.Subjects = append(tr.Subjects, Pattern{Raw: "*:environment:prod", Op: OpGlob})
			tr.Warnings = []string{"2 conditions on sub must all hold; treated as any one of them"}
			return tr
		}(), noEnv, Uncertain, "narrower"},
		{"custom sub template", sub(OpEquals, "repo:acme-app/web:job_workflow_ref:acme-actions/deploy/.github/workflows/release.yml@refs/heads/main"), prod, Uncertain, "custom sub template"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := Match(c.trust, c.w)
			if got != c.want {
				t.Fatalf("Match = %s (%q), want %s", got, reason, c.want)
			}
			if c.want == Uncertain && (reason == "" || !strings.Contains(reason, c.reason)) {
				t.Errorf("reason %q, want it to mention %q", reason, c.reason)
			}
			if c.want != Uncertain && reason != "" {
				t.Errorf("reason %q for %s", reason, got)
			}
		})
	}
}

func TestEvaluateDetails(t *testing.T) {
	tr := withClaim(sub(OpEquals, "repo:acme-app/web:environment:prod"), "repository_owner", OpEquals, "acme-app")
	tr.Subjects = append(tr.Subjects, Pattern{Raw: "repo:acme-app/web:environment:staging", Op: OpEquals})
	o := Evaluate(tr, claims("deploy", "prod", ""))
	if o.Result != Matched || strings.Join(o.MatchedSub, ",") != "repo:acme-app/web:environment:prod" ||
		strings.Join(o.Claims, ",") != "repository_owner,sub" {
		t.Errorf("Evaluate = %+v", o)
	}
}

func TestGlobPrefix(t *testing.T) {
	for _, c := range []struct {
		pat, prefix string
		want        tri
	}{
		{"repo:acme-app/web:*", "repo:acme-app/web:ref:", yes},
		{"repo:acme-app/web:ref:refs/heads/*", "repo:acme-app/web:ref:", maybe},
		{"repo:acme-app/api:*", "repo:acme-app/web:ref:", no},
		{"*", "", yes},
		{"repo:?cme-app/*", "repo:acme-app/web:", yes},
		{"repo:acme-app/web", "repo:acme-app/web:", no},
		{"repo:acme-app/web:**", "repo:acme-app/web:", yes},
	} {
		if got := globPrefix(c.pat, c.prefix); got != c.want {
			t.Errorf("globPrefix(%q, %q) = %d, want %d", c.pat, c.prefix, got, c.want)
		}
	}
}
