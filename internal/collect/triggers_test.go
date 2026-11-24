package collect

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

func TestParseTriggerShapes(t *testing.T) {
	cases := []struct {
		name, on string
		want     []string
	}{
		{"string", "on: pull_request_target", []string{"pull_request_target"}},
		{"list", "on: [push, issue_comment, push]", []string{"issue_comment", "push"}},
		{"map", "on:\n  pull_request_target:\n    types: [labeled]\n  workflow_dispatch:", []string{"pull_request_target", "workflow_dispatch"}},
		{"quoted key", "\"on\": issues", []string{"issues"}},
		{"anchor", "x: &t [discussion]\non: *t", []string{"discussion"}},
		{"absent", "name: none", nil},
		{"bad shape", "on: {pull_request_target: [a], \"\": x}", []string{"pull_request_target"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(c.on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.Triggers, c.want) {
				t.Errorf("triggers = %v, want %v", f.Triggers, c.want)
			}
		})
	}
}

func TestUntrustedExec(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		want  []UntrustedExec
		risky []string
	}{
		{
			name: "pull_request_target checks out the head",
			src: `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`,
			want:  []UntrustedExec{{Job: "test", Trigger: "pull_request_target", Kind: ExecCheckout, Detail: "ref: ${{ github.event.pull_request.head.sha }}", Line: 7}},
			risky: []string{"pull_request_target"},
		},
		{
			name: "issue_comment body in run",
			src: `on: [issue_comment]
jobs:
  echo:
    steps:
      - run: echo "${{ github.event.comment.body }}"
`,
			want:  []UntrustedExec{{Job: "echo", Trigger: "issue_comment", Kind: ExecInjection, Detail: "github.event.comment.body", Line: 5}},
			risky: []string{"issue_comment"},
		},
		{
			name: "plain pull_request is not risky",
			src: `on: pull_request
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
`,
		},
		{
			name: "risky trigger without an exec pattern",
			src: `on: {pull_request_target: {types: [labeled]}}
jobs:
  label:
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.number }}"
`,
			risky: []string{"pull_request_target"},
		},
		{
			name: "workflow_run head checkout and fork repository",
			src: `on:
  workflow_run:
    workflows: [ci]
jobs:
  report:
    steps:
      - uses: Actions/Checkout@v4
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: make report
`,
			want: []UntrustedExec{
				{Job: "report", Trigger: "workflow_run", Kind: ExecCheckout, Detail: "ref: ${{ github.event.workflow_run.head_sha }}", Line: 10},
				{Job: "report", Trigger: "workflow_run", Kind: ExecCheckout, Detail: "repository: ${{ github.event.workflow_run.head_repository.full_name }}", Line: 9},
			},
			risky: []string{"workflow_run"},
		},
		{
			name: "gh pr checkout and github-script injection, two triggers",
			src: `on: [issue_comment, pull_request_review_comment, push]
jobs:
  b:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
  a:
    steps:
      - run: gh pr checkout ${{ github.event.issue.number }} && make
`,
			want: []UntrustedExec{
				{Job: "a", Trigger: "issue_comment", Kind: ExecCheckout, Detail: "gh pr checkout", Line: 11},
				{Job: "a", Trigger: "pull_request_review_comment", Kind: ExecCheckout, Detail: "gh pr checkout", Line: 11},
				{Job: "b", Trigger: "issue_comment", Kind: ExecInjection, Detail: "github.event.issue.title", Line: 7},
				{Job: "b", Trigger: "pull_request_review_comment", Kind: ExecInjection, Detail: "github.event.issue.title", Line: 7},
			},
			risky: []string{"issue_comment", "pull_request_review_comment"},
		},
		{
			name: "attacker contexts",
			src: `on: pull_request_target
jobs:
  x:
    steps:
      - run: |
          echo ${{ github.head_ref }} ${{ github.event.pull_request.head.label }}
          echo ${{ toJSON(github.event.commits.*.message) }} ${{ github.event.commits[0].message }}
          echo ${{ github.event.workflow_run.head_branch }}
          echo github.event.issue.body outside an expression
          echo ${{ github.event.pull_request.title_suffix }} ${{ github.event.issue.bodyx }}
`,
			want: []UntrustedExec{
				{Job: "x", Trigger: "pull_request_target", Kind: ExecInjection, Detail: "github.head_ref", Line: 5},
				{Job: "x", Trigger: "pull_request_target", Kind: ExecInjection, Detail: "github.event.pull_request.head.label", Line: 5},
				{Job: "x", Trigger: "pull_request_target", Kind: ExecInjection, Detail: "github.event.commits.*.message", Line: 5},
				{Job: "x", Trigger: "pull_request_target", Kind: ExecInjection, Detail: "github.event.commits[0].message", Line: 5},
				{Job: "x", Trigger: "pull_request_target", Kind: ExecInjection, Detail: "github.event.workflow_run.head_branch", Line: 5},
			},
			risky: []string{"pull_request_target"},
		},
		{
			name: "fetch of a pull ref and env-only use",
			src: `on: issues
jobs:
  x:
    steps:
      - run: git fetch origin pull/1/head
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.issue.title }}
`,
			want:  []UntrustedExec{{Job: "x", Trigger: "issues", Kind: ExecCheckout, Detail: "git fetch origin pull/", Line: 5}},
			risky: []string{"issues"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseWorkflow([]byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.UntrustedExec, c.want) {
				t.Errorf("execs = %+v\nwant    %+v", f.UntrustedExec, c.want)
			}
			if got := f.RiskyTriggers(); !reflect.DeepEqual(got, c.risky) {
				t.Errorf("risky = %v, want %v", got, c.risky)
			}
		})
	}
}

const previewWF = "workflow:acme-app/docs/.github/workflows/preview.yml"

// collectWith collects the acme fixture after edit changes it.
func collectWith(t *testing.T, edit func(f *fakeGitHub)) *index {
	t.Helper()
	f := newFakeGitHub(t)
	edit(f)
	g, err := Collect(context.Background(), Config{Enterprise: "acme", Client: f.client(t)})
	if err != nil {
		t.Fatal(err)
	}
	return newIndex(g)
}

// setVisibility rewrites one fixture repo's visibility.
func setVisibility(t *testing.T, f *fakeGitHub, org, repo, vis string) {
	t.Helper()
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login != org {
			continue
		}
		for j, raw := range f.fx.Orgs[i].Repos {
			var r apiRepo
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			if r.Name == repo {
				out, err := json.Marshal(map[string]string{"name": repo, "visibility": vis})
				if err != nil {
					t.Fatal(err)
				}
				f.fx.Orgs[i].Repos[j] = out
				return
			}
		}
	}
	t.Fatalf("no repo %s/%s in the fixture", org, repo)
}

// setSetting sets (or, with val "", removes) one org's ownerInfo setting.
func setSetting(f *fakeGitHub, org, field, val string) {
	for i := range f.fx.Orgs {
		if f.fx.Orgs[i].Login != org {
			continue
		}
		if val == "" {
			delete(f.fx.Orgs[i].Settings, field)
		} else {
			f.fx.Orgs[i].Settings[field] = val
		}
	}
}

const (
	forkSetting = "allowPrivateRepositoryForkingSettingOrganizations"
	permSetting = "defaultRepositoryPermissionSettingOrganizations"
)

func TestUntrustedTriggers(t *testing.T) {
	t.Run("internal repo, forks not allowed: no edge", func(t *testing.T) {
		ix := collectWith(t, func(*fakeGitHub) {})
		n := ix.node(t, previewWF)
		if n.Attrs[attrRiskyTriggers] != "pull_request_target" {
			t.Errorf("risky_triggers = %q", n.Attrs[attrRiskyTriggers])
		}
		for _, e := range ix.g.Edges {
			if e.Kind == graph.CanTrigger {
				t.Errorf("unexpected %s -CAN_TRIGGER-> %s", e.From, e.To)
			}
		}
		if _, ok := ix.nodes[externalAnyone]; ok {
			t.Error("external:anyone declared without a public trigger")
		}
	})

	t.Run("public repo: anyone on the internet", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) { setVisibility(t, f, "acme-app", "docs", "public") })
		e := ix.mustEdge(t, externalAnyone, previewWF, graph.CanTrigger)
		if e.Evidence != graph.Live || e.Attrs[attrTrigger] != "pull_request_target" || e.Attrs[attrExec] != ExecCheckout ||
			e.Attrs[attrJob] != "preview" || e.SourceAPI != srcWorkflow {
			t.Errorf("edge = %+v", e)
		}
		if n := ix.node(t, externalAnyone); n.Kind != graph.KindExternal {
			t.Errorf("kind = %q", n.Kind)
		}
		if e.Attrs[graph.AttrFile] != ".github/workflows/preview.yml" || e.Attrs[graph.AttrLine] != "14" {
			t.Errorf("position = %s:%s, want .github/workflows/preview.yml:14 (the with.ref of the checkout)", e.Attrs[graph.AttrFile], e.Attrs[graph.AttrLine])
		}
		r := graph.Reach(ix.g, externalAnyone, graph.Options{})
		if !contains(r.Confirmed.Secrets, "secret:acme-app/docs") {
			t.Errorf("confirmed secrets = %v", r.Confirmed.Secrets)
		}
		ix.noEdge(t, "members:acme-app", previewWF, graph.CanTrigger)

		// Hardening preview.yml removes the docs secret from anyone's reach.
		harden := []graph.Fix{graph.HardenTrigger{Workflow: previewWF}}
		h := graph.Reach(ix.g, externalAnyone, graph.Options{Fixes: harden})
		if contains(h.Confirmed.Secrets, "secret:acme-app/docs") || contains(h.Possible.Secrets, "secret:acme-app/docs") {
			t.Errorf("after harden_trigger: confirmed %v possible %v", h.Confirmed.Secrets, h.Possible.Secrets)
		}
		if d := graph.WhatIf(ix.g, harden); d.After.ConfirmedPairs >= d.Before.ConfirmedPairs {
			t.Errorf("WhatIf(harden_trigger) pairs %d -> %d", d.Before.ConfirmedPairs, d.After.ConfirmedPairs)
		}
	})

	t.Run("internal repo, forks unknown: every org's members, not_visible", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) { setSetting(f, "acme-app", forkSetting, "") })
		for _, m := range []string{"members:acme-actions", "members:acme-app", "members:acme-legacy", "members:acme-secure"} {
			if e := ix.mustEdge(t, m, previewWF, graph.CanTrigger); e.Evidence != graph.NotVisible {
				t.Errorf("%s evidence = %q, want not_visible", m, e.Evidence)
			}
		}
		ix.noEdge(t, "members:acme-archive", previewWF, graph.CanTrigger)
		r := graph.Reach(ix.g, "members:acme-actions", graph.Options{})
		if !contains(r.Possible.Workflows, previewWF) && !contains(r.Confirmed.Workflows, previewWF) {
			t.Errorf("preview not reached: %+v", r)
		}
	})

	t.Run("internal repo, forks allowed: live", func(t *testing.T) {
		ix := collectWith(t, func(f *fakeGitHub) { setSetting(f, "acme-app", forkSetting, "true") })
		if e := ix.mustEdge(t, "members:acme-secure", previewWF, graph.CanTrigger); e.Evidence != graph.Live {
			t.Errorf("evidence = %q, want live", e.Evidence)
		}
	})

	t.Run("private repo: the org's members by default permission", func(t *testing.T) {
		const comment = "on: issue_comment\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n"
		const target = "on: pull_request_target\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh pr checkout 1 && make test\n"
		const (
			webComment   = "workflow:acme-app/web/.github/workflows/comment.yml"
			webTarget    = "workflow:acme-app/web/.github/workflows/target.yml"
			vaultComment = "workflow:acme-secure/vault-proxy/.github/workflows/comment.yml"
			legacyTarget = "workflow:acme-legacy/old-site/.github/workflows/target.yml"
		)
		ix := collectWith(t, func(f *fakeGitHub) {
			f.extraWorkflows["acme-app/web/comment.yml"] = comment // default_perm read
			f.extraWorkflows["acme-app/web/target.yml"] = target   // forks not allowed in acme-app
			f.extraWorkflows["acme-secure/vault-proxy/comment.yml"] = comment
			setSetting(f, "acme-secure", permSetting, "NONE")
			f.extraWorkflows["acme-legacy/old-site/target.yml"] = target
			setVisibility(t, f, "acme-legacy", "old-site", "private")
			setSetting(f, "acme-legacy", permSetting, "") // default_perm unknown
		})
		e := ix.mustEdge(t, "members:acme-app", webComment, graph.CanTrigger)
		if e.Evidence != graph.Live || e.Attrs[attrTrigger] != "issue_comment" || e.Attrs[attrExec] != ExecInjection ||
			e.Attrs[attrDetail] != "github.event.comment.body" {
			t.Errorf("edge = %+v", e)
		}
		ix.noEdge(t, "members:acme-actions", webComment, graph.CanTrigger)
		ix.noEdge(t, "members:acme-app", webTarget, graph.CanTrigger)

		ix.noEdge(t, "members:acme-secure", vaultComment, graph.CanTrigger)
		if c, ok := hasCoverage(ix.g, "repo:acme-secure/vault-proxy", factTriggering); !ok || !strings.Contains(c.Reason, "default permission is none") {
			t.Errorf("coverage = %+v (%v)", c, ok)
		}

		if e := ix.mustEdge(t, "members:acme-legacy", legacyTarget, graph.CanTrigger); e.Evidence != graph.NotVisible {
			t.Errorf("unknown default_perm: evidence = %q, want not_visible", e.Evidence)
		}
	})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
