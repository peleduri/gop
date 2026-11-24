package report

import "html/template"

// evIcon is the icon shown before every evidence label, so evidence never
// depends on color alone: a check for what was read, a question mark for
// what was not visible, a page for a supplied file, an approximately-equal
// sign for a fact inferred from other observed facts.
func evIcon(class string) string {
	switch class {
	case "live", "audit":
		return "✓"
	case "inferred":
		return "≈"
	case "supplied":
		return "≡"
	}
	return "?"
}

// pageTmpl is the whole report: one inline style, the embedded data and one
// inline script, all pinned by the CSP; no external resources. Every
// content section is server-rendered, so the report reads the same with
// JavaScript off; the script only adds filtering and per-org views.
// html/template escapes every value.
var pageTmpl = template.Must(template.New("report").Funcs(template.FuncMap{"icon": evIcon, "nkind": nodeKind, "nshort": nodeShort, "ntitle": nodeTitle, "settingTitles": settingTitles}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="` + csp + `">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>{{if .Demo}}[demo data] {{end}}gop report{{if .Enterprise}}: {{.Enterprise}}{{end}}</title>
<style>` + styleCSS + `</style>
</head>
<body>
<a class="skip" href="#main">Skip to the report</a>
<header class="top"><div class="wrap">
<div class="brand"><span class="mark" aria-hidden="true">g</span><div>
<h1>{{if .Demo}}[demo data] {{end}}gop: who can make code run where</h1>
<p class="meta">{{if .Enterprise}}Enterprise <strong>{{.Enterprise}}</strong>{{end}}{{if .CollectedAt}}<span class="sep" aria-hidden="true">·</span>collected <time>{{.CollectedAt}}</time>{{end}}</p>
</div></div>
{{if .Demo}}<p class="demo">Synthetic demo graph</p>{{end}}
</div></header>
<nav aria-label="Report sections"><div class="wrap"><ul><li><a href="#verdict">Verdict</a></li>{{if .Banner}}<li><a href="#changes">What changed</a></li>{{end}}<li><a href="#fixes">Top fixes</a></li><li><a href="#top-risks">Top risks</a></li>{{if .Ownership}}<li><a href="#org-ownership">Org ownership</a></li>{{end}}<li><a href="#coverage">Not visible</a></li>{{if .Pinned}}<li><a href="#pinned">Pinned, still reachable</a></li>{{end}}<li><a href="#top-paths">Top paths</a></li>{{if .Orgs}}<li><a href="#org-settings">Org settings</a></li>{{end}}{{if .RepoHardening}}<li><a href="#repo-hardening">Repo hardening</a></li>{{end}}<li><a href="#gop-explore-h">Explore</a></li></ul></div></nav>
<main id="main" class="wrap">
<div id="gop-static">
<section id="verdict" class="hero v-{{.Verdict}}" aria-labelledby="verdict-h">
<h2 id="verdict-h" class="vh">Verdict</h2>
<div class="hero-top"><p class="verdict"><span class="dot" aria-hidden="true"></span>{{.VerdictLabel}}</p>{{if .PickWho}}<p class="meta">Widest confirmed reach: <strong>{{.PickWho}}</strong></p>{{end}}</div>
<p class="big">{{.Headline}}</p>
{{if .FixLine}}<p class="start"><span class="tag">Start here</span> {{.FixLine}} <a href="#fixes">All fixes</a></p>{{end}}
{{- if .PinLine}}
<p class="pinline"><span class="tag warn">Heads up</span> {{.PinLine}} <a href="#pinned">See which</a></p>{{end}}
{{if .KPIs}}<ul class="kpis" aria-label="Key figures{{if .PickWho}}; reach figures are for {{.PickWho}}, the widest confirmed reach{{end}}">{{range .KPIs}}<li class="kpi t-{{.Tone}}"><a href="{{.Href}}"><span class="k-label">{{.Label}}</span><span class="k-val">{{.Value}} <span class="k-unit">{{.Unit}}</span></span><span class="k-sub">{{.Sub}}</span>{{if .Possible}}<span class="k-poss"><span aria-hidden="true">?</span> {{.Possible}}</span>{{end}}</a></li>{{end}}</ul>{{end}}
<p class="legend">Confirmed means every hop was read live, <span class="badge inferred"><span aria-hidden="true">≈</span> inferred</span> from other observed facts by a documented rule, or read from a recent audit log entry{{if .HasCloud}}, or (a cloud hop) from a <span class="badge supplied"><span aria-hidden="true">≡</span> supplied file</span>: a cloud trust policy you supplied, not read from the cloud{{end}}. Possible means at least one hop is <span class="badge nv"><span aria-hidden="true">?</span> not visible</span> to the token: unknown, not absent. The two are separate figures and never added up.</p>
</section>
{{with .Banner}}<section id="changes" class="card banner" aria-labelledby="changes-h">
<h2 id="changes-h">What changed</h2>
<p class="meta">Previous snapshot {{.Since}} → this snapshot {{.Until}}</p>
<p class="big">{{.Summary}}</p>
{{if .Score.Text}}<p>Top principal: <a href="{{.Score.Href}}">{{.Score.Text}}</a></p>
{{end}}<div class="groups">
{{range .Groups}}<div class="group" id="changes-{{.ID}}" data-count="{{.Count}}">
<h3>{{.Title}} <span class="count">{{.Count}}</span></h3>
{{if and .Note .Count}}<p class="note">{{.Note}}</p>
{{end}}{{if .Items}}<ul>{{range .Items}}<li>{{if eq .Ev "confirmed"}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span> {{else if eq .Ev "possible"}}<span class="badge nv"><span aria-hidden="true">?</span> possible</span> {{end}}{{if .Href}}<a href="{{.Href}}"><code>{{.Text}}</code></a>{{else}}<code>{{.Text}}</code>{{end}}</li>
{{end}}{{if .More}}<li class="note">and {{.More}} more: gop diff lists every change</li>
{{end}}</ul>{{end}}
</div>
{{end}}</div>
<p class="note">Each link opens the filtered paths or the org view (needs JavaScript). <code>gop diff</code> on the two graphs lists every change, including edges.</p>
</section>
{{end}}
<section aria-labelledby="fixes">
<h2 id="fixes">Top fixes</h2>
{{if .Fixes}}<p class="lede">Choke points first: each fix removes the most confirmed reach left after the fixes above it.</p>
<ol class="fixes">{{range .Fixes}}<li class="card fix">
<span class="fix-n" aria-hidden="true">{{.N}}</span>
<div class="fix-body"><p class="fix-title">{{.Description}}</p>
{{if .Why}}<p class="fix-why">{{.Why}}</p>{{end}}
{{if .Caveat}}<p class="fix-caveat"><span class="badge nv"><span aria-hidden="true">?</span> caveat</span> {{.Caveat}}</p>{{end}}
<p class="fix-id"><code>{{.FixID}}</code></p></div>
<div class="fix-impact"><p class="fix-pct"><strong>{{if .Pct}}{{.Pct}}{{else}}{{.Removed}}{{end}}</strong> {{if .Pct}}of confirmed reach{{else}}confirmed pairs{{end}}</p>
<div class="track" aria-hidden="true"><span class="seg prev {{.PrevWidth}}"></span><span class="seg cur {{.Width}}"></span></div>
<p class="fix-cum">{{.Removed}} confirmed {{if eq .Removed 1}}pair{{else}}pairs{{end}} · <strong>{{.CumulativePct}}</strong> cumulative</p></div>
</li>
{{end}}</ol>
<p class="note">Greedy pick by confirmed (principal, repo) pairs removed; the bar shows the earlier fixes in a lighter shade. Fixes that only touch not visible edges are never suggested.</p>
{{else}}<p class="note">No candidate fix removes confirmed reach.</p>{{end}}
</section>
<section aria-labelledby="top-risks">
<h2 id="top-risks">Top risks</h2>
{{if .Risks}}<div class="card flush scroll"><table class="risks stack">
<caption class="vh">Top risks: confirmed reach per principal</caption>
<thead><tr><th scope="col" class="n">#</th><th scope="col">Principal</th><th scope="col">Impact</th><th scope="col" class="n">Confirmed repos</th><th scope="col" class="n">Orgs</th><th scope="col">Reaches (confirmed)</th><th scope="col">Possible</th><th scope="col" class="n">Score</th></tr></thead>
<tbody>{{range .Risks}}<tr><td class="n rank">{{.Rank}}</td><td class="who">{{if .Group}}<span class="grp">{{.Group}}</span> <code>{{.MembersText}}</code>{{else}}<code>{{.Principal}}</code>{{end}}{{if .MemberRows}}<details class="mem"><summary>Each member's own reach</summary><ul>{{range .MemberRows}}<li><code>{{.Principal}}</code>: {{.Repos}} {{if eq .Repos 1}}repo{{else}}repos{{end}} across {{.Orgs}} {{if eq .Orgs 1}}org{{else}}orgs{{end}}{{if .Owned}}; owns {{.Owned}} {{if eq .Owned 1}}org{{else}}orgs{{end}}{{end}}; score {{.Score}}</li>{{end}}</ul></details>{{end}}{{if .Advisory}}<span class="adv"><span aria-hidden="true">!</span> {{.Advisory}}</span>{{end}}{{if .Poutine}}<span class="adv inj"><span aria-hidden="true">!</span> {{.Poutine}} injectable {{if eq .Poutine 1}}workflow{{else}}workflows{{end}} (poutine)</span>{{end}}</td><td class="sevc"><span class="sev s-{{.Sev}}" title="Severity of the confirmed impact (cloud, secrets, runners, repos), as in gop sarif; an advisory states its own severity">{{if eq .Sev "unknown"}}<span aria-hidden="true">?</span> possible only{{else}}{{.Sev}} impact{{end}}</span></td><td class="n strong" data-l="Confirmed repos">{{if .ReposRange}}{{.ReposRange}}{{else}}{{.Repos}}{{end}}</td><td class="n" data-l="Orgs">{{if .OrgsRange}}{{.OrgsRange}}{{else}}{{.Orgs}}{{end}}</td><td class="reach">{{if .Bar}}<div class="impact"><span class="ibar" aria-hidden="true">{{range .Bar}}<span class="c-{{.Kind}} {{.Width}}"></span>{{end}}</span><span class="itext">{{range .Bar}}<span class="it"><span class="sw c-{{.Kind}}" aria-hidden="true"></span>{{.N}} {{.Label}}</span>{{end}}</span></div>{{else if .Repos}}<span class="muted">repo CI only</span>{{else}}<span class="muted">no confirmed reach</span>{{end}}</td><td class="poss" data-l="Possible">{{if or .PossibleRepos .PossibleOther}}<span aria-hidden="true">?</span> {{.PossibleRepos}} {{if eq .PossibleRepos 1}}repo{{else}}repos{{end}}{{if .PossibleOther}} + {{.PossibleOther}} impact{{end}}{{else}}none{{end}}</td><td class="n" data-l="Score">{{.Score}}</td></tr>
{{end}}</tbody></table></div>
<p class="note">Impact is the severity of confirmed reach, as in <code>gop sarif</code>, and is separate from an advisory's own severity: critical for cloud OIDC trust or a cloud role, high for secrets or self-hosted runners, medium for CI in repos. Score counts confirmed reach only; possible reach depends on at least one fact gop could not see.{{if .Ranged}} A row grouped by cause (several accounts whose reach comes mostly through the same grant) shows the range of its members' confirmed repos and orgs; its other columns are its first member's.{{end}}</p>
{{else}}<p class="note">The graph has no principals.</p>{{end}}
</section>{{with .Ownership}}
<section aria-labelledby="org-ownership">
<h2 id="org-ownership">Org ownership</h2>
<p class="lede">{{.Line}}</p>
<div class="card"><ul class="ownh" aria-label="Accounts by number of orgs owned">{{range .Buckets}}<li class="t-{{.Tone}}"><span class="ol">{{.Label}}</span><span class="track" aria-hidden="true"><span class="seg cur {{.Width}}"></span></span><span class="on">{{.Accounts}} <span class="vh">{{if eq .Accounts 1}}account{{else}}accounts{{end}}</span></span></li>
{{end}}</ul></div>
<p class="note">{{.Note}}</p>
</section>{{end}}
<section aria-labelledby="coverage">
<h2 id="coverage">What gop could not see</h2>
{{if .Coverage}}<p class="lede">These facts are unknown, not absent: reach through them shows as possible, never as confirmed or as safe. The access below would let gop see them.</p>
<ul class="gaps">{{range .CovGroups}}<li class="card gap"><p class="gap-t"><span class="gi" aria-hidden="true">?</span>{{.Title}}</p><p class="gap-s">{{.Facts}} {{if eq .Facts 1}}fact{{else}}facts{{end}} not visible{{if .Targets}}: {{range $i, $t := .Targets}}{{if $i}}, {{end}}<code>{{$t}}</code>{{end}}{{end}}</p></li>
{{end}}</ul>
{{if .LockLine}}<p class="note">{{.LockLine}}</p>
{{end}}<div class="card flush scroll"><table class="stack cov">
<caption class="vh">Coverage: facts the token could not see</caption>
<thead><tr><th scope="col">Scope</th><th scope="col">Not visible</th><th scope="col">Why</th><th scope="col">Access that fixes it</th></tr></thead>
<tbody>{{range .Coverage}}<tr><td><code>{{.Scope}}</code></td><td><span class="badge nv"><span aria-hidden="true">?</span> {{.Fact}}</span></td><td data-l="Why">{{.Reason}}</td><td data-l="Fix">{{.NeedsFix}}</td></tr>
{{end}}</tbody></table></div>
{{else}}{{if .LockLine}}<p class="note">{{.LockLine}}</p>
{{end}}<p class="card ok-note"><span aria-hidden="true">✓</span> Every fact gop looked for was visible to the token.</p>{{end}}
</section>
{{if .Pinned}}<section aria-labelledby="pinned">
<h2 id="pinned">Pinned, still reachable</h2>
<p class="lede">A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:</p>
{{range .Pinned}}<div class="card pinned">
<p><code>{{.Action}}</code> (used by {{.Consumers}} {{if eq .Consumers 1}}workflow{{else}}workflows{{end}}) runs <code>{{.Via}}</code>{{if .ViaNote}} ({{.ViaNote}}){{end}}. <code>{{.Principal}}</code> can change it {{if .Path.Confirmed}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span>{{else}}<span class="badge nv"><span aria-hidden="true">?</span> possible: a hop is not visible</span>{{end}}</p>
{{- if .Path.PushNote}}
<p class="ctx"><span aria-hidden="true">ⓘ</span> Context, not part of the score: {{.Path.PushNote}}</p>{{end}}
{{template "chain" .Path}}
</div>
{{end}}</section>
{{end}}
<section aria-labelledby="top-paths">
<h2 id="top-paths">Top paths</h2>
{{if .Paths}}<p class="lede">How each top principal gets there, one hop at a time. Open a path to see every hop and its evidence; hover or focus a hop for the API it was read from (reversed: the evidence edge points the other way).</p>{{end}}
{{if .Paths}}<div class="card plist">{{end}}{{range .Paths}}<div class="pgroup"><h3><code>{{.Principal}}</code>{{if .Group}} <span class="src">one of {{.Group}}</span>{{end}} <span class="hopn">{{len .Paths}} {{if eq (len .Paths) 1}}path{{else}}paths{{end}}</span></h3>
{{range .Paths}}<details class="pathc{{if not .Confirmed}} is-poss{{end}}">
<summary>{{if .Confirmed}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span>{{else}}<span class="badge nv"><span aria-hidden="true">?</span> possible: a hop is not visible</span>{{end}} <span class="to">to <code>{{.To}}</code></span> <span class="hopn">{{len .Hops}} {{if eq (len .Hops) 1}}hop{{else}}hops{{end}}</span></summary>
{{- if .Note}}
<p class="note">{{.Note}}</p>{{end}}
{{- if .Hardening}}
<p class="ctx"><span aria-hidden="true">ⓘ</span> Context, not part of the score: {{.Hardening}}</p>{{end}}
{{- if .PushNote}}
<p class="ctx"><span aria-hidden="true">ⓘ</span> Context, not part of the score: {{.PushNote}}</p>{{end}}
{{template "chain" .}}
</details>
{{end}}</div>
{{else}}<p class="note">No paths.</p>{{end}}{{if .Paths}}</div>{{end}}
</section>
{{if .Orgs}}<section aria-labelledby="org-settings">
<h2 id="org-settings">Org settings</h2>
<p class="lede keys"><span class="g g-good"><span aria-hidden="true">✓</span> strong</span> <span class="g g-weak"><span aria-hidden="true">!</span> weak</span> <span class="g g-unk"><span aria-hidden="true">?</span> unknown: follow it for why</span></p>
<div class="card flush scroll"><table class="grid">
<caption class="vh">Org settings; a setting gop could not see reads unknown, linked to why</caption>
<thead><tr><th scope="col">Org</th>{{range settingTitles}}<th scope="col">{{.}}</th>{{end}}</tr></thead>
<tbody>{{range .Orgs}}<tr><th scope="row"><code>{{.Org}}</code></th>{{range .Cells}}{{if .NV}}<td class="g-unk tipcell"><a class="badge nv" href="#{{.Ref}}"><span aria-hidden="true">?</span> {{.Value}}</a><span class="tip">{{.Reason}}</span></td>{{else}}<td{{if .Tone}} class="g-{{.Tone}}"{{end}}>{{if eq .Tone "good"}}<span aria-hidden="true">✓</span> {{else if eq .Tone "weak"}}<span aria-hidden="true">!</span> {{end}}{{.Value}}</td>{{end}}{{end}}</tr>
{{end}}</tbody></table></div>
{{if .OrgWhy}}<h3 id="why-unknown">Why unknown</h3>
<ul class="card whys">{{range .OrgWhy}}<li id="{{.Anchor}}"><code>{{.Org}}</code><ul>{{range .Items}}<li><strong>{{.Settings}}</strong>: {{.Reason}}{{if .Fix}}. Access that fixes it: {{.Fix}}{{end}}</li>{{end}}</ul></li>
{{end}}</ul>{{end}}
</section>{{end}}
{{if .RepoHardening}}<section aria-labelledby="repo-hardening">
<h2 id="repo-hardening">Repo hardening</h2>
<p class="lede">Context, not part of the score: default-branch protection, CODEOWNERS and secret scanning never change evidence, counts or scores. Each cell is repos where the fact holds / repos with the fact; repos gop could not read are counted as unknown, never as off.</p>
<p class="lede keys"><span class="g g-good"><span aria-hidden="true">✓</span> every repo</span> <span class="g g-weak"><span aria-hidden="true">!</span> some repos lack it</span> <span class="g g-unk"><span aria-hidden="true">?</span> some repos unknown</span></p>
<div class="card flush scroll"><table class="grid">
<caption class="vh">Repo hardening per org; unknown repos are counted separately</caption>
<thead><tr><th scope="col">Org</th><th scope="col">Repos</th><th scope="col">Protected default branch</th><th scope="col">Required reviews</th><th scope="col">CODEOWNERS covers workflows</th><th scope="col">Secret scanning</th><th scope="col">Push protection</th></tr></thead>
<tbody>{{range .RepoHardening}}<tr><th scope="row"><code>{{.Org}}</code></th><td>{{.Repos}}</td>{{range .Cells}}<td{{if .Tone}} class="g-{{.Tone}}"{{end}}>{{if eq .Tone "good"}}<span aria-hidden="true">✓</span> {{else if eq .Tone "weak"}}<span aria-hidden="true">!</span> {{else if eq .Tone "unk"}}<span aria-hidden="true">?</span> {{end}}{{.Value}}</td>{{end}}</tr>
{{end}}</tbody></table></div>
{{if .HardenRepos}}<h3 id="repo-hardening-top">Repos on the top paths</h3>
<ul class="card whys">{{range .HardenRepos}}<li><code>{{.Repo}}</code>: {{.State}}</li>
{{end}}</ul>{{end}}
{{if .HardenFixes}}<h3 id="repo-hardening-fixes">Hardening suggestions</h3>
<p class="lede">Advisory: these settings are not counted as removing confirmed reach.</p>
<ul class="card whys">{{range .HardenFixes}}<li>{{.Description}} ({{.Reason}})</li>
{{end}}</ul>{{end}}
</section>{{end}}
</div>

<section id="gop-explore" hidden>
<h2 id="gop-explore-h" tabindex="-1">Explore paths</h2>
<p class="lede">Filter every embedded path. The view is saved in the address, so a link to it opens the same filters.</p>
<form id="gop-filters" class="filters">
<label>Evidence <select name="ev"><option value="">confirmed and possible</option><option value="confirmed">confirmed</option><option value="possible">possible</option></select></label>
<label>Ends at <select name="kind"><option value="">any</option><option value="oidc">oidc</option><option value="secret">secret</option><option value="runner">runner</option><option value="repo">repo</option><option value="cloud">cloud</option></select></label>
<label>Action ref <select name="ref"><option value="">any</option><option value="branch">branch</option><option value="tag">tag</option><option value="sha">sha</option></select></label>
<label>Principal <input name="q" type="search" placeholder="members:acme-app"></label>
<label>Through node <input name="via" type="search" placeholder="action:acme-actions/deploy@main"></label>
{{if .OrgNames}}<fieldset><legend>Orgs</legend>{{range .OrgNames}}<label><input type="checkbox" name="org" value="{{.}}"> {{.}}</label>{{end}}</fieldset>{{end}}
<button type="button" id="gop-reset">Reset</button>
</form>
{{if .Truncated}}<p class="note">{{.Truncated}}</p>{{end}}
<p id="gop-count" class="note" role="status" aria-live="polite"></p>
<div class="tabs" role="tablist" aria-label="Path views"><button type="button" role="tab" id="gop-tab-list" aria-controls="gop-list-panel" aria-selected="true">List</button><button type="button" role="tab" id="gop-tab-graph" aria-controls="gop-graph-panel" aria-selected="false" tabindex="-1">Graph</button></div>
<div id="gop-list-panel" role="tabpanel" aria-labelledby="gop-tab-list"><div id="gop-paths"></div></div>
<div id="gop-graph-panel" role="tabpanel" aria-labelledby="gop-tab-graph" hidden>
<p class="note">The filtered paths as one diagram, principals on the left, impact on the right, each hop drawn in control direction. Lines: solid is live, long dashes are inferred, dashed is audit, thin dashed marked "stale" is an audit fact too old to confirm (possible only), dotted with a question mark is not visible (unknown, not absent), dash-dot is a supplied file, and a thin grey line is an evidence class this report does not know, named in the hop's details. Select a node (click, or Tab to it and press Enter) to keep only the paths through it; select it again to clear. Hover or focus shows each hop's source.</p>
<fieldset id="gop-pins" class="pins" hidden><legend>Simulate a pin</legend><div id="gop-pin-options"></div></fieldset>
<p id="gop-graph-status" class="note" role="status" aria-live="polite"></p>
<div id="gop-graph" class="graph"></div>
<div id="gop-graph-detail" class="detail"></div>
<details class="path"><summary>Paths in this graph, as text</summary><ol id="gop-graph-text"></ol></details>
</div>
<h3>Fixes for the selected orgs</h3>
<div id="gop-fixes"></div>
{{if .OrgNames}}<h3>Org views</h3>
<p class="orglinks">{{range .OrgNames}}<a href="#/org/{{.}}">{{.}}</a> {{end}}</p>{{end}}
</section>

<section id="gop-orgview" hidden></section>
</main>
<footer><div class="wrap">Generated by gop {{.Version}}. ` + footer + `</div></footer>
{{if .DataJSON}}<script type="application/json" id="gop-data">{{.DataJSON}}</script>
<script>` + scriptJS + `</script>{{end}}
</body>
</html>
{{define "chip"}}<span class="chip"><small>{{nkind .}}</small><code{{with ntitle .}} title="{{.}}"{{end}}>{{nshort .}}</code></span>{{end}}
{{- define "chain"}}{{if .Hops}}<ol class="chain">{{with index .Hops 0}}<li>{{template "chip" .From}}</li>{{end}}
{{range .Hops}}<li><span class="hop" tabindex="0"><span class="hk">{{.Kind}}</span><span class="badge {{.Class}}"><span aria-hidden="true">{{icon .Class}}</span> {{.Evidence}}</span><span class="tip">{{if .SourceAPI}}source {{.SourceAPI}}{{else}}no source API recorded{{end}}{{if .Reverse}} (reversed){{end}}</span></span>{{template "chip" .To}}{{if .Reason}}<em>undecided: {{.Reason}}</em>{{end}}</li>
{{end}}</ol>{{end}}{{end}}`))
