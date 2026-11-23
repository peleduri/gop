package report

import "html/template"

// pageTmpl is the whole report: one inline style, the embedded data and one
// inline script, all pinned by the CSP; no external resources. Every
// content section is server-rendered, so the report reads the same with
// JavaScript off; the script only adds filtering and per-org views.
// html/template escapes every value.
var pageTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="` + csp + `">
<meta name="referrer" content="no-referrer">
<title>{{if .Demo}}[demo data] {{end}}gop report{{if .Enterprise}}: {{.Enterprise}}{{end}}</title>
<style>` + styleCSS + `</style>
</head>
<body>
<main>
<div id="gop-static">
<h1>{{if .Demo}}[demo data] {{end}}gop: who can make code run where</h1>
<p class="meta">{{if .Enterprise}}Enterprise <strong>{{.Enterprise}}</strong>{{end}}{{if .CollectedAt}} · collected {{.CollectedAt}}{{end}}</p>

<section class="headline">
<p class="big">{{.Headline}}</p>
{{if .FixLine}}<p>{{.FixLine}}</p>{{end}}
{{- if .PinLine}}
<p>{{.PinLine}}</p>{{end}}
<p class="note">Confirmed means every hop was read live or from the audit log. Possible means at least one hop is <span class="badge nv">not visible</span> to the token: unknown, not absent.</p>
</section>

<h2>Top risks</h2>
{{if .Risks}}<div class="scroll"><table>
<thead><tr><th>Principal</th><th>Confirmed repos</th><th>Orgs</th><th>OIDC</th><th>Secrets</th><th>Runners</th><th>Possible</th><th>Score</th></tr></thead>
<tbody>{{range .Risks}}<tr><td><code>{{.Principal}}</code></td><td class="n">{{.Repos}}</td><td class="n">{{.Orgs}}</td><td class="n">{{.OIDC}}</td><td class="n">{{.Secrets}}</td><td class="n">{{.Runners}}</td><td class="n">{{.PossibleRepos}} {{if eq .PossibleRepos 1}}repo{{else}}repos{{end}}{{if .PossibleOther}} + {{.PossibleOther}} impact{{end}}</td><td class="n">{{.Score}}</td></tr>
{{end}}</tbody></table></div>
<p class="note">Score counts confirmed reach only. Possible reach depends on at least one fact gop could not see.</p>
{{else}}<p class="note">The graph has no principals.</p>{{end}}

<h2>Suggested fixes</h2>
{{if .Fixes}}<div class="scroll"><table>
<thead><tr><th>#</th><th>Fix</th><th>Confirmed pairs removed</th><th>Cumulative removed</th></tr></thead>
<tbody>{{range .Fixes}}<tr><td class="n">{{.N}}</td><td>{{.Description}}<br><span class="src"><code>{{.FixID}}</code></span></td><td class="n">{{.Removed}}</td><td class="n">{{.CumulativePct}}</td></tr>
{{end}}</tbody></table></div>
<p class="note">Greedy pick by confirmed (principal, repo) pairs removed. Fixes that only touch not visible edges are never suggested.</p>
{{else}}<p class="note">No candidate fix removes confirmed reach.</p>{{end}}
{{if .Pinned}}<h2>Pinned, still reachable</h2>
<p class="note">A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:</p>
{{range .Pinned}}<div class="path">
<div><code>{{.Action}}</code> (used by {{.Consumers}} {{if eq .Consumers 1}}workflow{{else}}workflows{{end}}) runs <code>{{.Via}}</code>. <code>{{.Principal}}</code> can change it {{if .Path.Confirmed}}<span class="badge live">confirmed</span>{{else}}<span class="badge nv">possible: a hop is not visible</span>{{end}}</div>
<ol>{{range .Path.Hops}}<li><code>{{.From}}</code> → <code>{{.To}}</code> <span class="src">{{.Kind}}{{if .Reverse}} (reversed){{end}}</span> <span class="badge {{.Class}}">{{.Evidence}}</span>{{if .SourceAPI}} <span class="src">{{.SourceAPI}}</span>{{end}}</li>
{{end}}</ol></div>
{{end}}
{{end}}
<h2>Top paths</h2>
{{range .Paths}}<h3><code>{{.Principal}}</code></h3>
{{range .Paths}}<div class="path">
<div>{{if .Confirmed}}<span class="badge live">confirmed</span>{{else}}<span class="badge nv">possible: a hop is not visible</span>{{end}} to <code>{{.To}}</code></div>
<ol>{{range .Hops}}<li><code>{{.From}}</code> → <code>{{.To}}</code> <span class="src">{{.Kind}}{{if .Reverse}} (reversed){{end}}</span> <span class="badge {{.Class}}">{{.Evidence}}</span>{{if .SourceAPI}} <span class="src">{{.SourceAPI}}</span>{{end}}</li>
{{end}}</ol></div>
{{end}}{{else}}<p class="note">No paths.</p>{{end}}

{{if .Orgs}}<h2>Org settings</h2>
<div class="scroll"><table>
<thead><tr><th>Org</th><th>Default permission</th><th>2FA</th><th>SSO</th><th>IP allow list</th><th>Members</th></tr></thead>
<tbody>{{range .Orgs}}<tr><td><code>{{.Org}}</code></td>{{range .Cells}}<td>{{if .NV}}<span class="badge nv">{{.Value}}</span>{{else}}{{.Value}}{{end}}</td>{{end}}</tr>
{{end}}</tbody></table></div>{{end}}

<h2>Coverage</h2>
{{if .Coverage}}<div class="scroll"><table>
<thead><tr><th>Scope</th><th>Not visible</th><th>Why</th><th>Access that fixes it</th></tr></thead>
<tbody>{{range .Coverage}}<tr><td><code>{{.Scope}}</code></td><td><span class="badge nv">{{.Fact}}</span></td><td>{{.Reason}}</td><td>{{.NeedsFix}}</td></tr>
{{end}}</tbody></table></div>
{{else}}<p class="note">Every fact gop looked for was visible to the token.</p>{{end}}

</div>

<section id="gop-explore" hidden>
<h2>Explore paths</h2>
<p class="note">Filter every embedded path. The view is saved in the address, so a link to it opens the same filters.</p>
<form id="gop-filters" class="filters">
<label>Evidence <select name="ev"><option value="">confirmed and possible</option><option value="confirmed">confirmed</option><option value="possible">possible</option></select></label>
<label>Ends at <select name="kind"><option value="">any</option><option value="oidc">oidc</option><option value="secret">secret</option><option value="runner">runner</option><option value="repo">repo</option><option value="cloud">cloud</option></select></label>
<label>Action ref <select name="ref"><option value="">any</option><option value="branch">branch</option><option value="tag">tag</option><option value="sha">sha</option></select></label>
<label>Principal <input name="q" type="search" placeholder="members:acme-app"></label>
{{if .OrgNames}}<fieldset><legend>Orgs</legend>{{range .OrgNames}}<label><input type="checkbox" name="org" value="{{.}}"> {{.}}</label>{{end}}</fieldset>{{end}}
<button type="button" id="gop-reset">Reset</button>
</form>
{{if .Truncated}}<p class="note">{{.Truncated}}</p>{{end}}
<p id="gop-count" class="note"></p>
<div id="gop-paths"></div>
<h3>Fixes for the selected orgs</h3>
<div id="gop-fixes"></div>
{{if .OrgNames}}<h3>Org views</h3>
<p class="orglinks">{{range .OrgNames}}<a href="#/org/{{.}}">{{.}}</a> {{end}}</p>{{end}}
</section>

<section id="gop-orgview" hidden></section>

<footer>Generated by gop {{.Version}}. ` + footer + `</footer>
</main>
{{if .DataJSON}}<script type="application/json" id="gop-data">{{.DataJSON}}</script>
<script>` + scriptJS + `</script>{{end}}
</body>
</html>
`))
