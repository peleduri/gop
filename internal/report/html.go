package report

import "html/template"

// evIcon is the icon shown before every evidence label, so evidence never
// depends on color alone: a check for what was read, a question mark for
// what was not visible, a page for a supplied file.
func evIcon(class string) string {
	switch class {
	case "live", "audit":
		return "✓"
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
var pageTmpl = template.Must(template.New("report").Funcs(template.FuncMap{"icon": evIcon}).Parse(`<!doctype html>
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
<a class="skip" href="#main">Skip to the report</a>
<header>
<h1>{{if .Demo}}[demo data] {{end}}gop: who can make code run where</h1>
<p class="meta">{{if .Enterprise}}Enterprise <strong>{{.Enterprise}}</strong>{{end}}{{if .CollectedAt}} · collected {{.CollectedAt}}{{end}}</p>
</header>
<nav aria-label="Report sections"><ul>{{if .Banner}}<li><a href="#changes">What changed</a></li>{{end}}<li><a href="#top-risks">Top risks</a></li><li><a href="#fixes">Suggested fixes</a></li>{{if .Pinned}}<li><a href="#pinned">Pinned, still reachable</a></li>{{end}}<li><a href="#top-paths">Top paths</a></li>{{if .Orgs}}<li><a href="#org-settings">Org settings</a></li>{{end}}<li><a href="#coverage">Coverage</a></li></ul></nav>
<main id="main">
<div id="gop-static">
{{with .Banner}}<section id="changes" class="banner" aria-labelledby="changes-h">
<h2 id="changes-h">What changed</h2>
<p class="meta">Previous snapshot {{.Since}} → this snapshot {{.Until}}</p>
<p class="big">{{.Summary}}</p>
{{if .Score.Text}}<p>Top principal: <a href="{{.Score.Href}}">{{.Score.Text}}</a></p>
{{end}}<div class="groups">
{{range .Groups}}<div class="group" id="changes-{{.ID}}" data-count="{{.Count}}">
<h3>{{.Title}}: {{.Count}}</h3>
{{if and .Note .Count}}<p class="note">{{.Note}}</p>
{{end}}{{if .Items}}<ul>{{range .Items}}<li>{{if eq .Ev "confirmed"}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span> {{else if eq .Ev "possible"}}<span class="badge nv"><span aria-hidden="true">?</span> possible</span> {{end}}{{if .Href}}<a href="{{.Href}}"><code>{{.Text}}</code></a>{{else}}<code>{{.Text}}</code>{{end}}</li>
{{end}}{{if .More}}<li class="note">and {{.More}} more: gop diff lists every change</li>
{{end}}</ul>{{end}}
</div>
{{end}}</div>
<p class="note">Each link opens the filtered paths or the org view (needs JavaScript). <code>gop diff</code> on the two graphs lists every change, including edges.</p>
</section>
{{end}}
<section class="headline">
<p class="big">{{.Headline}}</p>
{{if .FixLine}}<p>{{.FixLine}}</p>{{end}}
{{- if .PinLine}}
<p>{{.PinLine}}</p>{{end}}
<p class="note">Confirmed means every hop was read live or from the audit log{{if .HasCloud}}, or (a cloud hop) from a <span class="badge supplied"><span aria-hidden="true">≡</span> supplied file</span>: a cloud trust policy you supplied, not read from the cloud{{end}}. Possible means at least one hop is <span class="badge nv"><span aria-hidden="true">?</span> not visible</span> to the token: unknown, not absent.</p>
</section>

<h2 id="top-risks">Top risks</h2>
{{if .Risks}}<div class="scroll"><table>
<caption class="vh">Top risks: confirmed reach per principal</caption>
<thead><tr><th scope="col">Principal</th><th scope="col">Confirmed repos</th><th scope="col">Orgs</th>{{if .HasCloud}}<th scope="col">Cloud roles</th>{{end}}<th scope="col">OIDC</th><th scope="col">Secrets</th><th scope="col">Runners</th><th scope="col">Possible</th><th scope="col">Score</th></tr></thead>
<tbody>{{range .Risks}}<tr><td><code>{{.Principal}}</code></td><td class="n">{{.Repos}}</td><td class="n">{{.Orgs}}</td>{{if $.HasCloud}}<td class="n">{{.Cloud}}</td>{{end}}<td class="n">{{.OIDC}}</td><td class="n">{{.Secrets}}</td><td class="n">{{.Runners}}</td><td class="n">{{.PossibleRepos}} {{if eq .PossibleRepos 1}}repo{{else}}repos{{end}}{{if .PossibleOther}} + {{.PossibleOther}} impact{{end}}</td><td class="n">{{.Score}}</td></tr>
{{end}}</tbody></table></div>
<p class="note">Score counts confirmed reach only. Possible reach depends on at least one fact gop could not see.</p>
{{else}}<p class="note">The graph has no principals.</p>{{end}}

<h2 id="fixes">Suggested fixes</h2>
{{if .Fixes}}<div class="scroll"><table>
<caption class="vh">Suggested fixes, in order</caption>
<thead><tr><th scope="col">#</th><th scope="col">Fix</th><th scope="col">Confirmed pairs removed</th><th scope="col">Cumulative removed</th></tr></thead>
<tbody>{{range .Fixes}}<tr><td class="n">{{.N}}</td><td>{{.Description}}<br><span class="src"><code>{{.FixID}}</code></span></td><td class="n">{{.Removed}}</td><td class="n">{{.CumulativePct}}</td></tr>
{{end}}</tbody></table></div>
<p class="note">Greedy pick by confirmed (principal, repo) pairs removed. Fixes that only touch not visible edges are never suggested.</p>
{{else}}<p class="note">No candidate fix removes confirmed reach.</p>{{end}}
{{if .Pinned}}<h2 id="pinned">Pinned, still reachable</h2>
<p class="note">A SHA pin blocks a path only when everything the pinned action runs is pinned too. These pinned actions run a nested branch or tag ref:</p>
{{range .Pinned}}<div class="path">
<div><code>{{.Action}}</code> (used by {{.Consumers}} {{if eq .Consumers 1}}workflow{{else}}workflows{{end}}) runs <code>{{.Via}}</code>{{if .ViaNote}} ({{.ViaNote}}){{end}}. <code>{{.Principal}}</code> can change it {{if .Path.Confirmed}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span>{{else}}<span class="badge nv"><span aria-hidden="true">?</span> possible: a hop is not visible</span>{{end}}</div>
<ol>{{range .Path.Hops}}<li><code>{{.From}}</code> → <code>{{.To}}</code> <span class="src">{{.Kind}}{{if .Reverse}} (reversed){{end}}</span> <span class="badge {{.Class}}"><span aria-hidden="true">{{icon .Class}}</span> {{.Evidence}}</span>{{if .SourceAPI}} <span class="src">{{.SourceAPI}}</span>{{end}}{{if .Reason}} <span class="src">undecided: {{.Reason}}</span>{{end}}</li>
{{end}}</ol></div>
{{end}}
{{end}}
<h2 id="top-paths">Top paths</h2>
{{range .Paths}}<h3><code>{{.Principal}}</code></h3>
{{range .Paths}}<div class="path">
<div>{{if .Confirmed}}<span class="badge live"><span aria-hidden="true">✓</span> confirmed</span>{{else}}<span class="badge nv"><span aria-hidden="true">?</span> possible: a hop is not visible</span>{{end}} to <code>{{.To}}</code></div>
{{- if .Note}}
<div class="note">{{.Note}}</div>{{end}}
<ol>{{range .Hops}}<li><code>{{.From}}</code> → <code>{{.To}}</code> <span class="src">{{.Kind}}{{if .Reverse}} (reversed){{end}}</span> <span class="badge {{.Class}}"><span aria-hidden="true">{{icon .Class}}</span> {{.Evidence}}</span>{{if .SourceAPI}} <span class="src">{{.SourceAPI}}</span>{{end}}{{if .Reason}} <span class="src">undecided: {{.Reason}}</span>{{end}}</li>
{{end}}</ol></div>
{{end}}{{else}}<p class="note">No paths.</p>{{end}}

{{if .Orgs}}<h2 id="org-settings">Org settings</h2>
<div class="scroll"><table>
<caption class="vh">Org settings; a setting gop could not see reads not visible or unknown</caption>
<thead><tr><th scope="col">Org</th><th scope="col">Default permission</th><th scope="col">2FA</th><th scope="col">SSO</th><th scope="col">IP allow list</th><th scope="col">Members</th></tr></thead>
<tbody>{{range .Orgs}}<tr><td><code>{{.Org}}</code></td>{{range .Cells}}<td>{{if .NV}}<span class="badge nv"><span aria-hidden="true">?</span> {{.Value}}</span>{{else}}{{.Value}}{{end}}</td>{{end}}</tr>
{{end}}</tbody></table></div>{{end}}

<h2 id="coverage">Coverage</h2>
{{if .Coverage}}<div class="scroll"><table>
<caption class="vh">Coverage: facts the token could not see</caption>
<thead><tr><th scope="col">Scope</th><th scope="col">Not visible</th><th scope="col">Why</th><th scope="col">Access that fixes it</th></tr></thead>
<tbody>{{range .Coverage}}<tr><td><code>{{.Scope}}</code></td><td><span class="badge nv"><span aria-hidden="true">?</span> {{.Fact}}</span></td><td>{{.Reason}}</td><td>{{.NeedsFix}}</td></tr>
{{end}}</tbody></table></div>
{{else}}<p class="note">Every fact gop looked for was visible to the token.</p>{{end}}

</div>

<section id="gop-explore" hidden>
<h2 id="gop-explore-h" tabindex="-1">Explore paths</h2>
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
<p id="gop-count" class="note" role="status" aria-live="polite"></p>
<div id="gop-paths"></div>
<h3>Fixes for the selected orgs</h3>
<div id="gop-fixes"></div>
{{if .OrgNames}}<h3>Org views</h3>
<p class="orglinks">{{range .OrgNames}}<a href="#/org/{{.}}">{{.}}</a> {{end}}</p>{{end}}
</section>

<section id="gop-orgview" hidden></section>
</main>
<footer>Generated by gop {{.Version}}. ` + footer + `</footer>
{{if .DataJSON}}<script type="application/json" id="gop-data">{{.DataJSON}}</script>
<script>` + scriptJS + `</script>{{end}}
</body>
</html>
`))
