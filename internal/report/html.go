package report

import "html/template"

// pageTmpl is the whole report: inline CSS only, no scripts, no external
// resources. html/template escapes every value.
var pageTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{if .Demo}}[demo data] {{end}}gop report{{if .Enterprise}}: {{.Enterprise}}{{end}}</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--accent:#0969da;
--live:#1a7f37;--live-bg:#dafbe1;--audit:#9a6700;--audit-bg:#fff8c5;--nv:#57606a;--nv-bg:#eaeef2;--warn:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--card:#161b22;
--accent:#4493f8;--live:#3fb950;--live-bg:#12261e;--audit:#d29922;--audit-bg:#2b2111;--nv:#8d96a0;--nv-bg:#21262d;--warn:#f85149}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.1rem;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
.meta,.note{color:var(--muted);font-size:.9rem}
.headline{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:6px;padding:12px 16px;margin:16px 0}
.headline p{margin:4px 0}.headline .big{font-size:1.15rem;font-weight:600}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}
code{font:.85em ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.badge{display:inline-block;padding:0 6px;border-radius:10px;font-size:.75rem;font-weight:600;white-space:nowrap}
.live{color:var(--live);background:var(--live-bg)}.audit{color:var(--audit);background:var(--audit-bg)}
.nv{color:var(--nv);background:var(--nv-bg);border:1px dashed var(--nv)}
.path{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:8px 0}
.path ol{margin:6px 0 0;padding-left:20px}.path li{margin:2px 0}
.src{color:var(--muted);font-size:.8rem}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
</style>
</head>
<body>
<main>
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

<footer>Generated by gop {{.Version}}. ` + footer + `</footer>
</main>
</body>
</html>
`))
