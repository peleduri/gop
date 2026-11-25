package report

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/peleduri/gop/brand"
)

// The report's only style and script blocks. Both are fixed when the
// package initializes, so their CSP hashes are too; html/template copies template text
// verbatim, so the bytes hashed are the bytes served. Keep both free of
// comments: html/template drops CSS and JS comments from template text,
// which would change the served bytes and break the hash (a test checks).

// styleCSS is the brand tokens (brand.CSS: --gop-* custom properties, light
// on :root, dark under prefers-color-scheme) followed by the report's own
// rules. The report's short variable names are aliases of the tokens, so
// the theme switch and every color come from brand/tokens.json.
var styleCSS = brand.CSS() + reportCSS

const reportCSS = `:root{--bg:var(--gop-bg);--card:var(--gop-surface);--sunken:var(--gop-sunken);--fg:var(--gop-fg);--muted:var(--gop-muted);--line:var(--gop-line);--line2:var(--gop-line-subtle);--line3:var(--gop-line-strong);
--accent:var(--gop-accent);--accent-bg:var(--gop-accent-bg);--on-accent:var(--gop-on-accent);
--live:var(--gop-ev-live);--live-bg:var(--gop-ev-live-bg);--inf:var(--gop-ev-inferred);--inf-bg:var(--gop-ev-inferred-bg);--audit:var(--gop-ev-audit);--audit-bg:var(--gop-ev-audit-bg);--sup:var(--gop-ev-supplied);--sup-bg:var(--gop-ev-supplied-bg);--nv:var(--gop-ev-not-visible);--nv-bg:var(--gop-ev-not-visible-bg);
--crit:var(--gop-danger);--crit-fg:var(--gop-danger);--crit-bg:var(--gop-danger-bg);--crit-solid:var(--gop-danger-solid);--on-crit:var(--gop-on-danger);--high:var(--gop-danger);--high-fg:var(--gop-danger);--high-bg:var(--gop-danger-bg);
--med:var(--gop-possible);--med-fg:var(--gop-possible);--med-bg:var(--gop-possible-bg);--low:var(--gop-neutral);--low-fg:var(--gop-neutral);--low-bg:var(--gop-neutral-bg);
--good:var(--gop-ok);--good-bg:var(--gop-ok-bg);--good-tint:var(--gop-ok-bg);--weak:var(--gop-danger);--weak-bg:var(--gop-danger-bg);--weak-tint:var(--gop-danger-bg);--ok:var(--gop-ok);
--poss:var(--gop-possible);--poss-bg:var(--gop-possible-bg);--tgt:var(--gop-target);--tgt-bg:var(--gop-target-bg);
--c-cloud:var(--gop-target);--c-oidc:color-mix(in srgb,var(--gop-target) 72%,var(--gop-surface));--c-secret:color-mix(in srgb,var(--gop-target) 50%,var(--gop-surface));--c-runner:color-mix(in srgb,var(--gop-target) 30%,var(--gop-surface));
--track:var(--gop-sunken);--prev:color-mix(in srgb,var(--gop-accent) 40%,var(--gop-surface));--shadow:none;
--s1:var(--gop-space-1);--s2:var(--gop-space-2);--s3:var(--gop-space-3);--s4:var(--gop-space-4);--s6:var(--gop-space-6);--r:var(--gop-radius-md);--rs:var(--gop-radius-sm);
--mono:var(--gop-font-mono);--sans:var(--gop-font-sans)}
*{box-sizing:border-box}
.ap .ag-h{margin-bottom:6px}
.ap-banner{margin:0 0 var(--s2);padding:8px 12px;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:var(--r);background:var(--accent-bg);color:var(--fg);font-weight:600}
.ap-banner.crit{border-color:var(--crit);background:var(--crit-bg);color:var(--crit-fg)}
.ap-banner.cut{border-color:var(--good);background:var(--good-bg);color:var(--good)}
.ap-canvas{border:1px solid var(--line2);border-radius:var(--r);background:var(--bg);overflow:hidden}
.ap-svg{display:block;width:100%;height:auto}
.ap-zone rect{fill:var(--card);stroke:var(--line);stroke-dasharray:4 5}
.ap-zone.danger rect{stroke:var(--crit);stroke-dasharray:none;fill:var(--crit-bg)}
.ap-zone .t{fill:var(--fg);font-weight:700;font-size:15px}.ap-zone .s{fill:var(--muted);font:12px var(--mono)}
.ap-zone .dm{fill:var(--crit);font-weight:700;font-size:12px;letter-spacing:.04em}
.ap-node .box{fill:var(--card);stroke:var(--line3);stroke-width:1.4}
.ap-node .t{fill:var(--fg);font-weight:600;font-size:12.5px}.ap-node .s{fill:var(--muted);font-size:11px}
.ap-node[data-n]{cursor:pointer}.ap-node[data-n]:focus{outline:none}.ap-node[data-n]:focus-visible .box{stroke:var(--accent);stroke-width:3}
.ap-node.off .box{fill:var(--bg);stroke:var(--nv);stroke-dasharray:var(--gop-dash-ev-not-visible)}.ap-node.off .t,.ap-node.off .s{fill:var(--nv)}
.ap-node.on .box{stroke:var(--accent);stroke-width:2.5}.ap-node.on.red .box,.ap-node.on.danger .box{stroke:var(--crit);stroke-width:3}
.ap-node .ring{fill:none;stroke:var(--crit);stroke-width:2.5}
.ap-node .dml{fill:var(--crit);font-weight:700;font-size:11.5px}
.ap-node.on.danger .ring{animation:appulse 1.4s ease-out infinite;transform-box:fill-box;transform-origin:center}
@keyframes appulse{0%{opacity:1;transform:scale(1)}100%{opacity:.25;transform:scale(1.06)}}
.ap-node.cut .box{stroke:var(--good);stroke-width:2;stroke-dasharray:none}
.ap-ic{color:var(--muted)}.ap-ic .f{fill:currentColor}.ap-ic .o{fill:none;stroke:currentColor;stroke-width:2.5}.ap-ic .h{fill:var(--card)}
.ap-ic.c-fg{color:var(--fg)}.ap-ic.c-accent{color:var(--accent)}.ap-ic.c-target{color:var(--tgt)}.ap-ic.c-danger{color:var(--crit)}
.ap-node.off .ap-ic{color:var(--nv)}.ap-node.off .ap-ic .h{fill:var(--bg)}
.ap-edge path{fill:none;stroke:var(--line3);stroke-width:2}
.ap-edge.ev-inferred path{stroke-dasharray:var(--gop-dash-ev-inferred)}.ap-edge.ev-audit path{stroke-dasharray:var(--gop-dash-ev-audit)}.ap-edge.ev-supplied path{stroke-dasharray:var(--gop-dash-ev-supplied)}.ap-edge.ev-nv path{stroke-dasharray:var(--gop-dash-ev-not-visible)}
.ap-edge.on path{stroke:var(--accent);stroke-width:2.5}.ap-edge.on.ev-inferred path{stroke:var(--poss)}.ap-edge.on.ev-nv path{stroke:var(--nv)}
.ap-edge.on.red path{stroke:var(--crit);stroke-width:3}
.ap-edge.cut path{stroke:var(--good);stroke-width:2;stroke-dasharray:none}
.ap-edge .x{display:none;fill:var(--good);font-weight:700;font-size:16px;text-anchor:middle}.ap-edge.cut .x{display:inline}
.ap-dot{fill:var(--accent);stroke:var(--card);stroke-width:3;transform:translateY(-25px);transition:cx .5s ease,cy .5s ease}.ap-dot.red{fill:var(--crit)}
.ap-card{margin:var(--s2) 0 var(--s1);padding:12px 14px;border:1px solid var(--line);border-radius:var(--r);background:var(--bg)}
.ap-k{margin:0;font-size:.75rem;letter-spacing:.06em;text-transform:uppercase;font-weight:700;color:var(--accent)}.ap-k.crit,.ap-m.crit{color:var(--crit-fg)}
.ap-h{margin:4px 0 2px;font:600 .9rem var(--mono);overflow-wrap:anywhere}.ap-d{margin:0;color:var(--muted);font-size:.88rem}
.ap-m{margin:6px 0;font-size:1.25rem;font-weight:700;color:var(--accent)}
.ap-ctl{display:flex;align-items:center;gap:6px;margin:var(--s1) 0}
.ap-ctl button{min-width:36px;height:34px;border:1px solid var(--line3);border-radius:var(--rs);background:var(--card);color:var(--fg);font:inherit;cursor:pointer}
.ap-ctl .ap-play{padding:0 16px;background:var(--accent);border-color:var(--accent);color:var(--on-accent);font-weight:700}
.ap-count{color:var(--muted);margin-left:6px}
.ap-steps{list-style:none;display:flex;gap:0;margin:var(--s1) 0;padding:0;overflow-x:auto;min-width:0}
.ap-steps li{flex:0 0 140px;position:relative}
.ap-steps li:before{content:"";position:absolute;left:24px;right:0;top:12px;height:2px;background:var(--line)}.ap-steps li:last-child:before{display:none}
.ap-steps button{all:unset;cursor:pointer;display:block;width:100%;padding-right:8px}
.ap-steps button:focus-visible{outline:2px solid var(--accent);border-radius:4px}
.ap-n{position:relative;z-index:1;display:grid;place-items:center;width:24px;height:24px;border-radius:50%;border:2px solid var(--line3);background:var(--card);font-size:.75rem;font-weight:700}
.ap-l{display:block;margin-top:4px;font-size:.68rem;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ap-v{display:block;font-size:.82rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ap-steps li.done .ap-n{border-color:var(--accent)}.ap-steps li.done:before{background:var(--accent)}
.ap-steps li.red.done .ap-n,.ap-steps li.danger.done .ap-n{border-color:var(--crit)}.ap-steps li.red.done:before{background:var(--crit)}
.ap-steps li.cur .ap-n{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}.ap-steps li.cur.red .ap-n,.ap-steps li.cur.danger .ap-n{background:var(--crit-solid);border-color:var(--crit-solid);color:var(--on-crit)}
.ap-steps li.cutp .ap-n{border-color:var(--good);color:var(--good)}
.ap-fix{margin:var(--s2) 0 0;padding:10px 12px;border:1px solid var(--line);border-radius:var(--r)}
.ap-fix legend{padding:0 6px;font-weight:600;font-size:.85rem}
.ap-fix label{display:flex;gap:8px;align-items:flex-start;padding:6px 0;font-size:.88rem;border-top:1px dashed var(--line2)}.ap-fix label:first-of-type{border-top:0}
.ap-fix input{margin-top:4px;accent-color:var(--good)}
.ap-key{display:flex;flex-wrap:wrap;gap:4px 14px;margin:var(--s1) 0 0;padding:0;list-style:none;font-size:.78rem;color:var(--muted)}
.ap-key li{display:inline-flex;align-items:center;gap:6px}.ap-key svg{flex:none}
.ap-key .k-path{stroke:var(--accent)}.ap-key .k-red{stroke:var(--crit)}.ap-key .k-cut{stroke:var(--good)}.ap-key .k-poss{stroke:var(--poss)}.ap-key .k-nv{stroke:var(--nv)}
@media (prefers-reduced-motion: reduce){.ap-dot{transition:none}.ap-node.on.danger .ring{animation:none}}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 var(--sans);font-variant-numeric:tabular-nums}
.wrap{max-width:1200px;margin:0 auto;padding-left:var(--s2);padding-right:var(--s2)}
a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:2px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.skip{position:absolute;left:-9999px;top:8px;z-index:10}.skip:focus{left:16px;background:var(--card);padding:4px 8px}
.vh{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
code{font:.86em/1.4 var(--mono);overflow-wrap:anywhere}
p{margin:0 0 var(--s1)}
.top{background:var(--card);border-bottom:1px solid var(--line)}
.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:var(--s2);flex-wrap:wrap;padding-top:20px;padding-bottom:20px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.mark{flex:none;display:block;width:40px;height:40px}.mk-l{stroke:var(--accent)}.mk-f{fill:var(--accent)}.mk-s{fill:var(--fg)}
.wm{margin:0 0 2px;font:700 .9rem/1.2 var(--mono);color:var(--fg);letter-spacing:.01em}.wm span{font-weight:400;color:var(--muted)}
h1{font-size:1.15rem;line-height:1.3;margin:0;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:.85rem;margin:2px 0 0}.sep{margin:0 6px}
.demo{margin:0;padding:4px 10px;border-left:4px solid var(--nv);border-radius:var(--rs);background:var(--nv-bg);color:var(--nv);font-size:.8rem;font-weight:600}
.partial{margin:8px 0 0;padding:8px 12px;border-left:4px solid var(--poss);border-radius:var(--r);background:var(--poss-bg);color:var(--poss);font-weight:600}
nav{position:sticky;top:0;z-index:5;max-width:100%;background:var(--card);border-bottom:1px solid var(--line)}
nav .wrap{min-width:0}
nav ul{list-style:none;display:flex;gap:4px;margin:0;padding:0;min-width:0;max-width:100%;contain:inline-size;overflow-x:auto;scrollbar-width:none}
nav a{display:block;padding:10px 10px;color:var(--muted);font-size:.85rem;font-weight:500;text-decoration:none;white-space:nowrap;border-bottom:2px solid transparent}
nav a:hover{color:var(--fg);border-bottom-color:var(--accent)}
main{padding-top:var(--s3);padding-bottom:var(--s4)}
section{margin:0 0 var(--s4);scroll-margin-top:56px}
h2{font-size:1.2rem;line-height:1.3;letter-spacing:-.01em;margin:0 0 var(--s1);scroll-margin-top:56px}
h3{font-size:.95rem;margin:var(--s3) 0 var(--s1)}
.lede{color:var(--muted);margin:0 0 var(--s2);max-width:80ch}
.note{color:var(--muted);font-size:.85rem;margin:var(--s1) 0}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow)}
.flush{padding:0;overflow:hidden}
.hero{position:relative;background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:var(--s3);overflow:hidden}
.hero:before{content:"";position:absolute;left:0;top:0;right:0;height:4px;background:var(--low)}
.v-critical:before{background:var(--crit)}.v-high:before{background:var(--high)}.v-medium:before{background:var(--med)}.v-ok:before{background:var(--ok)}
.v-unk:before{background:repeating-linear-gradient(90deg,var(--nv) 0 8px,transparent 8px 14px)}
.hero-top{display:flex;align-items:center;gap:var(--s1) var(--s2);flex-wrap:wrap;margin-bottom:var(--s2)}
.hero-top .meta{margin:0}
.verdict{display:inline-flex;align-items:center;gap:8px;margin:0;padding:4px 12px;border-radius:999px;font-size:.8rem;font-weight:700;letter-spacing:.02em;text-transform:uppercase;background:var(--low-bg);color:var(--low-fg)}
.verdict .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.v-critical .verdict{background:var(--crit-solid);color:var(--on-crit)}.v-high .verdict{background:var(--high-bg);color:var(--high-fg);box-shadow:inset 0 0 0 1px var(--high)}
.v-medium .verdict{background:var(--med-bg);color:var(--med-fg)}.v-ok .verdict{background:var(--good-bg);color:var(--good)}
.v-unk .verdict{background:var(--nv-bg);color:var(--nv);border:1px dashed var(--nv)}
.big{font-size:1.3rem;line-height:1.4;font-weight:600;letter-spacing:-.01em;margin:0 0 var(--s2);max-width:70ch;text-wrap:pretty}
.start,.pinline{margin:0 0 var(--s1)}.start .tag,.pinline .tag{margin-right:6px}
.tag{display:inline-block;padding:1px 8px;border-radius:6px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;background:var(--accent-bg);color:var(--accent)}
.tag.warn{background:var(--high-bg);color:var(--high-fg)}
.kpis{list-style:none;margin:var(--s3) 0 var(--s2);padding:0;display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.kpi a{display:flex;flex-direction:column;height:100%;padding:14px 16px;border:1px solid var(--line);border-left:3px solid var(--line);border-radius:var(--r);background:var(--card);color:var(--fg);text-decoration:none}
.kpi a:hover{border-color:var(--accent);border-left-color:var(--accent)}
.t-crit a{border-left-color:var(--crit)}.t-high a{border-left-color:var(--high)}.t-med a{border-left-color:var(--med)}.t-ok a{border-left-color:var(--ok)}
.t-unk a{border-left:3px dashed var(--nv)}
.k-label{font-size:.72rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.k-val{font-size:1.9rem;font-weight:700;line-height:1.15;margin:6px 0 2px;letter-spacing:-.02em}
.k-unit{font-size:.85rem;font-weight:500;color:var(--muted);letter-spacing:0}
.k-sub{font-size:.8rem;color:var(--muted)}
.k-poss{margin-top:8px;padding-top:6px;border-top:1px dashed var(--line);font-size:.8rem;color:var(--muted);font-style:italic}
.legend{font-size:.82rem;color:var(--muted);margin:0;padding-top:var(--s2);border-top:1px solid var(--line2)}
.badge{display:inline-flex;align-items:center;gap:3px;padding:0 7px;border-radius:999px;font-size:.72rem;font-weight:600;line-height:1.6;white-space:nowrap;vertical-align:baseline}
.live{color:var(--live);background:var(--live-bg)}.inferred{color:var(--inf);background:var(--inf-bg);border:1px dashed var(--inf)}.audit{color:var(--audit);background:var(--audit-bg)}
.nv{color:var(--nv);background:var(--nv-bg);border:1px dashed var(--nv)}
.supplied{color:var(--sup);background:var(--sup-bg);border:1px solid var(--sup)}
.other{color:var(--fg);background:var(--card);border:1px solid var(--muted)}
.banner{padding:var(--s3);border-left:3px solid var(--accent)}
.banner .big{font-size:1.1rem}.banner h3{display:flex;align-items:center;gap:8px;font-size:.9rem;margin:var(--s2) 0 4px}
.count{display:inline-block;min-width:22px;padding:0 6px;border-radius:999px;background:var(--nv-bg);color:var(--fg);font-size:.75rem;text-align:center}
.banner ul{margin:0;padding-left:18px;font-size:.9rem}.group:has(ul){grid-column:1/-1}.groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:0 var(--s3)}
.fixes{list-style:none;margin:0;padding:0;display:grid;gap:12px}
.fix{display:grid;grid-template-columns:auto 1fr 260px;gap:var(--s2);align-items:start;padding:var(--s2) 20px}
.fix-n{display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:var(--fg);color:var(--card);font-weight:700;font-size:.9rem}
.fix:first-child .fix-n{background:var(--accent);color:var(--on-accent)}
.fix-title{font-weight:600;margin:4px 0 4px;line-height:1.4}
.fix-why{color:var(--muted);font-size:.88rem;margin:0 0 6px}
.fix-caveat{font-size:.85rem;margin:0 0 6px}
.fix-id{margin:0;color:var(--muted);font-size:.85rem}
.fix-impact{padding-top:4px}
.fix-pct{margin:0 0 6px;font-size:.85rem;color:var(--muted)}.fix-pct strong{font-size:1.35rem;color:var(--fg);margin-right:2px}
.track{display:flex;height:8px;border-radius:999px;background:var(--track);overflow:hidden}
.seg{display:block;height:100%}.seg.prev{background:var(--prev)}.seg.cur{background:var(--accent)}
.fix-cum{margin:6px 0 0;font-size:.8rem;color:var(--muted)}.fix-cum strong{color:var(--fg)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line2);vertical-align:middle}
thead th{background:var(--bg);color:var(--muted);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--line);white-space:nowrap}
tbody tr:last-child>*{border-bottom:0}
tbody tr:hover>*{background:var(--bg)}
.n,td.n,th.n{text-align:right}
.rank{color:var(--muted);width:1%}
.strong{font-weight:700}
.who code{font-size:.85em}.grp{display:block;font-weight:600;font-size:.85rem}
.mem{margin-top:4px;font-size:.8rem}.mem summary{cursor:pointer;color:var(--accent)}.mem ul{margin:4px 0 0;padding-left:18px;color:var(--muted)}.mem li{margin:2px 0}
.ownh{list-style:none;margin:0;padding:var(--s2);display:grid;gap:10px}
.ownh li{display:grid;grid-template-columns:7em 1fr 4em;align-items:center;gap:12px;font-size:.88rem}
.ownh .on{text-align:right;font-weight:700}.ownh .track{height:10px}
.ownh .t-high .seg.cur{background:var(--high)}.ownh .t-crit .seg.cur{background:var(--crit)}
.adv{display:block;width:fit-content;max-width:320px;margin-top:4px;padding:1px 8px;border-radius:6px;background:var(--crit-bg);color:var(--crit-fg);font-size:.75rem;font-weight:600;white-space:normal}.adv.inj{background:var(--high-bg);color:var(--high-fg)}
.sev{display:inline-block;padding:1px 8px;border-radius:6px;font-size:.72rem;font-weight:700;white-space:nowrap}.sev:first-letter{text-transform:uppercase}
.s-critical{background:var(--crit-solid);color:var(--on-crit)}.s-high{background:var(--high-bg);color:var(--high-fg);box-shadow:inset 0 0 0 1px var(--high)}
.s-medium{background:var(--med-bg);color:var(--med-fg)}.s-low{background:var(--low-bg);color:var(--low-fg)}.s-unknown{background:var(--nv-bg);color:var(--nv);border:1px dashed var(--nv);text-transform:none}
.impact{display:flex;flex-direction:column;gap:4px;min-width:170px}
.ibar{display:flex;width:160px;height:8px;border-radius:999px;background:var(--track);overflow:hidden;gap:1px}
.ibar span{display:block;height:100%}
.c-cloud{background:var(--c-cloud)}.c-oidc{background:var(--c-oidc)}.c-secret{background:var(--c-secret)}.c-runner{background:var(--c-runner)}
.itext{display:flex;flex-wrap:wrap;gap:2px 10px;font-size:.78rem;color:var(--muted)}
.it{display:inline-flex;align-items:center;gap:4px;white-space:nowrap}
.sw{display:inline-block;width:8px;height:8px;border-radius:2px}
.poss{color:var(--muted);font-style:italic;white-space:nowrap}
.gaps{list-style:none;margin:0 0 var(--s2);padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.gap{padding:14px 16px;border:1px dashed var(--nv);box-shadow:none}
.gap-t{display:flex;align-items:center;gap:8px;font-weight:600;margin:0 0 4px}
.gi{display:grid;place-items:center;flex:none;width:22px;height:22px;border-radius:50%;border:1px dashed var(--nv);background:var(--nv-bg);color:var(--nv);font-size:.8rem;font-weight:700}
.gap-s{margin:0;color:var(--muted);font-size:.85rem}
.ok-note{padding:12px 16px;color:var(--good)}
.pinned{padding:var(--s2) 20px;margin:0 0 12px}
.agent{padding:var(--s2) 20px;margin:0 0 12px;border-left:4px solid var(--line)}.agent.t-crit{border-left-color:var(--crit-fg)}.agent.t-high{border-left-color:var(--high-fg)}.ag-h{margin:0 0 6px}.ag-k{margin-left:6px;font-size:.8rem;font-weight:600}.ag-h .adv{display:inline-block;margin:0 0 0 6px}dl.ag{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}dl.ag dt{font-weight:600}dl.ag dd{margin:0}.ag-fix{margin:8px 0 0;padding-left:20px}a.adv{text-decoration:none}@media (max-width:640px){dl.ag{grid-template-columns:1fr}}
.plist{overflow:hidden}.pgroup+.pgroup{border-top:1px solid var(--line)}
.pgroup h3{display:flex;align-items:center;gap:8px;margin:0;padding:10px 16px;background:var(--bg);border-bottom:1px solid var(--line);font-size:.9rem}
.pathc{margin:0;padding:0;border-top:1px solid var(--line2)}
.pgroup h3+.pathc{border-top:0}
.is-poss summary{background:repeating-linear-gradient(135deg,transparent 0 6px,var(--nv-bg) 6px 7px)}.is-poss li:last-child .chip{border-style:dashed}
.pathc summary{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:10px 16px;cursor:pointer;list-style:none}
.pathc summary::-webkit-details-marker{display:none}
.pathc summary:before{content:"";flex:none;width:7px;height:7px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(-45deg);margin-right:2px;transition:transform .15s}
.pathc[open] summary:before{transform:rotate(45deg)}
.pathc[open] summary{border-bottom:1px dashed var(--line2)}
.pathc summary:hover{background:var(--bg)}
.pathc .to{min-width:0}
.hopn{margin-left:auto;color:var(--muted);font-size:.8rem}
.pathc>.note{margin:10px 16px 0}
.ctx{margin:10px 16px 0;padding:6px 10px;border-radius:6px;background:var(--nv-bg);color:var(--fg);font-size:.82rem}
.whys{list-style:none;margin:8px 0 0;padding:12px 16px;font-size:.85rem}.whys>li+li{margin-top:8px}.whys ul{margin:4px 0 0;padding-left:18px;color:var(--muted)}.whys strong{color:var(--fg)}
.chain{list-style:none;margin:0;padding:14px 16px;display:flex;flex-wrap:wrap;align-items:center;row-gap:12px}
.chain>li{display:flex;align-items:center;min-width:0;position:relative}
.chip{display:inline-flex;flex-direction:column;padding:5px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);max-width:340px;min-width:0}
.chip code{font-size:.8rem}
.chip>small{font-size:.66rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);line-height:1.3}
.chain>li:first-child .chip{border-color:var(--fg)}
.chain>li:last-child .chip{border-width:2px;border-color:var(--accent)}
.hop{position:relative;display:inline-flex;flex-direction:column;align-items:center;gap:2px;padding:0 10px 0 6px;margin:0 2px;outline-offset:0}
.hop:after{content:"";position:absolute;left:4px;right:2px;top:50%;border-top:1px solid var(--line);z-index:0}
.hop:before{content:"";position:absolute;right:0;top:50%;margin-top:-4px;border:4px solid transparent;border-left:6px solid var(--line);border-right:0}
.hop .hk{position:relative;z-index:1;font:600 .62rem/1.2 var(--mono);color:var(--muted);background:var(--card);padding:0 4px}
.hop .badge{position:relative;z-index:1}
.tip{position:absolute;left:50%;top:100%;z-index:4;transform:translate(-50%,6px);width:max-content;max-width:280px;padding:6px 10px;border-radius:6px;background:var(--fg);color:var(--card);font:.75rem/1.4 var(--mono);opacity:0;pointer-events:none;transition:opacity .12s}
.hop:hover .tip,.hop:focus .tip,.tipcell:hover .tip,.tipcell:focus .tip{opacity:1}
.chain em{display:block;font-style:normal;width:100%;font-size:.78rem;color:var(--muted);margin-left:8px}
.grid th[scope=row]{font-weight:600;white-space:nowrap}
.grid td{white-space:nowrap}.grid th,.grid td{padding:8px 10px}.grid thead th{white-space:normal;vertical-align:bottom;min-width:84px}
.g-good{color:var(--good)}.g-weak{color:var(--weak)}
.grid td.g-good{background:var(--good-tint)}.grid td.g-weak{background:var(--weak-tint)}.grid td.g-unk{background:var(--nv-bg)}
.g.g-weak{background:var(--weak-bg)}
.tipcell{position:relative;cursor:help}
.keys{display:flex;flex-wrap:wrap;gap:8px}
.g{display:inline-block;padding:1px 8px;border-radius:6px;font-size:.78rem;font-weight:600}
.g.g-good{background:var(--good-bg)}.g.g-unk{color:var(--nv);border:1px dashed var(--nv)}
.path{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 14px;margin:8px 0}
.path ol{margin:6px 0 0;padding-left:20px}.path li{margin:2px 0}
.path summary{cursor:pointer}
#gop-paths{margin-top:12px;background:var(--card);border:1px solid var(--line);border-radius:var(--r);overflow:hidden}#gop-paths:empty{display:none}
#gop-paths .path{margin:0;padding:8px 14px;border:0;border-radius:0;border-bottom:1px solid var(--line2)}#gop-paths .path:last-child{border-bottom:0}
.src{color:var(--muted);font-size:.8rem}
.filters{display:flex;flex-wrap:wrap;gap:12px 16px;align-items:flex-end;background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:var(--s2)}
.filters label{display:flex;flex-direction:column;gap:4px;font-size:.8rem;font-weight:500;color:var(--muted)}
.filters select,.filters input,.filters button{font:inherit;font-size:.88rem;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:5px 8px}
.filters button{cursor:pointer;font-weight:600}
.filters fieldset{border:1px solid var(--line);border-radius:6px;margin:0;padding:4px 10px;font-size:.85rem}
.filters fieldset label{display:inline-flex;flex-direction:row;align-items:center;gap:4px;margin-right:10px;color:var(--fg)}
.orglinks a{margin-right:12px}
.tabs{display:flex;gap:4px;margin:var(--s2) 0 0;border-bottom:1px solid var(--line)}
.tabs button{font:inherit;font-size:.9rem;color:var(--muted);background:none;border:0;border-bottom:2px solid transparent;padding:8px 14px;cursor:pointer;margin-bottom:-1px}
.tabs button[aria-selected=true]{color:var(--fg);border-bottom-color:var(--accent);font-weight:600}
.pins{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:4px 10px;font-size:.85rem}
.pins label{display:inline-block;margin-right:12px}
.graph{overflow:auto;max-height:80vh;background:var(--card);border:1px solid var(--line);border-radius:var(--r);margin:8px 0}
.graph svg{display:block}
.node>rect{fill:var(--bg);stroke:var(--line3);stroke-width:1}
.node{cursor:pointer}.node:focus{outline:none}
.node text{fill:var(--fg);font:12px var(--mono)}
.node:hover>rect,.node:focus-visible>rect{stroke:var(--accent);stroke-width:2}
.node.sel>rect{stroke:var(--accent);stroke-width:3}
.node.off>rect{stroke-dasharray:3 3}.node.off text{fill:var(--muted)}
.node .ic{color:var(--muted)}.node .ic .f{fill:currentColor}.node .ic .o{fill:none;stroke:currentColor;stroke-width:2.5}.node .ic .h{fill:var(--bg)}
.k-enterprise .ic,.k-org .ic,.k-org_members .ic,.k-identity .ic{color:var(--fg)}.k-external .ic{color:var(--crit)}.k-secret .ic,.k-oidc .ic,.k-cloud_target .ic,.k-runner .ic{color:var(--tgt)}.node.off .ic{color:var(--nv)}
.edge path{fill:none;stroke-width:1.5}.edge:hover path{stroke-width:3}
.e-live path{stroke:var(--live)}.e-audit path{stroke:var(--audit);stroke-dasharray:var(--gop-dash-ev-audit)}
.e-inferred path{stroke:var(--inf);stroke-dasharray:var(--gop-dash-ev-inferred)}
.e-stale path{stroke:var(--nv);stroke-dasharray:var(--gop-dash-ev-not-visible);stroke-width:1}
.e-nv path{stroke:var(--nv);stroke-dasharray:var(--gop-dash-ev-not-visible)}.e-supplied path{stroke:var(--sup);stroke-dasharray:var(--gop-dash-ev-supplied)}
.e-other path{stroke:var(--muted);stroke-width:1}
.edge.off path{stroke:var(--line);stroke-width:1}
.edge text{fill:var(--muted);font:700 12px system-ui,sans-serif}
.detail{font-size:.85rem}.detail ul{margin:4px 0;padding-left:20px}
#gop-orgview h2{margin-top:var(--s3)}
footer{border-top:1px solid var(--line);background:var(--card);color:var(--muted);font-size:.82rem}
footer .wrap{padding-top:var(--s2);padding-bottom:var(--s4)}
.w0{width:0%}.w4{width:4%}.w8{width:8%}.w12{width:12%}.w16{width:16%}.w20{width:20%}.w24{width:24%}.w28{width:28%}.w32{width:32%}.w36{width:36%}.w40{width:40%}.w44{width:44%}.w48{width:48%}.w52{width:52%}.w56{width:56%}.w60{width:60%}.w64{width:64%}.w68{width:68%}.w72{width:72%}.w76{width:76%}.w80{width:80%}.w84{width:84%}.w88{width:88%}.w92{width:92%}.w96{width:96%}.w100{width:100%}
@media screen and (max-width:720px){body{font-size:14.5px}.hero{padding:var(--s2);border-radius:var(--r)}.big{font-size:1.12rem}
.kpis{grid-template-columns:1fr 1fr;gap:8px}.kpi a{padding:12px}.k-val{font-size:1.5rem}
.fix{grid-template-columns:auto 1fr;padding:var(--s2)}.fix-impact{grid-column:1/-1}
.chain{flex-direction:column;align-items:stretch}.chain>li{flex-direction:column;align-items:stretch}
.chip{max-width:none}
.hop{flex-direction:row;justify-content:flex-start;padding:10px 0 10px 18px;margin:0 0 0 14px;border-left:1px solid var(--line)}
.hop:after,.hop:before{display:none}.hop .hk{background:none;padding:0 6px 0 0}
.hop .tip{left:18px;transform:translate(0,4px)}.chain em{margin:4px 0 0}
th,td{padding:8px 10px}
.stack,.stack tbody{display:block;width:100%}
.stack thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
.stack tr{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px;padding:12px 14px;border-bottom:1px solid var(--line2)}
.stack tbody tr:last-child{border-bottom:0}
.stack td{display:block;padding:0;border:0;text-align:left}
.stack td[data-l]:before{content:attr(data-l) " ";color:var(--muted);font-size:.75rem;font-weight:400}
.risks .rank{width:auto;font-weight:600}.risks .who{flex:1 1 calc(100% - 150px);min-width:0}.risks .who code{font-size:.9em}
.risks .sevc{margin-left:auto}.risks .reach{order:9;flex-basis:100%;padding-left:24px;font-size:.85rem}
.risks td.strong{padding-left:24px}.risks .poss,.risks td.n[data-l]{font-size:.85rem}
.cov td{flex-basis:100%}.cov td:nth-child(-n+2){flex-basis:auto}}
@media print{
@page{margin:14mm}
body{font-size:10.5pt;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:none;padding:0}
nav,.skip,#gop-explore,#gop-orgview,.pathc summary:before{display:none!important}
.tip{position:static;opacity:1;transform:none;width:auto;max-width:150px;padding:0;background:none;color:var(--muted);font-size:6.5pt;text-align:center}.tipcell .tip{display:block;text-align:left}
.top .wrap{padding:0 0 12px}main{padding-top:16px}
.kpi a,.fix,.gap,.pathc,.pinned,.agent,tr{break-inside:avoid}
.kpis{grid-template-columns:repeat(3,1fr)}
.pathc::details-content{content-visibility:visible;display:block}
.pathc>*{display:block}
.chain,.chain>li{display:flex}
section{margin-bottom:20px}h2,.lede{break-after:avoid}
.scroll{overflow:visible}table{font-size:8.5pt}th,td{padding:6px 8px}thead th,.grid td,.grid th[scope=row]{white-space:normal}.impact{min-width:0}.ibar{width:96px}
a{color:var(--fg);text-decoration:none}
a[href]:not([href^="#"]):after{content:" (" attr(href) ")";font-size:.8em;color:var(--muted)}
footer{background:none}}
`

const scriptJS = `
var GOP=(function(){
"use strict";
var KINDS=["oidc","secret","runner","repo","cloud"],REFS=["branch","tag","sha"],EVS=["confirmed","possible"];
function dec(v){try{return decodeURIComponent(v);}catch(e){return "";}}
function blank(){return {ev:"",kind:"",ref:"",q:"",via:"",view:"",orgs:[]};}
function parseHash(h){
var s={route:"",org:"",f:blank()};
h=String(h||"");
if(h.charAt(0)==="#"){h=h.slice(1);}
if(h.indexOf("/org/")===0){s.route="org";s.org=dec(h.slice(5));return s;}
h.split("&").forEach(function(kv){
var i=kv.indexOf("=");
if(i<1){return;}
var k=kv.slice(0,i),raw=kv.slice(i+1),v=dec(raw);
if(k==="ev"&&EVS.indexOf(v)>=0){s.f.ev=v;}
else if(k==="kind"&&KINDS.indexOf(v)>=0){s.f.kind=v;}
else if(k==="ref"&&REFS.indexOf(v)>=0){s.f.ref=v;}
else if(k==="q"){s.f.q=v;}
else if(k==="via"){s.f.via=v;}
else if(k==="view"&&v==="graph"){s.f.view=v;}
else if(k==="org"){s.f.orgs=raw.split(",").map(dec).filter(Boolean);}
});
return s;
}
function toHash(f){
var p=[];
if(f.orgs.length){p.push("org="+f.orgs.map(encodeURIComponent).join(","));}
if(f.ev){p.push("ev="+f.ev);}
if(f.kind){p.push("kind="+f.kind);}
if(f.ref){p.push("ref="+f.ref);}
if(f.q){p.push("q="+encodeURIComponent(f.q));}
if(f.via){p.push("via="+encodeURIComponent(f.via));}
if(f.view){p.push("view="+f.view);}
return p.join("&");
}
function anyIn(a,b){return a.some(function(x){return b.indexOf(x)>=0;});}
function matchPath(p,f){
if(f.ev&&p.ev!==f.ev){return false;}
if(f.kind&&p.to_kind!==f.kind){return false;}
if(f.ref&&p.refs.indexOf(f.ref)<0){return false;}
if(f.orgs.length&&f.orgs.indexOf(p.to_org)<0&&!anyIn(p.from_orgs,f.orgs)){return false;}
if(f.q&&p.from.toLowerCase().indexOf(f.q.toLowerCase())<0){return false;}
if(f.via&&!p.hops.some(function(x){return x.from===f.via||x.to===f.via;})){return false;}
return true;
}
function filterPaths(d,f){return d.paths.filter(function(p){return matchPath(p,f);});}
function fixesFor(d,orgs){return orgs.length?d.fixes.filter(function(x){return anyIn(x.orgs,orgs);}):d.fixes;}
function inbound(d,org){return d.paths.filter(function(p){return p.to_org===org&&p.from_orgs.indexOf(org)<0;});}
function outbound(d,org){return d.paths.filter(function(p){return p.from_orgs.indexOf(org)>=0&&p.to_org!==org;});}
function coverageFor(d,org){return d.coverage.filter(function(c){return c.org===org;});}
function edgeKey(x){return x.from+"\n"+x.kind+"\n"+x.to;}
function lookup(d){
if(!d.gi){
d.gi={node:{},edge:{},pos:new Map()};
d.graph.nodes.forEach(function(n){d.gi.node[n.id]=n;});
d.graph.edges.forEach(function(e){d.gi.edge[edgeKey(e)]=e;});
d.paths.forEach(function(p,i){d.gi.pos.set(p,i);});
}
return d.gi;
}
function graphModel(d,ps){
var gi=lookup(d),seen={},ids=[],ekeys={},edges=[];
ps.forEach(function(p){p.hops.forEach(function(x){
[x.from,x.to].forEach(function(id){if(!seen[id]){seen[id]=1;ids.push(id);}});
var k=edgeKey(x);
if(!ekeys[k]){ekeys[k]=1;edges.push(gi.edge[k]||{from:x.from,to:x.to,kind:x.kind,ev:x.ev,api:x.api,rev:x.rev});}
});});
if(ids.length>d.graph.max_nodes){return {over:true,count:ids.length,ids:[],edges:[],pos:{},cols:0,rows:0};}
var by={},pos={},rows=0;
ids.forEach(function(id){var n=gi.node[id]||{layer:0,order:0};(by[n.layer]=by[n.layer]||[]).push(id);});
var layers=Object.keys(by).map(Number).sort(function(a,b){return a-b;});
layers.forEach(function(l){rows=Math.max(rows,by[l].length);});
layers.forEach(function(l,c){
var col=by[l].sort(function(a,b){return (gi.node[a]||{order:0}).order-(gi.node[b]||{order:0}).order;}),off=(rows-col.length)/2;
col.forEach(function(id,r){pos[id]={col:c,row:r+off};});
});
ids.sort(function(a,b){return pos[a].col-pos[b].col||pos[a].row-pos[b].row;});
return {over:false,count:ids.length,ids:ids,edges:edges,pos:pos,cols:layers.length,rows:rows};
}
function removedBy(d,fix){
var out={};
d.graph.what_if.forEach(function(w){if(w.fix===fix){w.removed.forEach(function(i){out[i]=1;});}});
return out;
}
function pathIndex(d,p){return lookup(d).pos.get(p);}
function evClass(ev){return {"live":"live","inferred":"inferred","audit":"audit","audit, stale":"nv","not visible":"nv","supplied file":"supplied"}[ev]||"other";}
function edgeClass(e){return e.stale||e.ev==="audit, stale"?"stale":evClass(e.ev);}
function short(id){
var i=id.indexOf(":"),r=i>0?id.slice(i+1):id,w=r.indexOf("/.github/workflows/");
if(w>0){r=r.slice(0,w)+" "+r.slice(w+19);}
var t=(i>0?id.slice(0,i)+" ":"")+r;
return t.length>30?t.slice(0,29)+"…":t;
}
function edgeText(e){
var t=[e.from+" → "+e.to,e.kind+", evidence: "+e.ev];
if(e.stale||e.ev==="audit, stale"){t.push("Stale: this audit fact is older than the audit age limit, so the hop counts as not visible and its paths are possible only.");}
if(e.rev){t.push("Drawn in control direction. The evidence edge points the other way ("+e.to+" "+e.kind+" "+e.from+"): whoever controls "+e.from+" controls "+e.to+".");}
if(e.api){t.push("source_api: "+e.api);}
if(e.at){t.push("observed_at: "+e.at);}
var a=e.attrs||{};
if(a.file){t.push("at "+a.file+(a.line?":"+a.line:""));}
Object.keys(a).sort().forEach(function(k){if(k!=="file"&&k!=="line"){t.push(k+": "+a[k]);}});
return t;
}
return {parseHash:parseHash,toHash:toHash,matchPath:matchPath,filterPaths:filterPaths,fixesFor:fixesFor,
inbound:inbound,outbound:outbound,coverageFor:coverageFor,blank:blank,graphModel:graphModel,removedBy:removedBy,
pathIndex:pathIndex,edgeKey:edgeKey,evClass:evClass,edgeClass:edgeClass,short:short,edgeText:edgeText};
})();
if(typeof document!=="undefined"){(function(){
"use strict";
var LIMIT=200;
var el=document.getElementById("gop-data"),D;
if(!el){return;}
try{D=JSON.parse(el.textContent);}catch(e){return;}
function $(id){return document.getElementById(id);}
function h(tag,cls){
var e=document.createElement(tag);
if(cls){e.className=cls;}
for(var i=2;i<arguments.length;i++){
var c=arguments[i];
if(c===null||c===undefined){continue;}
e.appendChild(typeof c==="object"?c:document.createTextNode(String(c)));
}
return e;
}
function code(t){return h("code","",t);}
function clear(e){while(e.firstChild){e.removeChild(e.firstChild);}}
function icon(t){var e=h("span","",t);e.setAttribute("aria-hidden","true");return e;}
function badge(cls,t,txt){return h("span","badge "+cls,icon(t)," "+txt);}
function evBadge(ev){var c=GOP.evClass(ev);return badge(c,{supplied:"≡",inferred:"≈",audit:"↺",nv:"?",other:"•"}[c]||"✓",ev);}
function pathBadge(p){return p.ev==="confirmed"?badge("live","✓","confirmed"):badge("nv","?","possible: a hop is not visible");}
function table(cap,heads,tb){
var tr=h("tr");
heads.forEach(function(t){var th=h("th","",t);th.scope="col";tr.appendChild(th);});
return h("div","scroll",h("table","",h("caption","vh",cap),h("thead","",tr),tb));
}
function plural(n,one,many){return n+" "+(n===1?one:many);}
function pathEl(p){
var ol=h("ol");
p.hops.forEach(function(x){
ol.appendChild(h("li","",code(x.from)," → ",code(x.to)," ",h("span","src",x.kind+(x.rev?" (reversed)":""))," ",evBadge(x.ev),
x.api?" ":null,x.api?h("span","src",x.api):null,x.why?h("span","src"," undecided: "+x.why):null,x.note?h("span","src"," ("+x.note+")"):null));
});
return h("details","path",h("summary","",pathBadge(p)," ",code(p.from)," to ",code(p.to)," ",h("span","src",p.to_kind)),p.note?h("div","note",p.note):null,ol);
}
function pathList(box,ps){
ps.slice(0,LIMIT).forEach(function(p){box.appendChild(pathEl(p));});
if(ps.length>LIMIT){box.appendChild(h("p","note","Showing the first "+LIMIT+" of "+ps.length+" paths. Narrow the filters to see the rest."));}
if(!ps.length){box.appendChild(h("p","note","No paths match."));}
}
function fixTable(box,fs,none){
if(!fs.length){box.appendChild(h("p","note",none));return;}
var tb=h("tbody");
fs.forEach(function(x){tb.appendChild(h("tr","",h("td","n",x.n),h("td","",x.desc,h("br"),h("span","src",code(x.id))),h("td","n",x.removed),h("td","n",x.pct)));});
box.appendChild(table("Suggested fixes for this view",["#","Fix","Confirmed pairs removed","Cumulative removed"],tb));
}
function counts(ps){
var c=0,pr={};
ps.forEach(function(p){if(p.ev==="confirmed"){c++;}pr[p.from]=1;});
return {conf:c,poss:ps.length-c,princ:Object.keys(pr).length};
}
var form=$("gop-filters");
function readForm(){
var f=GOP.blank();
f.ev=form.elements.ev.value;f.kind=form.elements.kind.value;f.ref=form.elements.ref.value;f.q=form.elements.q.value.trim();
f.via=form.elements.via.value.trim();f.view=view;
Array.prototype.forEach.call(form.querySelectorAll("input[name=org]"),function(b){if(b.checked){f.orgs.push(b.value);}});
return f;
}
function writeForm(f){
form.elements.ev.value=f.ev;form.elements.kind.value=f.kind;form.elements.ref.value=f.ref;form.elements.q.value=f.q;
form.elements.via.value=f.via;setView(f.view);
Array.prototype.forEach.call(form.querySelectorAll("input[name=org]"),function(b){b.checked=f.orgs.indexOf(b.value)>=0;});
}
function renderExplore(f){
var ps=GOP.filterPaths(D,f),c=counts(ps);
var cnt=$("gop-count");clear(cnt);
cnt.appendChild(document.createTextNode(plural(ps.length,"path","paths")+" match ("+c.conf+" confirmed, "+c.poss+" possible) from "+plural(c.princ,"principal","principals")+", of "+D.paths.length+" embedded."));
var box=$("gop-paths");clear(box);pathList(box,ps);
shown=ps;if(view){renderGraph();}
var fx=$("gop-fixes");clear(fx);fixTable(fx,GOP.fixesFor(D,f.orgs),"No suggested fix touches the selected orgs.");
}
var SVGNS="http://www.w3.org/2000/svg",COLW=248,ROWH=36,NW=216,NH=26,view="",pin="",shown=[],nodeEls={};
var DIA="M12 0L24 12L12 24L0 12Z",SQ={x:2,y:2,width:20,height:20,rx:2},SH={enterprise:[["path","f",{d:"M12 0L23 6V18L12 24L1 18V6Z"}]],org:[["path","f",{d:"M1 3H10L12 6H23V22H1Z"}]],org_members:[["circle","o",{cx:12,cy:12,r:10.5}],["circle","f",{cx:12,cy:12,r:6}]],identity:[["circle","f",{cx:12,cy:12,r:10}]],external:[["circle","f",{cx:12,cy:12,r:6}],["circle","o",{cx:12,cy:12,r:10.5}]],repo:[["rect","f",{x:1,y:4,width:22,height:16,rx:4}]],workflow:[["path","f",{d:DIA}]],action_ref:[["path","o",{d:"M12 2L22 12L12 22L2 12Z"}]],secret:[["rect","f",SQ]],oidc:[["path","f",{d:"M2 2H22V12C22 18 17 22 12 24C7 22 2 18 2 12Z"}]],cloud_target:[["rect","f",{x:0,y:5,width:24,height:14,rx:7}]],runner:[["rect","f",SQ],["rect","h",{x:5,y:14,width:14,height:3}]]};
function shape(k){var g=sv("g","ic",{transform:"translate(5 6) scale(.58)","aria-hidden":"true"});(SH[k]||[["circle","o",{cx:12,cy:12,r:9}]]).forEach(function(x){g.appendChild(sv(x[0],x[1],x[2]));});return g;}
function sv(tag,cls,at){
var e=document.createElementNS(SVGNS,tag);
if(cls){e.setAttribute("class",cls);}
Object.keys(at||{}).forEach(function(k){e.setAttribute(k,String(at[k]));});
return e;
}
function tip(e,t){var x=sv("title");x.appendChild(document.createTextNode(t));e.appendChild(x);return e;}
function setView(v){
view=v==="graph"?"graph":"";
var g=!!view,tl=$("gop-tab-list"),tg=$("gop-tab-graph");
tl.setAttribute("aria-selected",String(!g));tg.setAttribute("aria-selected",String(g));
tl.tabIndex=g?-1:0;tg.tabIndex=g?0:-1;
$("gop-list-panel").hidden=g;$("gop-graph-panel").hidden=!g;
}
function renderPins(m){
var box=$("gop-pin-options"),fs=$("gop-pins"),opts=[{fix:"",desc:"No pin"}],ok=false;
clear(box);
D.graph.what_if.forEach(function(w){if(w.kind==="pin"&&m.pos[w.node]){opts.push({fix:w.fix,desc:w.node.replace(/^action:/,"")});ok=ok||w.fix===pin;}});
if(!ok){pin="";}
fs.hidden=opts.length<2;
opts.forEach(function(o){
var r=h("input");r.type="radio";r.name="gop-pin";r.value=o.fix;r.checked=o.fix===pin;
r.addEventListener("change",function(){if(r.checked){pin=r.value;renderGraph();}});
box.appendChild(h("label","",r," "+o.desc));
});
}
function nodeDetail(id,m,use){
var det=$("gop-graph-detail");clear(det);
var n=use[id]||{all:0,on:0},ul=h("ul");
det.appendChild(h("p","",h("strong","",id)," ",plural(n.all,"path","paths")+" through it"+(pin?", "+(n.all-n.on)+" removed by the simulated pin":"")+"."));
m.edges.forEach(function(e){if(e.from===id||e.to===id){ul.appendChild(edgeLi(e));}});
det.appendChild(ul);
}
function edgeLi(e){
var t=GOP.edgeText(e);
return h("li","",code(e.from)," → ",code(e.to)," ",h("span","src",e.kind+(e.rev?" (reversed)":""))," ",evBadge(e.ev),h("br"),h("span","src",t.slice(2).join(" · ")));
}
function choose(id){
form.elements.via.value=form.elements.via.value===id?"":id;
onInput();
focusOn(nodeEls[id]);
}
function renderGraph(){
var box=$("gop-graph"),st=$("gop-graph-status"),tx=$("gop-graph-text"),ps=shown;
clear(box);clear(tx);clear($("gop-graph-detail"));clear(st);nodeEls={};
var m=GOP.graphModel(D,ps);
renderPins(m);
if(m.over){st.appendChild(document.createTextNode("Too many paths to draw: "+m.count+" nodes, the graph shows at most "+D.graph.max_nodes+". Narrow the filter, for example to one org, principal or node."));return;}
if(!ps.length){st.appendChild(document.createTextNode("No paths match."));return;}
var rm=GOP.removedBy(D,pin),use={},off=0,via=form.elements.via.value.trim();
ps.forEach(function(p){
var gone=!!rm[GOP.pathIndex(D,p)];
if(gone){off++;}
p.hops.forEach(function(x){[x.from,x.to,GOP.edgeKey(x)].forEach(function(k){var u=use[k]=use[k]||{all:0,on:0};if(u.last!==p){u.last=p;u.all++;if(!gone){u.on++;}}});});
});
st.appendChild(document.createTextNode(plural(m.count,"node","nodes")+", "+plural(m.edges.length,"hop","hops")+", "+plural(ps.length,"path","paths")+"."+(pin?" Simulating "+pin+": "+off+" of "+ps.length+" paths removed (greyed).":"")));
var W=Math.max(1,m.cols)*COLW,H=Math.max(1,m.rows)*ROWH+8;
var svg=sv("svg","",{width:W,height:H,viewBox:"0 0 "+W+" "+H,role:"group","aria-label":"Path graph: "+plural(m.count,"node","nodes")+" and "+plural(ps.length,"path","paths")+". The same paths are listed as text below the graph."});
svg.setAttribute("aria-describedby","gop-graph-text");
function at(id){var q=m.pos[id];return {x:q.col*COLW+8,y:q.row*ROWH+8};}
var eg=sv("g");
m.edges.forEach(function(e){
var a=at(e.from),b=at(e.to),x1=a.x+NW,y1=a.y+NH/2,x2=b.x,y2=b.y+NH/2,d,u=use[GOP.edgeKey(e)]||{on:1};
d=x2>x1?"M"+x1+" "+y1+"C"+(x1+40)+" "+y1+" "+(x2-40)+" "+y2+" "+x2+" "+y2:"M"+x1+" "+y1+"C"+(x1+60)+" "+(y1+ROWH)+" "+(x2-60)+" "+(y2+ROWH)+" "+x2+" "+y2;
var ec=GOP.edgeClass(e),g=sv("g","edge e-"+ec+(pin&&!u.on?" off":""));
g.appendChild(sv("path","",{d:d}));
if(ec==="nv"||ec==="stale"){var q=sv("text","",{x:(x1+x2)/2-(ec==="nv"?3:14),y:(y1+y2)/2-3});q.appendChild(document.createTextNode(ec==="nv"?"?":"stale"));g.appendChild(q);}
tip(g,GOP.edgeText(e).join("\n")+(pin&&!u.on?"\nRemoved by the simulated pin.":""));
g.addEventListener("mouseenter",function(){var det=$("gop-graph-detail");clear(det);det.appendChild(h("ul","",edgeLi(e)));});
eg.appendChild(g);
});
svg.appendChild(eg);
m.ids.forEach(function(id){
var p=at(id),u=use[id]||{all:0,on:0},gone=pin&&!u.on,sel=id===via;
var g=sv("g","node k-"+((D.gi.node[id]||{}).kind||"other")+(sel?" sel":"")+(gone?" off":""),{transform:"translate("+p.x+" "+p.y+")",tabindex:0,role:"button"});
g.setAttribute("aria-pressed",String(sel));
g.setAttribute("aria-label",id+": "+plural(u.all,"path","paths")+(gone?", all removed by the simulated pin":"")+". "+(sel?"Showing only paths through it; press Enter to clear.":"Press Enter to show only paths through it."));
g.appendChild(sv("rect","",{width:NW,height:NH,rx:4}));
g.appendChild(shape((D.gi.node[id]||{}).kind));
var t=sv("text","",{x:24,y:17});t.appendChild(document.createTextNode(GOP.short(id)));g.appendChild(t);
tip(g,id);
g.addEventListener("click",function(){choose(id);});
g.addEventListener("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();choose(id);}});
g.addEventListener("focus",function(){nodeDetail(id,m,use);});
g.addEventListener("mouseenter",function(){nodeDetail(id,m,use);});
nodeEls[id]=g;svg.appendChild(g);
});
box.appendChild(svg);
ps.slice(0,LIMIT).forEach(function(p){
var li=h("li","",pathBadge(p)," ",code(p.from)),gone=!!rm[GOP.pathIndex(D,p)];
p.hops.forEach(function(x){li.appendChild(document.createTextNode(" → "));li.appendChild(code(x.to));li.appendChild(h("span","src"," ("+x.kind+", "+(GOP.edgeKey(x) in D.gi.edge?D.gi.edge[GOP.edgeKey(x)].ev:x.ev)+(x.rev?", reversed":"")+")"));});
if(gone){li.appendChild(h("strong",""," Removed by the simulated pin."));}
li.setAttribute("data-i",GOP.pathIndex(D,p));
tx.appendChild(li);
});
if(ps.length>LIMIT){tx.appendChild(h("li","note","and "+(ps.length-LIMIT)+" more: narrow the filters to list them."));}
}
function section(title,note){var s=h("section","");s.appendChild(h("h3","",title));if(note){s.appendChild(h("p","note",note));}return s;}
function grouped(box,ps){
var by={},order=[];
ps.forEach(function(p){if(!by[p.from]){by[p.from]=[];order.push(p.from);}by[p.from].push(p);});
order.forEach(function(k){
var c=counts(by[k]);
box.appendChild(h("h4","",code(k)," ",h("span","note",plural(by[k].length,"path","paths")+" ("+c.conf+" confirmed)")));
pathList(box,by[k]);
});
if(!order.length){box.appendChild(h("p","note","None in the embedded paths."));}
}
function renderOrg(name){
var v=$("gop-orgview");clear(v);
var org=null;
D.orgs.forEach(function(o){if(o.name===name){org=o;}});
var back=h("a","","← Back to the full report");back.href="#";
v.appendChild(h("p","",back));
var hd=h("h2","","Org ",code(name));hd.tabIndex=-1;v.appendChild(hd);
var st=section("Settings","A setting gop could not see reads unknown, never off.");
if(org){
var tb=h("tbody");
org.settings.forEach(function(a){tb.appendChild(h("tr","",h("td","",a.title),h("td","",a.known?a.value:badge("nv","?",a.value)),h("td","",evBadge(a.evidence))));});
st.appendChild(table("Settings of "+name,["Setting","Value","Evidence"],tb));
}else{st.appendChild(h("p","note","gop has no org node for this name: every setting is unknown."));}
v.appendChild(st);
var inb=GOP.inbound(D,name),s1=section("Inbound reach","Principals from other orgs that reach this org's repos and their impact.");
grouped(s1,inb);v.appendChild(s1);
var out=GOP.outbound(D,name),s2=section("Outbound reach","What this org's members reach in other orgs.");
grouped(s2,out);v.appendChild(s2);
var s3=section("Fixes that touch this org");fixTable(s3,GOP.fixesFor(D,[name]),"No suggested fix touches this org.");v.appendChild(s3);
var cov=GOP.coverageFor(D,name),s4=section("Coverage gaps");
if(cov.length){
var cb=h("tbody");
cov.forEach(function(x){cb.appendChild(h("tr","",h("td","",code(x.scope)),h("td","",badge("nv","?",x.fact)),h("td","",x.reason),h("td","",x.needs_fix)));});
s4.appendChild(table("Coverage gaps of "+name,["Scope","Not visible","Why","Access that fixes it"],cb));
}else{s4.appendChild(h("p","note","No coverage gap recorded for this org."));}
v.appendChild(s4);
return hd;
}
function focusOn(e){if(e&&e.focus){e.focus();}}
function route(moved){
var s=GOP.parseHash(location.hash),isOrg=s.route==="org";
$("gop-static").hidden=isOrg;$("gop-explore").hidden=isOrg;$("gop-orgview").hidden=!isOrg;
if(isOrg){var hd=renderOrg(s.org);window.scrollTo(0,0);if(moved){focusOn(hd);}return;}
writeForm(s.f);renderExplore(s.f);
if(moved&&location.hash.indexOf("=")>0){focusOn($("gop-explore-h"));}
}
function onInput(){
var f=readForm(),hs=GOP.toHash(f);
history.replaceState(null,"",hs?"#"+hs:location.pathname+location.search);
renderExplore(f);
}
form.addEventListener("input",onInput);
form.addEventListener("change",onInput);
form.addEventListener("submit",function(e){e.preventDefault();});
$("gop-reset").addEventListener("click",function(){var b=GOP.blank();b.view=view;writeForm(b);onInput();});
["gop-tab-list","gop-tab-graph"].forEach(function(id,i){
var t=$(id);
t.addEventListener("click",function(){setView(i?"graph":"");onInput();});
t.addEventListener("keydown",function(ev){
var k=ev.key,to=k==="ArrowRight"||k==="End"?1:k==="ArrowLeft"||k==="Home"?0:-1;
if(to<0){return;}
ev.preventDefault();setView(to?"graph":"");onInput();focusOn($(to?"gop-tab-graph":"gop-tab-list"));
});
});
window.addEventListener("hashchange",function(){route(true);});
route();
})();}
(function(){
"use strict";
if(typeof document.querySelectorAll!=="function"){return;}
var cards=document.querySelectorAll("[data-ap]");if(!cards.length){return;}
var still=window.matchMedia&&window.matchMedia("(prefers-reduced-motion: reduce)").matches;
Array.prototype.forEach.call(cards,function(card,ci){
var steps=Array.prototype.slice.call(card.querySelectorAll(".ap-steps li")),n=steps.length;if(!n){return;}
var nodes=card.querySelectorAll(".ap-node[data-n]"),edges=card.querySelectorAll(".ap-edge"),dot=card.querySelector("[data-ap-dot]"),banner=card.querySelector("[data-ap-banner]");
var crd=card.querySelector("[data-ap-card]"),play=card.querySelector("[data-act=play]"),count=card.querySelector("[data-count]"),fixes=card.querySelectorAll(".ap-fix input");
var orig=banner.textContent,origCrit=banner.classList.contains("crit"),i=1,timer=null;
card.querySelector("[data-ap-ctl]").hidden=false;
Array.prototype.forEach.call(fixes,function(f){f.disabled=false;f.addEventListener("change",function(){if(removed().set[i]){stop();}draw();});});
function removed(){
var r={},chain=Infinity;
Array.prototype.forEach.call(fixes,function(f){if(!f.checked){return;}f.getAttribute("data-cuts").split(" ").forEach(function(c){var k=+c;if(!k){return;}if(f.getAttribute("data-chain")==="true"){chain=Math.min(chain,k);}else{r[k]=true;}});});
for(var k=1;k<=n;k++){if(k>=chain){r[k]=true;}}
return {set:r,chain:chain};
}
function hop(k){return steps[k-1];}
function setText(sel,v){var e=crd.querySelector(sel);if(e){e.textContent=v;}}
function draw(){
var rm=removed(),cur=i;
while(cur>1&&rm.set[cur]){cur--;}
Array.prototype.forEach.call(nodes,function(g){var k=+g.getAttribute("data-n");g.classList.toggle("on",k<=i&&!rm.set[k]);g.classList.toggle("cut",!!rm.set[k]);});
Array.prototype.forEach.call(edges,function(e){var k=+e.getAttribute("data-to"),li=hop(k);e.classList.toggle("on",k<=i&&!rm.set[k]);e.classList.toggle("red",!!(li&&li.classList.contains("red")));e.classList.toggle("cut",!!rm.set[k]);});
steps.forEach(function(li,x){var k=x+1;li.classList.toggle("done",k<=i&&!rm.set[k]);li.classList.toggle("cur",k===i&&!rm.set[k]);li.classList.toggle("cutp",!!rm.set[k]);});
var h=hop(cur),bad=h.classList.contains("red")||h.classList.contains("danger"),stopped=!!rm.set[i];
if(dot){dot.setAttribute("cx",h.getAttribute("data-cx"));dot.setAttribute("cy",h.getAttribute("data-cy"));dot.classList.toggle("red",h.classList.contains("red"));}
var k0=crd.querySelector("[data-k]"),m0=crd.querySelector("[data-m]"),ev=crd.querySelector("[data-ev]");
k0.textContent="Hop "+cur+" · "+h.getAttribute("data-kind");k0.classList.toggle("crit",bad);
setText("[data-h]",h.getAttribute("data-title"));
setText("[data-d]",stopped?"A fix you selected stops the path here.":h.getAttribute("data-detail"));
m0.textContent=stopped?"Path cut":h.getAttribute("data-risk");m0.classList.toggle("crit",bad&&!stopped);
ev.className="badge "+h.getAttribute("data-ev");ev.lastChild.textContent=" "+h.getAttribute("data-evl");
var icons={live:"✓",audit:"↺",inferred:"≈",supplied:"≡"};ev.firstChild.textContent=icons[h.getAttribute("data-ev")]||"?";
count.textContent=i+" / "+n;
var gone=Object.keys(rm.set).length;
if(rm.chain!==Infinity){banner.textContent="Path cut at hop "+rm.chain+": the selected fixes stop the agent from reaching anything after it.";}
else if(gone){banner.textContent="The selected fixes remove "+gone+" of "+n+" hops; the rest of the path stays.";}
else{banner.textContent=orig;}
banner.classList.toggle("cut",gone>0);banner.classList.toggle("crit",origCrit&&!gone);
if(!still){var s=steps[i-1];if(s&&s.parentNode.scrollWidth>s.parentNode.clientWidth){s.parentNode.scrollLeft=Math.max(0,s.offsetLeft-s.parentNode.clientWidth/2);}}
}
function go(k){i=Math.max(1,Math.min(n,k));draw();}
function stop(){clearInterval(timer);timer=null;play.textContent="Play";play.setAttribute("aria-pressed","false");}
function start(){
var rm=removed();if(i>=n||rm.set[i+1]){i=1;}
clearInterval(timer);play.textContent="Pause";play.setAttribute("aria-pressed","true");draw();
timer=setInterval(function(){var r=removed();if(i>=n||r.set[i+1]){stop();return;}go(i+1);},1400);
}
card.addEventListener("click",function(ev){
var b=ev.target.closest("[data-act]");
if(b){var a=b.getAttribute("data-act");if(a==="play"){if(timer){stop();}else{start();}}else{stop();if(a==="restart"){go(1);}else{go(i+(a==="next"?1:-1));}}return;}
var li=ev.target.closest(".ap-steps li");if(li){stop();go(+li.getAttribute("data-n"));return;}
var g=ev.target.closest(".ap-node[data-n]");if(g){stop();go(+g.getAttribute("data-n"));}
});
card.addEventListener("keydown",function(ev){
var tg=ev.target;if(tg.tagName==="INPUT"){return;}
if(ev.key==="ArrowRight"){ev.preventDefault();stop();go(i+1);}
else if(ev.key==="ArrowLeft"){ev.preventDefault();stop();go(i-1);}
else if((ev.key==="Enter"||ev.key===" ")&&tg.classList&&tg.classList.contains("ap-node")){ev.preventDefault();stop();go(+tg.getAttribute("data-n"));}
});
draw();
if(ci===0&&!still){start();}
});
})();
`

func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// csp allows exactly the inline style and script above and nothing else: no
// network fetch, no other script, no form submission, no <base> rewrite.
var csp = "default-src 'none'; script-src " + cspHash(scriptJS) + "; style-src " + cspHash(styleCSS) +
	"; base-uri 'none'; form-action 'none'"
