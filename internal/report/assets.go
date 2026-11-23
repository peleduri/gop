package report

import (
	"crypto/sha256"
	"encoding/base64"
)

// The report's only style and script blocks. They are constants so their
// CSP hashes are fixed at build time; html/template copies template text
// verbatim, so the bytes hashed are the bytes served. Keep both free of
// comments: html/template drops CSS and JS comments from template text,
// which would change the served bytes and break the hash (a test checks).

const styleCSS = `
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--accent:#0969da;
--live:#1a7f37;--live-bg:#dafbe1;--audit:#9a6700;--audit-bg:#fff8c5;--nv:#57606a;--nv-bg:#eaeef2;--warn:#cf222e}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--card:#161b22;
--accent:#4493f8;--live:#3fb950;--live-bg:#12261e;--audit:#d29922;--audit-bg:#2b2111;--nv:#8d96a0;--nv-bg:#21262d;--warn:#f85149}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header,nav,main,footer{max-width:1080px;margin:0 auto;padding-left:16px;padding-right:16px}
header{padding-top:24px}
a{color:var(--accent)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.skip{position:absolute;left:-9999px;top:8px}.skip:focus{left:16px;background:var(--bg);padding:4px 8px}
.vh{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
nav ul{list-style:none;display:flex;flex-wrap:wrap;gap:4px 16px;margin:8px 0 0;padding:0;font-size:.9rem}
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.1rem;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
.meta,.note{color:var(--muted);font-size:.9rem}
.headline{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:6px;padding:12px 16px;margin:16px 0}
.headline p{margin:4px 0}.headline .big,.banner .big{font-size:1.15rem;font-weight:600}
.banner{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;padding:12px 16px;margin:16px 0}
.banner h2{margin:0 0 4px;padding:0;border:0}.banner p{margin:4px 0}.banner h3{font-size:.95rem;margin:12px 0 4px}
.banner ul{margin:0;padding-left:20px}.groups{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:0 24px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}
code{font:.85em ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.badge{display:inline-block;padding:0 6px;border-radius:10px;font-size:.75rem;font-weight:600;white-space:nowrap}
.live{color:var(--live);background:var(--live-bg)}.inferred{color:var(--live);background:var(--live-bg);border:1px dashed var(--live)}.audit{color:var(--audit);background:var(--audit-bg)}
.nv{color:var(--nv);background:var(--nv-bg);border:1px dashed var(--nv)}
.supplied{color:var(--accent);background:var(--card);border:1px solid var(--accent)}
.path{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:8px 0}
.path ol{margin:6px 0 0;padding-left:20px}.path li{margin:2px 0}
.path summary{cursor:pointer}
.src{color:var(--muted);font-size:.8rem}
.filters{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:flex-end;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px}
.filters label{display:flex;flex-direction:column;font-size:.85rem;color:var(--muted)}
.filters select,.filters input,.filters button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:2px 6px}
.filters fieldset{border:1px solid var(--line);border-radius:4px;margin:0;padding:2px 8px;font-size:.85rem}
.filters fieldset label{display:inline;margin-right:8px;color:var(--fg)}
.orglinks a{margin-right:12px}
.other{color:var(--fg);background:var(--card);border:1px solid var(--muted)}
.tabs{display:flex;gap:4px;margin:12px 0 0;border-bottom:1px solid var(--line)}
.tabs button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-bottom:0;border-radius:6px 6px 0 0;padding:4px 14px;cursor:pointer}
.tabs button[aria-selected=true]{background:var(--card);border-color:var(--accent);font-weight:600}
.pins{border:1px solid var(--line);border-radius:4px;margin:8px 0;padding:2px 8px;font-size:.85rem}
.pins label{display:inline-block;margin-right:12px}
.graph{overflow:auto;max-height:80vh;background:var(--card);border:1px solid var(--line);border-radius:6px;margin:8px 0}
.graph svg{display:block}
.node{cursor:pointer}.node:focus{outline:none}
.node rect{fill:var(--bg);stroke:var(--line);stroke-width:1}
.node text{fill:var(--fg);font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.node:hover rect,.node:focus-visible rect{stroke:var(--accent);stroke-width:2}
.node.sel rect{stroke:var(--accent);stroke-width:3}
.node.off rect{stroke-dasharray:3 3}.node.off text{fill:var(--muted)}
.edge path{fill:none;stroke-width:1.5}.edge:hover path{stroke-width:3}
.e-live path{stroke:var(--live)}.e-audit path{stroke:var(--audit);stroke-dasharray:6 4}
.e-inferred path{stroke:var(--live);stroke-dasharray:10 3}
.e-stale path{stroke:var(--audit);stroke-dasharray:6 4;stroke-width:1}
.e-nv path{stroke:var(--nv);stroke-dasharray:2 3}.e-supplied path{stroke:var(--accent);stroke-dasharray:8 3 2 3}
.e-other path{stroke:var(--muted);stroke-width:1}
.edge.off path{stroke:var(--line);stroke-width:1}
.edge text{fill:var(--muted);font:700 12px system-ui,sans-serif}
.detail{font-size:.85rem}.detail ul{margin:4px 0;padding-left:20px}
footer{margin-top:40px;padding-top:12px;padding-bottom:48px;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
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
function evBadge(ev){var c=GOP.evClass(ev);return badge(c,{supplied:"≡",inferred:"≈",nv:"?",other:"•"}[c]||"✓",ev);}
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
x.api?" ":null,x.api?h("span","src",x.api):null,x.why?h("span","src"," undecided: "+x.why):null));
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
var t=sv("text","",{x:6,y:17});t.appendChild(document.createTextNode(GOP.short(id)));g.appendChild(t);
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
`

func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// csp allows exactly the inline style and script above and nothing else: no
// network fetch, no other script, no form submission, no <base> rewrite.
var csp = "default-src 'none'; script-src " + cspHash(scriptJS) + "; style-src " + cspHash(styleCSS) +
	"; base-uri 'none'; form-action 'none'"
