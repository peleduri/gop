// Drives the script loaded above and prints what each view rendered.
function summaries(box) {
  return box.find("summary").map(function (s) { return s.textContent; });
}
function go(hash) {
  location.hash = hash;
  winListeners.hashchange();
}
var D = JSON.parse(RAW);
var out = {};

out.initialExploreHidden = ids["gop-explore"].hidden;

go("#/org/acme-app");
out.org = {
  staticHidden: ids["gop-static"].hidden,
  exploreHidden: ids["gop-explore"].hidden,
  viewHidden: ids["gop-orgview"].hidden,
  headings: ids["gop-orgview"].find("h4").map(function (e) { return e.textContent; }),
  text: ids["gop-orgview"].textContent,
};
out.inbound = GOP.inbound(D, "acme-app").map(function (p) { return p.from; })
  .filter(function (v, i, a) { return a.indexOf(v) === i; });

out.a11y = {
  tables: ids["gop-orgview"].find("table").map(function (t) {
    var th = t.find("th");
    return {
      Caption: t.find("caption").map(function (c) { return c.textContent; }).join(""),
      Th: th.length,
      Scoped: th.filter(function (x) { return x.scope === "col"; }).length,
    };
  }),
  focused: global.focused ? global.focused.tagName : "",
};
var badges = [];
(function collect(e) {
  e.childNodes.forEach(function (c) {
    if (c instanceof El) { if (/\bbadge\b/.test(c.className)) { badges.push(c); } collect(c); }
  });
})(ids["gop-orgview"]);
out.a11y.badges = badges.length;
out.a11y.iconBadges = badges.filter(function (b) {
  var i = b.childNodes[0];
  return i instanceof El && i.attrs && i.attrs["aria-hidden"] === "true" && /[a-z]/.test(b.textContent);
}).length;
out.a11y.bannerQ = GOP.parseHash("#ev=confirmed&kind=oidc&q=identity%3Abob").f.q;

go("#/org/acme-legacy");
out.legacyText = ids["gop-orgview"].textContent;

go("#ev=confirmed&kind=oidc");
out.filtered = {
  staticHidden: ids["gop-static"].hidden,
  formEv: form.elements.ev.value,
  formKind: form.elements.kind.value,
  count: ids["gop-count"].textContent,
  summaries: summaries(ids["gop-paths"]),
  paths: GOP.filterPaths(D, GOP.parseHash(location.hash).f).map(function (p) { return [p.from, p.to, p.ev, p.to_kind]; }),
  text: ids["gop-paths"].textContent,
};

go("#org=acme-legacy");
out.orgFilter = GOP.filterPaths(D, GOP.parseHash(location.hash).f).map(function (p) { return [p.from_orgs, p.to_org]; });
out.orgFixes = ids["gop-fixes"].find("code").map(function (e) { return e.textContent; });

form.elements.ev.value = "possible";
form.elements.kind.value = "";
orgBoxes.forEach(function (b) { b.checked = b.value === "acme-app"; });
form.fire("input");
out.hashAfterInput = location.hash;

ids["gop-reset"].fire("click");
out.hashAfterReset = location.hash;

out.roundTrip = GOP.toHash(GOP.parseHash("#org=acme-app&ev=confirmed&kind=oidc").f);
out.junk = GOP.parseHash("#ev=off&kind=%3Cscript%3E&ref=main&org=%E0%A4%A,acme-app&q=%");

// Graph tab: the whole acme graph, then a simulated pin, then a node pick.
function cls(e) { return (e.attrs && e.attrs["class"]) || ""; }
function titleOf(e) { var t = e.find("title"); return t.length ? t[0].textContent : ""; }
function graphState() {
  var svg = ids["gop-graph"].find("svg")[0] || null;
  var gs = svg ? svg.find("g") : [];
  return {
    status: ids["gop-graph-status"].textContent,
    listHidden: ids["gop-list-panel"].hidden,
    graphHidden: ids["gop-graph-panel"].hidden,
    tabSelected: ids["gop-tab-graph"].attrs["aria-selected"],
    svg: svg ? { ns: svg.ns, role: svg.attrs.role, label: svg.attrs["aria-label"], describedby: svg.attrs["aria-describedby"] } : null,
    nodes: gs.filter(function (g) { return /\bnode\b/.test(cls(g)); }).map(function (g) {
      return { id: titleOf(g), cls: cls(g), tabindex: g.attrs.tabindex, role: g.attrs.role, label: g.attrs["aria-label"],
        pressed: g.attrs["aria-pressed"], text: g.find("text").map(function (t) { return t.textContent; }).join("") };
    }),
    edges: gs.filter(function (g) { return /\bedge\b/.test(cls(g)); }).map(function (g) {
      return { title: titleOf(g), cls: cls(g), q: g.find("text").map(function (t) { return t.textContent; }).join("") };
    }),
    text: ids["gop-graph-text"].find("li").filter(function (li) { return li.attrs && li.attrs["data-i"] !== undefined; }).map(function (li) {
      return { i: Number(li.attrs["data-i"]), text: li.textContent };
    }),
    pins: ids["gop-pin-options"].find("input").map(function (r) { return r.value; }),
    pinsHidden: ids["gop-pins"].hidden,
  };
}
go("#view=graph");
out.graph = { all: graphState() };
var radio = ids["gop-pin-options"].find("input").filter(function (r) { return r.value === "pin:action:acme-actions/deploy@main"; })[0];
if (radio) { radio.checked = true; radio.fire("change"); }
out.graph.pinned = graphState();
var node = ids["gop-graph"].find("g").filter(function (g) { return titleOf(g) === "action:acme-actions/deploy@main" && /\bnode\b/.test(cls(g)); })[0];
node.fire("click");
out.graph.hashAfterPick = location.hash;
out.graph.picked = graphState();
out.graph.focusedAfterPick = global.focused ? titleOf(global.focused) : "";
var again = ids["gop-graph"].find("g").filter(function (g) { return titleOf(g) === "action:acme-actions/deploy@main" && /\bnode\b/.test(cls(g)); })[0];
var enter = { key: "Enter" };
again.fire("keydown", enter);
out.graph.enterPrevented = !!enter.prevented;
out.graph.hashAfterEnter = location.hash;
ids["gop-tab-graph"].fire("keydown", { key: "ArrowLeft" });
out.graph.afterArrow = { hash: location.hash, listHidden: ids["gop-list-panel"].hidden, focused: global.focused === ids["gop-tab-list"] };
out.graph.inferredClass = GOP.evClass("inferred");
out.graph.unknownClass = GOP.evClass("speculative");
out.graph.staleClass = GOP.edgeClass({ ev: "audit, stale", stale: true });
out.graph.staleText = GOP.edgeText({ from: "a", to: "b", kind: "CAN_PUSH", ev: "audit, stale", stale: true }).join(" ");
out.graph.reversedText = GOP.edgeText({ from: "repo:acme-actions/deploy", to: "action:acme-actions/deploy@main", kind: "RESOLVES_TO", ev: "live", rev: true }).join(" ");
out.graph.capOver = GOP.graphModel({ graph: { max_nodes: 5, nodes: [], edges: [], what_if: [] }, paths: D.paths }, D.paths).over;

process.stdout.write(JSON.stringify(out));
