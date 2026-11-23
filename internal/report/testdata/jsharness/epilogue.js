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

process.stdout.write(JSON.stringify(out));
