// Test harness for the report's inline script: a minimal fake DOM, just
// enough for the script to render its views under node. The Go test runs
// prelude.js + the script extracted from a rendered report + epilogue.js
// as one file and reads the JSON the epilogue prints.
"use strict";
var fs = require("fs");
var RAW = fs.readFileSync(process.argv[2], "utf8");

function Text(s) { this.data = String(s); }
Object.defineProperty(Text.prototype, "textContent", { get: function () { return this.data; } });

function El(tag) {
  this.tagName = tag; this.childNodes = []; this.className = ""; this.hidden = false;
  this.listeners = {}; this.value = ""; this.checked = false; this.href = "";
}
Object.defineProperty(El.prototype, "firstChild", { get: function () { return this.childNodes[0] || null; } });
Object.defineProperty(El.prototype, "textContent", {
  get: function () { return this.childNodes.map(function (c) { return c.textContent; }).join(""); },
});
El.prototype.appendChild = function (c) {
  if (!(c instanceof El) && !(c instanceof Text)) { throw new Error("appendChild of a non-node: " + typeof c); }
  this.childNodes.push(c); return c;
};
El.prototype.removeChild = function (c) { this.childNodes.splice(this.childNodes.indexOf(c), 1); return c; };
El.prototype.setAttribute = function (k, v) { (this.attrs = this.attrs || {})[k] = String(v); };
El.prototype.focus = function () { global.focused = this; };
El.prototype.addEventListener = function (t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); };
El.prototype.fire = function (t, ev) {
  ev = ev || {};
  ev.preventDefault = function () { ev.prevented = true; };
  (this.listeners[t] || []).forEach(function (f) { f(ev); });
};
El.prototype.find = function (tag, out) {
  out = out || [];
  this.childNodes.forEach(function (c) { if (c instanceof El) { if (c.tagName === tag) { out.push(c); } c.find(tag, out); } });
  return out;
};

var ids = {};
["gop-static", "gop-explore", "gop-orgview", "gop-count", "gop-paths", "gop-fixes", "gop-reset",
  "gop-tab-list", "gop-tab-graph", "gop-list-panel", "gop-graph-panel", "gop-pins", "gop-pin-options",
  "gop-graph-status", "gop-graph", "gop-graph-detail", "gop-graph-text"].forEach(function (id) {
  ids[id] = new El(/^gop-(reset|tab-)/.test(id) ? "button" : "div");
});
ids["gop-graph-panel"].hidden = true;
ids["gop-pins"].hidden = true;
ids["gop-explore"].hidden = true;
ids["gop-orgview"].hidden = true;
ids["gop-data"] = { textContent: RAW };
var form = new El("form");
form.elements = { ev: new El("select"), kind: new El("select"), ref: new El("select"), q: new El("input"), via: new El("input") };
var orgBoxes = JSON.parse(RAW).orgs.map(function (o) { var b = new El("input"); b.value = o.name; return b; });
form.querySelectorAll = function (sel) {
  if (sel !== "input[name=org]") { throw new Error("unexpected selector " + sel); }
  return orgBoxes;
};
ids["gop-filters"] = form;

var winListeners = {};
global.document = {
  getElementById: function (id) { return ids[id] || null; },
  createElement: function (t) { return new El(t); },
  createElementNS: function (ns, t) { var e = new El(t); e.ns = ns; return e; },
  createTextNode: function (s) { return new Text(s); },
};
global.location = { hash: "", pathname: "/report.html", search: "" };
global.history = { replaceState: function (a, b, u) { location.hash = u.charAt(0) === "#" ? u : ""; } };
global.window = {
  addEventListener: function (t, f) { winListeners[t] = f; },
  scrollTo: function () {},
};
