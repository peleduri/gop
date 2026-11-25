package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// appInstallFix is the access GET /orgs/{org}/installations needs (GitHub
// REST docs: the user must be an org owner; classic tokens need the scope
// the docs name, fine-grained tokens and Apps Organization "Administration"
// read).
const appInstallFix = "an org owner's token (classic: the scope GitHub documents for GET /orgs/{org}/installations; fine-grained or GitHub App: Organization permission Administration: read)"

// srcAppInstallations is the source of App push edges.
const srcAppInstallations = "rest:GET /orgs/{org}/installations"

// appSelectedFix is the fix for an App installed on selected repositories:
// GitHub lists them only to the App itself (GET /installation/repositories
// takes the App's installation token, GET /user/installations/{id}/repositories
// a GitHub App user access token), never to an org owner's token.
const appSelectedFix = "none with an org token: GitHub lists an installation's selected repositories only to the App's own tokens; " +
	"an org owner can read the list in the org settings (GitHub Apps, Configure) and narrow it or drop contents: write"

// appGrant is one installation in an org that can push (contents: write).
type appGrant struct {
	identity  string // identity:<slug>[bot]
	slug      string
	selection string // all | selected
	workflows bool   // workflows: write
}

// apiInstallation is the part of an org installation gop keeps.
type apiInstallation struct {
	AppID               int64             `json:"app_id"`
	AppSlug             string            `json:"app_slug"`
	RepositorySelection string            `json:"repository_selection"`
	Permissions         map[string]string `json:"permissions"`
}

// collectInstallations reads the GitHub Apps installed in an org and records
// each as an identity node. It never reads the selected repository list
// (that needs the App's own credentials).
func (k *collector) collectInstallations(ctx context.Context, o *orgState) error {
	if !o.ownerVisible {
		// The endpoint answers org owners only: the same fix as the other
		// owner-only facts (gop doctor predicts it).
		setAttr(o.node, graph.AttrAppInstallations, "unknown", graph.NotVisible)
		k.cover(o.node.ID, graph.FactAppInstallations, "token is not an org owner", k.ownerFix(o))
		return nil
	}
	var all []apiInstallation
	err := k.cl(o.login).GetPages(ctx, "/orgs/"+url.PathEscape(o.login)+"/installations?per_page=100", func(page []byte) error {
		var p struct {
			Installations []apiInstallation `json:"installations"`
		}
		if err := json.Unmarshal(page, &p); err != nil {
			return fmt.Errorf("decoding installations: %w", err)
		}
		all = append(all, p.Installations...)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setAttr(o.node, graph.AttrAppInstallations, "unknown", graph.NotVisible)
		k.cover(o.node.ID, graph.FactAppInstallations, "could not list installed GitHub Apps: "+err.Error(), appInstallFix)
		return nil
	}
	setAttr(o.node, graph.AttrAppInstallations, strconv.Itoa(len(all)), graph.Live)
	for _, in := range all {
		if in.AppSlug == "" || in.AppID == 0 {
			continue
		}
		n := k.identity(in.AppSlug + "[bot]")
		setAttr(n, graph.AttrAppID, strconv.FormatInt(in.AppID, 10), graph.Live)
		setAttr(n, graph.AttrAppSlug, in.AppSlug, graph.Live)
		setAttr(n, graph.AttrAppOrgs, addToList(n.Attrs[graph.AttrAppOrgs], o.login), graph.Live)
		write := splitList(n.Attrs[graph.AttrAppWrite])
		for p, lvl := range in.Permissions {
			if lvl == "write" || lvl == "admin" {
				write = append(write, p)
			}
		}
		setAttr(n, graph.AttrAppWrite, joinSet(write), graph.Live)
		repos := in.RepositorySelection
		if n.Attrs[graph.AttrAppRepos] == "all" || repos != "all" && repos != "selected" {
			repos = n.Attrs[graph.AttrAppRepos]
		}
		if repos != "" {
			setAttr(n, graph.AttrAppRepos, repos, graph.Live)
		}
		if graph.AppNamesAI(in.AppSlug) {
			setAttr(n, graph.AttrAppAI, "name", graph.Live)
		}
		if writes(in.Permissions["contents"]) {
			o.appPush = append(o.appPush, appGrant{identity: n.ID, slug: in.AppSlug,
				selection: in.RepositorySelection, workflows: writes(in.Permissions["workflows"])})
		}
	}
	return nil
}

// writes reports whether a permission level allows writing.
func writes(lvl string) bool { return lvl == "write" || lvl == "admin" }

// appPushEdges turns the org's App installations with contents: write into
// CAN_PUSH edges from the App identity to the org's collected repositories.
// An installation on all repositories gives inferred edges (rule
// app_install: the installation's scope applied to the org's repository
// list). An installation on selected repositories gives not_visible edges
// (possible reach only) and a coverage entry: an org token cannot read which
// repositories were selected, so gop does not guess. Run after the other
// push grants: k.edge keeps the first edge per (from, kind, to).
func (k *collector) appPushEdges(o *orgState) {
	var selected []string
	for _, a := range o.appPush {
		ev, attrs := graph.Inferred, map[string]string{
			graph.AttrVia: graph.ViaAppInstall, graph.AttrRule: graph.RuleAppInstall, attrPermission: "write", graph.AttrAppRepos: "all",
		}
		if a.selection != "all" {
			ev, attrs = graph.NotVisible, map[string]string{
				graph.AttrVia: graph.ViaAppInstall, attrPermission: "write", graph.AttrAppRepos: "selected",
				graph.AttrReason: "installed on selected repositories; the list is not visible to an org token",
			}
			selected = append(selected, a.slug)
		}
		if a.workflows {
			attrs[graph.AttrAppWorkflows] = "write"
		}
		for _, r := range o.repos {
			e := make(map[string]string, len(attrs))
			for key, v := range attrs {
				e[key] = v
			}
			k.edge(a.identity, r.ID, graph.CanPush, ev, srcAppInstallations, e)
		}
	}
	if len(selected) > 0 {
		sort.Strings(selected)
		k.cover(o.node.ID, graph.FactAppPush, "GitHub Apps with contents: write on selected repositories, which an org token cannot list: "+
			strings.Join(selected, ", ")+" (each counts as possible push to every repository of the org)", appSelectedFix)
	}
}

// addToList adds v to a sorted comma list.
func addToList(list, v string) string { return joinSet(append(splitList(list), v)) }

// joinSet is the sorted, de-duplicated comma list of vs, or "none".
func joinSet(vs []string) string {
	set := map[string]bool{}
	for _, v := range vs {
		if v != "" && v != "none" {
			set[v] = true
		}
	}
	if len(set) == 0 {
		return "none"
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
