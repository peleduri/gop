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
	}
	return nil
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
