package collect

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// GitHub Enterprise Server support.
//
// A run is against GHES when Config.Host names a host other than github.com,
// or, with Config.Host empty, when Config.BaseURL ends in /api/v3. gop then
// reads the server version from GET /meta (installed_version), records it on
// the enterprise node (ghes_version, next to host), and skips the collectors
// the version does not support (ghesCapabilities): each skip writes coverage
// with reason "not available on GHES <version>", so the gap is not_visible,
// never an error. When the version can't be read every collector runs, and
// the ones the server lacks fail into coverage as they do on github.com.

// Capability keys of ghesCapabilities.
const (
	capEnterpriseSettings = "enterprise_settings"
	capConsumedLicenses   = "consumed_licenses"
	capActionsAccess      = "actions_access"
	capRulesets           = "rulesets"
)

// ghesCapability is the minimum GHES version of one collector. Min "" means
// the API is not available on any GHES version.
type ghesCapability struct {
	key       string
	collector string // what gop reads, for coverage and docs
	min       string
}

// ghesCapabilities lists every collector that depends on a GHES version.
// Every row is UNVERIFIED: the minimums come from GitHub's public docs and
// release notes and were not checked against a running server of each
// version. Sources (GitHub's public GHES docs, one reference per version under
// https://docs.github.com/en/enterprise-server@<version>/):
//
//   - enterprise_settings: GraphQL Enterprise.ownerInfo per-org setting lists
//     (graphql/reference/objects#enterpriseownerinfo). Present in the 3.0
//     GraphQL reference. UNVERIFIED for every list gop reads.
//   - consumed_licenses: REST GET /enterprises/{enterprise}/consumed-licenses
//     (rest/enterprise-admin/licensing). Documented for GitHub Enterprise Cloud
//     only; GHES has GET /enterprise/settings/license (site admin), which gop
//     does not use. UNVERIFIED; members then come from each org's members API.
//   - actions_access: REST GET /repos/{owner}/{repo}/actions/permissions/access
//     (rest/actions/permissions), added with sharing actions from internal
//     repositories in GHES 3.4. UNVERIFIED.
//   - rulesets: REST GET /repos/{owner}/{repo}/rules/branches/{branch} and
//     /repos/{owner}/{repo}/rulesets (rest/repos/rules), repository rulesets
//     in GHES 3.11. UNVERIFIED.
//
// Collectors not listed (repositories, collaborators, teams, contents, classic
// branch protection, releases, GraphQL object reads) are in every supported
// GHES version.
var ghesCapabilities = []ghesCapability{
	{key: capEnterpriseSettings, collector: "graphql:enterprise.ownerInfo setting lists", min: "3.0"},
	{key: capConsumedLicenses, collector: srcLicenses, min: ""},
	{key: capActionsAccess, collector: "rest:GET /repos/{owner}/{repo}/actions/permissions/access", min: "3.4"},
	{key: capRulesets, collector: "rest:GET /repos/{owner}/{repo}/rules/branches/{branch} and /rulesets", min: "3.11"},
}

// HostOf returns the GitHub host a REST API root belongs to: "github.com" for
// an empty root or api.github.com, the URL's host for a GHES root ending in
// /api/v3, and "github.com" for anything else (a proxy or test server in front
// of github.com).
func HostOf(baseURL string) string {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if b == "" {
		return graph.GitHubDotCom
	}
	u, err := url.Parse(b)
	if err != nil || u.Host == "" {
		return graph.GitHubDotCom
	}
	if strings.EqualFold(u.Host, "api.github.com") || !strings.HasSuffix(u.Path, "/api/v3") {
		return graph.GitHubDotCom
	}
	return strings.ToLower(u.Host)
}

// host returns the GitHub host of the run.
func (cfg Config) host() string {
	if h := strings.ToLower(strings.TrimSpace(cfg.Host)); h != "" {
		return h
	}
	if cfg.Client != nil {
		return HostOf(cfg.Client.base.String())
	}
	return HostOf(cfg.BaseURL)
}

// isGHES reports whether host is a GitHub Enterprise Server host.
func isGHES(host string) bool { return host != "" && host != graph.GitHubDotCom }

// parseVersion reads "3.14.2" (or "3.14") into its major and minor numbers.
func parseVersion(v string) (major, minor int, ok bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	mnr, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || maj < 0 || mnr < 0 {
		return 0, 0, false
	}
	return maj, mnr, true
}

// versionBelow reports whether have is older than min (major.minor). Unknown
// or unparseable versions are never below.
func versionBelow(have, min string) bool {
	hm, hn, ok1 := parseVersion(have)
	mm, mn, ok2 := parseVersion(min)
	if !ok1 || !ok2 {
		return false
	}
	return hm < mm || (hm == mm && hn < mn)
}

// ghesGate decides whether a collector runs on this server. It returns skip
// with the coverage reason and fix when the server's version does not support
// it; on github.com, or when the version is unknown, it never skips.
func (k *collector) ghesGate(key string) (reason, fix string, skip bool) {
	if !k.ghes || k.ghesVersion == "" {
		return "", "", false
	}
	for _, c := range ghesCapabilities {
		if c.key != key {
			continue
		}
		reason = "not available on GHES " + k.ghesVersion
		switch {
		case c.min == "":
			return reason + " (" + c.collector + ")", "run as site admin, or collect from GitHub Enterprise Cloud", true
		case versionBelow(k.ghesVersion, c.min):
			return reason + " (" + c.collector + " needs GHES " + c.min + ")",
				"upgrade to GHES >= " + c.min + " or run as site admin", true
		}
		return "", "", false
	}
	return "", "", false
}

// ghesSkip is ghesGate that also writes the coverage entry on scope.
func (k *collector) ghesSkip(scope, fact, key string) bool {
	reason, fix, skip := k.ghesGate(key)
	if skip {
		k.cover(scope, fact, reason, fix)
	}
	return skip
}

// detectGHES records host on the enterprise node and, on GHES, reads the
// server version from GET /meta into ghes_version. A failed read leaves
// ghes_version unknown (not_visible) with coverage; collection goes on.
func (k *collector) detectGHES(ctx context.Context, ent *graph.Node) error {
	setAttr(ent, graph.AttrHost, k.host, graph.Live)
	if !k.ghes {
		return nil
	}
	c := k.c
	if k.app != nil && len(k.orgs) > 0 {
		c = k.cl(k.orgs[0].login)
	}
	var meta struct {
		InstalledVersion string `json:"installed_version"`
	}
	err := c.GetJSON(ctx, "/meta", &meta)
	reason := ""
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		reason = "could not read the GHES version: " + err.Error()
	default:
		if _, _, ok := parseVersion(meta.InstalledVersion); !ok {
			reason = "GET /meta returned no installed_version: " + strconv.Quote(meta.InstalledVersion)
		}
	}
	if reason != "" {
		setAttr(ent, graph.AttrGHESVersion, "unknown", graph.NotVisible)
		k.cover(ent.ID, graph.AttrGHESVersion, reason+"; version-gated collectors ran anyway", "check --github-url and the token")
		return nil
	}
	k.ghesVersion = strings.TrimSpace(meta.InstalledVersion)
	setAttr(ent, graph.AttrGHESVersion, k.ghesVersion, graph.Live)
	k.logf("collect: GitHub Enterprise Server %s at %s", k.ghesVersion, k.host)
	return nil
}
