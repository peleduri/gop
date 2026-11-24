package main

import (
	"flag"
	"net/url"
	"strings"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/graph"
)

// urlFlags are the GitHub endpoint flags of collect, doctor and pin.
type urlFlags struct {
	cmd      string
	github   *string
	api      *string
	graphql  *string
	insecure *bool
	useGH    *bool
}

// endpoints are the resolved GitHub endpoints. Empty rest and graphql mean
// the client defaults (api.github.com).
type endpoints struct {
	rest, graphql, host string
}

func addURLFlags(fs *flag.FlagSet, cmd string) *urlFlags {
	return &urlFlags{
		cmd: cmd,
		github: fs.String("github-url", "", "GitHub instance URL (env GOP_GITHUB_URL): https://github.com (default) or a GitHub Enterprise Server "+
			"such as https://github.acme.example, read through https://HOST/api/v3 and https://HOST/api/graphql"),
		api:      fs.String("api-url", "", "REST API root override, for a proxy (default derived from --github-url)"),
		graphql:  fs.String("graphql-url", "", "GraphQL endpoint override, for a proxy (default derived from --github-url)"),
		insecure: fs.Bool("insecure-http", false, "allow http:// URLs (local test servers only: the token then travels unencrypted)"),
		useGH: fs.Bool("use-gh-auth", false, "use the token of the GitHub CLI login (gh auth token for the --github-url host, or GH_HOST) "+
			"instead of GITHUB_TOKEN or GH_TOKEN; gop never prints it"),
	}
}

// resolve turns the flags (and GOP_GITHUB_URL) into endpoints. An empty
// --github-url, https://github.com and https://api.github.com mean
// github.com. A URL ending in /api/v3 is taken as the REST root, as
// --github-url took before it named the instance.
func (f *urlFlags) resolve(getenv func(string) string) (endpoints, error) {
	gh := strings.TrimSpace(*f.github)
	if gh == "" {
		gh = strings.TrimSpace(getenv("GOP_GITHUB_URL"))
	}
	if gh == "" && ((f.useGH != nil && *f.useGH) || ghExtension(getenv)) {
		// With the gh login, follow gh's GH_HOST to a GitHub Enterprise
		// Server, as gh itself does.
		gh = ghHostURL(getenv("GH_HOST"))
	}
	var ep endpoints
	if gh != "" {
		u, err := f.parse("github-url", gh)
		if err != nil {
			return endpoints{}, err
		}
		root := u.Scheme + "://" + u.Host
		path := strings.TrimRight(u.Path, "/")
		switch {
		case strings.EqualFold(u.Host, graph.GitHubDotCom) || strings.EqualFold(u.Host, "api.github.com"):
			if path != "" {
				return endpoints{}, usagef("%s: --github-url: want https://github.com, got %q", f.cmd, gh)
			}
		case strings.HasSuffix(path, "/api/v3"):
			ep.rest = root + path
			ep.graphql = root + strings.TrimSuffix(path, "/v3") + "/graphql"
		case path == "":
			ep.rest, ep.graphql = root+"/api/v3", root+"/api/graphql"
		default:
			return endpoints{}, usagef("%s: --github-url: want the instance URL such as https://github.acme.example, got %q", f.cmd, gh)
		}
	}
	for _, o := range []struct {
		name string
		val  string
		dst  *string
	}{{"api-url", *f.api, &ep.rest}, {"graphql-url", *f.graphql, &ep.graphql}} {
		if v := strings.TrimSpace(o.val); v != "" {
			u, err := f.parse(o.name, v)
			if err != nil {
				return endpoints{}, err
			}
			*o.dst = strings.TrimRight(u.String(), "/")
		}
	}
	// The host is the instance --github-url names, even behind an --api-url
	// proxy; without --github-url it comes from the REST root.
	ep.host = collect.HostOf(ep.rest)
	if gh != "" {
		ep.host = instanceHost(gh)
	}
	return ep, nil
}

// ghHostURL turns GH_HOST (a bare host such as github.acme.example) into an
// instance URL, or "" for unset or github.com.
func ghHostURL(h string) string {
	h = strings.TrimSpace(h)
	if h == "" || strings.EqualFold(h, graph.GitHubDotCom) {
		return ""
	}
	if strings.Contains(h, "://") {
		return h
	}
	return "https://" + h
}

// instanceHost is the lower-case host of a --github-url, with api.github.com
// read as github.com.
func instanceHost(gh string) string {
	u, err := url.Parse(gh)
	if err != nil || u.Host == "" || strings.EqualFold(u.Host, "api.github.com") {
		return graph.GitHubDotCom
	}
	return strings.ToLower(u.Host)
}

// parse checks one URL flag: absolute, https (or http with --insecure-http),
// no credentials, query or fragment.
func (f *urlFlags) parse(name, v string) (*url.URL, error) {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, usagef("%s: --%s must be an absolute https:// URL, got %q", f.cmd, name, v)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, usagef("%s: --%s must not carry credentials, a query or a fragment", f.cmd, name)
	}
	if u.Scheme == "http" && !*f.insecure {
		return nil, usagef("%s: --%s %q uses http://: the token would travel unencrypted; use https:// (or --insecure-http for a local test server)", f.cmd, name, v)
	}
	return u, nil
}
