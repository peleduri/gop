package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file holds gop doctor: a read-only preflight that tells, in a handful
// of requests, what a collect run with this token will and will not see. It
// never prints the token or a header value; it reports parsed facts only.

// CheckStatus is the outcome of one doctor check.
type CheckStatus string

// Check outcomes. Info is never counted towards the exit code.
const (
	StatusPass CheckStatus = "pass"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
	StatusInfo CheckStatus = "info"
)

// Token kinds, detected from the token's documented prefix and the API's answers.
const (
	KindClassicPAT     = "classic_pat"
	KindFineGrainedPAT = "fine_grained_pat"
	KindOAuth          = "oauth"
	KindAppUser        = "app_user"
	KindInstallation   = "app_installation"
	// KindApp is GitHub App mode: doctor signs an App JWT and mints a
	// read-only installation token per org, as collect does.
	KindApp     = "github_app"
	KindUnknown = "unknown"
)

// Token modes from the README "Token modes" table.
const (
	ModeOwner   = "a"
	ModePerOrg  = "b"
	ModeOneRepo = "c"
	ModeUnknown = "unknown"
)

// Estimate assumptions for gop collect. They are rough on purpose: doctor
// only sees counts it can read cheaply.
const (
	// DoctorMaxOrgs is how many orgs doctor probes, one request each.
	DoctorMaxOrgs = 100

	estAvgWorkflows  = 3   // workflow files per repository (not counted by doctor)
	estPerRepo       = 1   // workflow directory listing (collaborators ride in a batched GraphQL query)
	estPerOrg        = 8   // owner view, roles, teams, outside collaborators, members
	estEnterprise    = 10  // org list, licenses and other enterprise-level reads
	estLatencyMillis = 300 // average time per sequential request
	// estBotScriptPct is the share (percent) of repositories with a run:
	// step that invokes a repo script with a token, whose script gop reads
	// once (one contents GET, botscript.go).
	estBotScriptPct = 5
	// estFollowPct is the read-only contents GETs, per 100 repositories,
	// that following one level of indirection costs (indirect.go): the
	// local composite actions, same-repo reusable workflows and keyed repo
	// scripts of workflows with a trigger outsiders can cause, each read
	// once per repo.
	estFollowPct    = 20
	estReposPerPage = 100
	// GraphQL cost per repository, in GitHub's unit: one "request" per
	// connection page a query may need, assuming every first: limit is
	// reached; a query costs that sum / 100, rounded, and at least 1 point.
	// Protection: rules(first: 50), bypassActors(first: 20) on each of the 50
	// rules, bypassPullRequestAllowances(first: 20). Collaborators: one
	// collaborators(first: 100).
	estProtectionCostPerRepo = 52
	estCollabCostPerRepo     = 1
	headerScopes             = "X-OAuth-Scopes"
	headerSSO                = "X-GitHub-SSO"
	headerTokenExpiry        = "GitHub-Authentication-Token-Expiration"
)

// GitHub App mode in the estimate.
const (
	// estAppBudget is the hourly REST budget assumed for each GitHub App
	// installation when doctor cannot read it (GitHub's floor; large orgs
	// get more).
	estAppBudget = 5000
	// recommendAppMinutes and recommendAppWaits are the token-mode estimate
	// above which doctor recommends GitHub App mode.
	recommendAppMinutes = 180
	recommendAppWaits   = 2
	// AppModeDoc documents GitHub App mode and why it suits large enterprises.
	AppModeDoc = "https://github.com/peleduri/gop/blob/main/docs/github-app-token.md"
)

// DoctorConfig drives one doctor run.
type DoctorConfig struct {
	Enterprise string
	// Token is used only to detect its kind from the prefix and to build a
	// Client when Client is nil. It is never printed.
	Token string
	// Orgs, when non-empty, are the orgs to probe when the token cannot read
	// the enterprise (same meaning as collect --orgs).
	Orgs []string

	// GitHub App mode (mutually exclusive with Token), as in Config: doctor
	// lists the App's installations, mints a read-only installation token
	// per selected org and checks the granted permissions. The key is held
	// in memory only and never printed.
	AppID            int64
	AppPrivateKeyPEM []byte
	AppPermissions   map[string]string

	BaseURL    string
	GraphQLURL string
	// Client is the client doctor uses (with no token in App mode, where
	// every request gets its token from the App).
	Client *Client
	// Now defaults to time.Now; tests fix it for stable estimates.
	Now func() time.Time
	// Parallel is the collect --parallel value the estimate assumes for
	// GitHub App mode (0 means DefaultParallel).
	Parallel int
}

// DoctorCheck is one line of the checks table.
type DoctorCheck struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// DoctorToken describes the token without revealing it.
type DoctorToken struct {
	Kind        string   `json:"kind"`
	Login       string   `json:"login,omitempty"`
	Scopes      []string `json:"scopes"`
	ScopesKnown bool     `json:"scopes_known"`
	Expires     string   `json:"expires,omitempty"`
	// AppID and Installations are set in GitHub App mode: the App ID and
	// the account logins of its usable installations.
	AppID         int64    `json:"app_id,omitempty"`
	Installations []string `json:"installations,omitempty"`
}

// Org roles of the token's user, as doctor reads them.
const (
	RoleOwner  = "owner"
	RoleMember = "member"
	RoleNone   = "none" // not a member
)

// Repository count sources.
const (
	ReposGraphQL = "graphql" // enterprise organizations { repositories { totalCount } }
	ReposREST    = "rest"    // GET /orgs/{org} public_repos + total_private_repos
	// ReposVisible is the count of repositories the token can see in an org
	// it does not own: the larger of the enterprise GraphQL totalCount and
	// GET /orgs/{org} public_repos. Both count only what the token can see
	// there, so it is a lower bound, never a total.
	ReposVisible = "visible_to_token"
)

// DoctorOrg is the probe result for one org.
type DoctorOrg struct {
	Login  string `json:"login"`
	Status string `json:"status"` // ok, sso_unauthorized, forbidden, not_found, error
	Repos  *int   `json:"repos,omitempty"`
	// ReposSource says where Repos came from (graphql, rest or
	// visible_to_token).
	ReposSource string `json:"repos_source,omitempty"`
	// ReposLowerBound is set when the token is not an org owner: Repos then
	// counts only the repositories the token can see, and private ones it
	// cannot see are missing from it.
	ReposLowerBound bool `json:"repos_lower_bound,omitempty"`
	// Role is the token user's role in the org (owner, member or none);
	// empty when doctor could not tell.
	Role string `json:"role,omitempty"`

	defaultPermVisible bool // GET /orgs/{org} returned default_repository_permission
	gqlEmpty           bool // the enterprise query counted no repositories the token can see
}

// PredictedCoverage is one coverage entry doctor expects gop collect to
// record. Scope, Fact and NeedsFix use the same values as graph.Coverage.
type PredictedCoverage struct {
	Scope    string `json:"scope"`
	Fact     string `json:"fact"`
	NeedsFix string `json:"needs_fix"`
}

// RateBucket is one /rate_limit resource.
type RateBucket struct {
	Limit     int    `json:"limit"`
	Remaining int    `json:"remaining"`
	Reset     string `json:"reset"`
	reset     time.Time
}

// DoctorEstimate predicts the cost of gop collect.
type DoctorEstimate struct {
	Orgs          int `json:"orgs"`
	OrgsUncounted int `json:"orgs_uncounted"`
	Repos         int `json:"repos"`
	// ReposLowerBound counts the orgs whose repository count is a lower bound.
	ReposLowerBound int `json:"repos_lower_bound_orgs,omitempty"`
	// ReposGraphQL and ReposREST count the orgs whose repository count came
	// from each source.
	ReposGraphQL     int `json:"repos_graphql_orgs,omitempty"`
	ReposREST        int `json:"repos_rest_orgs,omitempty"`
	ReposVisible     int `json:"repos_visible_orgs,omitempty"`
	AssumedWorkflows int `json:"assumed_workflows_per_repo"`
	// Requests is RESTRequests plus GraphQLQueries.
	Requests     int `json:"requests"`
	RESTRequests int `json:"rest_requests"`
	// GraphQLQueries are the batched queries (protection and
	// collaborators, one each per DefaultBatchSize repositories) and
	// GraphQLPoints the GraphQL rate-limit points they cost.
	GraphQLQueries int `json:"graphql_queries"`
	GraphQLPoints  int `json:"graphql_points"`
	Minutes        int `json:"minutes"`
	RateLimitWaits int `json:"rate_limit_waits"`
	// PerInstallation is set in GitHub App mode: each org spends its own
	// installation's budget, Parallel orgs are read at once, and
	// MaxOrgRequests is the estimate for the largest org. RateLimitWaits is
	// then the most resets any one installation waits for.
	PerInstallation bool `json:"per_installation,omitempty"`
	Parallel        int  `json:"parallel,omitempty"`
	MaxOrgRequests  int  `json:"max_org_requests,omitempty"`
}

// DoctorRecommendation is doctor's advice when a token-mode collect would
// take long: GitHub App mode gives every org installation its own budget.
type DoctorRecommendation struct {
	// Mode is the recommended authentication mode, KindApp.
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
	// Minutes and RateLimitWaits repeat the token-mode estimate.
	Minutes        int `json:"minutes"`
	RateLimitWaits int `json:"rate_limit_waits"`
	// AppMinutes is the estimate in GitHub App mode with Parallel org
	// workers and estAppBudget requests per installation and hour.
	AppMinutes int    `json:"app_minutes"`
	Parallel   int    `json:"parallel"`
	Doc        string `json:"doc"`
}

// DoctorReport is the result of Doctor.
type DoctorReport struct {
	Enterprise string          `json:"enterprise"`
	Mode       string          `json:"mode"`
	ModeLabel  string          `json:"mode_label"`
	Token      DoctorToken     `json:"token"`
	Checks     []DoctorCheck   `json:"checks"`
	Orgs       []DoctorOrg     `json:"orgs"`
	OrgsTotal  int             `json:"orgs_total"`
	REST       *RateBucket     `json:"rate_limit_rest,omitempty"`
	GraphQL    *RateBucket     `json:"rate_limit_graphql,omitempty"`
	Estimate   *DoctorEstimate `json:"estimate,omitempty"`
	// Recommendation is set when the token-mode estimate is above the
	// threshold for GitHub App mode.
	Recommendation *DoctorRecommendation `json:"recommendation,omitempty"`
	NotVisible     []string              `json:"not_visible"`
	// Predicted lists the org coverage entries collect will record for orgs
	// the token does not own.
	Predicted []PredictedCoverage `json:"predicted_coverage,omitempty"`
}

// Counts returns the number of failed and warning checks.
func (r *DoctorReport) Counts() (fails, warns int) {
	for _, c := range r.Checks {
		switch c.Status {
		case StatusFail:
			fails++
		case StatusWarn:
			warns++
		}
	}
	return fails, warns
}

func (r *DoctorReport) check(name string, st CheckStatus, detail, fix string) {
	r.Checks = append(r.Checks, DoctorCheck{Name: name, Status: st, Detail: detail, Fix: fix})
}

func (r *DoctorReport) notVisible(s string) { r.NotVisible = append(r.NotVisible, s) }

// TokenKind detects the token kind from GitHub's documented token prefixes.
func TokenKind(token string) string {
	switch {
	case strings.HasPrefix(token, "ghp_"):
		return KindClassicPAT
	case strings.HasPrefix(token, "github_pat_"):
		return KindFineGrainedPAT
	case strings.HasPrefix(token, "gho_"):
		return KindOAuth
	case strings.HasPrefix(token, "ghu_"):
		return KindAppUser
	case strings.HasPrefix(token, "ghs_"):
		return KindInstallation
	}
	return KindUnknown
}

// requiredScope is one classic scope gop needs, with the scopes that imply it.
type requiredScope struct {
	name    string
	implied []string
	missing string // what goes not_visible without it
}

var requiredScopes = []requiredScope{
	{"read:enterprise", []string{"read:enterprise", "admin:enterprise"},
		"enterprise settings and membership (ownerInfo, consumed licenses)"},
	{"read:org", []string{"read:org", "write:org", "admin:org"},
		"org settings, IP allow lists and CAN_PUSH edges"},
	{"repo", []string{"repo"},
		"workflows in private and internal repositories (USES and EXECUTES_WITH edges)"},
	{"read:audit_log", []string{"read:audit_log"},
		"audit evidence (planned, not used yet)"},
}

// scopeEffect says what a missing scope costs.
func scopeEffect(rs requiredScope) string {
	if rs.name == "read:audit_log" {
		return "no " + rs.missing
	}
	return rs.missing + " will be not_visible"
}

// writeScopes are classic scopes that grant more than gop needs. repo is
// required for private contents and is not listed.
var writeScopes = map[string]bool{
	"admin:enterprise": true, "manage_runners:enterprise": true, "manage_billing:enterprise": true,
	"admin:org": true, "write:org": true, "manage_runners:org": true,
	"admin:repo_hook": true, "write:repo_hook": true, "admin:org_hook": true,
	"delete_repo": true, "workflow": true, "write:packages": true, "delete:packages": true,
	"admin:public_key": true, "write:public_key": true, "admin:gpg_key": true, "write:gpg_key": true,
	"admin:ssh_signing_key": true, "write:ssh_signing_key": true, "write:discussion": true,
	"user": true, "gist": true, "codespace": true, "project": true, "copilot": true,
}

const enterpriseQueryDoctor = `query($slug: String!) {
  enterprise(slug: $slug) {
    slug
    ownerInfo { admins(first: 1) { totalCount } }
    organizations(first: 100) {
      totalCount
      nodes { login archivedAt viewerCanAdminister viewerIsAMember repositories { totalCount } }
    }
  }
}`

// Doctor runs the preflight. It returns an error only when it cannot run at
// all (bad config, canceled context); API failures become checks.
func Doctor(ctx context.Context, cfg DoctorConfig) (*DoctorReport, error) {
	if cfg.Enterprise == "" {
		return nil, errors.New("doctor: enterprise slug is required")
	}
	if cfg.AppID != 0 || len(cfg.AppPrivateKeyPEM) > 0 {
		return doctorApp(ctx, cfg)
	}
	c := cfg.Client
	if c == nil {
		var err error
		c, err = NewClient(ClientOptions{BaseURL: cfg.BaseURL, GraphQLURL: cfg.GraphQLURL, Token: cfg.Token,
			MaxAttempts: 2, MaxWait: 30 * time.Second})
		if err != nil {
			return nil, err
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	d := &doctor{c: c, cfg: cfg, now: now().UTC(),
		r: &DoctorReport{Enterprise: cfg.Enterprise, Mode: ModeUnknown, Token: DoctorToken{Kind: TokenKind(cfg.Token), Scopes: []string{}},
			Checks: []DoctorCheck{}, Orgs: []DoctorOrg{}, NotVisible: []string{}}}
	if err := d.run(ctx); err != nil {
		return nil, err
	}
	return d.r, nil
}

type doctor struct {
	c   *Client
	cfg DoctorConfig
	now time.Time
	r   *DoctorReport

	installRepos int      // total_count of /installation/repositories, -1 if not read
	installOwner []string // owners of the first page of installation repositories
}

func (d *doctor) run(ctx context.Context) error {
	r := d.r
	d.installRepos = -1
	if ok, err := d.identify(ctx); err != nil || !ok {
		return err
	}
	ownerInfo, err := d.enterprise(ctx)
	if err != nil {
		return err
	}
	d.mode(ownerInfo)
	d.scopes()
	if r.Mode != ModeOneRepo {
		if err := d.orgs(ctx, ownerInfo); err != nil {
			return err
		}
	}
	if err := d.rateLimit(ctx); err != nil {
		return err
	}
	d.estimate()
	return nil
}

// identify reads who the token is: GET /user for user tokens, GET
// /installation/repositories for installation tokens. It returns false when
// the token is rejected and nothing else can be checked.
func (d *doctor) identify(ctx context.Context) (bool, error) {
	r := d.r
	if r.Token.Kind != KindInstallation {
		var u struct {
			Login string `json:"login"`
		}
		h, err := d.c.GetJSONHeader(ctx, "/user", &u)
		switch {
		case err == nil:
			r.Token.Login = u.Login
			if v, ok := headerValue(h, headerScopes); ok {
				r.Token.ScopesKnown = true
				r.Token.Scopes = parseScopes(v)
				if r.Token.Kind == KindUnknown {
					r.Token.Kind = KindClassicPAT
				}
			}
			if v, ok := headerValue(h, headerTokenExpiry); ok {
				r.Token.Expires = v
			}
			r.check("token", StatusPass, "authenticated as "+u.Login+" ("+kindLabel(r.Token.Kind)+")", "")
			return true, nil
		case ctx.Err() != nil:
			return false, ctx.Err()
		case StatusOf(err) == http.StatusUnauthorized:
			r.check("token", StatusFail, "token rejected (HTTP 401): expired, revoked or mistyped",
				"create a new token and set it in GITHUB_TOKEN")
			return false, nil
		case StatusOf(err) == http.StatusForbidden && r.Token.Kind == KindUnknown:
			// Installation tokens may not read /user; fall through to the installation probe.
			r.Token.Kind = KindInstallation
		default:
			r.check("token", StatusFail, "could not read GET /user: "+statusText(err),
				"check --github-url and the token")
			return false, nil
		}
	}
	var body struct {
		TotalCount   int `json:"total_count"`
		Repositories []struct {
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repositories"`
	}
	_, err := d.c.GetJSONHeader(ctx, "/installation/repositories?per_page=100", &body)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if StatusOf(err) == http.StatusUnauthorized {
			r.check("token", StatusFail, "token rejected (HTTP 401): expired, revoked or mistyped",
				"mint a new installation token")
			return false, nil
		}
		r.check("token", StatusFail, "could not read GET /installation/repositories: "+statusText(err),
			"use an App installation token or a personal access token")
		return false, nil
	}
	d.installRepos = body.TotalCount
	seen := map[string]bool{}
	for _, repo := range body.Repositories {
		l := repo.Owner.Login
		if l != "" && !seen[strings.ToLower(l)] {
			seen[strings.ToLower(l)] = true
			d.installOwner = append(d.installOwner, l)
		}
	}
	sort.Strings(d.installOwner)
	r.check("token", StatusPass, fmt.Sprintf("installation token with access to %d repositories", body.TotalCount), "")
	return true, nil
}

type doctorEnterprise struct {
	ownerInfo bool
	visible   bool
	total     int
	logins    []string
	orgs      map[string]entOrg // by lowercase login
}

// entOrg is what the enterprise query returned for one org. Nil fields were
// not returned.
type entOrg struct {
	archived bool
	admin    *bool
	member   *bool
	repos    *int
}

// enterprise runs the one enterprise GraphQL query.
func (d *doctor) enterprise(ctx context.Context) (*doctorEnterprise, error) {
	var data struct {
		Enterprise *struct {
			Slug      string          `json:"slug"`
			OwnerInfo *map[string]any `json:"ownerInfo"`
			Orgs      *struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Login               string  `json:"login"`
					ArchivedAt          *string `json:"archivedAt"`
					ViewerCanAdminister *bool   `json:"viewerCanAdminister"`
					ViewerIsAMember     *bool   `json:"viewerIsAMember"`
					Repositories        *struct {
						TotalCount int `json:"totalCount"`
					} `json:"repositories"`
				} `json:"nodes"`
			} `json:"organizations"`
		} `json:"enterprise"`
	}
	out := &doctorEnterprise{orgs: map[string]entOrg{}}
	_, err := d.c.GraphQL(ctx, enterpriseQueryDoctor, map[string]any{"slug": d.cfg.Enterprise}, &data)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		d.r.check("enterprise", StatusFail, "enterprise GraphQL query failed: "+statusText(err),
			"check --github-url (GHES: https://HOST) and the enterprise slug")
		return out, nil
	}
	if e := data.Enterprise; e != nil {
		out.visible = true
		out.ownerInfo = e.OwnerInfo != nil
		if e.Orgs != nil {
			out.total = e.Orgs.TotalCount
			for _, n := range e.Orgs.Nodes {
				out.logins = append(out.logins, n.Login)
				eo := entOrg{archived: n.ArchivedAt != nil && *n.ArchivedAt != "",
					admin: n.ViewerCanAdminister, member: n.ViewerIsAMember}
				if n.Repositories != nil {
					c := n.Repositories.TotalCount
					eo.repos = &c
				}
				out.orgs[strings.ToLower(n.Login)] = eo
			}
		}
	}
	return out, nil
}

// mode decides the README token mode and reports the enterprise check.
func (d *doctor) mode(e *doctorEnterprise) {
	r := d.r
	switch {
	case e.ownerInfo:
		r.Mode, r.ModeLabel = ModeOwner, "(a) enterprise-owner token"
		r.check("enterprise", StatusPass,
			fmt.Sprintf("ownerInfo readable for %s; %d organizations", d.cfg.Enterprise, e.total), "")
		return
	case r.Token.Kind == KindInstallation && d.installRepos == 1:
		r.Mode, r.ModeLabel = ModeOneRepo, "(c) single-repository token"
		r.check("mode", StatusFail,
			"the token reaches one repository only (a repository GITHUB_TOKEN or an App installed on one repository); gop is not useful in this mode",
			"run gop locally with an enterprise owner token")
		r.notVisible("everything outside the one repository the token can read")
		return
	case r.Token.Kind == KindInstallation:
		r.Mode, r.ModeLabel = ModePerOrg, "(b) per-org App installation token"
	default:
		r.Mode, r.ModeLabel = ModePerOrg, "(b) per-org: token cannot read enterprise ownerInfo"
	}
	if len(r.Checks) > 0 && r.Checks[len(r.Checks)-1].Name == "enterprise" {
		return // the query itself failed; already reported
	}
	detail := "cannot read enterprise " + d.cfg.Enterprise + "; collect runs per org and enterprise settings are not_visible"
	if e.visible {
		detail = "enterprise " + d.cfg.Enterprise + " is visible but its ownerInfo is not (not an enterprise owner); enterprise settings are not_visible"
	}
	r.check("enterprise", StatusWarn, detail, "use an "+enterpriseFix)
	r.notVisible("enterprise settings (ownerInfo: SSO, 2FA, default permission, repo creation, visibility, deletion and fork policies); per-org values come from GET /orgs/{org} where readable, SSO stays not_visible")
	r.notVisible("enterprise membership (consumed licenses); members come from the org members API")
	r.notVisible("in_enterprise for action owners outside the collected orgs")
}

// scopes checks classic scopes, write scopes and expiry.
func (d *doctor) scopes() {
	r := d.r
	t := r.Token
	if !t.ScopesKnown {
		switch t.Kind {
		case KindInstallation:
			r.check("permissions", StatusInfo,
				"installation token permissions are not exposed in headers; the App needs read access to organization administration, members, metadata and contents", "")
		default:
			r.check("permissions", StatusInfo,
				kindLabel(t.Kind)+" permissions are not exposed in headers; grant read access to organization administration, members, metadata and contents", "")
		}
		return
	}
	have := map[string]bool{}
	for _, s := range t.Scopes {
		have[s] = true
	}
	for _, rs := range requiredScopes {
		ok := false
		for _, s := range rs.implied {
			ok = ok || have[s]
		}
		name := "scope " + rs.name
		switch {
		case ok:
			r.check(name, StatusPass, "present", "")
		case rs.name == "read:enterprise" && r.Mode == ModeOwner:
			r.check(name, StatusPass, "not listed, but ownerInfo is readable", "")
		default:
			r.check(name, StatusWarn, "missing: "+scopeEffect(rs), "add the "+rs.name+" scope to the token")
			if rs.name != "read:enterprise" && rs.name != "read:audit_log" {
				r.notVisible(rs.missing + " (token lacks " + rs.name + ")")
			}
		}
	}
	var broad []string
	for _, s := range t.Scopes {
		if writeScopes[s] {
			broad = append(broad, s)
		}
	}
	if len(broad) > 0 {
		sort.Strings(broad)
		r.check("write scopes", StatusWarn, "broader than gop needs: "+strings.Join(broad, ", "),
			"use a token with only read:enterprise, read:org, repo and read:audit_log")
	} else {
		r.check("write scopes", StatusPass, "none beyond repo, which private contents require", "")
	}
	if t.Kind == KindClassicPAT {
		if t.Expires == "" {
			r.check("expiry", StatusWarn, "classic token has no expiry", "set an expiry on the token, or rotate it after the run")
		} else {
			r.check("expiry", StatusPass, "expires "+t.Expires, "")
		}
	}
}

// orgs lists the orgs to probe and probes each one with GET /orgs/{org}.
func (d *doctor) orgs(ctx context.Context, e *doctorEnterprise) error {
	r := d.r
	logins, src, total, err := d.orgList(ctx, e)
	if err != nil {
		return err
	}
	r.OrgsTotal = total
	if len(logins) == 0 {
		r.check("orgs", StatusFail, "no organizations found for the token", "pass --orgs org1,org2")
		return nil
	}
	if len(logins) > DoctorMaxOrgs {
		logins = logins[:DoctorMaxOrgs]
	}
	readable := 0
	for _, login := range logins {
		o, err := d.probeOrg(ctx, d.c, login)
		if err != nil {
			return err
		}
		if o.Status == "ok" {
			readable++
		}
		r.Orgs = append(r.Orgs, o)
	}
	if err := d.ownership(ctx, e); err != nil {
		return err
	}
	// Unreadable orgs already carry their own warn or fail check; the
	// summary stays informational so they are not counted twice.
	st := StatusPass
	if readable < len(logins) {
		st = StatusInfo
	}
	r.check("orgs", st, fmt.Sprintf("%d of %d organizations readable (from %s)", readable, len(logins), src), "")
	if total > len(logins) {
		r.check("orgs checked", StatusInfo, fmt.Sprintf("checked the first %d of %d organizations", len(logins), total), "")
	}
	return nil
}

// probeOrg reads GET /orgs/{org} with c and records a check for an org it
// cannot read. It returns an error only when ctx is done.
func (d *doctor) probeOrg(ctx context.Context, c *Client, login string) (DoctorOrg, error) {
	r := d.r
	o := DoctorOrg{Login: login}
	var body struct {
		PublicRepos       *int    `json:"public_repos"`
		TotalPrivateRepos *int    `json:"total_private_repos"`
		DefaultPerm       *string `json:"default_repository_permission"`
	}
	_, err := c.GetJSONHeader(ctx, "/orgs/"+url.PathEscape(login), &body)
	switch {
	case err == nil:
		o.Status = "ok"
		o.defaultPermVisible = body.DefaultPerm != nil
		if body.PublicRepos != nil || body.TotalPrivateRepos != nil {
			n := 0
			if body.PublicRepos != nil {
				n += *body.PublicRepos
			}
			if body.TotalPrivateRepos != nil {
				n += *body.TotalPrivateRepos
			}
			o.Repos = &n
			o.ReposSource = ReposREST
		}
	case ctx.Err() != nil:
		return o, ctx.Err()
	case ssoRequired(err):
		o.Status = "sso_unauthorized"
		r.check("sso "+login, StatusFail, "token is not authorized for SAML SSO in "+login,
			"authorize this token for SSO in "+login)
		r.notVisible("org " + login + ": everything (token not authorized for SSO)")
	case IsForbidden(err) || IsNotFound(err):
		o.Status = "forbidden"
		if IsNotFound(err) {
			o.Status = "not_found"
		}
		fix := "membership in " + login + ", or check the org login"
		if r.Token.Kind == KindInstallation || r.Token.Kind == KindApp {
			fix = "install the App in " + login
		}
		r.check("org "+login, StatusWarn, "cannot read organization ("+statusText(err)+")", fix)
		r.notVisible("org " + login + ": everything (organization not readable)")
	default:
		o.Status = "error"
		r.check("org "+login, StatusWarn, "could not read organization ("+statusText(err)+")", "retry gop doctor")
	}
	return o, nil
}

// orgList returns the orgs collect would read, where they came from, and
// the total known count.
func (d *doctor) orgList(ctx context.Context, e *doctorEnterprise) ([]string, string, int, error) {
	r := d.r
	switch {
	case e.visible && len(e.logins) > 0:
		logins := e.logins
		if len(d.cfg.Orgs) > 0 {
			allow := map[string]bool{}
			for _, o := range d.cfg.Orgs {
				allow[strings.ToLower(o)] = true
			}
			logins = nil
			for _, l := range e.logins {
				if allow[strings.ToLower(l)] {
					logins = append(logins, l)
				}
			}
			return logins, "enterprise organizations filtered by --orgs", len(logins), nil
		}
		total := e.total
		if total < len(logins) {
			total = len(logins)
		}
		return logins, "enterprise organizations", total, nil
	case len(d.cfg.Orgs) > 0:
		return dedupe(d.cfg.Orgs), "--orgs", len(dedupe(d.cfg.Orgs)), nil
	case r.Token.Kind == KindInstallation:
		return d.installOwner, "installation repositories", len(d.installOwner), nil
	}
	var batch []struct {
		Login string `json:"login"`
	}
	h, err := d.c.GetJSONHeader(ctx, "/user/orgs?per_page=100", &batch)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", 0, ctx.Err()
		}
		r.check("user orgs", StatusWarn, "could not list the token's orgs: "+statusText(err), "pass --orgs org1,org2")
		return nil, "GET /user/orgs", 0, nil
	}
	var logins []string
	for _, o := range batch {
		if o.Login != "" {
			logins = append(logins, o.Login)
		}
	}
	if v, ok := headerValue(h, headerSSO); ok && strings.HasPrefix(strings.TrimSpace(v), "partial-results") {
		n := countPartialOrgs(v)
		r.check("sso hidden orgs", StatusFail,
			fmt.Sprintf("%d organizations are hidden from GET /user/orgs until the token is authorized for SAML SSO", n),
			"authorize this token for SSO in every organization (token settings, Configure SSO)")
		r.notVisible(fmt.Sprintf("%d organizations hidden by SAML SSO", n))
	}
	return logins, "GET /user/orgs", len(logins), nil
}

// rateLimit reads GET /rate_limit, which does not count against the limit.
func (d *doctor) rateLimit(ctx context.Context) error {
	var body struct {
		Resources map[string]struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
		} `json:"resources"`
	}
	if _, err := d.c.GetJSONHeader(ctx, "/rate_limit", &body); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d.r.check("rate limit", StatusWarn, "could not read GET /rate_limit: "+statusText(err), "")
		return nil
	}
	bucket := func(name string) *RateBucket {
		b, ok := body.Resources[name]
		if !ok {
			return nil
		}
		t := time.Unix(b.Reset, 0).UTC()
		return &RateBucket{Limit: b.Limit, Remaining: b.Remaining, Reset: t.Format(time.RFC3339), reset: t}
	}
	d.r.REST, d.r.GraphQL = bucket("core"), bucket("graphql")
	return nil
}

// estimate predicts requests and minutes for gop collect and checks them
// against the remaining REST budget: the token's one budget, or in GitHub
// App mode each installation's own.
func (d *doctor) estimate() {
	r := d.r
	if r.Mode == ModeOneRepo || r.Mode == ModeUnknown || len(r.Orgs) == 0 {
		return
	}
	e := &DoctorEstimate{AssumedWorkflows: estAvgWorkflows}
	var orgReqs []int // per-org requests, for App-mode scheduling
	for _, o := range r.Orgs {
		if o.Status != "ok" {
			continue
		}
		e.Orgs++
		if o.Repos == nil {
			e.OrgsUncounted++
			orgReqs = append(orgReqs, estPerOrg)
			continue
		}
		e.Repos += *o.Repos
		switch o.ReposSource {
		case ReposGraphQL:
			e.ReposGraphQL++
		case ReposREST:
			e.ReposREST++
		case ReposVisible:
			e.ReposVisible++
		}
		if o.ReposLowerBound {
			e.ReposLowerBound++
		}
		e.Requests += estPerOrg + int(math.Ceil(float64(*o.Repos)/estReposPerPage))
		orgReqs = append(orgReqs, estOrgRequests(*o.Repos))
	}
	e.Requests += estEnterprise + e.OrgsUncounted*estPerOrg
	if r.Mode == ModeOwner {
		for _, spec := range settingSpecs {
			e.Requests += len(spec.values)
		}
	}
	e.Requests += e.Repos * (estPerRepo + estAvgWorkflows)
	// Bot merge scripts: one read-only contents GET per followed script.
	e.Requests += int(math.Ceil(float64(e.Repos) * estBotScriptPct / 100))
	// One level of indirection for agents and exec: one read-only contents
	// GET per followed file.
	e.Requests += int(math.Ceil(float64(e.Repos) * estFollowPct / 100))
	e.RESTRequests = e.Requests
	// Default-branch protection and direct collaborators: one batched
	// GraphQL query each per DefaultBatchSize repositories (CODEOWNERS rides
	// in the batched workflow read and secret scanning in the repository
	// listing, at no extra request).
	for _, perRepo := range []int{estProtectionCostPerRepo, estCollabCostPerRepo} {
		q, pts := batchCost(e.Repos, perRepo)
		e.GraphQLQueries += q
		e.GraphQLPoints += pts
	}
	e.Requests += e.GraphQLQueries
	if r.Token.Kind == KindApp {
		d.estimateApp(e, orgReqs)
		return
	}
	minutes := float64(e.Requests) * estLatencyMillis / 1000 / 60
	if b := r.REST; b != nil && e.RESTRequests > b.Remaining && b.Limit > 0 {
		short := e.RESTRequests - b.Remaining
		e.RateLimitWaits = int(math.Ceil(float64(short) / float64(b.Limit)))
		wait := b.reset.Sub(d.now)
		if wait < 0 {
			wait = 0
		}
		minutes += wait.Minutes() + float64(e.RateLimitWaits-1)*60
	}
	e.Minutes = max(int(math.Ceil(minutes)), 1)
	r.Estimate = e
	gql, gqlShort := "", false
	if g := r.GraphQL; g != nil && e.GraphQLQueries > 0 {
		gql = fmt.Sprintf("; about %d GraphQL points and %d of %d remain", e.GraphQLPoints, g.Remaining, g.Limit)
		gqlShort = e.GraphQLPoints > g.Remaining
	}
	switch b := r.REST; {
	case b == nil:
	case e.RateLimitWaits > 0:
		r.check("rate limit", StatusWarn,
			fmt.Sprintf("collect needs about %d REST requests and %d remain; it will wait for %d rate-limit reset(s)%s",
				e.RESTRequests, b.Remaining, e.RateLimitWaits, gql),
			"run collect after the reset at "+b.Reset+", or with a token that has more budget")
	case gqlShort:
		r.check("rate limit", StatusWarn,
			fmt.Sprintf("collect needs about %d REST requests and %d of %d remain%s", e.RESTRequests, b.Remaining, b.Limit, gql),
			"run collect after the GraphQL reset at "+r.GraphQL.Reset+", or with a token that has more budget")
	default:
		r.check("rate limit", StatusPass,
			fmt.Sprintf("collect needs about %d REST requests and %d of %d remain%s", e.RESTRequests, b.Remaining, b.Limit, gql), "")
	}
	d.recommendApp(e, orgReqs)
}

// estOrgRequests estimates one org's requests with repos repositories, as
// estimate counts them for the whole run.
func estOrgRequests(repos int) int {
	// Two batched GraphQL queries per DefaultBatchSize repositories:
	// branch protection and direct collaborators.
	return estPerOrg + int(math.Ceil(float64(repos)/estReposPerPage)) + repos*(estPerRepo+estAvgWorkflows) +
		2*int(math.Ceil(float64(repos)/DefaultBatchSize)) + int(math.Ceil(float64(repos)*estBotScriptPct/100)) +
		int(math.Ceil(float64(repos)*estFollowPct/100))
}

// estimateApp finishes the estimate in GitHub App mode: each org spends its
// own installation's budget, and collect reads Parallel orgs at once. Every
// installation is assumed to have the budget doctor read for the first
// readable one (estAppBudget when it could not).
func (d *doctor) estimateApp(e *DoctorEstimate, orgReqs []int) {
	r := d.r
	e.PerInstallation = true
	e.Parallel = (Config{Parallel: d.cfg.Parallel}).parallel()
	for _, n := range orgReqs {
		e.MaxOrgRequests = max(e.MaxOrgRequests, n)
	}
	remaining, limit, firstWait := estAppBudget, estAppBudget, time.Hour
	if b := r.REST; b != nil && b.Limit > 0 {
		remaining, limit, firstWait = b.Remaining, b.Limit, max(b.reset.Sub(d.now), 0)
	}
	minutes, waits := appSchedule(orgReqs, e.Requests-sum(orgReqs), remaining, limit, firstWait, e.Parallel)
	e.Minutes, e.RateLimitWaits = max(int(math.Ceil(minutes)), 1), waits
	r.Estimate = e
	b := r.REST
	if b == nil {
		return
	}
	if waits > 0 {
		r.check("rate limit", StatusWarn,
			fmt.Sprintf("the largest org needs about %d REST requests and its installation has %d left; it will wait for %d rate-limit reset(s)",
				e.MaxOrgRequests, b.Remaining, waits),
			"run collect after the reset at "+b.Reset+"; installations of large orgs get a larger budget from GitHub")
		return
	}
	r.check("rate limit", StatusPass,
		fmt.Sprintf("collect needs about %d REST requests, at most %d per org; each installation has its own budget (%d of %d remain on the first)",
			e.Requests, e.MaxOrgRequests, b.Remaining, b.Limit), "")
}

// recommendApp recommends GitHub App mode when the token-mode estimate is
// above recommendAppMinutes or recommendAppWaits rate-limit resets.
func (d *doctor) recommendApp(e *DoctorEstimate, orgReqs []int) {
	if e.Minutes <= recommendAppMinutes && e.RateLimitWaits <= recommendAppWaits {
		return
	}
	parallel := (Config{Parallel: d.cfg.Parallel}).parallel()
	appMin, _ := appSchedule(orgReqs, e.Requests-sum(orgReqs), estAppBudget, estAppBudget, time.Hour, parallel)
	d.r.Recommendation = &DoctorRecommendation{
		Mode:           KindApp,
		Reason:         "one token has one hourly rate-limit budget; in GitHub App mode each org installation has its own, and collect reads orgs in parallel",
		Minutes:        e.Minutes,
		RateLimitWaits: e.RateLimitWaits,
		AppMinutes:     max(int(math.Ceil(appMin)), 1),
		Parallel:       parallel,
		Doc:            AppModeDoc,
	}
}

// appSchedule estimates the minutes of an App-mode collect. Each org takes
// its requests at estLatencyMillis each, plus a wait for every reset its
// installation needs (the first after firstWait, then hourly) once it has
// spent remaining requests of limit per hour. Orgs are spread over parallel
// workers, largest first; shared requests run before them. It also returns
// the most resets one installation waits for.
func appSchedule(orgReqs []int, shared, remaining, limit int, firstWait time.Duration, parallel int) (float64, int) {
	perReq := float64(estLatencyMillis) / 1000 / 60
	times := make([]float64, 0, len(orgReqs))
	waits := 0
	for _, n := range orgReqs {
		t := float64(n) * perReq
		if n > remaining && limit > 0 {
			w := int(math.Ceil(float64(n-remaining) / float64(limit)))
			waits = max(waits, w)
			t += firstWait.Minutes() + float64(w-1)*60
		}
		times = append(times, t)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(times)))
	loads := make([]float64, max(min(parallel, len(times)), 1))
	for _, t := range times {
		i := 0
		for j := range loads {
			if loads[j] < loads[i] {
				i = j
			}
		}
		loads[i] += t
	}
	return float64(max(shared, 0))*perReq + slices.Max(loads), waits
}

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}

// batchCost returns the batched GraphQL queries for repos repositories,
// DefaultBatchSize per query, and the points they cost when each repository
// adds perRepo connection requests (see estProtectionCostPerRepo).
func batchCost(repos, perRepo int) (queries, points int) {
	for left := repos; left > 0; left -= DefaultBatchSize {
		n := min(left, DefaultBatchSize)
		queries++
		points += max(1, int(math.Round(float64(n*perRepo)/100)))
	}
	return queries, points
}

// ssoRequired reports a 403 carrying X-GitHub-SSO: required.
func ssoRequired(err error) bool {
	if StatusOf(err) != http.StatusForbidden {
		return false
	}
	v, ok := headerValue(ResponseHeader(err), headerSSO)
	return ok && strings.HasPrefix(strings.TrimSpace(v), "required")
}

func headerValue(h http.Header, key string) (string, bool) {
	if h == nil {
		return "", false
	}
	vs, ok := h[http.CanonicalHeaderKey(key)]
	if !ok || len(vs) == 0 {
		return "", false
	}
	return vs[0], true
}

func parseScopes(v string) []string {
	out := []string{}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// countPartialOrgs counts the ids in "partial-results; organizations=1,2,3".
func countPartialOrgs(v string) int {
	_, ids, ok := strings.Cut(v, "organizations=")
	if !ok {
		return 0
	}
	n := 0
	for _, id := range strings.Split(ids, ",") {
		if _, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64); err == nil {
			n++
		}
	}
	return n
}

// statusText describes an API error by its HTTP status only, so no response
// text reaches the output.
func statusText(err error) string {
	if s := StatusOf(err); s != 0 {
		return fmt.Sprintf("HTTP %d", s)
	}
	var ge GraphQLErrors
	if errors.As(err, &ge) {
		return ge.Error()
	}
	return "request failed"
}

func kindLabel(kind string) string {
	switch kind {
	case KindClassicPAT:
		return "classic personal access token"
	case KindFineGrainedPAT:
		return "fine-grained personal access token"
	case KindOAuth:
		return "OAuth token"
	case KindAppUser:
		return "GitHub App user token"
	case KindInstallation:
		return "GitHub App installation token"
	case KindApp:
		return "GitHub App (read-only installation token minted per org)"
	}
	return "token of unknown kind"
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[strings.ToLower(s)] {
			seen[strings.ToLower(s)] = true
			out = append(out, s)
		}
	}
	return out
}

// WriteDoctor writes the report as text. It prints parsed facts only, never
// the token or a raw header value.
func WriteDoctor(w io.Writer, r *DoctorReport) error {
	var b strings.Builder
	fmt.Fprintf(&b, "gop doctor: enterprise %s\n\n", r.Enterprise)
	b.WriteString("Token\n")
	fmt.Fprintf(&b, "  kind    %s\n", kindLabel(r.Token.Kind))
	if r.Token.Login != "" {
		fmt.Fprintf(&b, "  user    %s\n", r.Token.Login)
	}
	mode := r.ModeLabel
	if mode == "" {
		mode = "unknown"
	}
	fmt.Fprintf(&b, "  mode    %s\n", mode)
	if r.Token.ScopesKnown {
		scopes := strings.Join(r.Token.Scopes, ", ")
		if scopes == "" {
			scopes = "(none)"
		}
		fmt.Fprintf(&b, "  scopes  %s\n", scopes)
	}
	if r.Token.Expires != "" {
		fmt.Fprintf(&b, "  expires %s\n", r.Token.Expires)
	}
	if r.Token.AppID != 0 {
		installs := "no installations"
		if len(r.Token.Installations) > 0 {
			installs = "installed on " + strings.Join(r.Token.Installations, ", ")
		}
		fmt.Fprintf(&b, "  app     %d (%s)\n", r.Token.AppID, installs)
	}

	b.WriteString("\nChecks\n")
	width := 0
	for _, c := range r.Checks {
		width = max(width, len(c.Name))
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  %-4s  %-*s  %s\n", strings.ToUpper(string(c.Status)), width, c.Name, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "        %-*s  fix: %s\n", width, "", c.Fix)
		}
	}

	if r.REST != nil || r.GraphQL != nil {
		b.WriteString("\nRate limit\n")
		for _, x := range []struct {
			name string
			b    *RateBucket
		}{{"REST   ", r.REST}, {"GraphQL", r.GraphQL}} {
			if x.b != nil {
				fmt.Fprintf(&b, "  %s %d of %d remaining, resets %s\n", x.name, x.b.Remaining, x.b.Limit, x.b.Reset)
			}
		}
	}

	if e := r.Estimate; e != nil {
		b.WriteString("\nEstimate for gop collect\n")
		fmt.Fprintf(&b, "  %d orgs, %d repos (%s), %d workflows per repo assumed\n",
			e.Orgs, e.Repos, repoCountLabel(e), e.AssumedWorkflows)
		if e.ReposLowerBound > 0 {
			fmt.Fprintf(&b, "  the repo count and the request estimate are lower bounds: %s not owned by the token count only the repositories it can see\n",
				plural(e.ReposLowerBound, "org"))
		}
		if e.OrgsUncounted > 0 {
			fmt.Fprintf(&b, "  %d orgs did not expose repository counts and are counted without repos\n", e.OrgsUncounted)
		}
		wait := ""
		if e.RateLimitWaits > 0 {
			wait = fmt.Sprintf(", including %d rate-limit wait(s)", e.RateLimitWaits)
		}
		fmt.Fprintf(&b, "  about %d requests (%d REST, %d GraphQL queries costing about %d points) and %d minutes%s\n",
			e.Requests, e.RESTRequests, e.GraphQLQueries, e.GraphQLPoints, e.Minutes, wait)
		if e.PerInstallation {
			fmt.Fprintf(&b, "  GitHub App mode: each org spends its own installation's budget (largest org about %d requests), up to %d orgs at a time (--parallel)\n",
				e.MaxOrgRequests, e.Parallel)
		}
	}

	if rec := r.Recommendation; rec != nil {
		b.WriteString("\nRecommendation: use GitHub App mode\n")
		fmt.Fprintf(&b, "  with this token collect takes about %d minutes", rec.Minutes)
		if rec.RateLimitWaits > 0 {
			fmt.Fprintf(&b, " (%d rate-limit waits)", rec.RateLimitWaits)
		}
		b.WriteString(": one token has one hourly budget\n")
		fmt.Fprintf(&b, "  in GitHub App mode each org installation has its own budget; with --parallel %d collect takes about %d minutes\n",
			rec.Parallel, rec.AppMinutes)
		fmt.Fprintf(&b, "  set up a read-only App: %s\n", rec.Doc)
	}

	b.WriteString("\nPredicted not_visible\n")
	if len(r.NotVisible) == 0 {
		b.WriteString("  nothing predicted\n")
	}
	for _, s := range r.NotVisible {
		fmt.Fprintf(&b, "  - %s\n", s)
	}

	fails, warns := r.Counts()
	result := "all checks pass"
	switch {
	case fails > 0:
		result = fmt.Sprintf("%d failed, %s", fails, plural(warns, "warning"))
	case warns > 0:
		result = plural(warns, "warning")
	}
	fmt.Fprintf(&b, "\nResult: %s\n", result)
	_, err := io.WriteString(w, b.String())
	return err
}

// repoCountLabel names where the estimate's repository counts came from.
func repoCountLabel(e *DoctorEstimate) string {
	var parts []string
	if e.ReposGraphQL > 0 {
		parts = append(parts, "enterprise GraphQL")
	}
	if e.ReposREST > 0 || (e.ReposGraphQL == 0 && e.ReposVisible == 0) {
		parts = append(parts, "GET /orgs/{org}")
	}
	if e.ReposVisible > 0 {
		parts = append(parts, "visible-to-token")
	}
	return strings.Join(parts, " and ") + " counts"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
