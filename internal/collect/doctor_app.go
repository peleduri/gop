package collect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// This file holds gop doctor in GitHub App mode. It authenticates the way
// collect does (App JWT, then one read-only installation token per org),
// lists the installations, flags selected orgs without one, checks that the
// granted permissions are read-only and cover what collect requests, and
// predicts what App mode leaves not_visible. The key, the JWT and the
// installation tokens are never printed.

// appPermissionEffects says what goes not_visible without each permission
// collect requests by default.
var appPermissionEffects = map[string]string{
	"metadata":                    "repositories, direct collaborators, rulesets and branches",
	"contents":                    "workflow and action file contents (USES and EXECUTES_WITH edges)",
	"members":                     "org members, teams and outside collaborators (CAN_PUSH edges)",
	"administration":              "repository Actions access settings and branch protection",
	"actions":                     "Actions metadata",
	"organization_administration": "org Actions workflow permissions",
}

// doctorApp runs the preflight in GitHub App mode.
func doctorApp(ctx context.Context, cfg DoctorConfig) (*DoctorReport, error) {
	acfg := Config{Enterprise: cfg.Enterprise, Token: cfg.Token, AppID: cfg.AppID,
		AppPrivateKeyPEM: cfg.AppPrivateKeyPEM, AppPermissions: cfg.AppPermissions}
	if err := acfg.validateAuth(); err != nil {
		return nil, errors.New("doctor" + strings.TrimPrefix(err.Error(), "collect"))
	}
	base := cfg.Client
	if base == nil {
		var err error
		base, err = newClient(ClientOptions{BaseURL: cfg.BaseURL, GraphQLURL: cfg.GraphQLURL,
			MaxAttempts: 2, MaxWait: 30 * time.Second}, false)
		if err != nil {
			return nil, err
		}
	}
	a, err := newAppAuth(acfg, base)
	if err != nil {
		return nil, errors.New("doctor" + strings.TrimPrefix(err.Error(), "collect"))
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	r := &DoctorReport{Enterprise: cfg.Enterprise, Mode: ModeUnknown,
		Token:  DoctorToken{Kind: KindApp, Scopes: []string{}, AppID: cfg.AppID},
		Checks: []DoctorCheck{}, Orgs: []DoctorOrg{}, NotVisible: []string{}}
	d := &doctor{c: base, cfg: cfg, now: now().UTC(), r: r, installRepos: -1}
	if err := d.runApp(ctx, a); err != nil {
		return nil, err
	}
	return r, nil
}

func (d *doctor) runApp(ctx context.Context, a *appAuth) error {
	r := d.r
	if ok, err := d.appIdentify(ctx, a); err != nil || !ok {
		return err
	}
	r.Mode, r.ModeLabel = ModePerOrg, "(b) GitHub App, one read-only installation token per org"
	r.check("enterprise", StatusWarn,
		"GitHub App mode: installation tokens cover one org each, so enterprise APIs are not called and enterprise settings are not_visible",
		"use an "+enterpriseFix+" for enterprise settings")
	r.notVisible("enterprise settings (ownerInfo: SSO, 2FA, default permission, repo creation, visibility, deletion and fork policies); per-org values come from GET /orgs/{org} where readable, SSO stays not_visible")
	r.notVisible("the enterprise org list and membership (consumed licenses); orgs come from the App's installations and --orgs, members from each org's members API")
	r.notVisible("in_enterprise for action owners outside the installed orgs")

	selected := d.appSelected(a)
	r.OrgsTotal = len(selected)
	d.appPermissions(a, selected)

	readable, installed := 0, 0
	var rateClient *Client
	for i, login := range selected {
		if i >= DoctorMaxOrgs {
			r.check("orgs checked", StatusInfo, fmt.Sprintf("checked the first %d of %d organizations", DoctorMaxOrgs, len(selected)), "")
			break
		}
		in, ok := a.installation(login)
		if !ok {
			d.appNotInstalled(a, login)
			continue
		}
		installed++
		if ok, err := d.appMint(ctx, a, in); err != nil {
			return err
		} else if !ok {
			r.Orgs = append(r.Orgs, DoctorOrg{Login: in.login, Status: "token_refused"})
			continue
		}
		c, _ := a.client(in.login)
		o, err := d.probeOrg(ctx, c, in.login)
		if err != nil {
			return err
		}
		if o.Status == "ok" {
			readable++
			if rateClient == nil {
				rateClient = c
			}
		}
		r.Orgs = append(r.Orgs, o)
	}
	switch {
	case len(selected) == 0:
		r.check("orgs", StatusFail, "the App has no installations and --orgs is empty",
			"install the App with read-only permissions on each org to collect")
	case installed == 0:
		r.check("orgs", StatusFail, "the App is not installed on any selected organization",
			"install the App with read-only permissions on each org to collect")
	default:
		st := StatusPass
		if readable < len(selected) {
			st = StatusInfo // each gap already carries its own check
		}
		r.check("orgs", st, fmt.Sprintf("%d of %d organizations readable (from %s)", readable, len(selected), d.appOrgSource()), "")
	}
	if rateClient != nil {
		saved := d.c
		d.c = rateClient
		err := d.rateLimit(ctx)
		d.c = saved
		if err != nil {
			return err
		}
	}
	d.estimate()
	return nil
}

// appIdentify lists the App's installations with the App JWT. It returns
// false when the App cannot authenticate and nothing else can be checked.
func (d *doctor) appIdentify(ctx context.Context, a *appAuth) (bool, error) {
	r := d.r
	if err := a.listInstallations(ctx); err != nil {
		switch {
		case ctx.Err() != nil:
			return false, ctx.Err()
		case StatusOf(err) == http.StatusUnauthorized:
			r.check("app", StatusFail, "App JWT rejected (HTTP 401): wrong App ID, a key of another App, or a revoked key",
				"check --app-id and the private key file")
		default:
			r.check("app", StatusFail, "could not list the App's installations (GET /app/installations): "+statusText(err),
				"check --github-url, --app-id and the private key")
		}
		return false, nil
	}
	r.Token.Installations = a.logins()
	var suspended []string
	for _, in := range a.installs {
		if in.suspended {
			suspended = append(suspended, in.login)
		}
	}
	sort.Strings(suspended)
	detail := fmt.Sprintf("App %d authenticated; installed on %s", a.id, plural(len(r.Token.Installations), "organization"))
	if len(suspended) > 0 {
		detail += "; suspended on " + strings.Join(suspended, ", ")
	}
	r.check("app", StatusPass, detail, "")
	return true, nil
}

// appMint mints the installation's read-only token, as collect does on its
// first request to the org. It returns false, with a failed check, when
// GitHub refuses the token or grants it a non-read permission.
func (d *doctor) appMint(ctx context.Context, a *appAuth, in *appInstallation) (bool, error) {
	_, err := installSource{a: a, in: in}.Token(ctx)
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, ctx.Err()
	case StatusOf(err) != 0:
		d.r.check("token "+in.login, StatusFail, "could not mint a read-only installation token: "+statusText(err),
			"grant the App read access to every permission collect requests, and check the installation on "+in.login)
	default:
		// mint's own errors (a non-read grant, an empty response) name no secret.
		d.r.check("token "+in.login, StatusFail, err.Error(), "reduce the App's permissions to read only")
	}
	d.r.notVisible("org " + in.login + ": everything (no installation token)")
	return false, nil
}

// appSelected returns the orgs collect would read: --orgs, else every usable
// installation.
func (d *doctor) appSelected(a *appAuth) []string {
	if len(d.cfg.Orgs) > 0 {
		return dedupe(d.cfg.Orgs)
	}
	return a.logins()
}

func (d *doctor) appOrgSource() string {
	if len(d.cfg.Orgs) > 0 {
		return "--orgs"
	}
	return "App installations"
}

// appNotInstalled records a selected org without a usable installation.
func (d *doctor) appNotInstalled(a *appAuth, login string) {
	r := d.r
	o := DoctorOrg{Login: login, Status: "not_installed"}
	reason := "GitHub App not installed on " + login
	if in, ok := a.installs[strings.ToLower(login)]; ok && in.suspended {
		o.Status = "suspended"
		reason = "GitHub App installation on " + login + " is suspended"
	}
	r.Orgs = append(r.Orgs, o)
	r.check("installation "+login, StatusWarn, reason, "install the App on "+login+" with read-only permissions")
	r.notVisible("org " + login + ": everything (" + reason + ")")
}

// appPermissions checks each selected installation's granted permissions:
// every one must be read, and each permission collect requests must be granted.
func (d *doctor) appPermissions(a *appAuth, selected []string) {
	r := d.r
	want := make([]string, 0, len(a.perms))
	for p := range a.perms {
		want = append(want, p)
	}
	sort.Strings(want)
	clean := true
	for _, login := range selected {
		in, ok := a.installation(login)
		if !ok {
			continue
		}
		if in.perms == nil {
			clean = false
			r.check("permissions "+in.login, StatusInfo, "GET /app/installations did not list the granted permissions", "")
			continue
		}
		var write, missing []string
		for p, v := range in.perms {
			if v != "read" {
				write = append(write, p+":"+v)
			}
		}
		for _, p := range want {
			if in.perms[p] == "" {
				missing = append(missing, p)
			}
		}
		sort.Strings(write)
		if len(write) > 0 {
			clean = false
			r.check("permissions "+in.login, StatusWarn,
				"the App is granted "+strings.Join(write, ", ")+"; gop requests read-only tokens, but the key can mint tokens with these",
				"reduce the App's permissions to read only")
		}
		if len(missing) > 0 {
			clean = false
			names := make([]string, len(missing))
			for i, p := range missing {
				names[i] = p + ":read"
				eff := appPermissionEffects[p]
				if eff == "" {
					eff = p
				}
				r.notVisible("org " + in.login + ": " + eff + " (App lacks " + p + ":read)")
			}
			r.check("permissions "+in.login, StatusWarn,
				"the App is not granted "+strings.Join(names, ", ")+", which collect requests",
				"grant the App "+strings.Join(names, ", "))
		}
	}
	if clean {
		r.check("permissions", StatusPass, "granted permissions are read-only and cover "+strings.Join(want, ", "), "")
	}
}
