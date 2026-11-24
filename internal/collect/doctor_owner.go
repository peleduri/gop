package collect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// This file holds the doctor's org ownership check. An org the token does
// not own (an enterprise owner is not an org owner) hides its IP allow list,
// private repositories, outside collaborators, secret teams and direct
// collaborators. Collect records each of these as an org coverage entry;
// doctor predicts the same entries so the gap is known before a long run.

// ownership reads the token user's role in every readable org, replaces the
// repository counts with the enterprise GraphQL ones for orgs the token owns
// (or whose role it cannot read), marks the counts of the other orgs as a
// lower bound, and predicts the coverage facts collect will record for orgs
// it does not own.
func (d *doctor) ownership(ctx context.Context, e *doctorEnterprise) error {
	r := d.r
	var notOwned []int
	for i := range r.Orgs {
		o := &r.Orgs[i]
		if o.Status != "ok" {
			continue
		}
		info, inEnt := e.orgs[strings.ToLower(o.Login)]
		role, err := d.orgRole(ctx, o.Login, info, inEnt)
		if err != nil {
			return err
		}
		o.Role = role
		if role != RoleMember && role != RoleNone {
			if inEnt && info.repos != nil {
				// Complete for an org owner: it sees every repository.
				n := *info.repos
				o.Repos, o.ReposSource = &n, ReposGraphQL
			}
			continue
		}
		// Not an org owner: the enterprise totalCount and GET /orgs/{org}
		// (public_repos; total_private_repos is returned to owners only)
		// both count only the repositories the token can see. Keep the
		// larger one, as a lower bound.
		if inEnt && info.repos != nil {
			o.gqlEmpty = *info.repos == 0
			if o.Repos == nil || *info.repos > *o.Repos {
				n := *info.repos
				o.Repos = &n
			}
		}
		if o.Repos != nil {
			o.ReposSource = ReposVisible
		}
		o.ReposLowerBound = true
		if inEnt && info.archived {
			continue // collect skips archived orgs
		}
		notOwned = append(notOwned, i)
	}
	if len(notOwned) == 0 {
		return nil
	}
	enforced := map[string]bool{}
	if r.Mode == ModeOwner {
		// Collect reads SSO enforcement from ownerInfo and names it in the
		// fix; an error leaves the fix without the SSO note, as in collect.
		logins, err := settingOrgs(ctx, d.c, d.cfg.Enterprise, "samlIdentityProviderSettingOrganizations", "ENFORCED")
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, l := range logins {
			enforced[strings.ToLower(l)] = true
		}
	}
	for _, i := range notOwned {
		d.predictNotOwned(&r.Orgs[i], enforced[strings.ToLower(r.Orgs[i].Login)], e.visible)
	}
	return nil
}

// orgRole returns the token user's role in org: from the enterprise query's
// viewerCanAdminister and viewerIsAMember when it returned them, else from
// GET /orgs/{org}/memberships/{user} (404: not a member). It returns "" when
// the role cannot be read, and an error only when ctx is done.
func (d *doctor) orgRole(ctx context.Context, org string, info entOrg, inEnt bool) (string, error) {
	if inEnt && info.admin != nil {
		switch {
		case *info.admin:
			return RoleOwner, nil
		case info.member != nil && *info.member:
			return RoleMember, nil
		}
		return RoleNone, nil
	}
	login := d.r.Token.Login
	if login == "" || d.r.Token.Kind == KindInstallation {
		return "", nil
	}
	var m struct {
		Role  string `json:"role"`
		State string `json:"state"`
	}
	_, err := d.c.GetJSONHeader(ctx, "/orgs/"+url.PathEscape(org)+"/memberships/"+url.PathEscape(login), &m)
	switch {
	case err == nil:
		switch {
		case m.State != "active":
			return RoleNone, nil // a pending invitation grants nothing yet
		case m.Role == "admin":
			return RoleOwner, nil
		}
		return RoleMember, nil
	case ctx.Err() != nil:
		return "", ctx.Err()
	case IsNotFound(err):
		return RoleNone, nil
	}
	return "", nil
}

// predictNotOwned records the coverage facts collect will record for an org
// the token does not own: the same scope, fact and fix strings collect uses.
func (d *doctor) predictNotOwned(o *DoctorOrg, ssoEnforced, entVisible bool) {
	r := d.r
	fix := orgOwnerFix(o.Login, ssoEnforced)
	scope := "org:" + o.Login
	add := func(fact, needsFix string) {
		r.Predicted = append(r.Predicted, PredictedCoverage{Scope: scope, Fact: fact, NeedsFix: needsFix})
	}
	var facts []string
	note := func(fact, needsFix string) {
		add(fact, needsFix)
		facts = append(facts, fact)
	}
	note("ip_allow_list", fix)
	note(attrRepositories, fix)
	// Without ownerInfo, the default permission comes from GET /orgs/{org},
	// which returns it to org owners only.
	if r.Mode != ModeOwner && (entVisible || !o.defaultPermVisible) {
		note("can_push:default_perm", "enterprise owner on "+d.cfg.Enterprise+", or "+fix)
	}
	note("outside_collaborators", fix)
	// Direct collaborators need push access on each repository; an org in
	// which the token sees no repository has none for collect to try.
	if !o.gqlEmpty || o.Repos == nil || *o.Repos > 0 {
		note("can_push:collaborators", fix+", or push access on each repository")
		// security_and_analysis is returned to repo admins, org owners and
		// security managers only.
		note(graph.FactSecretScanning, "admin on those repositories, or org owner or security manager in "+o.Login)
	}
	note("can_push:teams", fix)

	relation := "not a member"
	if o.Role == RoleMember {
		relation = "a member, not an owner"
	}
	// The token's view of the org's repositories is never its total: say
	// "at least N", or "unknown" when the token sees none.
	repos := "collect lists only the repositories the token can see"
	if o.Repos != nil && *o.Repos > 0 {
		repos += fmt.Sprintf(" (at least %d visible to this token; the real total needs org owner)", *o.Repos)
	} else {
		repos += " (repo count unknown: none visible to this token; the real total needs org owner)"
	}
	r.check("owner "+o.Login, StatusWarn,
		fmt.Sprintf("token is %s of %s: %d facts will be not_visible and %s", relation, o.Login, len(facts), repos), fix)
	r.notVisible("org " + o.Login + ": " + strings.Join(facts, ", ") + " (token is not an org owner)")
}
