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

// This file holds per-org collection for tokens that cannot read the
// enterprise (org-scoped App installation tokens, non-owner PATs, tokens
// without read:enterprise). Enterprise-level facts become not_visible with
// coverage, and the graph is built from the orgs the token can see.

const (
	srcConfigOrgs   = "config:--orgs"
	srcUserOrgs     = "rest:GET /user/orgs"
	srcInstallRepos = "rest:GET /installation/repositories"
	srcOrgREST      = "rest:GET /orgs/{org}"
	srcOrgMembers   = "rest:GET /orgs/{org}/members"
	srcOrgAdmins    = "rest:GET /orgs/{org}/members?role=admin"

	attrInEnterprise       = "in_enterprise"
	attrInEnterpriseSource = "in_enterprise_source"
	attrSource             = "source"

	// maxListedOwners bounds the owners named in the aggregated in_enterprise coverage entry.
	maxListedOwners = 20
)

// enterpriseFix is the access that closes every enterprise-level gap.
const enterpriseFix = "enterprise owner token with read:enterprise"

// apiOrg is the subset of GET /orgs/{org} that maps onto org attributes.
// Pointer fields are absent when the token may not read them (owner-only).
type apiOrg struct {
	Login                        string  `json:"login"`
	ArchivedAt                   *string `json:"archived_at"`
	DefaultRepositoryPermission  *string `json:"default_repository_permission"`
	MembersCanCreateRepositories *bool   `json:"members_can_create_repositories"`
	MembersCanCreatePublic       *bool   `json:"members_can_create_public_repositories"`
	MembersCanCreatePrivate      *bool   `json:"members_can_create_private_repositories"`
	MembersCanCreateInternal     *bool   `json:"members_can_create_internal_repositories"`
	TwoFactorRequirementEnabled  *bool   `json:"two_factor_requirement_enabled"`
	MembersCanForkPrivateRepos   *bool   `json:"members_can_fork_private_repositories"`
}

// collectOrgsWithoutEnterprise runs when enterprise(slug) came back null. It
// records the gap and discovers the orgs to collect: cfg.Orgs, else the
// token's own orgs (/user/orgs) or installation repositories' owners.
func (k *collector) collectOrgsWithoutEnterprise(ctx context.Context, gqlErrs GraphQLErrors) error {
	k.entHidden = true
	k.cover("enterprise:"+k.enterprise, "enterprise", "token cannot read enterprise "+k.enterprise, enterpriseFix)
	if len(gqlErrs) > 0 {
		k.logf("collect: enterprise %s: %v", k.enterprise, gqlErrs)
	}

	var logins []string
	src, inSrc := srcConfigOrgs, "config"
	if len(k.cfg.Orgs) > 0 {
		seen := map[string]bool{}
		for _, o := range k.cfg.Orgs {
			if !seen[strings.ToLower(o)] {
				seen[strings.ToLower(o)] = true
				logins = append(logins, o)
			}
		}
	} else {
		var err error
		logins, src, inSrc, err = k.discoverOrgs(ctx)
		if err != nil {
			return err
		}
	}
	if len(logins) == 0 {
		return fmt.Errorf("collect: token cannot read enterprise %q and no organizations were found for it; pass --orgs org1,org2", k.enterprise)
	}
	k.orgsSrc = src
	k.logf("collect: token cannot read enterprise %s; collecting %d orgs from %s", k.enterprise, len(logins), src)
	for _, login := range logins {
		n := k.node("org:"+login, graph.KindOrg, login)
		setAttr(n, attrInEnterpriseSource, inSrc, graph.Live)
		setAttr(n, attrSource, src, graph.Live)
		o := &orgState{login: login, node: n}
		var ao apiOrg
		if err := k.c.GetJSON(ctx, "/orgs/"+url.PathEscape(login), &ao); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			setAttr(n, graph.AttrArchived, "unknown", graph.NotVisible)
			k.cover(n.ID, "org", "could not read organization: "+err.Error(), "membership in "+login+", or check the org login")
		} else {
			o.rest = &ao
			o.archived = ao.ArchivedAt != nil && *ao.ArchivedAt != ""
			setAttr(n, graph.AttrArchived, strconv.FormatBool(o.archived), graph.Live)
		}
		k.orgs = append(k.orgs, o)
		k.byLower[strings.ToLower(login)] = o
		k.entOrgs[strings.ToLower(login)] = login
	}
	return nil
}

// discoverOrgs lists the orgs a token without enterprise access can see:
// /user/orgs for user tokens, else the distinct owners of /installation/repositories.
func (k *collector) discoverOrgs(ctx context.Context) (logins []string, src, inSrc string, err error) {
	userErr := k.c.GetPages(ctx, "/user/orgs?per_page=100", func(page []byte) error {
		var batch []struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(page, &batch); err != nil {
			return fmt.Errorf("decoding user orgs: %w", err)
		}
		for _, o := range batch {
			if o.Login != "" {
				logins = append(logins, o.Login)
			}
		}
		return nil
	})
	if userErr == nil && len(logins) > 0 {
		return logins, srcUserOrgs, "user_orgs", nil
	}
	if ctx.Err() != nil {
		return nil, "", "", ctx.Err()
	}
	logins = nil
	seen := map[string]bool{}
	instErr := k.c.GetPages(ctx, "/installation/repositories?per_page=100", func(page []byte) error {
		var body struct {
			Repositories []struct {
				Owner struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		if err := json.Unmarshal(page, &body); err != nil {
			return fmt.Errorf("decoding installation repositories: %w", err)
		}
		for _, r := range body.Repositories {
			l := r.Owner.Login
			if l != "" && !seen[strings.ToLower(l)] {
				seen[strings.ToLower(l)] = true
				logins = append(logins, l)
			}
		}
		return nil
	})
	if instErr == nil {
		sort.Strings(logins)
		return logins, srcInstallRepos, "installation", nil
	}
	if ctx.Err() != nil {
		return nil, "", "", ctx.Err()
	}
	if userErr == nil {
		return nil, srcUserOrgs, "user_orgs", nil // no orgs; caller asks for --orgs
	}
	return nil, "", "", fmt.Errorf("collect: token cannot read enterprise %q and org discovery failed (%v; %v); pass --orgs org1,org2",
		k.enterprise, userErr, instErr)
}

// collectSettingsPerOrg replaces the ownerInfo queries when the enterprise is
// not visible: every setting starts unknown with one enterprise-scope coverage
// entry per attribute, then GET /orgs/{org} fills in what the token may read.
func (k *collector) collectSettingsPerOrg() {
	for _, spec := range settingSpecs {
		k.cover("enterprise:"+k.enterprise, spec.attr,
			"token cannot read enterprise "+k.enterprise+": ownerInfo."+spec.field+" skipped; per-org values come from "+
				srcOrgREST+" where the token may read them",
			enterpriseFix)
		for _, o := range k.orgs {
			setAttr(o.node, spec.attr, "unknown", graph.NotVisible)
		}
	}
	for _, o := range k.orgs {
		if o.rest == nil {
			continue
		}
		for attr, val := range orgRESTSettings(o.rest) {
			setAttr(o.node, attr, val, graph.Live)
		}
	}
}

// orgRESTSettings maps the GET /orgs/{org} fields that are present onto org
// attributes. Absent fields are left out, so they stay not_visible.
func orgRESTSettings(a *apiOrg) map[string]string {
	out := map[string]string{}
	if a.DefaultRepositoryPermission != nil {
		switch p := strings.ToLower(*a.DefaultRepositoryPermission); p {
		case "none", "read", "write", "admin":
			out[graph.AttrDefaultPerm] = p
		}
	}
	if a.TwoFactorRequirementEnabled != nil {
		out[graph.AttrTwoFactor] = map[bool]string{true: "required", false: "not_required"}[*a.TwoFactorRequirementEnabled]
	}
	if a.MembersCanForkPrivateRepos != nil {
		out[graph.AttrPrivateForks] = strconv.FormatBool(*a.MembersCanForkPrivateRepos)
	}
	// members_create means members may create every repository type, as the
	// enterprise ownerInfo value ALL does.
	var kinds []*bool
	for _, b := range []*bool{a.MembersCanCreatePublic, a.MembersCanCreatePrivate, a.MembersCanCreateInternal} {
		if b != nil {
			kinds = append(kinds, b)
		}
	}
	switch {
	case len(kinds) > 0:
		all := true
		for _, b := range kinds {
			all = all && *b
		}
		out[graph.AttrMembersCreate] = strconv.FormatBool(all)
	case a.MembersCanCreateRepositories != nil:
		out[graph.AttrMembersCreate] = strconv.FormatBool(*a.MembersCanCreateRepositories)
	}
	return out
}

// collectOrgMembers is the members fallback when consumed licenses can't be
// read: org admins (owners) and members from the org members API.
func (k *collector) collectOrgMembers(ctx context.Context, o *orgState, mn *graph.Node) error {
	list := func(path string) ([]string, error) {
		var logins []string
		err := k.c.GetPages(ctx, path, func(page []byte) error {
			var batch []struct {
				Login string `json:"login"`
			}
			if err := json.Unmarshal(page, &batch); err != nil {
				return fmt.Errorf("decoding org members: %w", err)
			}
			for _, u := range batch {
				if u.Login != "" {
					logins = append(logins, u.Login)
				}
			}
			return nil
		})
		return logins, err
	}
	base := "/orgs/" + url.PathEscape(o.login) + "/members?"
	admins, aerr := list(base + "role=admin&per_page=100")
	if aerr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	members, merr := list(base + "per_page=100")
	if merr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if aerr != nil {
		setAttr(o.node, attrOwners, "unknown", graph.NotVisible)
		k.cover(o.node.ID, attrOwners, "could not list org owners: "+aerr.Error(), k.ownerFix(o))
	} else {
		// Owner MEMBER_OF edges go first: k.edge keeps the first edge per pair.
		for _, l := range admins {
			idn := k.identity(l)
			k.edge(idn.ID, o.node.ID, graph.MemberOf, graph.Live, srcOrgAdmins, map[string]string{attrRole: "owner"})
			o.owners = append(o.owners, idn.Name)
		}
		sort.Strings(o.owners)
		setAttr(o.node, attrOwners, strconv.Itoa(len(admins)), graph.Live)
	}
	if merr != nil {
		setAttr(o.node, graph.AttrMembers, "unknown", graph.NotVisible)
		setAttr(mn, graph.AttrMembers, "unknown", graph.NotVisible)
		k.cover(o.node.ID, graph.AttrMembers, "could not list org members: "+merr.Error(), "membership in "+o.login)
		return nil
	}
	for _, l := range members {
		idn := k.identity(l)
		k.edge(idn.ID, o.node.ID, graph.MemberOf, graph.Live, srcOrgMembers, map[string]string{attrRole: "member"})
	}
	m := strconv.Itoa(len(members))
	setAttr(o.node, graph.AttrMembers, m, graph.Live)
	setAttr(mn, graph.AttrMembers, m, graph.Live)
	return nil
}

// markUnknownOwner records an action owner whose enterprise membership can't be
// known: the token can't read the enterprise and the owner is not a collected org.
func (k *collector) markUnknownOwner(an *graph.Node, owner string) {
	setAttr(an, attrInEnterprise, "unknown", graph.NotVisible)
	if k.unknownOwners == nil {
		k.unknownOwners = map[string]string{}
	}
	if _, ok := k.unknownOwners[strings.ToLower(owner)]; !ok {
		k.unknownOwners[strings.ToLower(owner)] = owner
	}
}

// coverUnknownOwners adds one aggregated coverage entry for every action owner
// marked by markUnknownOwner, naming up to maxListedOwners of them.
func (k *collector) coverUnknownOwners() {
	if len(k.unknownOwners) == 0 {
		return
	}
	owners := make([]string, 0, len(k.unknownOwners))
	for _, o := range k.unknownOwners {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	listed := owners
	more := ""
	if len(listed) > maxListedOwners {
		listed = listed[:maxListedOwners]
		more = fmt.Sprintf(" (+%d more)", len(owners)-maxListedOwners)
	}
	k.cover("enterprise:"+k.enterprise, attrInEnterprise,
		fmt.Sprintf("token cannot read enterprise %s: %d action owners outside the collected orgs may be enterprise orgs: %s%s",
			k.enterprise, len(owners), strings.Join(listed, ", "), more),
		enterpriseFix+", or add the owner to --orgs")
}
