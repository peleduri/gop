package collect

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var protAliasRe = regexp.MustCompile(`(r\d+): repository\(owner: \$(o\d+), name: \$(n\d+)\) \{ \.\.\.gopProtection \}`)

// protectionQuery answers a batched repository { ...gopProtection } query
// from the same fixture data the REST protection endpoints serve: classic
// protection (its non-admin refUpdateRule view always, branchProtectionRule
// only in orgs the token owns), the branch's active rules, and ruleset
// bypass actors (only in owned orgs, unless hideBypass). forbidRule answers
// the alias's rules with a FORBIDDEN error; objectErrors fail the whole alias.
func (f *fakeGitHub) protectionQuery(w http.ResponseWriter, q string, vars map[string]any) {
	f.mu.Lock()
	limit := f.limitAbove
	f.protQueries++
	f.mu.Unlock()
	ms := protAliasRe.FindAllStringSubmatch(q, -1)
	if limit != 0 && len(ms) > limit {
		writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"type": "RESOURCE_LIMITS_EXCEEDED", "message": "query too expensive"}}})
		return
	}
	if f.protUnsupported {
		writeJSON(w, 200, map[string]any{"errors": []map[string]any{{"message": "Field 'rules' doesn't exist on type 'Ref'"}}})
		return
	}
	withRules := strings.Contains(q, "rules(first:")
	data := map[string]any{"rateLimit": map[string]any{"cost": 1, "remaining": 4900, "resetAt": "2030-01-01T14:05:00Z"}}
	var errs []map[string]any
	for _, m := range ms {
		alias := m[1]
		owner, _ := vars[m[2]].(string)
		repo, _ := vars[m[3]].(string)
		full := owner + "/" + repo
		f.mu.Lock()
		typ := f.objectErrors[full]
		forbid := f.forbidRule[full]
		f.mu.Unlock()
		if typ == "" && !f.knownRepo(owner, repo) {
			typ = "NOT_FOUND"
		}
		if typ != "" {
			data[alias] = nil
			errs = append(errs, map[string]any{"type": typ, "path": []string{alias}, "message": "refused"})
			continue
		}
		r, ruleErr := f.protRepo(owner, repo, withRules, forbid)
		data[alias] = r
		if ruleErr {
			errs = append(errs, map[string]any{"type": "FORBIDDEN", "path": []any{alias, "defaultBranchRef", "rules"},
				"message": "Resource not accessible by integration"})
		}
	}
	resp := map[string]any{"data": data}
	if errs != nil {
		resp["errors"] = errs
	}
	writeJSON(w, 200, resp)
}

func (f *fakeGitHub) defaultBranch(owner, repo string) string {
	for _, o := range f.fx.Orgs {
		if o.Login != owner {
			continue
		}
		for _, raw := range o.Repos {
			var m struct {
				Name          string `json:"name"`
				DefaultBranch string `json:"default_branch"`
			}
			_ = json.Unmarshal(raw, &m)
			if m.Name == repo {
				return m.DefaultBranch
			}
		}
	}
	return ""
}

// protRepo builds one repository's answer; ruleErr is true when rules were
// refused (forbid).
func (f *fakeGitHub) protRepo(owner, repo string, withRules, forbid bool) (map[string]any, bool) {
	owned := f.orgOwner(owner)
	perm := "WRITE"
	if owned {
		perm = "ADMIN"
	}
	out := map[string]any{"viewerPermission": perm}
	branch := f.defaultBranch(owner, repo)
	if branch == "" {
		out["defaultBranchRef"] = nil
		return out, false
	}
	full := owner + "/" + repo
	f.mu.Lock()
	defer f.mu.Unlock()
	ref := map[string]any{"name": branch, "refUpdateRule": nil, "branchProtectionRule": nil}
	if raw, ok := f.protection[full+"@"+branch]; ok {
		var cp apiFullProtection
		_ = json.Unmarshal(raw, &cp)
		var contexts []string
		if sc := cp.RequiredStatusChecks; sc != nil {
			contexts = append(contexts, sc.Contexts...)
		}
		count, codeOwner, dismiss, last := 0, false, false, false
		var allowances []any
		total := 0
		if r := cp.RequiredPullRequestReviews; r != nil {
			count, codeOwner, dismiss, last = r.RequiredApprovals, r.RequireCodeOwnerReviews, r.DismissStaleReviews, r.RequireLastPushApproval
			if a := r.BypassAllowances; a != nil {
				for range a.Users {
					allowances = append(allowances, map[string]any{"actor": map[string]any{"__typename": "User"}})
				}
				for range a.Teams {
					allowances = append(allowances, map[string]any{"actor": map[string]any{"__typename": "Team"}})
				}
				for range a.Apps {
					allowances = append(allowances, map[string]any{"actor": map[string]any{"__typename": "App"}})
				}
				total = len(allowances)
			}
		}
		force := cp.AllowForcePushes != nil && cp.AllowForcePushes.Enabled
		signed := cp.RequiredSignatures != nil && cp.RequiredSignatures.Enabled
		var countV any
		if cp.RequiredPullRequestReviews != nil {
			countV = count
		}
		ref["refUpdateRule"] = map[string]any{"requiredApprovingReviewCount": countV, "requiresCodeOwnerReviews": codeOwner,
			"allowsForcePushes": force, "requiresSignatures": signed, "requiredStatusCheckContexts": contexts}
		if owned {
			if allowances == nil {
				allowances = []any{}
			}
			ref["branchProtectionRule"] = map[string]any{
				"requiresApprovingReviews": cp.RequiredPullRequestReviews != nil, "requiredApprovingReviewCount": countV,
				"requiresCodeOwnerReviews": codeOwner, "dismissesStaleReviews": dismiss, "requireLastPushApproval": last,
				"isAdminEnforced": cp.EnforceAdmins != nil && cp.EnforceAdmins.Enabled, "allowsForcePushes": force,
				"requiresCommitSignatures": signed, "requiredStatusCheckContexts": contexts, "restrictsPushes": cp.Restrictions != nil,
				"bypassPullRequestAllowances": map[string]any{"totalCount": total, "nodes": allowances},
			}
		}
	}
	ruleErr := false
	if withRules {
		if forbid {
			ref["rules"] = nil
			ruleErr = true
		} else {
			nodes := []any{}
			for _, raw := range f.rules[full+"@"+branch] {
				var r struct {
					Type       string         `json:"type"`
					SourceType string         `json:"ruleset_source_type"`
					RulesetID  int64          `json:"ruleset_id"`
					Parameters map[string]any `json:"parameters"`
				}
				_ = json.Unmarshal(raw, &r)
				params := map[string]any{"__typename": "Other"}
				switch r.Type {
				case "pull_request":
					params = map[string]any{"__typename": "PullRequestParameters",
						"requiredApprovingReviewCount": r.Parameters["required_approving_review_count"],
						"requireCodeOwnerReview":       r.Parameters["require_code_owner_review"] == true,
						"dismissStaleReviewsOnPush":    r.Parameters["dismiss_stale_reviews_on_push"] == true,
						"requireLastPushApproval":      r.Parameters["require_last_push_approval"] == true}
				case "required_status_checks":
					var checks []any
					list, _ := r.Parameters["required_status_checks"].([]any)
					for _, c := range list {
						cm, _ := c.(map[string]any)
						checks = append(checks, map[string]any{"context": cm["context"]})
					}
					params = map[string]any{"__typename": "RequiredStatusChecksParameters", "requiredStatusChecks": checks}
				}
				src := r.SourceType
				if src == "" {
					src = "Repository"
				}
				nodes = append(nodes, map[string]any{"type": strings.ToUpper(r.Type), "parameters": params,
					"repositoryRuleset": map[string]any{"databaseId": r.RulesetID, "source": map[string]any{"__typename": src},
						"bypassActors": f.gqlBypassActors(full, r.RulesetID, owned)}})
			}
			ref["rules"] = map[string]any{"totalCount": len(nodes), "nodes": nodes}
		}
	}
	out["defaultBranchRef"] = ref
	return out, ruleErr
}

// gqlBypassActors maps a fixture ruleset's REST bypass_actors to GraphQL;
// nil when the token may not see them.
func (f *fakeGitHub) gqlBypassActors(full string, id int64, owned bool) any {
	raw, ok := f.rulesets[full+"#"+strconv.FormatInt(id, 10)]
	if !ok || f.hideBypass || !owned {
		return nil
	}
	var rs struct {
		BypassActors []struct {
			ActorID   int64  `json:"actor_id"`
			ActorType string `json:"actor_type"`
		} `json:"bypass_actors"`
	}
	_ = json.Unmarshal(raw, &rs)
	nodes := []any{}
	for _, a := range rs.BypassActors {
		n := map[string]any{"organizationAdmin": false, "enterpriseOwner": false, "repositoryRoleName": nil, "actor": nil}
		switch a.ActorType {
		case "OrganizationAdmin":
			n["organizationAdmin"] = true
		case "EnterpriseOwner":
			n["enterpriseOwner"] = true
		case "RepositoryRole":
			n["repositoryRoleName"] = builtinRoleIDs[a.ActorID]
		case "Integration":
			n["actor"] = map[string]any{"__typename": "App"}
		default:
			n["actor"] = map[string]any{"__typename": a.ActorType}
		}
		nodes = append(nodes, n)
	}
	return map[string]any{"totalCount": len(nodes), "nodes": nodes}
}
