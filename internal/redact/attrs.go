package redact

import (
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

type attrCtx struct {
	node *graph.Node // the node the attrs belong to, or nil
	edge *graph.Edge // the edge the attrs belong to, or nil
}

// policy rewrites one attr value. ok false drops it. vocab true says the
// value is gop's own vocabulary (an enum value, a number), which the
// self-check does not treat as a name.
type policy func(r *redactor, c attrCtx, v string) (out string, vocab, ok bool)

// DefaultAttrs are the attr keys kept by default: the keys gop defines in
// internal/graph/types.go and documents in the JSON Schema, plus secret
// names, runner labels and source_api, which the redaction renames or keeps
// as gop's vocabulary. Every other key is dropped unless --keep-attr names it.
var DefaultAttrs = map[string]bool{}

func init() {
	for _, k := range []string{
		// types.go
		graph.AttrSSO, graph.AttrTwoFactor, graph.AttrDefaultPerm, graph.AttrMembersCreate, graph.AttrChangeVisiblity,
		graph.AttrDeleteRepos, graph.AttrPrivateForks, graph.AttrIPAllowList, graph.AttrIPAllowEntries, graph.AttrMembers,
		graph.AttrArchived, graph.AttrRefKind, graph.AttrVisibility, graph.AttrDemo,
		graph.AttrFile, graph.AttrFileRef, graph.AttrLine, graph.AttrCol,
		graph.AttrJobs, graph.AttrEnvironments, graph.AttrJobWorkflowRef, graph.AttrRepository, graph.AttrRepositoryOwner,
		graph.AttrMatchedSub, graph.AttrClaims, graph.AttrPointer, graph.AttrProvider, graph.AttrOIDC, graph.AttrReason,
		graph.AttrTrust, graph.AttrAccount, graph.AttrRole, graph.AttrWarnings,
		graph.AttrVia, graph.AttrRule, graph.AttrRefProtected, graph.AttrRefProtection, graph.AttrBypass, graph.AttrRef,
		graph.AttrRefKindSource, graph.AttrRefAmbiguous, graph.AttrRefImmutable, graph.AttrRefImmutableBy,
		graph.AttrActionsAccess, graph.AttrConsumerOrg,
		graph.AttrActionsLock, graph.AttrLockedSHA, graph.AttrLockEntry, graph.AttrLockMissing,
		graph.AttrSource, graph.AttrObservedUse, graph.AttrTimesUsed, graph.AttrLastUsed,
		graph.AttrPoutineRules, graph.AttrPoutineSeverity, graph.AttrPoutineJobs, graph.AttrPoutineFile,
		graph.AttrAdvisories, graph.AttrAdvisorySeverity, graph.AttrAdvisoryFixed, graph.AttrLockAdvisories,
		// documented in the JSON Schema
		"token_write", "token_scopes", "risky_triggers", "trigger", "exec",
		// named by the redaction itself
		"secrets", "labels", "source_api",
	} {
		DefaultAttrs[k] = true
	}
}

var (
	// advisoryIDRe finds advisory IDs (GHSA-..., CVE-..., PYSEC-...) in coverage text.
	advisoryIDRe = regexp.MustCompile(`\b[A-Z][A-Z0-9]+-[A-Za-z0-9]+(-[A-Za-z0-9]+)+\b`)
	versionRe    = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}$`)
	wordRe       = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	intRe        = regexp.MustCompile(`^[0-9]+$`)
)

func enum(values ...string) policy {
	set := map[string]bool{}
	for _, v := range values {
		set[v] = true
	}
	return func(_ *redactor, _ attrCtx, v string) (string, bool, bool) { return v, true, set[v] }
}

var boolish = enum("true", "false", "unknown")

// words keeps a comma list of lower-case vocabulary words (rule names,
// trigger names, scopes, warning codes).
func words(_ *redactor, _ attrCtx, v string) (string, bool, bool) {
	for _, w := range strings.Split(v, ",") {
		if !wordRe.MatchString(w) {
			return "", false, false
		}
	}
	return v, true, true
}

func integer(_ *redactor, _ attrCtx, v string) (string, bool, bool) {
	return v, true, intRe.MatchString(v)
}

// bucket rounds a count down to 0, 1, 2, 5, 10, 20, 50, ...
func bucket(_ *redactor, _ attrCtx, v string) (string, bool, bool) {
	if v == "unknown" {
		return v, true, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return "", false, false
	}
	if n == 0 {
		return "0", true, true
	}
	best := int64(1)
	for p := int64(1); ; p *= 10 {
		for _, m := range []int64{1, 2, 5} {
			if p*m <= n {
				best = p * m
			}
		}
		if p > n/10 {
			break
		}
	}
	return strconv.FormatInt(best, 10), true, true
}

// list applies f to each item of a comma list.
func list(f func(r *redactor, s string) string) policy {
	return func(r *redactor, _ attrCtx, v string) (string, bool, bool) {
		items := strings.Split(v, ",")
		for i, s := range items {
			items[i] = f(r, strings.TrimSpace(s))
		}
		return strings.Join(items, ","), false, true
	}
}

// advisoryID maps an advisory ID to a stable ADV-<hex> name: a real ID
// names the public action it is about, which the redaction renames.
func advisoryID(r *redactor, s string) string {
	return "ADV-" + hex.EncodeToString(r.mac("advisory\x00" + s))[:12]
}

// versionAttr keeps a dotted version number (advisory_fixed), gop's
// vocabulary, and drops anything else.
func versionAttr(_ *redactor, _ attrCtx, v string) (string, bool, bool) {
	return v, true, versionRe.MatchString(v)
}

func text(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.text(v), false, true }

func ownerAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.owner(v), false, true }

func idAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.id(v), false, true }

func refAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.ref(v), false, true }

// lockedSHAAttr maps a locked commit like any SHA ref (so it matches the
// redacted action IDs); a SHA-256 commit becomes another 64-hex string.
func lockedSHAAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	if len(v) == 64 && hexRe.MatchString(v) {
		return hex.EncodeToString(r.mac("sha\x00" + v)), false, true
	}
	return r.ref(v), false, true
}

func supplied(c attrCtx) bool {
	return c.edge != nil && (c.edge.Evidence == graph.Supplied || c.edge.Kind == graph.CanAssume ||
		strings.HasPrefix(c.edge.SourceAPI, graph.SourceSupplied))
}

// fileAttr: a supplied trust file on CAN_ASSUME edges, else a path in a repo.
func fileAttr(r *redactor, c attrCtx, v string) (string, bool, bool) {
	if supplied(c) {
		return r.file(v), false, true
	}
	return r.path(v), false, true
}

// jobWorkflowRef maps owner/repo/path@ref items.
func jobWorkflowRef(r *redactor, s string) string { return r.action(s) }

func environment(r *redactor, s string) string {
	if s == graph.EnvDynamic {
		return s
	}
	return r.environment(s)
}

func secretName(r *redactor, s string) string {
	if strings.EqualFold(s, "GITHUB_TOKEN") {
		return s
	}
	return r.secret(s)
}

func bypassAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	if v == "none" || v == "unknown" {
		return v, true, true
	}
	return list(func(r *redactor, s string) string { return r.id(s) })(r, attrCtx{}, v)
}

// roleAttr: a cloud role name on cloud_target nodes, an org role elsewhere.
func roleAttr(r *redactor, c attrCtx, v string) (string, bool, bool) {
	if c.node != nil && (c.node.Kind == graph.KindCloudTarget || strings.HasPrefix(c.node.ID, "cloud:")) {
		return r.name(r.roles, CatCloud, v, true), false, true
	}
	return words(r, c, v)
}

func accountAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	return r.name(r.accounts, CatCloud, v, true), false, true
}

// repoAttr is the "repo" attr of an action_ref node; its owner is in "owner".
func repoAttr(r *redactor, c attrCtx, v string) (string, bool, bool) {
	if c.node == nil || c.node.Attrs["owner"] == "" {
		return r.text(v), false, true
	}
	return r.repo(c.node.Attrs["owner"], v), false, true
}

func repositoryAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	return r.repoPath(v), false, true
}

func pathAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.path(v), false, true }

func sourceAPIAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	out := r.sourceAPI(v)
	return out, out == v, true
}

// timeLayouts are the timestamp forms timeAttr understands.
var timeLayouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"}

// timeAttr shifts a timestamp by the redaction's offset, keeping its layout
// (unix seconds or milliseconds stay numbers). An unparsed value is dropped.
func timeAttr(r *redactor, _ attrCtx, v string) (string, bool, bool) {
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, v); err == nil {
			return t.Add(r.offset).Format(l), true, true
		}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
		unit := int64(time.Second)
		if n > 1e12 {
			unit = int64(time.Millisecond)
		}
		return strconv.FormatInt(n+int64(r.offset)/unit, 10), true, true
	}
	return "", false, false
}

var policies = map[string]policy{
	graph.AttrSSO:             enum("enforced", "configured", "none", "unknown"),
	graph.AttrTwoFactor:       enum("required", "not_required", "unknown"),
	graph.AttrDefaultPerm:     enum("none", "read", "write", "admin", "unknown"),
	graph.AttrMembersCreate:   boolish,
	graph.AttrChangeVisiblity: boolish,
	graph.AttrDeleteRepos:     boolish,
	graph.AttrPrivateForks:    boolish,
	graph.AttrIPAllowList:     enum("on", "off", "unknown"),
	graph.AttrIPAllowEntries:  bucket,
	graph.AttrMembers:         bucket,
	graph.AttrArchived:        boolish,
	graph.AttrRefKind:         enum("sha", "tag", "branch"),
	graph.AttrVisibility:      enum("public", "private", "internal"),
	graph.AttrDemo:            boolish,
	graph.AttrFile:            fileAttr,
	graph.AttrFileRef:         refAttr,
	graph.AttrLine:            integer,
	graph.AttrCol:             integer,
	graph.AttrJobs:            list(func(r *redactor, s string) string { return r.job(s) }),
	graph.AttrEnvironments:    list(environment),
	graph.AttrJobWorkflowRef:  list(jobWorkflowRef),
	graph.AttrRepository:      repositoryAttr,
	graph.AttrRepositoryOwner: ownerAttr,
	graph.AttrMatchedSub:      text,
	graph.AttrClaims:          words,
	graph.AttrPointer:         text,
	graph.AttrProvider:        enum("aws", "gcp", "azure"),
	graph.AttrOIDC:            idAttr,
	graph.AttrReason:          text,
	graph.AttrTrust:           func(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.cloud(v), false, true },
	graph.AttrAccount:         accountAttr,
	graph.AttrRole:            roleAttr,
	graph.AttrWarnings:        words,
	graph.AttrVia: enum(graph.ViaDefaultPerm, graph.ViaOrgOwner, graph.ViaDirect, graph.ViaOutsideCollaborator,
		graph.ViaTeam, graph.ViaRefBypass, graph.ViaTokenWrite, graph.ViaUnknown),
	graph.AttrRule:            words,
	graph.AttrRefProtected:    boolish,
	graph.AttrRefProtection:   words,
	graph.AttrBypass:          bypassAttr,
	graph.AttrRef:             refAttr,
	graph.AttrRefKindSource:   enum(graph.RefKindSourceAPI, graph.RefKindSourceName),
	graph.AttrRefAmbiguous:    boolish,
	graph.AttrRefImmutable:    boolish,
	graph.AttrRefImmutableBy:  enum(graph.RefImmutableRelease, graph.RefImmutableRuleset),
	graph.AttrActionsAccess:   enum("none", "user", "organization", "enterprise", "public", "unknown"),
	graph.AttrConsumerOrg:     ownerAttr,
	graph.AttrActionsLock:     enum("true", "unknown", graph.LockLocked, graph.LockStale),
	graph.AttrLockedSHA:       lockedSHAAttr,
	graph.AttrLockEntry:       list(func(r *redactor, s string) string { return r.action(s) }),
	graph.AttrLockMissing:     list(func(r *redactor, s string) string { return r.action(s) }),
	graph.AttrSource:          sourceAPIAttr,
	graph.AttrObservedUse:     enum("true"),
	graph.AttrTimesUsed:       bucket,
	graph.AttrLastUsed:        timeAttr,
	graph.AttrPoutineRules:    words,
	graph.AttrPoutineSeverity: enum("error", "warning", "note"),
	graph.AttrPoutineJobs:     list(func(r *redactor, s string) string { return r.job(s) }),
	graph.AttrPoutineFile:     func(r *redactor, _ attrCtx, v string) (string, bool, bool) { return r.file(v), false, true },
	"token_write":             boolish,
	"token_scopes":            words,
	"risky_triggers":          words,
	"trigger":                 words,
	"exec":                    enum("checkout", "injection"),
	"secrets":                 list(secretName),
	"labels":                  list(func(r *redactor, s string) string { return r.label(s) }),
	"source_api":              sourceAPIAttr,

	// Collector attrs kept only with --keep-attr.
	"owner":             ownerAttr,
	"repo":              repoAttr,
	"path":              pathAttr,
	"job":               list(func(r *redactor, s string) string { return r.job(s) }),
	"permission":        enum("read", "triage", "write", "maintain", "admin", "bypass", "unknown", "contents: write", "id-token: write"),
	"level":             words,
	"classification":    words,
	"base_role":         words,
	"privacy":           words,
	"bypass_mode":       words,
	"nested":            words,
	"inherit":           boolish,
	"reusable_workflow": boolish,
	"in_enterprise":     boolish,
	"teams_partial":     boolish,
	"org":               ownerAttr,
}

// Advisory attrs (docs/advisories.md), registered apart from the table above.
func init() {
	policies[graph.AttrAdvisories] = list(advisoryID)
	policies[graph.AttrAdvisorySeverity] = enum("critical", "high", "medium", "low", "unknown")
	policies[graph.AttrAdvisoryFixed] = versionAttr
	policies[graph.AttrLockAdvisories] = list(advisoryID)
}

// attrs rewrites an attr map. Keys outside the kept set are dropped; a kept
// key without a policy is rewritten as free text.
func (r *redactor) attrs(in map[string]string, c attrCtx) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out map[string]string
	for _, k := range keys {
		v := in[k]
		if !r.keep[k] {
			r.drop(k)
			continue
		}
		p := policies[k]
		if p == nil {
			p = text
		}
		nv, vocab, ok := p(r, c, v)
		if !ok {
			r.drop(k)
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = nv
		if vocab && r.mode == final {
			r.vocab[strings.ToLower(nv)] = true
		}
	}
	return out
}

func (r *redactor) drop(k string) {
	if r.mode == final {
		r.dropped[k]++
	}
}
