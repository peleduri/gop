package advisory

import (
	"regexp"
	"sort"
	"strings"
)

// Status is the outcome of matching one ref against one advisory.
type Status string

const (
	// StatusAffected: the ref is a version or commit the advisory names.
	StatusAffected Status = "affected"
	// StatusNotAffected: the advisory's data places the ref outside every
	// affected span.
	StatusNotAffected Status = "not_affected"
	// StatusUnknown: gop cannot place the ref (a branch, a SHA the advisory does
	// not list, a partial tag that only some affected versions share). It is
	// never read as safe.
	StatusUnknown Status = "unknown"
)

// Severities, as gop writes them in advisory_severity (lowest first).
const (
	SeverityUnknown  = "unknown"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank orders severities: unknown 0 ... critical 4.
func SeverityRank(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

func severityOf(r *Record) string {
	switch strings.ToUpper(r.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MODERATE", "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	}
	return SeverityUnknown
}

// Match is the result for one action ref across all advisories of its
// package.
type Match struct {
	// Affected lists the IDs of the advisories that affect the ref, sorted.
	Affected []string
	// Unknown lists the IDs that gop could not decide for the ref, sorted.
	Unknown []string
	// Severity is the highest severity among Affected ("" when none).
	Severity string
	// Fixed is the version to move to: the highest first-fixed version over
	// Affected. Empty when an affecting advisory lists no fix.
	Fixed string
	// Why says why Unknown is not empty, for the coverage entry.
	Why string
}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// Match checks an action ref (owner/repo[/path]@ref) against the advisories
// of its package.
func (db *DB) Match(owner, repo, path, ref string) Match {
	var m Match
	noFix := false
	var fixes []version
	var fixRaw []string
	for _, r := range db.lookup(owner, repo, path) {
		st, fixed, why := matchRecord(r, owner, repo, path, ref)
		switch st {
		case StatusAffected:
			m.Affected = append(m.Affected, r.ID)
			if s := severityOf(r); m.Severity == "" || SeverityRank(s) > SeverityRank(m.Severity) {
				m.Severity = s
			}
			if fixed == "" {
				noFix = true
			} else if v, ok := parseVersion(fixed); ok {
				fixes, fixRaw = append(fixes, v), append(fixRaw, fixed)
			}
		case StatusUnknown:
			m.Unknown = append(m.Unknown, r.ID)
			if m.Why == "" {
				m.Why = why
			}
		}
	}
	if !noFix && len(fixes) > 0 {
		best := 0
		for i := range fixes {
			if fixes[i].cmp(fixes[best]) > 0 {
				best = i
			}
		}
		m.Fixed = fixRaw[best]
	}
	sort.Strings(m.Affected)
	sort.Strings(m.Unknown)
	return m
}

// samePackage reports whether an affected entry names this action.
func samePackage(a Affected, owner, repo, path string) bool {
	if a.Package.Ecosystem != Ecosystem {
		return false
	}
	name := strings.ToLower(a.Package.Name)
	base := strings.ToLower(owner + "/" + repo)
	if path != "" && name == base+"/"+strings.ToLower(strings.Trim(path, "/")) {
		return true
	}
	return name == base
}

// matchRecord decides one advisory for one ref. fixed is the first fixed
// version of the span the ref is in (for an affected ref).
func matchRecord(r *Record, owner, repo, path, ref string) (st Status, fixed, why string) {
	st = StatusNotAffected
	for _, a := range r.Affected {
		if !samePackage(a, owner, repo, path) {
			continue
		}
		s, f, w := matchAffected(a, ref)
		switch {
		case s == StatusAffected:
			return StatusAffected, f, ""
		case s == StatusUnknown && st != StatusUnknown:
			st, why = StatusUnknown, w
		}
	}
	return st, "", why
}

func matchAffected(a Affected, ref string) (Status, string, string) {
	if shaRe.MatchString(ref) {
		return matchSHA(a, strings.ToLower(ref))
	}
	for _, v := range a.Versions {
		if strings.EqualFold(v, ref) || strings.EqualFold("v"+v, ref) || strings.EqualFold(v, "v"+ref) {
			return StatusAffected, lastFixed(a), ""
		}
	}
	v, ok := parseVersion(ref)
	if !ok {
		return StatusUnknown, "", "ref " + ref + " is not a version (a branch or an abbreviated SHA): gop cannot tell which commit it points at"
	}
	evaluated := false
	for _, rg := range a.Ranges {
		if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
			continue
		}
		ivs, good := intervals(rg.Events)
		if !good {
			return StatusUnknown, "", "the advisory's version range does not parse"
		}
		evaluated = true
		if hi, partial := v.next(); partial {
			for _, iv := range ivs {
				if iv.covers(v, hi) {
					return StatusAffected, iv.fixed, ""
				}
				if !iv.misses(v, hi) {
					return StatusUnknown, "", "tag " + ref + " moves across versions and only some of them are affected"
				}
			}
			continue
		}
		for _, iv := range ivs {
			if iv.contains(v) {
				return StatusAffected, iv.fixed, ""
			}
		}
	}
	if !evaluated && len(a.Versions) == 0 {
		return StatusUnknown, "", "the advisory lists no version range for tags"
	}
	return StatusNotAffected, "", ""
}

// matchSHA places a full commit SHA: listed in versions or as an introduced
// or last_affected commit is affected, a fixed or limit commit is not, and
// anything else is unknown (gop does not walk git history).
func matchSHA(a Affected, sha string) (Status, string, string) {
	for _, v := range a.Versions {
		if strings.EqualFold(v, sha) {
			return StatusAffected, lastFixed(a), ""
		}
	}
	for _, rg := range a.Ranges {
		if rg.Type != "GIT" {
			continue
		}
		for _, e := range rg.Events {
			switch {
			case strings.EqualFold(e.Introduced, sha), strings.EqualFold(e.LastAffected, sha):
				return StatusAffected, lastFixed(a), ""
			case strings.EqualFold(e.Fixed, sha), strings.EqualFold(e.Limit, sha):
				return StatusNotAffected, "", ""
			}
		}
	}
	return StatusUnknown, "", "commit " + sha[:12] + " is not listed in the advisory: gop does not walk git history to place it"
}

// lastFixed is the highest fixed version in an entry's version ranges: for
// a ref matched without a version (a listed tag or commit) moving to it
// leaves every affected span.
func lastFixed(a Affected) string {
	var best version
	raw := ""
	for _, rg := range a.Ranges {
		if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
			continue
		}
		for _, e := range rg.Events {
			if e.Fixed == "" {
				continue
			}
			if v, ok := parseVersion(e.Fixed); ok && (raw == "" || v.cmp(best) > 0) {
				best, raw = v, e.Fixed
			}
		}
	}
	return raw
}
