package oidc

import (
	"fmt"
	"strings"
)

// scopingClaims tie a token to a repository or its owner. A trust with none
// of them (and no sub) accepts tokens from any GitHub repository.
var scopingClaims = []string{"repository", "repository_owner", "repository_id", "repository_owner_id", "job_workflow_ref"}

// riskWarnings flags the dangerous patterns: no sub (or other repository
// scoping) condition, wildcard owner, and no audience check.
func riskWarnings(t Trust) []string {
	var w []string
	scoped := len(t.Subjects) > 0 || len(t.Claims[CELKey]) > 0
	for _, k := range scopingClaims {
		if len(t.Claims[k]) > 0 {
			scoped = true
		}
	}
	if !scoped {
		w = append(w, WarnNoSub)
	} else {
		// The owner is pinned if every pattern of at least one scoping claim
		// pins it (claims are ANDed). Otherwise report the loose patterns.
		pinned := false
		var loose []string
		check := func(key string, pats []Pattern, pins func(Pattern) pinState) {
			if len(pats) == 0 {
				return
			}
			all := true
			for _, p := range pats {
				switch pins(p) {
				case pinLoose:
					all = false
					loose = append(loose, fmt.Sprintf("%s %q", key, p.Raw))
				case pinUnknown:
					all = false
				}
			}
			if all {
				pinned = true
			}
		}
		check("sub", t.Subjects, subPins)
		check("repository", t.Claims["repository"], repoPins)
		check("job_workflow_ref", t.Claims["job_workflow_ref"], repoPins)
		check("repository_owner", t.Claims["repository_owner"], ownerPins)
		check("repository_id", t.Claims["repository_id"], idPins)
		check("repository_owner_id", t.Claims["repository_owner_id"], idPins)
		if !pinned {
			for _, l := range loose {
				w = append(w, "wildcard owner: "+l+" does not pin the repository owner; repositories of other GitHub users can match")
			}
		}
	}
	if len(t.Audiences) == 0 {
		w = append(w, WarnNoAud)
	}
	return w
}

type pinState int

const (
	pinYes pinState = iota
	pinLoose
	pinUnknown
)

func hasWild(s string) bool { return strings.ContainsAny(s, "*?") }

// ownerPart checks that s starts with a literal "OWNER/".
func ownerPart(s string, op string) pinState {
	switch op {
	case OpEquals:
		return pinYes
	case OpGlob:
		owner, _, ok := strings.Cut(s, "/")
		if hasWild(owner) || (!ok && hasWild(s)) {
			return pinLoose
		}
		return pinYes
	case OpLike:
		owner, _, ok := strings.Cut(s, "/")
		if !ok || owner == "" {
			return pinLoose // "acme" is also a prefix of "acme-evil"
		}
		return pinYes
	}
	return pinUnknown
}

// subPins: "repo:OWNER/..." must have a literal owner. Custom sub templates
// (include_claim_keys) are pinned unless they start with a wildcard.
func subPins(p Pattern) pinState {
	if p.Op == OpCEL {
		return pinUnknown
	}
	if rest, ok := strings.CutPrefix(p.Raw, "repo:"); ok {
		return ownerPart(rest, p.Op)
	}
	if p.Op == OpLike && p.Raw == "" || p.Op == OpGlob && strings.HasPrefix(p.Raw, "*") {
		return pinLoose
	}
	if p.Op == OpLike && strings.HasPrefix("repo:", p.Raw) {
		return pinLoose // a prefix of "repo:" itself, e.g. "repo"
	}
	return pinYes
}

func repoPins(p Pattern) pinState { return ownerPart(p.Raw, p.Op) }

func ownerPins(p Pattern) pinState {
	switch {
	case p.Op == OpEquals, p.Op == OpGlob && !hasWild(p.Raw):
		return pinYes
	case p.Op == OpCEL:
		return pinUnknown
	}
	return pinLoose
}

func idPins(p Pattern) pinState { return ownerPins(p) }
