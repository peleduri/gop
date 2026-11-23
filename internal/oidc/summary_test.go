package oidc

import (
	"fmt"
	"sort"
	"strings"
)

// summary renders a trust as one deterministic line for table tests.
func summary(t Trust) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", t.Provider, t.Target)
	if len(t.Audiences) > 0 {
		fmt.Fprintf(&b, " aud=%s", strings.Join(t.Audiences, ","))
	}
	pats := func(ps []Pattern) string {
		var s []string
		for _, p := range ps {
			s = append(s, p.Op+":"+p.Raw)
		}
		return "[" + strings.Join(s, " | ") + "]"
	}
	if len(t.Subjects) > 0 {
		fmt.Fprintf(&b, " sub=%s", pats(t.Subjects))
	}
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, pats(t.Claims[k]))
	}
	for _, w := range t.Warnings {
		fmt.Fprintf(&b, "\n  ! %s", w)
	}
	return b.String()
}
