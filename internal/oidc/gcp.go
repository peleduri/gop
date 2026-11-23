package oidc

import (
	"fmt"
	"path/filepath"
	"strings"
)

// gcpProvider is a workload identity pool provider
// ("gcloud iam workload-identity-pools providers describe --format=json").
type gcpProvider struct {
	file, ptr   string
	name        string
	displayName string
	issuer      string
	audiences   []string
	mapping     map[string]string
	condition   string
	hasCond     bool
	disabled    bool
}

// gcpBinding is one workload identity member granted impersonation of a
// service account in its IAM policy.
type gcpBinding struct {
	file, ptr string
	sa        string
	member    string
}

// impersonationRoles let a federated identity act as the service account.
var impersonationRoles = map[string]bool{
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.serviceAccountTokenCreator": true,
}

func isGCPProvider(m map[string]any) bool {
	if m["attributeMapping"] != nil || m["attributeCondition"] != nil || isMap(m["oidc"]) {
		return true
	}
	n := str(m["name"])
	return strings.Contains(n, "/workloadIdentityPools/") && strings.Contains(n, "/providers/")
}

func (b *batch) gcpProvider(ptr string, m map[string]any) error {
	oidc, _ := m["oidc"].(map[string]any)
	if oidc == nil {
		kind := "non-OIDC"
		for _, k := range []string{"aws", "saml", "x509"} {
			if m[k] != nil {
				kind = k
			}
		}
		b.warnf("%s: %s workload identity provider %s skipped", ptr, kind, str(m["name"]))
		return nil
	}
	p := gcpProvider{
		file: b.file, ptr: ptr,
		name:        str(m["name"]),
		displayName: str(m["displayName"]),
		issuer:      str(oidc["issuerUri"]),
		audiences:   strs(oidc["allowedAudiences"]),
		mapping:     map[string]string{},
		disabled:    m["disabled"] == true || str(m["state"]) == "DELETED",
	}
	if am, ok := m["attributeMapping"].(map[string]any); ok {
		for k, v := range am {
			p.mapping[k] = strings.TrimSpace(str(v))
		}
	}
	if c, ok := m["attributeCondition"].(string); ok && strings.TrimSpace(c) != "" {
		p.condition, p.hasCond = c, true
	}
	if !isGitHubIssuer(p.issuer) {
		b.warnf("%s: issuer %s is not GitHub Actions, skipped", ptr, p.issuer)
		return nil
	}
	b.providers = append(b.providers, p)
	return nil
}

// gcpPolicy reads a service account IAM policy
// ("gcloud iam service-accounts get-iam-policy --format=json"), optionally
// with a "serviceAccount" field naming the account.
func (b *batch) gcpPolicy(ptr string, m map[string]any) error {
	sa := str(m["serviceAccount"])
	if sa == "" {
		sa = b.opts.ServiceAccount
	}
	if stem := strings.TrimSuffix(filepath.Base(b.file), filepath.Ext(b.file)); sa == "" && strings.Contains(stem, "@") {
		sa = stem
	}
	for i, bv := range m["bindings"].([]any) {
		bm, ok := bv.(map[string]any)
		if !ok {
			return unknownf("bindings[%d] is not an object", i)
		}
		role := str(bm["role"])
		for j, member := range strs(bm["members"]) {
			if !strings.Contains(member, "/workloadIdentityPools/") {
				continue
			}
			mptr := fmt.Sprintf("%s/bindings/%d/members/%d", ptr, i, j)
			if !impersonationRoles[role] {
				b.warnf("%s: %s granted directly to %s; direct resource access is not modeled", mptr, role, member)
				continue
			}
			b.bindings = append(b.bindings, gcpBinding{file: b.file, ptr: mptr, sa: sa, member: member})
		}
	}
	return nil
}

// resolver maps condition paths to GitHub claim names through the
// provider's attribute mapping.
func (p *gcpProvider) resolver() func(string) (string, bool) {
	return func(path string) (string, bool) {
		if c, ok := assertionClaim(path); ok {
			return c, true
		}
		if v, ok := p.mapping[path]; ok {
			return assertionClaim(v)
		}
		return "", false
	}
}

// assertionClaim returns X for "assertion.X" when X is a plain identifier.
func assertionClaim(s string) (string, bool) {
	c, ok := strings.CutPrefix(s, "assertion.")
	if !ok || c == "" {
		return "", false
	}
	for _, r := range c {
		if !isIdentRune(r) {
			return "", false
		}
	}
	return c, true
}

func (p *gcpProvider) trusts() []Trust {
	target, name := p.name, p.displayName
	var warns []string
	if target == "" {
		target = unknownTarget(p.file, p.ptr)
		warns = append(warns, "provider name unknown")
	}
	if name == "" {
		name = target[strings.LastIndex(target, "/")+1:]
	}
	if p.disabled {
		warns = append(warns, "provider is disabled or deleted")
	}
	aud := p.audiences
	if len(aud) == 0 && p.name != "" {
		// GCP's default allowed audience is the provider's full resource name.
		aud = []string{"https://iam.googleapis.com/" + p.name}
	}
	base := Trust{Provider: GCP, Target: target, TargetName: name, Issuer: p.issuer, Audiences: aud,
		File: p.file, Pointer: p.ptr, Warnings: warns}
	if !p.hasCond {
		return []Trust{base}
	}
	base.Pointer = p.ptr + "/attributeCondition"
	var out []Trust
	for _, conj := range parseExpr(p.condition, celDialect, p.resolver()) {
		t := base.clone()
		t.applyConj(conj)
		out = append(out, t)
	}
	return out
}

// poolOf splits ".../projects/P/locations/L/workloadIdentityPools/POOL/..."
// into project and pool ID.
func poolOf(s string) (project, pool string, ok bool) {
	segs := strings.Split(s, "/")
	for i := 0; i+1 < len(segs); i++ {
		switch segs[i] {
		case "projects":
			if project == "" {
				project = segs[i+1]
			}
		case "workloadIdentityPools":
			return project, segs[i+1], segs[i+1] != ""
		}
	}
	return "", "", false
}

func numeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// samePool: IAM members name the project by number, exported providers may
// name it by ID; a number and an ID are assumed to be the same project.
func samePool(a, b string) bool {
	pa, la, ok1 := poolOf(a)
	pb, lb, ok2 := poolOf(b)
	if !ok1 || !ok2 || la != lb {
		return false
	}
	return pa == pb || numeric(pa) != numeric(pb)
}

// joinGCP builds the provider trusts, then one more trust per provider and
// impersonation binding: provider condition AND member condition.
func joinGCP(providers []gcpProvider, bindings []gcpBinding, warnings *[]string) []Trust {
	var out []Trust
	for i := range providers {
		out = append(out, providers[i].trusts()...)
	}
	for _, bd := range bindings {
		matched := false
		for i := range providers {
			p := &providers[i]
			if p.name == "" || !samePool(p.name, bd.member) {
				continue
			}
			matched = true
			for _, t := range p.trusts() {
				out = append(out, bindTrust(t, p, bd))
			}
		}
		if !matched {
			*warnings = append(*warnings, fmt.Sprintf("%s: %s: no workload identity provider for this pool among the parsed files", bd.file, bd.ptr))
		}
	}
	return out
}

func bindTrust(t Trust, p *gcpProvider, bd gcpBinding) Trust {
	sa := bd.sa
	if sa == "" {
		sa = "unknown"
		t.Warnings = append(t.Warnings, "service account unknown: add a serviceAccount field, name the file EMAIL.json, or pass the service account")
	}
	t.Target += "+serviceAccount:" + sa
	t.TargetName = sa
	t.ServiceAccount = sa
	t.File, t.Pointer = bd.file, bd.ptr
	_, rest, _ := strings.Cut(bd.member, "/workloadIdentityPools/")
	_, rest, _ = strings.Cut(rest, "/") // drop POOL
	attr := func(mappingKey, value, raw string) {
		if c, ok := assertionClaim(p.mapping[mappingKey]); ok {
			if (c == "sub" && len(t.Subjects) > 0) || (c != "sub" && len(t.Claims[c]) > 0) {
				t.Warnings = append(t.Warnings, fmt.Sprintf("provider condition and IAM member both constrain %s and must both hold; treated as any one of them", c))
			}
			t.addCond(c, Pattern{Raw: value, Op: OpEquals})
			return
		}
		t.addCond(CELKey, Pattern{Raw: raw, Op: OpCEL})
		t.Warnings = append(t.Warnings, "condition not fully understood, treated as possible: "+raw)
	}
	switch {
	case rest == "*":
	case strings.HasPrefix(rest, "attribute."):
		name, value, _ := strings.Cut(strings.TrimPrefix(rest, "attribute."), "/")
		attr("attribute."+name, value, fmt.Sprintf("attribute.%s == %q", name, value))
	case strings.HasPrefix(rest, "subject/"):
		value := strings.TrimPrefix(rest, "subject/")
		attr("google.subject", value, fmt.Sprintf("google.subject == %q", value))
	default:
		t.addCond(CELKey, Pattern{Raw: bd.member, Op: OpCEL})
		t.Warnings = append(t.Warnings, "condition not fully understood, treated as possible: "+bd.member)
	}
	return t
}

func isIdentRune(r rune) bool {
	return r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}
