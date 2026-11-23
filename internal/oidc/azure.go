package oidc

import (
	"fmt"
	"strings"
)

// isAzureFIC recognizes a federated identity credential
// ("az ad app federated-credential list" element).
func isAzureFIC(m map[string]any) bool {
	_, hasIss := m["issuer"].(string)
	return hasIss && (m["subject"] != nil || m["claimsMatchingExpression"] != nil || m["audiences"] != nil)
}

// azureList reads {"value": [...]} (Microsoft Graph list output) or a wrapper
// {"appId": "...", "federatedCredentials": [...]} that names the application.
func (b *batch) azureList(ptr string, m map[string]any) error {
	key := "value"
	if isList(m["federatedCredentials"]) {
		key = "federatedCredentials"
	}
	app := str(m["appId"])
	if app == "" {
		app = b.opts.Target
	}
	for i, e := range m[key].([]any) {
		fm, ok := e.(map[string]any)
		if !ok || !isAzureFIC(fm) {
			return unknownf("%s[%d] is not a federated identity credential", key, i)
		}
		if err := b.azureFIC(fmt.Sprintf("%s/%s/%d", ptr, key, i), fm, app); err != nil {
			return err
		}
	}
	return nil
}

func (b *batch) azureFIC(ptr string, m map[string]any, app string) error {
	name := str(m["name"])
	issuer := str(m["issuer"])
	if !isGitHubIssuer(issuer) {
		b.warnf("%s: issuer %s is not GitHub Actions, skipped", ptr, issuer)
		return nil
	}
	t := Trust{Provider: Azure, Issuer: issuer, Audiences: strs(m["audiences"]), File: b.file, Pointer: ptr, TargetName: name}
	id := str(m["id"])
	switch {
	case app != "":
		t.Target = "app:" + app + "/fic:" + name
	case indexFold(id, "/federatedIdentityCredentials/") > 0:
		// User-assigned managed identity: the id names the identity.
		i := indexFold(id, "/federatedIdentityCredentials/")
		t.Target = "identity:" + id[:i] + "/fic:" + name
		t.TargetName = id[strings.LastIndex(id[:i], "/")+1:i] + "/" + name
	default:
		t.Target = unknownTarget(b.file, ptr) + "/fic:" + name
		t.Warnings = append(t.Warnings, "application (client) ID unknown: pass it as the target or wrap the list as {\"appId\": ..., \"federatedCredentials\": [...]}")
	}
	if s := str(m["subject"]); s != "" {
		t.addCond("sub", Pattern{Raw: s, Op: OpEquals})
	}
	var expr string
	switch x := m["claimsMatchingExpression"].(type) {
	case map[string]any:
		expr = str(x["value"])
	case string:
		expr = x
	}
	if strings.TrimSpace(expr) == "" {
		b.trusts = append(b.trusts, t)
		return nil
	}
	t.Pointer = ptr + "/claimsMatchingExpression"
	for _, conj := range parseExpr(expr, azureDialect, azureResolve) {
		c := t.clone()
		c.applyConj(conj)
		b.trusts = append(b.trusts, c)
	}
	return nil
}

// indexFold is a case-insensitive strings.Index for an ASCII needle that
// returns a byte offset into s.
func indexFold(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}
