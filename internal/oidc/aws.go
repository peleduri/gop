package oidc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// awsRole reads a role object: "aws iam get-role" Role, an element of
// "aws iam list-roles" Roles, or "get-role --query Role".
func (b *batch) awsRole(ptr string, role map[string]any) error {
	arn := str(role["Arn"])
	if arn == "" {
		arn = b.opts.Target
	}
	return b.awsPolicy(ptr+"/AssumeRolePolicyDocument", role["AssumeRolePolicyDocument"], arn, str(role["RoleName"]))
}

// awsPolicy reads a trust policy document. The raw IAM API returns it
// URL-encoded; the CLI returns it decoded.
func (b *batch) awsPolicy(ptr string, doc any, arn, roleName string) error {
	if s, ok := doc.(string); ok {
		dec, err := url.QueryUnescape(s)
		if err != nil {
			return unknownf("AssumeRolePolicyDocument is a string but not URL-encoded JSON")
		}
		var v any
		if err := json.Unmarshal([]byte(dec), &v); err != nil {
			return unknownf("AssumeRolePolicyDocument is a string but not JSON")
		}
		doc = v
	}
	m, ok := doc.(map[string]any)
	if !ok || m["Statement"] == nil {
		return unknownf("AWS trust policy has no Statement")
	}
	var stmts []any
	var ptrs []string
	switch s := m["Statement"].(type) {
	case []any:
		for i, e := range s {
			stmts = append(stmts, e)
			ptrs = append(ptrs, fmt.Sprintf("%s/Statement/%d", ptr, i))
		}
	case map[string]any:
		stmts, ptrs = []any{s}, []string{ptr + "/Statement"}
	default:
		return unknownf("AWS trust policy Statement is not an object or a list")
	}

	target, name := arn, roleName
	var targetWarn string
	if target == "" {
		target = unknownTarget(b.file, ptr)
		targetWarn = "role ARN unknown: supply the aws iam get-role output or a target override"
	}
	if name == "" && arn != "" {
		name = arn[strings.LastIndex(arn, "/")+1:]
	}
	for i, sv := range stmts {
		st, ok := sv.(map[string]any)
		if !ok {
			return unknownf("statement %d is not an object", i)
		}
		if !allowsWebIdentity(st) {
			continue
		}
		if str(st["Effect"]) != "Allow" {
			b.warnf("%s: Deny statement for sts:AssumeRoleWithWebIdentity ignored; the real trust may be narrower", ptrs[i])
			continue
		}
		fed := strs(principalField(st["Principal"], "Federated"))
		for _, f := range fed {
			issuer, ok := awsIssuer(f)
			if !ok {
				b.warnf("%s: federated principal %q is not an OIDC provider, skipped", ptrs[i], f)
				continue
			}
			if !isGitHubIssuer(issuer) {
				b.warnf("%s: issuer %s is not GitHub Actions, skipped", ptrs[i], issuer)
				continue
			}
			t := Trust{Provider: AWS, Target: target, TargetName: name, Issuer: issuer, File: b.file, Pointer: ptrs[i]}
			if targetWarn != "" {
				t.Warnings = append(t.Warnings, targetWarn)
			}
			awsConditions(&t, st["Condition"], strings.TrimPrefix(issuer, "https://"))
			b.trusts = append(b.trusts, t)
		}
	}
	return nil
}

func principalField(p any, key string) any {
	m, ok := p.(map[string]any)
	if !ok {
		return nil
	}
	return m[key]
}

// allowsWebIdentity reports whether the statement's Action covers
// sts:AssumeRoleWithWebIdentity.
func allowsWebIdentity(st map[string]any) bool {
	for _, a := range strs(st["Action"]) {
		if globMatch(strings.ToLower(a), "sts:assumerolewithwebidentity") {
			return true
		}
	}
	return false
}

// awsIssuer turns "arn:aws:iam::111111111111:oidc-provider/HOST/PATH" into
// "https://HOST/PATH".
func awsIssuer(fed string) (string, bool) {
	if !strings.HasPrefix(fed, "arn:") {
		return "", false
	}
	_, rest, ok := strings.Cut(fed, ":oidc-provider/")
	if !ok || rest == "" {
		return "", false
	}
	return "https://" + rest, true
}

// awsConditions reads the Condition block. Values under one key are any-of;
// different keys and operators all must hold.
func awsConditions(t *Trust, cond any, prefix string) {
	cm, ok := cond.(map[string]any)
	if !ok {
		return
	}
	ops := make([]string, 0, len(cm))
	for op := range cm {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	perClaim := map[string]int{}
	for _, opFull := range ops {
		keys, ok := cm[opFull].(map[string]any)
		if !ok {
			continue
		}
		op := opFull
		for _, q := range []string{"ForAnyValue:", "ForAllValues:"} {
			op = strings.TrimPrefix(op, q)
		}
		ifExists := strings.HasSuffix(op, "IfExists")
		op = strings.TrimSuffix(op, "IfExists")
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			p, claim, ok := strings.Cut(k, ":")
			if !ok || !strings.EqualFold(p, prefix) || claim == "" {
				continue
			}
			claim = strings.ToLower(claim)
			vals := strs(keys[k])
			if ifExists {
				t.Warnings = append(t.Warnings, fmt.Sprintf("%s on %s: a token without this claim also matches", opFull, claim))
			}
			var pop string
			switch op {
			case "StringEquals", "StringEqualsIgnoreCase":
				pop = OpEquals
			case "StringLike":
				pop = OpGlob
			default:
				if strings.Contains(op, "Not") {
					t.Warnings = append(t.Warnings, fmt.Sprintf("negative condition %s on %s ignored, treated as possible", opFull, claim))
					continue
				}
			}
			if claim == "aud" && pop != "" {
				t.Audiences = append(t.Audiences, vals...)
				continue
			}
			perClaim[claim]++
			if pop == "" {
				raw := opFull + " " + strings.Join(vals, ",")
				t.addCond(claim, Pattern{Raw: raw, Op: OpCEL})
				t.Warnings = append(t.Warnings, "condition not fully understood, treated as possible: "+raw+" on "+claim)
				continue
			}
			for _, v := range vals {
				t.addCond(claim, Pattern{Raw: v, Op: pop})
			}
		}
	}
	claims := make([]string, 0, len(perClaim))
	for c, n := range perClaim {
		if n > 1 {
			claims = append(claims, c)
		}
	}
	sort.Strings(claims)
	for _, c := range claims {
		t.Warnings = append(t.Warnings, fmt.Sprintf("%d conditions on %s must all hold; treated as any one of them", perClaim[c], c))
	}
}

// globMatch matches s against an AWS-style glob ('*' any run, '?' one
// character), iteratively so hostile patterns stay linear-ish.
func globMatch(pat, s string) bool {
	px, sx := 0, 0
	nextPx, nextSx := -1, -1
	for px < len(pat) || sx < len(s) {
		if px < len(pat) {
			switch c := pat[px]; c {
			case '*':
				nextPx, nextSx = px, sx+1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px, sx = nextPx, nextSx
			continue
		}
		return false
	}
	return true
}
