// Package oidc reads the cloud OIDC trust configuration that users export
// from AWS, GCP and Azure and turns it into one model: which GitHub Actions
// tokens (issuer, audience, sub and other claims) may assume which cloud
// identity.
//
// It parses local files only. It never calls a cloud API and never reads
// cloud credentials.
//
// Matching semantics of a Trust: the token must come from Issuer and carry
// one of Audiences; it must match at least one of Subjects (when Subjects is
// not empty); and for every key in Claims it must match at least one of that
// key's patterns. A pattern with Op "cel" is a condition the parser did not
// understand: treat it as possibly matching, never as "match all" or "match
// none" (the Trust always carries a warning saying so).
package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Provider is the cloud a trust belongs to.
type Provider string

// Supported providers.
const (
	AWS   Provider = "aws"
	GCP   Provider = "gcp"
	Azure Provider = "azure"
)

// Pattern operators.
const (
	// OpEquals matches the exact string Raw.
	OpEquals = "equals"
	// OpLike matches strings that start with Raw (CEL startsWith).
	OpLike = "like"
	// OpGlob matches Raw as a glob: '*' is any run of characters (including
	// '/' and ':'), '?' is one character (AWS StringLike, Azure matches).
	OpGlob = "glob"
	// OpCEL is a condition the parser did not fully understand. Raw holds its
	// source text. Treat it as possibly matching.
	OpCEL = "cel"
)

// CELKey is the Claims key for conditions whose claim could not be resolved.
const CELKey = "cel"

// Trust is one way a GitHub Actions OIDC token can become a cloud identity.
type Trust struct {
	Provider Provider `json:"provider"`
	// Target is the cloud identity: an AWS role ARN; a GCP provider name
	// "projects/P/locations/global/workloadIdentityPools/POOL/providers/PROV",
	// plus "+serviceAccount:EMAIL" when an IAM binding lets it impersonate a
	// service account; an Azure "app:<clientId>/fic:<name>" (or
	// "identity:<resource id>/fic:<name>" for a managed identity). When the
	// file does not say, Target is "unknown:<file>..." and Warnings says so.
	Target     string `json:"target"`
	TargetName string `json:"target_name,omitempty"`
	// ServiceAccount is the GCP service account a bound trust can impersonate.
	ServiceAccount string               `json:"service_account,omitempty"`
	Issuer         string               `json:"issuer"`
	Audiences      []string             `json:"audiences,omitempty"`
	Subjects       []Pattern            `json:"subjects,omitempty"`
	Claims         map[string][]Pattern `json:"claims,omitempty"`
	File           string               `json:"file"`
	Pointer        string               `json:"pointer,omitempty"`
	Warnings       []string             `json:"warnings,omitempty"`
}

// Pattern is one condition on a claim value.
type Pattern struct {
	Raw string `json:"raw"`
	Op  string `json:"op"` // equals | like | glob | cel
}

// ErrUnknownFormat is returned (wrapped) for a file that is not one of the
// supported trust formats. Test with errors.Is.
var ErrUnknownFormat = errors.New("oidc: unknown trust file format")

// Options carries what a file may not say about itself.
type Options struct {
	// Target names the identity when the file does not: the AWS role ARN for a
	// bare trust policy document, or the Azure application (client) ID for a
	// federated credential list.
	Target string
	// ServiceAccount is the GCP service account email for an IAM policy file
	// (gcloud iam service-accounts get-iam-policy output) that does not carry
	// a "serviceAccount" field. A file named EMAIL.json also works.
	ServiceAccount string
}

// Result is what Parse found. Warnings are about files and statements that
// were skipped; warnings about a trust are on the Trust.
type Result struct {
	Trusts   []Trust  `json:"trusts"`
	Warnings []string `json:"warnings,omitempty"`
}

// Warning texts for risky patterns.
const (
	WarnNoSub = "no sub condition: any repo of any GitHub user can assume this role"
	WarnNoAud = "no aud condition: a token minted for any audience is accepted"
)

// maxFileBytes bounds a single input file.
const maxFileBytes = 16 << 20

// ParseFile parses one trust file, or every *.json file under a directory
// (unknown formats in a directory are skipped). Use Parse to pass Options or
// to see why files were skipped.
func ParseFile(path string) ([]Trust, error) {
	r, err := Parse(Options{}, path)
	if err != nil {
		return nil, err
	}
	return r.Trusts, nil
}

// Parse parses files and directories together, so a GCP service account IAM
// policy can be joined with its workload identity provider. A file given
// directly must be a known format; inside a directory, unknown *.json files
// are skipped with a warning.
func Parse(opts Options, paths ...string) (*Result, error) {
	c := &collector{opts: opts}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			data, err := readFile(p)
			if err != nil {
				return nil, err
			}
			if err := c.add(p, data); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() || !strings.EqualFold(filepath.Ext(path), ".json") {
				return nil
			}
			data, err := readFile(path)
			if err != nil {
				return err
			}
			if err := c.add(path, data); err != nil {
				if errors.Is(err, ErrUnknownFormat) {
					c.warnings = append(c.warnings, fmt.Sprintf("%s: skipped: %v", path, err))
					return nil
				}
				return fmt.Errorf("%s: %w", path, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return c.finish(), nil
}

// ParseBytes parses the contents of one file. name is recorded as Trust.File.
func ParseBytes(name string, data []byte, opts Options) (*Result, error) {
	c := &collector{opts: opts}
	if err := c.add(name, data); err != nil {
		return nil, err
	}
	return c.finish(), nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxFileBytes)
	}
	return data, nil
}

// collector accumulates parsed files. GCP providers and IAM bindings are
// joined in finish, after every file is read.
type collector struct {
	opts      Options
	trusts    []Trust
	providers []gcpProvider
	bindings  []gcpBinding
	warnings  []string
}

// batch is what one file contributes; it is merged only if the file parses.
type batch struct {
	opts      Options
	file      string
	trusts    []Trust
	providers []gcpProvider
	bindings  []gcpBinding
	warnings  []string
}

func (b *batch) warnf(format string, a ...any) {
	b.warnings = append(b.warnings, b.file+": "+fmt.Sprintf(format, a...))
}

func unknownf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnknownFormat, fmt.Sprintf(format, a...))
}

func (c *collector) add(file string, data []byte) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	dec := json.NewDecoder(bytes.NewReader(data))
	var v any
	if err := dec.Decode(&v); err != nil {
		return unknownf("not JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return unknownf("trailing data after the JSON value")
	}
	b := &batch{opts: c.opts, file: file}
	if err := b.value("", v); err != nil {
		return err
	}
	c.trusts = append(c.trusts, b.trusts...)
	c.providers = append(c.providers, b.providers...)
	c.bindings = append(c.bindings, b.bindings...)
	c.warnings = append(c.warnings, b.warnings...)
	return nil
}

// value classifies a top-level JSON value (or a list element).
func (b *batch) value(ptr string, v any) error {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return nil // e.g. "az ad app federated-credential list" with no credentials
		}
		for i, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				return unknownf("element %d of the top-level list is not an object", i)
			}
			if err := b.object(fmt.Sprintf("%s/%d", ptr, i), m, true); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		return b.object(ptr, x, false)
	default:
		return unknownf("top-level value is not an object or a list")
	}
}

func (b *batch) object(ptr string, m map[string]any, inList bool) error {
	switch {
	case isMap(m["Role"]):
		return b.awsRole(ptr+"/Role", m["Role"].(map[string]any))
	case !inList && isList(m["Roles"]):
		for i, r := range m["Roles"].([]any) {
			rm, ok := r.(map[string]any)
			if !ok {
				return unknownf("Roles[%d] is not an object", i)
			}
			if err := b.awsRole(fmt.Sprintf("%s/Roles/%d", ptr, i), rm); err != nil {
				return err
			}
		}
		return nil
	case m["AssumeRolePolicyDocument"] != nil:
		return b.awsRole(ptr, m)
	case m["Statement"] != nil:
		return b.awsPolicy(ptr, m, b.opts.Target, "")
	case isGCPProvider(m):
		return b.gcpProvider(ptr, m)
	case !inList && isList(m["bindings"]):
		return b.gcpPolicy(ptr, m)
	case isAzureFIC(m):
		return b.azureFIC(ptr, m, b.opts.Target)
	case !inList && (isList(m["value"]) || isList(m["federatedCredentials"])):
		return b.azureList(ptr, m)
	}
	return unknownf("not an AWS trust policy, GCP workload identity provider or IAM policy, or Azure federated credential")
}

func (c *collector) finish() *Result {
	trusts := append([]Trust(nil), c.trusts...)
	trusts = append(trusts, joinGCP(c.providers, c.bindings, &c.warnings)...)
	for i := range trusts {
		t := &trusts[i]
		t.Warnings = dedupe(append(t.Warnings, riskWarnings(*t)...))
	}
	if trusts == nil {
		trusts = []Trust{}
	}
	return &Result{Trusts: trusts, Warnings: c.warnings}
}

// isGitHubIssuer reports whether iss is a GitHub Actions token issuer:
// github.com (optionally with an enterprise slug path) or a GitHub
// Enterprise Server ("https://HOST/_services/token").
func isGitHubIssuer(iss string) bool {
	s := strings.TrimSuffix(strings.TrimSpace(iss), "/")
	s = strings.TrimPrefix(s, "https://")
	host, path, _ := strings.Cut(s, "/")
	if strings.EqualFold(host, "token.actions.githubusercontent.com") {
		return true
	}
	return host != "" && strings.HasSuffix(path, "_services/token")
}

// unknownTarget names an identity the file does not name.
func unknownTarget(file, ptr string) string {
	if ptr == "" {
		return "unknown:" + file
	}
	return "unknown:" + file + "#" + ptr
}

func isMap(v any) bool  { _, ok := v.(map[string]any); return ok }
func isList(v any) bool { _, ok := v.([]any); return ok }

func str(v any) string {
	s, _ := v.(string)
	return s
}

// strs reads a string or a list of strings; numbers and booleans become their
// JSON text.
func strs(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, strs(e)...)
		}
		return out
	case bool, float64:
		b, _ := json.Marshal(x)
		return []string{string(b)}
	}
	return nil
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// addCond adds a pattern under a claim name: "sub" goes to Subjects.
func (t *Trust) addCond(key string, p ...Pattern) {
	if key == "sub" {
		t.Subjects = append(t.Subjects, p...)
		return
	}
	if t.Claims == nil {
		t.Claims = map[string][]Pattern{}
	}
	t.Claims[key] = append(t.Claims[key], p...)
}

func (t Trust) clone() Trust {
	c := t
	c.Audiences = append([]string(nil), t.Audiences...)
	c.Subjects = append([]Pattern(nil), t.Subjects...)
	c.Warnings = append([]string(nil), t.Warnings...)
	if t.Claims != nil {
		c.Claims = make(map[string][]Pattern, len(t.Claims))
		for k, v := range t.Claims {
			c.Claims[k] = append([]Pattern(nil), v...)
		}
	}
	return c
}

// applyConj adds one conjunction of conditions to t, with warnings for
// conditions not understood and for several conditions on one claim (which
// the model can only keep as any-of, a superset of the real AND).
func (t *Trust) applyConj(conj []leaf) {
	count := map[string]int{}
	for _, l := range conj {
		key := l.key
		if key == "" {
			key = CELKey
		}
		if !l.known {
			t.Warnings = append(t.Warnings, "condition not fully understood, treated as possible: "+l.raw)
		}
		count[key]++
		t.addCond(key, l.pats...)
	}
	for _, l := range conj {
		key := l.key
		if key == "" {
			key = CELKey
		}
		if n := count[key]; n > 1 {
			t.Warnings = append(t.Warnings, fmt.Sprintf("%d conditions on %s must all hold; treated as any one of them", n, key))
			count[key] = 0
		}
	}
}
