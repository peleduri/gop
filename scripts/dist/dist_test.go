package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/brand/logo"
)

// schema compiles a vendored JSON Schema from testdata (see testdata/README.md).
func schema(t *testing.T, name string) *jsonschema.Resolved {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	r, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func validate(t *testing.T, r *jsonschema.Resolved, doc []byte, what string) {
	t.Helper()
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatalf("%s: not JSON: %v", what, err)
	}
	if err := r.Validate(v); err != nil {
		t.Errorf("%s does not match its schema: %v", what, err)
	}
}

func readRepo(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// strictJSON decodes b into v and fails on fields v does not declare.
func strictJSON(t *testing.T, b []byte, v any, what string) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// The schema rejects what it should: a sanity check of the validator itself.
func TestSchemasReject(t *testing.T) {
	r := schema(t, "server.schema.2025-12-11.json")
	var v any
	_ = json.Unmarshal([]byte(`{"name":"no-slash","description":"d","version":"1.0.0"}`), &v)
	if r.Validate(v) == nil {
		t.Error("server schema accepted a name without a slash")
	}
	m := schema(t, "mcpb-manifest-v0.3.schema.json")
	_ = json.Unmarshal([]byte(`{"manifest_version":"0.3","name":"x","version":"1","description":"d","author":{"name":"a"}}`), &v)
	if m.Validate(v) == nil {
		t.Error("mcpb schema accepted a manifest without server")
	}
}

func TestServerJSON(t *testing.T) {
	b := readRepo(t, "server.json")
	validate(t, schema(t, "server.schema.2025-12-11.json"), b, "server.json")
	var doc struct {
		Schema      string `json:"$schema"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Version     string `json:"version"`
		Packages    []struct {
			RegistryType string `json:"registryType"`
			Identifier   string `json:"identifier"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json" {
		t.Errorf("$schema %q does not match the vendored schema", doc.Schema)
	}
	if doc.Name != registryName {
		t.Errorf("name %q, want %q (GitHub OIDC grants io.github.peleduri/*)", doc.Name, registryName)
	}
	if doc.Description != description || len(doc.Description) > 100 {
		t.Errorf("description %q: want the shared description (max 100 chars)", doc.Description)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].RegistryType != "oci" || doc.Packages[0].Identifier != image+":"+doc.Version {
		t.Errorf("want exactly one oci package %s:%s (the release adds the mcpb packages), got %+v", image, doc.Version, doc.Packages)
	}
}

// The registry lists the image only when its io.modelcontextprotocol.server.name
// label equals the server.json name.
func TestImageLabel(t *testing.T) {
	var cfg struct {
		Dockers []struct {
			Images []string          `yaml:"images"`
			Labels map[string]string `yaml:"labels"`
		} `yaml:"dockers_v2"`
	}
	if err := yaml.Unmarshal(readRepo(t, ".goreleaser.yaml"), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dockers) != 1 || len(cfg.Dockers[0].Images) != 1 || cfg.Dockers[0].Images[0] != image {
		t.Fatalf("dockers_v2: %+v", cfg.Dockers)
	}
	if got := cfg.Dockers[0].Labels["io.modelcontextprotocol.server.name"]; got != registryName {
		t.Errorf("image label io.modelcontextprotocol.server.name = %q, want %q", got, registryName)
	}
}

func TestRegistryServerJSON(t *testing.T) {
	sums := []byte(strings.Join([]string{
		strings.Repeat("a", 64) + "  gop_0.7.0_darwin_arm64.mcpb",
		strings.Repeat("b", 64) + "  gop_0.7.0_windows_amd64.mcpb",
		strings.Repeat("c", 64) + "  gop_0.7.0_linux_amd64.tar.gz",
		strings.Repeat("d", 64) + "  gop_0.6.9_linux_amd64.mcpb", // another version: ignored
	}, "\n") + "\n")
	out, err := registryServerJSON(readRepo(t, "server.json"), "0.7.0", sums)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, schema(t, "server.schema.2025-12-11.json"), out, "generated server.json")
	var doc struct {
		Version  string `json:"version"`
		Packages []struct {
			RegistryType string `json:"registryType"`
			Identifier   string `json:"identifier"`
			FileSha256   string `json:"fileSha256"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "0.7.0" || len(doc.Packages) != 3 {
		t.Fatalf("version %q, %d packages:\n%s", doc.Version, len(doc.Packages), out)
	}
	if p := doc.Packages[0]; p.RegistryType != "oci" || p.Identifier != "ghcr.io/peleduri/gop:0.7.0" {
		t.Errorf("oci package %+v", p)
	}
	// The registry accepts an MCPB URL only as a GitHub release asset that contains "mcp".
	asset := regexp.MustCompile(`^https://github\.com/peleduri/gop/releases/download/v0\.7\.0/gop_0\.7\.0_[a-z]+_[a-z0-9]+\.mcpb$`)
	for i, want := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		p := doc.Packages[i+1]
		if p.RegistryType != "mcpb" || !asset.MatchString(p.Identifier) || !strings.Contains(p.Identifier, "mcp") || p.FileSha256 != want {
			t.Errorf("mcpb package %d: %+v", i, p)
		}
	}

	for _, bad := range []struct{ version, sums string }{
		{"v0.7.0", string(sums)},
		{"latest", string(sums)},
		{"0.7.0", strings.Repeat("c", 64) + "  gop_0.7.0_linux_amd64.tar.gz\n"},
	} {
		if _, err := registryServerJSON(readRepo(t, "server.json"), bad.version, []byte(bad.sums)); err == nil {
			t.Errorf("version %q with %q: want an error", bad.version, bad.sums)
		}
	}
}

func TestManifest(t *testing.T) {
	tools, err := serverTools()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
		if tl.Description == "" || strings.Contains(tl.Description, "\n") {
			t.Errorf("tool %s: description %q", tl.Name, tl.Description)
		}
	}
	for _, want := range []string{"check_answerable", "coverage", "who_can_reach", "top_risks", "paths", "fix_plan"} {
		if !names[want] {
			t.Errorf("tools list lacks %s: %v", want, names)
		}
	}
	r := schema(t, "mcpb-manifest-v0.3.schema.json")
	for goos, platform := range map[string]string{"darwin": "darwin", "linux": "linux", "windows": "win32"} {
		m, err := buildManifest("0.7.0", goos, tools)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		validate(t, r, b, goos+" manifest")
		if len(m.Compatibility.Platforms) != 1 || m.Compatibility.Platforms[0] != platform {
			t.Errorf("%s: platforms %v", goos, m.Compatibility.Platforms)
		}
		if m.Server.MCPConfig.Command != "${__dirname}/"+m.Server.EntryPoint {
			t.Errorf("%s: command %q does not run the entry point %q", goos, m.Server.MCPConfig.Command, m.Server.EntryPoint)
		}
		if strings.HasSuffix(m.Server.EntryPoint, ".exe") != (goos == "windows") {
			t.Errorf("%s: entry point %q", goos, m.Server.EntryPoint)
		}
		if strings.Join(m.Server.MCPConfig.Args, " ") != "serve --graph ${user_config.graph}" {
			t.Errorf("%s: args %q", goos, m.Server.MCPConfig.Args)
		}
		if o, ok := m.UserConfig["graph"]; !ok || o.Type != "file" || !o.Required {
			t.Errorf("%s: user_config.graph %+v", goos, o)
		}
	}
	if _, err := buildManifest("0.7.0", "plan9", tools); err == nil {
		t.Error("plan9: want an error")
	}
}

func TestWriteBundle(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "gop.exe")
	if err := os.WriteFile(bin, []byte("not really a binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"mcpb", "--binary", bin, "--os", "windows", "--arch", "arm64", "--version", "0.7.0", "--out", filepath.Join(dir, "a")}, &out); err != nil {
		t.Fatal(err)
	}
	p := strings.TrimSpace(out.String())
	if filepath.Base(p) != "gop_0.7.0_windows_arm64.mcpb" {
		t.Fatalf("wrote %q", p)
	}
	again, err := writeBundle(bin, "windows", "arm64", "0.7.0", filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(p)
	b2, _ := os.ReadFile(again)
	if !bytes.Equal(b1, b2) {
		t.Error("two builds of the same bundle differ")
	}
	zr, err := zip.NewReader(bytes.NewReader(b1), int64(len(b1)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	if len(files) != 4 || files["manifest.json"] == nil || files["server/gop.exe"] == nil {
		t.Fatalf("bundle entries %v", files)
	}
	for _, ic := range bundleIcons {
		f := files[ic.Src]
		if f == nil {
			t.Fatalf("bundle lacks icon %s", ic.Src)
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := png.DecodeConfig(r)
		_ = r.Close()
		if err != nil || fmt.Sprintf("%dx%d", cfg.Width, cfg.Height) != ic.Size {
			t.Errorf("icon %s: %dx%d (%v), want %s", ic.Src, cfg.Width, cfg.Height, err, ic.Size)
		}
	}
	if files["server/gop.exe"].Mode()&0o111 == 0 {
		t.Error("server binary is not executable")
	}
	rc, err := files["manifest.json"].Open()
	if err != nil {
		t.Fatal(err)
	}
	mj, _ := io.ReadAll(rc)
	_ = rc.Close()
	validate(t, schema(t, "mcpb-manifest-v0.3.schema.json"), mj, "bundled manifest.json")
	var m Manifest
	if err := json.Unmarshal(mj, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Icons) != 2 || m.Icon != m.Icons[0].Src || files[m.Icon] == nil {
		t.Errorf("manifest icon %q, icons %+v", m.Icon, m.Icons)
	}
	if m.Version != "0.7.0" || m.Server.EntryPoint != "server/gop.exe" {
		t.Errorf("manifest %+v", m)
	}

	for _, args := range [][]string{nil, {"nope"}, {"mcpb"}, {"server-json"}} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("%q: want an error", args)
		}
	}
}

// claudePlugin is .claude-plugin/plugin.json with only the fields gop uses,
// all documented in the Claude Code plugin manifest reference.
type claudePlugin struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Author      struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"author"`
	Homepage   string   `json:"homepage"`
	Repository string   `json:"repository"`
	License    string   `json:"license"`
	Keywords   []string `json:"keywords"`
	MCPServers map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	} `json:"mcpServers"`
	UserConfig map[string]struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Required    bool   `json:"required"`
	} `json:"userConfig"`
}

type claudeMarketplace struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"owner"`
	Plugins []struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		Source      string   `json:"source"`
		Description string   `json:"description"`
		Category    string   `json:"category"`
		Tags        []string `json:"tags"`
	} `json:"plugins"`
}

var (
	kebab      = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	cmName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	optionKey  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	userConfig = regexp.MustCompile(`\$\{user_config\.([^}]*)\}`)
)

func TestClaudePlugin(t *testing.T) {
	var p claudePlugin
	strictJSON(t, readRepo(t, ".claude-plugin/plugin.json"), &p, "plugin.json")
	if !kebab.MatchString(p.Name) || p.Description == "" || p.Author.Name == "" || p.License != "Apache-2.0" {
		t.Errorf("plugin.json metadata: %+v", p)
	}
	s, ok := p.MCPServers["gop"]
	if !ok || s.Command != "gop" || len(s.Args) != 3 || s.Args[0] != "serve" || s.Args[1] != "--graph" {
		t.Errorf("mcpServers.gop: %+v", s)
	}
	for _, a := range s.Args {
		for _, m := range userConfig.FindAllStringSubmatch(a, -1) {
			if _, ok := p.UserConfig[m[1]]; !ok {
				t.Errorf("mcpServers.gop references undeclared ${user_config.%s}", m[1])
			}
		}
	}
	types := map[string]bool{"string": true, "number": true, "boolean": true, "directory": true, "file": true}
	for k, o := range p.UserConfig {
		if !optionKey.MatchString(k) || !types[o.Type] || o.Title == "" || o.Description == "" {
			t.Errorf("userConfig.%s: %+v", k, o)
		}
	}
	// The plugin root is the repository root, so skills/gop is loaded from
	// the default skills/ directory.
	if _, err := os.Stat(filepath.Join("..", "..", "skills", p.Name, "SKILL.md")); err != nil {
		t.Errorf("skill: %v", err)
	}

	var m claudeMarketplace
	strictJSON(t, readRepo(t, ".claude-plugin/marketplace.json"), &m, "marketplace.json")
	reserved := map[string]bool{"claude-code-marketplace": true, "claude-code-plugins": true, "claude-plugins-official": true,
		"anthropic-marketplace": true, "anthropic-plugins": true, "agent-skills": true, "inline": true, "builtin": true,
		"skills-dir": true, "synced": true}
	if !cmName.MatchString(m.Name) || strings.Contains(m.Name, "..") || reserved[m.Name] || m.Owner.Name == "" || m.Description == "" {
		t.Errorf("marketplace.json metadata: %+v", m)
	}
	if len(m.Plugins) != 1 {
		t.Fatalf("marketplace lists %d plugins, want 1", len(m.Plugins))
	}
	e := m.Plugins[0]
	// /plugin install gop@gop: the entry name must equal the manifest name.
	if e.Name != p.Name || e.Source != "./" || e.Description == "" {
		t.Errorf("marketplace entry %+v (plugin.json name %q)", e, p.Name)
	}
}

// skillOnlyPlugin is the Cursor (.cursor-plugin) and Codex (.codex-plugin)
// manifest: the skill only. Neither client can prompt for the graph path the
// way Claude Code's userConfig does (Codex would start the Claude manifest's
// server with a literal ${user_config.graph}), so these manifests declare no
// MCP server; users add it with the install link or codex mcp add.
func TestSkillOnlyPlugins(t *testing.T) {
	for _, f := range []string{".cursor-plugin/plugin.json", ".codex-plugin/plugin.json"} {
		t.Run(f, func(t *testing.T) { checkSkillOnlyPlugin(t, f) })
	}
}

func checkSkillOnlyPlugin(t *testing.T, file string) {
	var p struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Author      struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"author"`
		Homepage   string   `json:"homepage"`
		Repository string   `json:"repository"`
		License    string   `json:"license"`
		Keywords   []string `json:"keywords"`
		Skills     string   `json:"skills"`
		Version    string   `json:"version"`
		Logo       string   `json:"logo"`
	}
	strictJSON(t, readRepo(t, file), &p, file)
	if !regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`).MatchString(p.Name) || p.Description == "" || p.Author.Name == "" {
		t.Errorf("metadata: %+v", p)
	}
	if !strings.HasPrefix(p.Skills, "./") || strings.Contains(p.Skills, "..") {
		t.Errorf("skills path %q must be relative and stay in the repo", p.Skills)
	}
	if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(p.Skills), p.Name, "SKILL.md")); err != nil {
		t.Errorf("skill: %v", err)
	}
}

// TestPluginVersionsAgree keeps every plugin manifest on one semver version, bumped with each release.
func TestPluginVersionsAgree(t *testing.T) {
	semver := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	var want string
	for _, f := range []string{".claude-plugin/plugin.json", ".cursor-plugin/plugin.json", ".codex-plugin/plugin.json"} {
		var v struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(readRepo(t, f), &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !semver.MatchString(v.Version) {
			t.Errorf("%s: version %q is not semver", f, v.Version)
		}
		if want == "" {
			want = v.Version
		} else if v.Version != want {
			t.Errorf("%s: version %q, want %q (same as .claude-plugin/plugin.json)", f, v.Version, want)
		}
	}
	var m claudeMarketplace
	if err := json.Unmarshal(readRepo(t, ".claude-plugin/marketplace.json"), &m); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.Plugins {
		if p.Version != want {
			t.Errorf("marketplace plugin %s: version %q, want %q", p.Name, p.Version, want)
		}
	}
}

// TestBrandListing keeps the plugin icons on the brand mark (the 1024 PNG in
// brand/logo/png) and every listing title on the brand display name.
func TestBrandListing(t *testing.T) {
	for _, f := range []string{".claude-plugin/icon.png", ".cursor-plugin/logo.png"} {
		if !bytes.Equal(readRepo(t, f), logo.Mark1024) {
			t.Errorf("%s differs from brand/logo/png/gop-mark-1024.png; copy it", f)
		}
	}
	var p claudePlugin
	strictJSON(t, readRepo(t, ".claude-plugin/plugin.json"), &p, "plugin.json")
	if p.DisplayName != displayName {
		t.Errorf("plugin.json displayName %q, want %q", p.DisplayName, displayName)
	}
	var sj struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(readRepo(t, "server.json"), &sj); err != nil {
		t.Fatal(err)
	}
	if sj.Title != displayName {
		t.Errorf("server.json title %q, want %q", sj.Title, displayName)
	}
}
