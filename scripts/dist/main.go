// Command dist builds the AI-client distribution files of a gop release. It
// is run by goreleaser and the release workflow, never by users:
//
//	go run ./scripts/dist mcpb --binary dist/gop_darwin_arm64_v8.0/gop --os darwin --arch arm64 --version 0.7.0 --out dist/mcpb
//	go run ./scripts/dist server-json --version 0.7.0 --checksums dist/checksums.txt [--base server.json]
//
// mcpb writes one Claude Desktop extension bundle (MCPB, manifest 0.3) for one
// platform: a zip with manifest.json and the gop binary under server/. The
// manifest's tools list is read from the MCP server itself, so it cannot drift
// from what gop serve registers.
//
// server-json prints the server.json published to the official MCP Registry:
// the committed server.json with its version and OCI tag set to the release,
// plus one mcpb package per bundle listed in checksums.txt.
//
// Neither command uses the network.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

const (
	repoURL      = "https://github.com/peleduri/gop"
	siteURL      = "https://peleduri.github.io/gop/"
	registryName = "io.github.peleduri/gop"
	image        = "ghcr.io/peleduri/gop"
	// description is shared by server.json (max 100 characters) and the
	// MCPB manifest.
	description = "Read-only evidence graph of who can make code run where in a GitHub Enterprise."
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "dist:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dist mcpb|server-json [flags]")
	}
	switch args[0] {
	case "mcpb":
		fs := flag.NewFlagSet("mcpb", flag.ContinueOnError)
		bin := fs.String("binary", "", "path to the gop binary for this platform")
		goos := fs.String("os", "", "GOOS of the binary")
		goarch := fs.String("arch", "", "GOARCH of the binary")
		version := fs.String("version", "", "release version, without the v")
		out := fs.String("out", "", "directory to write the .mcpb into")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bin == "" || *goos == "" || *goarch == "" || *version == "" || *out == "" {
			return errors.New("mcpb: --binary, --os, --arch, --version and --out are required")
		}
		p, err := writeBundle(*bin, *goos, *goarch, *version, *out)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, p)
		return err
	case "server-json":
		fs := flag.NewFlagSet("server-json", flag.ContinueOnError)
		version := fs.String("version", "", "release version, without the v")
		sums := fs.String("checksums", "", "the release checksums.txt")
		base := fs.String("base", "server.json", "the committed server.json")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *version == "" || *sums == "" {
			return errors.New("server-json: --version and --checksums are required")
		}
		b, err := os.ReadFile(*base)
		if err != nil {
			return err
		}
		c, err := os.ReadFile(*sums)
		if err != nil {
			return err
		}
		out, err := registryServerJSON(b, *version, c)
		if err != nil {
			return err
		}
		_, err = stdout.Write(out)
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// mcpbPlatform maps GOOS to the MCPB platform name (Node's process.platform).
var mcpbPlatform = map[string]string{"darwin": "darwin", "linux": "linux", "windows": "win32"}

// bundleName is the release asset name of one bundle. The registry requires
// an MCPB URL to contain "mcp"; the .mcpb extension does.
func bundleName(version, goos, goarch string) string {
	return fmt.Sprintf("gop_%s_%s_%s.mcpb", version, goos, goarch)
}

// Manifest is an MCPB manifest (spec 0.3). Field order is the output order.
type Manifest struct {
	ManifestVersion string                `json:"manifest_version"`
	Name            string                `json:"name"`
	DisplayName     string                `json:"display_name"`
	Version         string                `json:"version"`
	Description     string                `json:"description"`
	LongDescription string                `json:"long_description"`
	Author          Person                `json:"author"`
	Repository      Repo                  `json:"repository"`
	Homepage        string                `json:"homepage"`
	Documentation   string                `json:"documentation"`
	Support         string                `json:"support"`
	License         string                `json:"license"`
	Keywords        []string              `json:"keywords"`
	Server          Server                `json:"server"`
	Tools           []Tool                `json:"tools"`
	Compatibility   Compatibility         `json:"compatibility"`
	UserConfig      map[string]UserOption `json:"user_config"`
}

// Person is the manifest author.
type Person struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Repo is the manifest repository.
type Repo struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Server says how the client starts gop.
type Server struct {
	Type       string    `json:"type"`
	EntryPoint string    `json:"entry_point"`
	MCPConfig  MCPConfig `json:"mcp_config"`
}

// MCPConfig is the command line the client runs.
type MCPConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// Tool is one statically declared tool.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Compatibility limits a bundle to the platform its binary runs on.
type Compatibility struct {
	Platforms []string `json:"platforms"`
}

// UserOption is one value the client asks the user for at install time.
type UserOption struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// buildManifest returns the manifest of the bundle for one platform.
func buildManifest(version, goos string, tools []Tool) (Manifest, error) {
	platform, ok := mcpbPlatform[goos]
	if !ok {
		return Manifest{}, fmt.Errorf("no MCPB platform for GOOS %q", goos)
	}
	entry := "server/gop"
	if goos == "windows" {
		entry += ".exe"
	}
	return Manifest{
		ManifestVersion: "0.3",
		Name:            "gop",
		DisplayName:     "gop: who can make code run where",
		Version:         version,
		Description:     description,
		LongDescription: "gop reads a GitHub Enterprise with a read-only token and writes one evidence graph (graph.json): " +
			"which people, teams, apps and AI agents in CI can make code run in which repos, workflows, secrets, " +
			"OIDC trusts and runners, across orgs and nested Actions. This extension serves that graph to Claude over MCP. " +
			"Every tool is read-only, every answer keeps confirmed reach apart from possible reach, and gop sends nothing anywhere. " +
			"Run `gop collect` first, then choose the graph.json it wrote when you install the extension. " +
			"graph.json maps who can run code where in your enterprise: keep it out of synced folders, and only connect it " +
			"to a model provider your organization allows for this data.",
		Author:        Person{Name: "gop contributors", URL: repoURL},
		Repository:    Repo{Type: "git", URL: repoURL},
		Homepage:      siteURL,
		Documentation: repoURL + "/blob/main/docs/mcp-clients.md",
		Support:       repoURL + "/issues",
		License:       "Apache-2.0",
		Keywords:      []string{"github", "github-enterprise", "github-actions", "security", "supply-chain", "attack-paths", "read-only"},
		Server: Server{
			Type:       "binary",
			EntryPoint: entry,
			MCPConfig: MCPConfig{
				Command: "${__dirname}/" + entry,
				Args:    []string{"serve", "--graph", "${user_config.graph}"},
			},
		},
		Tools:         tools,
		Compatibility: Compatibility{Platforms: []string{platform}},
		UserConfig: map[string]UserOption{
			"graph": {
				Type:        "file",
				Title:       "Graph file",
				Description: "The graph.json written by gop collect (or gop demo). It is sensitive: keep it out of shared or synced folders.",
				Required:    true,
			},
		},
	}, nil
}

// serverTools lists the tools gop serve registers, each with the first
// sentence of its description, sorted by name.
func serverTools() ([]Tool, error) {
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := mcpserver.NewServer(&graph.Graph{}, "dist").Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "dist", Version: "dist"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	tools := make([]Tool, 0, len(res.Tools))
	for _, t := range res.Tools {
		tools = append(tools, Tool{Name: t.Name, Description: firstSentence(t.Description)})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

// writeBundle writes <out>/gop_<version>_<os>_<arch>.mcpb and returns its path.
// The zip is deterministic: fixed entry order and timestamps.
func writeBundle(bin, goos, goarch, version, out string) (string, error) {
	tools, err := serverTools()
	if err != nil {
		return "", err
	}
	m, err := buildManifest(version, goos, tools)
	if err != nil {
		return "", err
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	exe, err := os.ReadFile(bin)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mod := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, f := range []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"manifest.json", 0o644, append(mj, '\n')},
		{m.Server.EntryPoint, 0o755, exe},
	} {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: mod}
		h.SetMode(f.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return "", err
		}
		if _, err := w.Write(f.data); err != nil {
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	p := filepath.Join(out, bundleName(version, goos, goarch))
	return p, os.WriteFile(p, buf.Bytes(), 0o644)
}

// bundleLine matches a checksums.txt line for a bundle of this release.
var bundleLine = regexp.MustCompile(`^([0-9a-f]{64})\s+\*?(gop_(\S+)_([a-z0-9]+)_([a-z0-9]+)\.mcpb)$`)

// registryServerJSON returns the server.json to publish for version: base
// with version and the OCI tag set, and one mcpb package per bundle in sums.
func registryServerJSON(base []byte, version string, sums []byte) ([]byte, error) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`).MatchString(version) {
		return nil, fmt.Errorf("version %q is not X.Y.Z", version)
	}
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		return nil, fmt.Errorf("server.json: %w", err)
	}
	doc["version"] = version
	pkgs, _ := doc["packages"].([]any)
	var out []any
	oci := 0
	for _, p := range pkgs {
		pm, ok := p.(map[string]any)
		if !ok {
			return nil, errors.New("server.json: a package is not an object")
		}
		switch pm["registryType"] {
		case "oci":
			pm["identifier"] = image + ":" + version
			oci++
		case "mcpb":
			continue // replaced from checksums.txt below
		}
		out = append(out, pm)
	}
	if oci != 1 {
		return nil, fmt.Errorf("server.json: want one oci package, got %d", oci)
	}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	n := 0
	for sc.Scan() {
		m := bundleLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil || m[3] != version {
			continue
		}
		out = append(out, map[string]any{
			"registryType": "mcpb",
			"identifier":   fmt.Sprintf("%s/releases/download/v%s/%s", repoURL, version, m[2]),
			"fileSha256":   m[1],
			"transport":    map[string]any{"type": "stdio"},
		})
		n++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("checksums.txt lists no .mcpb bundle for %s", version)
	}
	doc["packages"] = out
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
