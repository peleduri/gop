package site

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/mcpserver"
)

const siteURL = "https://peleduri.github.io/gop/"

// cursorLink is the web form of Cursor's MCP install deeplink
// (https://cursor.com/docs/mcp/install-links, https://cursor.com/docs/reference/deeplinks).
const cursorLink = "https://cursor.com/link/mcp/install?"

// checkCursorLink decodes a Cursor install link and checks it installs gop
// serve: on ~/gop/graph.json as "gop", or on the demo graph as "gop-demo".
func checkCursorLink(t *testing.T, ref string) {
	t.Helper()
	u, err := url.Parse(ref)
	if err != nil {
		t.Errorf("cursor link %q: %v", ref, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("config"))
	if err != nil {
		t.Errorf("cursor link %q: config is not base64: %v", ref, err)
		return
	}
	var cfg struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		t.Errorf("cursor link %q: config %s: %v", ref, raw, err)
		return
	}
	want := map[string]string{
		"gop":      "serve --graph ${userHome}/gop/graph.json",
		"gop-demo": "serve --demo",
	}[u.Query().Get("name")]
	if cfg.Command != "gop" || want == "" || strings.Join(cfg.Args, " ") != want {
		t.Errorf("cursor link %q installs %s %q as %q", ref, cfg.Command, cfg.Args, u.Query().Get("name"))
	}
}

var mdURL = regexp.MustCompile(`https://[^\s)"<>]+`)

// TestCursorLinksInDocs checks the install links in the README and the MCP
// clients guide the same way as the page's.
func TestCursorLinksInDocs(t *testing.T) {
	for _, f := range []string{"../README.md", "../docs/mcp-clients.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, u := range mdURL.FindAllString(string(b), -1) {
			if strings.HasPrefix(u, cursorLink) {
				checkCursorLink(t, u)
				n++
			}
		}
		if n < 2 {
			t.Errorf("%s: found %d Cursor install links, want the graph and demo links", f, n)
		}
	}
}

// TestLLMsTxt checks site/llms.txt (https://llmstxt.org shape: an H1, a
// blockquote summary, then sections of links) and site/llms-full.txt: every
// link resolves to a repo file or a file site/build.sh writes, and the full
// text names every MCP tool gop serve registers.
func TestLLMsTxt(t *testing.T) {
	short, err := os.ReadFile("llms.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(short), "\n")
	if !strings.HasPrefix(lines[0], "# ") || !strings.HasPrefix(lines[2], "> ") {
		t.Errorf("llms.txt must start with an H1 and a blockquote summary")
	}
	if !strings.Contains(string(short), "\n## ") {
		t.Error("llms.txt has no link sections")
	}
	full, err := os.ReadFile("llms-full.txt")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"llms.txt": short, "llms-full.txt": full} {
		links := mdURL.FindAllString(string(b), -1)
		if len(links) < 8 {
			t.Errorf("%s: only %d links", name, len(links))
		}
		for _, l := range links {
			l = strings.TrimRight(l, ".,:;")
			switch {
			case l == repoURL, l == repoURL+"/releases":
			case strings.HasPrefix(l, repoURL+"/blob/main/"):
				p := strings.TrimPrefix(l, repoURL+"/blob/main/")
				if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(p))); err != nil {
					t.Errorf("%s: link %q: %s does not exist in the repo", name, l, p)
				}
			case l == siteURL:
			case strings.HasPrefix(l, siteURL):
				if p := strings.TrimPrefix(l, siteURL); !builtFiles[p] {
					t.Errorf("%s: link %q: %s is not a file site/build.sh writes", name, l, p)
				}
			default:
				t.Errorf("%s: link %q: only links to the repo and the site are expected", name, l)
			}
		}
	}

	g := &graph.Graph{}
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := mcpserver.NewServer(g, "test").Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if !strings.Contains(string(full), "- "+tool.Name+": ") {
			t.Errorf("llms-full.txt does not describe the MCP tool %s", tool.Name)
		}
	}
	for _, level := range []string{"live", "inferred", "audit", "supplied", "not_visible"} {
		if !strings.Contains(string(full), "- "+level+": ") {
			t.Errorf("llms-full.txt does not explain the evidence level %s", level)
		}
	}
}

// TestFAQ keeps the FAQ section plain HTML: questions in <summary>, answers
// in <p>, and a link to the MCP clients guide.
func TestFAQ(t *testing.T) {
	src, _ := loadPage(t)
	i := strings.Index(src, `<section id="faq"`)
	if i < 0 {
		t.Fatal("no FAQ section")
	}
	faq := src[i:]
	faq = faq[:strings.Index(faq, "</section>")]
	if n := strings.Count(faq, "<summary>"); n < 5 {
		t.Errorf("FAQ has %d questions, want at least 5", n)
	}
	for _, want := range []string{"docs/mcp-clients.md", "llms.txt", "llms-full.txt", "Claude Code", "Cursor", "Codex"} {
		if !strings.Contains(faq, want) {
			t.Errorf("FAQ does not mention %q", want)
		}
	}
}
