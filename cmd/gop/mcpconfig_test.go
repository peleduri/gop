package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peleduri/gop/internal/testutil"
)

// shellWords splits a shell line into words using the real shell.
func shellWords(t *testing.T, line string) []string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	out, err := exec.Command(sh, "-c", "set -- "+line+"; printf '%s\\n' \"$@\"").Output()
	if err != nil {
		t.Fatalf("sh rejected %q: %v", line, err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

func TestMCPConfigClients(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "it's a dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	want := filepath.Join(sub, "g.json")
	if err := os.WriteFile(want, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, client := range []string{"claude", "cursor", "vscode", "VSCode"} {
		t.Run(client, func(t *testing.T) {
			r := runApp(t, nil, nil, "mcp-config", "--client", client, "--graph", "./g.json")
			if r.code != exitOK || r.stderr != "" {
				t.Fatalf("%+v", r)
			}
			var args []string
			switch strings.ToLower(client) {
			case "claude":
				line := strings.TrimSuffix(r.stdout, "\n")
				if strings.Contains(line, "\n") {
					t.Fatalf("want one line, got %q", r.stdout)
				}
				words := shellWords(t, line)
				prefix := []string{"claude", "mcp", "add", "gop", "--", "gop"}
				if len(words) != len(prefix)+3 || strings.Join(words[:len(prefix)], " ") != strings.Join(prefix, " ") {
					t.Fatalf("words %q", words)
				}
				args = words[len(prefix):]
			case "cursor":
				var cfg struct {
					MCPServers map[string]mcpServer `json:"mcpServers"`
				}
				if err := json.Unmarshal([]byte(r.stdout), &cfg); err != nil {
					t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
				}
				s := cfg.MCPServers["gop"]
				if s.Command != "gop" || s.Type != "" {
					t.Fatalf("server %+v", s)
				}
				args = s.Args
			default:
				var cfg struct {
					Servers map[string]mcpServer `json:"servers"`
				}
				if err := json.Unmarshal([]byte(r.stdout), &cfg); err != nil {
					t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
				}
				s := cfg.Servers["gop"]
				if s.Command != "gop" || s.Type != "stdio" {
					t.Fatalf("server %+v", s)
				}
				args = s.Args
			}
			if len(args) != 3 || args[0] != "serve" || args[1] != "--graph" {
				t.Fatalf("args %q", args)
			}
			if !filepath.IsAbs(args[2]) || args[2] != want {
				t.Fatalf("graph path %q, want absolute %q", args[2], want)
			}
		})
	}

	// mcp-config prints only: the directory still holds just g.json.
	entries, err := os.ReadDir(sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("mcp-config wrote files: %v", entries)
	}
}

func TestMCPConfigMissingGraphWarns(t *testing.T) {
	t.Chdir(t.TempDir())
	r := runApp(t, nil, nil, "mcp-config", "--client", "vscode", "--graph", "missing.json")
	if r.code != exitOK || !strings.Contains(r.stderr, "does not exist yet") {
		t.Fatalf("%+v", r)
	}
	if !json.Valid([]byte(r.stdout)) {
		t.Fatalf("stdout not JSON: %q", r.stdout)
	}
}

func TestMCPConfigUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"mcp-config"},
		{"mcp-config", "--client", "vscode"},
		{"mcp-config", "--graph", "g.json"},
		{"mcp-config", "--client", "emacs", "--graph", "g.json"},
		{"mcp-config", "--client", "vscode", "--graph", "g.json", "extra"},
		{"mcp-config", "--client", "vscode", "--graph", "-"},
	} {
		r := runApp(t, nil, nil, args...)
		if r.code != exitUsage {
			t.Errorf("%v: code %d, want 2 (stderr %q)", args, r.code, r.stderr)
		}
		if r.stdout != "" {
			t.Errorf("%v: unexpected stdout %q", args, r.stdout)
		}
	}
	r := runApp(t, nil, nil, "mcp-config", "--client", "emacs", "--graph", "g.json")
	if !strings.Contains(r.stderr, `unknown client "emacs"; valid clients: claude, cursor, vscode`) {
		t.Errorf("stderr does not list valid clients: %q", r.stderr)
	}
}

// TestGoldenMCPConfigClaude goldens the claude line for a fixed absolute path.
func TestGoldenMCPConfigClaude(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX absolute path")
	}
	r := runApp(t, nil, nil, "mcp-config", "--client", "claude", "--graph", "/abs/graph.json")
	if r.code != exitOK {
		t.Fatalf("%+v", r)
	}
	testutil.Golden(t, "mcpconfig_claude.txt", []byte(r.stdout))
}
