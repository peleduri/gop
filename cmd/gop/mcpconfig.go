package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// mcpClients lists the clients gop mcp-config knows, in help order.
//
//	claude       a `claude mcp add` command (Claude Code)
//	codex        a `codex mcp add` command (Codex CLI and IDE extension)
//	cursor       .cursor/mcp.json
//	cursor-link  a Cursor MCP install link (cursor://anysphere.cursor-deeplink/mcp/install)
//	vscode       .vscode/mcp.json
var mcpClients = []string{"claude", "codex", "cursor", "cursor-link", "vscode"}

// cmdMCPConfig prints the MCP client config that starts gop serve with an
// absolute graph path. It only prints; it never writes or edits a file.
func (a *app) cmdMCPConfig(args []string) error {
	fs := a.flags("mcp-config")
	client := fs.String("client", "", "MCP client: "+strings.Join(mcpClients, ", "))
	gp := graphFlag(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("mcp-config", "client", *client, "graph", *gp); err != nil {
		return err
	}
	if *gp == "-" {
		return usagef("mcp-config: --graph must be a file path; serve uses stdin for MCP")
	}
	c := strings.ToLower(strings.TrimSpace(*client))
	if !contains(mcpClients, c) {
		return usagef("mcp-config: unknown client %q; valid clients: %s", *client, strings.Join(mcpClients, ", "))
	}
	abs, err := filepath.Abs(*gp)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		fmt.Fprintf(a.stderr, "gop mcp-config: warning: %s does not exist yet; run gop collect first\n", abs)
	}
	return writeMCPConfig(a.stdout, c, abs)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// mcpServer is one stdio server entry. Field order is the output order.
type mcpServer struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func writeMCPConfig(w io.Writer, client, graphPath string) error {
	args := []string{"serve", "--graph", graphPath}
	switch client {
	case "claude":
		_, err := fmt.Fprintf(w, "claude mcp add gop -- gop %s\n", shellJoin(args))
		return err
	case "codex":
		_, err := fmt.Fprintf(w, "codex mcp add gop -- gop %s\n", shellJoin(args))
		return err
	case "cursor-link":
		_, err := fmt.Fprintln(w, cursorInstallLink("gop", mcpServer{Command: "gop", Args: args}))
		return err
	case "cursor":
		return writeJSON(w, map[string]map[string]mcpServer{
			"mcpServers": {"gop": {Command: "gop", Args: args}},
		})
	case "vscode":
		return writeJSON(w, map[string]map[string]mcpServer{
			"servers": {"gop": {Type: "stdio", Command: "gop", Args: args}},
		})
	}
	return fmt.Errorf("unknown client %q", client)
}

// cursorInstallLink returns Cursor's MCP install deeplink for one server:
// the server entry (without its name) as compact JSON, base64 encoded, in the
// config query parameter. See docs/mcp-clients.md for the format's source.
func cursorInstallLink(name string, s mcpServer) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err) // a struct of strings always marshals
	}
	return "cursor://anysphere.cursor-deeplink/mcp/install?name=" + url.QueryEscape(name) +
		"&config=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// shellJoin quotes each word for a POSIX shell.
func shellJoin(words []string) string {
	out := make([]string, len(words))
	for i, s := range words {
		if shellSafe.MatchString(s) {
			out[i] = s
		} else {
			out[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}
