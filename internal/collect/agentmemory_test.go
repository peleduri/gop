package collect

import (
	"testing"

	"github.com/peleduri/gop/internal/graph"
)

// writerWF is an issue_comment agent anyone can start that saves a cache.
func writerWF(mode, key string) string {
	m := ""
	if mode != "" {
		m = "    cache-mode: " + mode + "\n"
	}
	return `on: issue_comment
permissions: {contents: read}
jobs:
  agent:
    runs-on: ubuntu-latest
` + m + `    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          allowed_non_write_users: "*"
      - uses: actions/cache/save@v4
        with:
          path: |
            ~/.claude/projects
            .claude/memory
          key: ` + key + `
`
}

// readerWF is a push job that restores a cache with the given keys.
func readerWF(perms, key, restoreKeys, paths string) string {
	rk := ""
	if restoreKeys != "" {
		rk = "          restore-keys: " + restoreKeys + "\n"
	}
	return `on: push
permissions: ` + perms + `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ` + paths + `
          key: ` + key + `
` + rk + `      - run: make
`
}

const memPaths = "|\n            ~/.claude/projects\n            .claude/memory"

func TestMemoryPoisons(t *testing.T) {
	cases := []struct {
		name           string
		writer, reader string
		ghes           bool
		want           bool
		how            string
		ev             graph.Evidence
	}{
		{name: "run-scoped key restored by prefix", writer: writerWF("write", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-${{ github.sha }}", "mem-", memPaths), want: true, how: MatchPrefix, ev: graph.Live},
		{name: "primary key is prefix matched too", writer: writerWF("write-only", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-", "", memPaths), want: true, how: MatchPrefix, ev: graph.Live},
		{name: "same static key", writer: writerWF("write", "agent-memory"),
			reader: readerWF("{id-token: write}", "agent-memory", "", memPaths), want: true, how: MatchExact, ev: graph.Live},
		{name: "same expression key: inferred", writer: writerWF("write", "mem-${{ hashFiles('a.lock') }}"),
			reader: readerWF("{contents: write}", "mem-${{ hashFiles('a.lock') }}", "", memPaths), want: true, how: MatchExpression, ev: graph.Inferred},
		{name: "github.ref is the default branch under issue_comment: inferred", writer: writerWF("write", "mem-${{ github.ref }}"),
			reader: readerWF("{contents: write}", "mem-${{ github.ref }}", "", memPaths), want: true, how: MatchExpression, ev: graph.Inferred},
		{name: "GHES with no cache-mode: possible", writer: writerWF("", "mem-${{ github.run_id }}"), ghes: true,
			reader: readerWF("{contents: write}", "mem-x", "mem-", memPaths), want: true, how: MatchPrefix, ev: graph.NotVisible},

		// negatives
		{name: "github.com read-only default", writer: writerWF("", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-x", "mem-", memPaths)},
		{name: "cache-mode read", writer: writerWF("read", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-x", "mem-", memPaths)},
		{name: "run-scoped key, exact restore only", writer: writerWF("write", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-${{ github.run_id }}", "", memPaths)},
		{name: "per-issue key, exact restore of another run's key", writer: writerWF("write", "mem-${{ github.event.issue.number }}"),
			reader: readerWF("{contents: write}", "mem-${{ github.run_id }}", "", memPaths)},
		{name: "different prefix", writer: writerWF("write", "pr-mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "main-mem-x", "main-mem-", memPaths)},
		{name: "different paths: another cache version", writer: writerWF("write", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: write}", "mem-x", "mem-", ".claude/memory")},
		{name: "read-only consumer", writer: writerWF("write", "mem-${{ github.run_id }}"),
			reader: readerWF("{contents: read}", "mem-x", "mem-", memPaths)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := ParseWorkflow([]byte(c.writer))
			if err != nil {
				t.Fatal(err)
			}
			r, err := ParseWorkflow([]byte(c.reader))
			if err != nil {
				t.Fatal(err)
			}
			got := memoryPoisons([]memoryWF{{ID: "workflow:w", F: w}, {ID: "workflow:r", F: r}}, c.ghes)
			if (len(got) > 0) != c.want {
				t.Fatalf("got %+v, want match %v", got, c.want)
			}
			if !c.want {
				return
			}
			p := got[0]
			if p.Reader != "workflow:r" || p.ReaderJob != "build" || p.WriterJob != "agent" || p.How != c.how || p.Ev != c.ev || p.Line < 11 {
				t.Errorf("poison = %+v, want how %s ev %s", p, c.how, c.ev)
			}
		})
	}
}

func TestMemoryPoisonsWriterSide(t *testing.T) {
	reader := readerWF("{contents: write}", "mem-x", "mem-", memPaths)
	cases := []struct{ name, writer string }{
		{"pull_request writes the merge ref's scope", `on: pull_request
jobs:
  agent:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {allowed_non_write_users: "*"}
      - uses: actions/cache/save@v4
        with: {path: "` + "~/.claude/projects\\n.claude/memory" + `", key: mem-1}
`},
		{"agent keeps the write-access check", `on: issue_comment
jobs:
  agent:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: anthropics/claude-code-action@v1
      - uses: actions/cache/save@v4
        with: {path: "` + "~/.claude/projects\\n.claude/memory" + `", key: mem-1}
`},
		{"the save is in another job", `on: issue_comment
cache-mode: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {allowed_non_write_users: "*"}
  other:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save@v4
        with: {path: "` + "~/.claude/projects\\n.claude/memory" + `", key: mem-1}
`},
	}
	r, err := ParseWorkflow([]byte(reader))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := ParseWorkflow([]byte(c.writer))
			if err != nil {
				t.Fatal(err)
			}
			if got := memoryPoisons([]memoryWF{{ID: "workflow:w", F: w}, {ID: "workflow:r", F: r}}, false); len(got) > 0 {
				t.Errorf("got %+v, want none", got)
			}
		})
	}
}

func TestMemoryPoisonsSelfRead(t *testing.T) {
	src := `on: issue_comment
jobs:
  agent:
    runs-on: ubuntu-latest
    cache-mode: write
    permissions: {contents: write}
    steps:
      - uses: actions/cache@v4
        with:
          path: memory-bank
          key: bank-${{ github.run_id }}
          restore-keys: bank-
      - uses: openai/codex-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          allow-users: "*"
`
	f, err := ParseWorkflow([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := memoryPoisons([]memoryWF{{ID: "workflow:w", F: f}}, false)
	if len(got) != 1 || got[0].Reader != "workflow:w" || got[0].How != MatchPrefix || got[0].Ev != graph.Live {
		t.Fatalf("got %+v", got)
	}
}

func TestReadCaches(t *testing.T) {
	f, err := ParseWorkflow([]byte(`on: push
cache-mode: read
jobs:
  a:
    runs-on: ubuntu-latest
    cache-mode: write
    steps:
      - uses: actions/cache@v4
        with: {path: x, key: k, lookup-only: true}
      - uses: actions/cache/restore@v4
        with: {path: x, key: k}
      - uses: actions/cache@v4
        with: {path: x}
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Cache/Save@v4
        with: {path: x, key: k}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Caches) != 3 || !f.Caches[0].Save || f.Caches[0].Restore || f.Caches[1].Save || !f.Caches[1].Restore || !f.Caches[2].Save {
		t.Errorf("caches = %+v", f.Caches)
	}
	if f.cacheModeOf("a") != "write" || f.cacheModeOf("b") != "read" {
		t.Errorf("modes = %q %q", f.cacheModeOf("a"), f.cacheModeOf("b"))
	}
}

func TestMemoryDir(t *testing.T) {
	for p, want := range map[string]string{
		"~/.claude/projects": ".claude", ".claude/memory": ".claude", "${{ github.workspace }}/memory-bank": "memory-bank",
		"~/.codex": ".codex", "AGENTS.md": "AGENTS.md", "notes/memories/x": "memory", "~/.npm": "", "node_modules": "",
		".agentrun/snapshot.json": ".agentrun", "~/.gemini": ".gemini",
	} {
		if got := MemoryDir(p); got != want {
			t.Errorf("MemoryDir(%q) = %q, want %q", p, got, want)
		}
	}
}
