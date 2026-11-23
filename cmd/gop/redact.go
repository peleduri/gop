package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/collect"
	"github.com/peleduri/gop/internal/redact"
)

// cmdRedact writes a pseudonymized copy of a graph that is safe to attach to
// a bug report. It is offline.
func (a *app) cmdRedact(args []string) error {
	fs := a.flags("redact")
	gp := graphFlag(fs)
	out := fs.String("out", "", `path to write the redacted graph.json ("-" for stdout)`)
	saltFile := fs.String("salt-file", "", "file whose contents key the pseudonyms: the same salt gives the same names (default: a random salt per run)")
	keep := fs.String("keep-attr", "", "comma list of extra attr keys to keep (values are rewritten through the name map); other keys gop does not define are dropped")
	mapOut := fs.String("map-out", "", "write the real-to-synthetic name mapping to this local file (sensitive: it undoes the redaction)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := required("redact", "graph", *gp, "out", *out); err != nil {
		return err
	}
	if *mapOut == "-" {
		return usagef("redact: --map-out - is not supported: write the mapping to a local file")
	}
	if *mapOut != "" && *mapOut == *out {
		return usagef("redact: --map-out and --out must differ")
	}
	salt, err := a.redactSalt(*saltFile)
	if err != nil {
		return err
	}
	g, err := a.loadGraph("redact", *gp, false)
	if err != nil {
		return err
	}
	res, err := redact.Redact(g, redact.Options{Salt: salt, KeepAttrs: splitList(*keep)})
	if err != nil {
		return err
	}
	if err := a.writeFile(*out, func(w io.Writer) error { return collect.WriteGraph(w, res.Graph) }); err != nil {
		return err
	}
	if *mapOut != "" {
		if err := a.writeFile(*mapOut, func(w io.Writer) error { return writeMapping(w, res.Mapping) }); err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "gop redact: warning: %s maps every synthetic name back to the real one; keep it local and never attach it\n", *mapOut)
	}
	if len(res.Dropped) > 0 {
		keys := make([]string, 0, len(res.Dropped))
		for k := range res.Dropped {
			keys = append(keys, fmt.Sprintf("%s (%d)", k, res.Dropped[k]))
		}
		sort.Strings(keys)
		fmt.Fprintf(a.stderr, "gop redact: dropped attrs gop does not define or values outside their vocabulary: %s (keep one with --keep-attr)\n", strings.Join(keys, ", "))
	}
	fmt.Fprintf(a.stderr, "gop redact: %d nodes, %d edges; self-check passed: no original name of 3+ characters appears in the output\n",
		len(res.Graph.Nodes), len(res.Graph.Edges))
	return nil
}

// redactSalt reads --salt-file, or makes a random salt.
func (a *app) redactSalt(path string) ([]byte, error) {
	if path == "" {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		fmt.Fprintln(a.stderr, "gop redact: no --salt-file: using a random salt, so names differ on every run")
		return salt, nil
	}
	salt, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--salt-file: %w", err)
	}
	if len(salt) == 0 {
		return nil, errors.New("--salt-file: file is empty")
	}
	return salt, nil
}

func writeMapping(w io.Writer, m map[string]map[string]string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(struct {
		Warning string                       `json:"warning"`
		Mapping map[string]map[string]string `json:"mapping"`
	}{"real -> synthetic names from gop redact; sensitive: never share this file", m})
}
