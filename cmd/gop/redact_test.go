package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactEndToEnd(t *testing.T) {
	dir := t.TempDir()
	salt := filepath.Join(dir, "key")
	if err := os.WriteFile(salt, []byte("acme-test-salt"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, mapping := filepath.Join(dir, "shareable.json"), filepath.Join(dir, "mapping.json")
	r := runApp(t, nil, nil, "redact", "--graph", fixture, "--out", out, "--salt-file", salt, "--map-out", mapping)
	if r.code != exitOK {
		t.Fatalf("redact: %+v", r)
	}
	if !strings.Contains(r.stderr, "self-check passed") || !strings.Contains(r.stderr, "never attach it") {
		t.Errorf("stderr = %q", r.stderr)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"acme-actions", "acme-app", "alice", "bob"} {
		if bytes.Contains(first, []byte(name)) {
			t.Errorf("output contains %q", name)
		}
	}
	for _, p := range []string{out, mapping} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", filepath.Base(p), st.Mode().Perm())
		}
	}
	var m struct {
		Mapping map[string]map[string]string `json:"mapping"`
	}
	data, err := os.ReadFile(mapping)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &m); err != nil || m.Mapping["orgs"]["acme-actions"] == "" {
		t.Errorf("mapping = %s (%v)", data, err)
	}

	// Same salt: byte-identical.
	out2 := filepath.Join(dir, "again.json")
	if r := runApp(t, nil, nil, "redact", "--graph", fixture, "--out", out2, "--salt-file", salt); r.code != exitOK {
		t.Fatalf("redact again: %+v", r)
	}
	second, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("same salt gave different output")
	}

	v := runApp(t, nil, nil, "validate", "--graph", out)
	if v.code != exitOK || !strings.Contains(v.stdout, "valid (gop.graph/v1, 0 errors") {
		t.Errorf("validate: %+v", v)
	}
}

func TestRedactRandomSaltToStdout(t *testing.T) {
	r := runApp(t, nil, nil, "redact", "--graph", fixture, "--out", "-")
	if r.code != exitOK || !strings.Contains(r.stderr, "random salt") || !strings.Contains(r.stdout, `"schema": "gop.graph/v1"`) {
		t.Fatalf("redact: code %d stderr %q", r.code, r.stderr)
	}
	if strings.Contains(r.stdout, "acme-app") {
		t.Error("stdout contains an original name")
	}
}

func TestRedactLeakWritesNothing(t *testing.T) {
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	planted := strings.Replace(string(data), `"visibility": "private"`, `"visibility": "private", "note": "owned by xalicex"`, 1)
	if planted == string(data) {
		t.Fatal("fixture has no visibility attr to plant next to")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.json"), filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runApp(t, nil, nil, "redact", "--graph", in, "--out", out, "--keep-attr", "note")
	if r.code != exitRuntime || !strings.Contains(r.stderr, "self-check failed") || !strings.Contains(r.stderr, "attrs.note") {
		t.Fatalf("redact: %+v", r)
	}
	if strings.Contains(r.stderr, "alice") {
		t.Errorf("error names the leaked name: %q", r.stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("output written despite the leak: %v", err)
	}
}

func TestRedactUsage(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"redact", "--graph", fixture}, exitUsage},
		{[]string{"redact", "--out", "x.json"}, exitUsage},
		{[]string{"redact", "--graph", fixture, "--out", "-", "--map-out", "-"}, exitUsage},
		{[]string{"redact", "--graph", fixture, "--out", "same.json", "--map-out", "same.json"}, exitUsage},
		{[]string{"redact", "--graph", fixture, "--out", "-", "--salt-file", empty}, exitRuntime},
		{[]string{"redact", "--graph", fixture, "--out", "-", "--salt-file", filepath.Join(dir, "missing")}, exitRuntime},
	} {
		if r := runApp(t, nil, nil, tc.args...); r.code != tc.code {
			t.Errorf("%v: code %d, want %d (%s)", tc.args, r.code, tc.code, r.stderr)
		}
	}
}
