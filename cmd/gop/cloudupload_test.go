package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Fake credentials for the cloud upload test. Not real tokens.
const (
	fakeRequestToken = "fake-request-token-0001"
	fakeOIDCToken    = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJnb3AtY2xvdWQifQ.c2lnbmF0dXJl"
)

// TestActionCloudUpload runs the Action's gop Cloud upload script
// (action/cloud-upload.sh) against a fake OIDC token endpoint and a fake
// ingest endpoint.
func TestActionCloudUpload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash may resolve to WSL on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "action", "cloud-upload.sh"))
	if err != nil {
		t.Fatal(err)
	}
	summaryPath := filepath.Join(t.TempDir(), "summary.json")
	r := runApp(t, nil, nil, "summary", "--demo", "--out", summaryPath)
	if r.code != exitOK {
		t.Fatalf("summary: %+v", r)
	}
	summaryBody, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}

	var ingestStatus atomic.Int32
	var ingested atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeRequestToken || r.URL.Query().Get("audience") != "gop-cloud" ||
			r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "bad token request", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"count":1,"value":"`+fakeOIDCToken+`"}`)
	})
	mux.HandleFunc("/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+fakeOIDCToken ||
			r.Header.Get("Content-Type") != "application/json" || !bytes.Equal(body, summaryBody) {
			http.Error(w, "bad ingest", http.StatusBadRequest)
			return
		}
		ingested.Add(1)
		w.WriteHeader(int(ingestStatus.Load()))
		_, _ = io.WriteString(w, `{"echo":"`+fakeOIDCToken+`"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ingest := srv.URL + "/v1/ingest"
	oidcEnv := []string{"ACTIONS_ID_TOKEN_REQUEST_URL=" + srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=" + fakeRequestToken}

	for _, tc := range []struct {
		name     string
		args     []string
		oidc     bool
		status   int32
		wantCode int
		want     string
		wantSent int32
	}{
		{"check ok", []string{"check", ingest}, true, 0, 0, "only summary.json will be sent", 0},
		{"check no id-token", []string{"check", ingest}, false, 0, 1, "permissions: id-token: write", 0},
		{"check empty url", []string{"check", ""}, true, 0, 1, "cloud-url is required", 0},
		{"check plain http", []string{"check", "http://cloud.example.com/v1/ingest"}, true, 0, 1, "must start with https://", 0},
		{"upload ok", []string{"upload", summaryPath, ingest}, true, 202, 0, "summary uploaded (HTTP 202)", 1},
		{"upload rejected", []string{"upload", summaryPath, ingest}, true, 403, 1, "answered HTTP 403", 1},
		{"upload no id-token", []string{"upload", summaryPath, ingest}, false, 202, 1, "Nothing was sent", 0},
		{"upload missing summary", []string{"upload", filepath.Join(t.TempDir(), "none.json"), ingest}, true, 202, 1, "missing or empty", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ingested.Store(0)
			ingestStatus.Store(tc.status)
			cmd := exec.Command(bash, append([]string{script}, tc.args...)...)
			env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
			if tc.oidc {
				env = append(env, oidcEnv...)
			}
			cmd.Env = env
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			log := out.String()
			if code != tc.wantCode || !strings.Contains(log, tc.want) {
				t.Fatalf("exit %d, want %d; log:\n%s", code, tc.wantCode, log)
			}
			if got := ingested.Load(); got != tc.wantSent {
				t.Errorf("ingested %d times, want %d", got, tc.wantSent)
			}
			// The request token never reaches the log; the OIDC token only
			// in the ::add-mask:: command, which the runner hides.
			if strings.Contains(log, fakeRequestToken) {
				t.Errorf("request token in log:\n%s", log)
			}
			for _, l := range strings.Split(log, "\n") {
				if strings.Contains(l, fakeOIDCToken) && l != "::add-mask::"+fakeOIDCToken {
					t.Errorf("OIDC token in log line %q", l)
				}
			}
		})
	}
}
