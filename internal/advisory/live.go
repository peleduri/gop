package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
)

// Default endpoints. Neither is GitHub.
const (
	// DefaultZipURL is the OSV export of the GitHub Actions ecosystem.
	DefaultZipURL = "https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip"
	// DefaultAPIURL is the OSV API root used by --advisories-live.
	DefaultAPIURL = "https://api.osv.dev"
)

const (
	maxBatch         = 1000    // queries per querybatch request (the API's limit)
	maxResponseBytes = 8 << 20 // one API response
	maxPages         = 100     // querybatch pages per package, a guard against a token loop
)

// Packages lists the distinct owner/repo[/path] names of the action refs in
// g, sorted: what Live queries.
func Packages(g *graph.Graph) []string {
	set := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind != graph.KindActionRef {
			continue
		}
		r, ok := RefOf(n)
		if !ok {
			continue
		}
		set[r.Owner+"/"+r.Repo] = true
		if r.Path != "" {
			set[r.Owner+"/"+r.Repo+"/"+strings.Trim(r.Path, "/")] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Live queries the OSV API (POST /v1/querybatch by package name, following
// next_page_token, then GET /v1/vulns/{id} for each advisory it names) and returns the advisories of
// the given packages. Only package names leave the machine, never refs,
// workflow names or anything else from the graph.
func Live(ctx context.Context, client *http.Client, apiURL string, packages []string, now time.Time) (*DB, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	apiURL = strings.TrimRight(apiURL, "/")
	ids, err := queryBatch(ctx, client, apiURL, packages)
	if err != nil {
		return nil, err
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	recs := make([]Record, 0, len(sorted))
	for _, id := range sorted {
		var rec Record
		if err := doJSON(ctx, client, http.MethodGet, apiURL+"/v1/vulns/"+url.PathEscape(id), nil, &rec); err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return NewDB(apiURL, now.UTC(), recs), nil
}

// queryBatch asks POST /v1/querybatch for the advisory IDs of packages, at
// most maxBatch queries per request. A result with a next_page_token has more
// IDs: its query goes out again, with that page_token, in the next request,
// until no token is left. A package that still has a token after maxPages
// pages, or that returns the same token twice, is an error: the advisory
// list would be incomplete.
func queryBatch(ctx context.Context, client *http.Client, apiURL string, packages []string) (map[string]bool, error) {
	type pending struct {
		name, token string
		pages       int
		seen        map[string]bool
	}
	type query struct {
		Package   Package `json:"package"`
		PageToken string  `json:"page_token,omitempty"`
	}
	todo := make([]*pending, 0, len(packages))
	for _, p := range packages {
		todo = append(todo, &pending{name: p})
	}
	ids := map[string]bool{}
	for len(todo) > 0 {
		batch := todo[:min(maxBatch, len(todo))]
		todo = todo[len(batch):]
		body := struct {
			Queries []query `json:"queries"`
		}{}
		for _, p := range batch {
			body.Queries = append(body.Queries, query{Package{Ecosystem: Ecosystem, Name: p.name}, p.token})
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := doJSON(ctx, client, http.MethodPost, apiURL+"/v1/querybatch", body, &res); err != nil {
			return nil, err
		}
		if len(res.Results) != len(batch) {
			return nil, fmt.Errorf("osv: querybatch: %d results for %d queries", len(res.Results), len(batch))
		}
		for i, r := range res.Results {
			for _, v := range r.Vulns {
				if v.ID != "" {
					ids[v.ID] = true
				}
			}
			if r.NextPageToken == "" {
				continue
			}
			p := batch[i]
			if p.seen == nil {
				p.seen = map[string]bool{}
			}
			p.pages++
			if p.pages >= maxPages || p.seen[r.NextPageToken] {
				return nil, fmt.Errorf("osv: querybatch: %s: results do not end after %d pages", p.name, p.pages)
			}
			p.seen[r.NextPageToken] = true
			p.token = r.NextPageToken
			todo = append(todo, p)
		}
	}
	return ids, nil
}

func doJSON(ctx context.Context, client *http.Client, method, u string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req) // #nosec G704 -- the OSV API root, or a URL the user configures
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("osv: %s %s: %w", method, u, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s %s: HTTP %d", method, u, resp.StatusCode)
	}
	if len(b) > maxResponseBytes {
		return fmt.Errorf("osv: %s %s: response larger than %d bytes", method, u, maxResponseBytes)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("osv: %s %s: %w", method, u, err)
	}
	return nil
}

// Download fetches the ecosystem export from zipURL into dest (written
// atomically, 0644: it is public data) and returns how many advisories it
// holds. The file is checked to be a zip of OSV records before it replaces
// the old copy.
func Download(ctx context.Context, client *http.Client, zipURL, dest string) (int, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	if zipURL == "" {
		zipURL = DefaultZipURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req) // #nosec G704 -- the OSV export URL, or one the user configures
	if err != nil {
		return 0, fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download %s: HTTP %d", zipURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxZipBytes+1))
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", zipURL, err)
	}
	if len(b) > MaxZipBytes {
		return 0, fmt.Errorf("download %s: larger than %d bytes", zipURL, MaxZipBytes)
	}
	recs, err := readZip(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", zipURL, err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(filepath.Dir(dest), ".osv-*")
	if err != nil {
		return 0, err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return 0, err
	}
	if err := f.Chmod(0o644); err != nil { // #nosec G302 -- public advisory data
		_ = f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return 0, err
	}
	return NewDB(dest, time.Now(), recs).Records, nil
}

// Resolve picks the advisory source for a run, in order: path when set,
// else the live API when live is set, else the default local copy when it
// exists. It returns ErrNoData (wrapped, with the reason) when there is
// none; callers record that with Skip and go on.
func Resolve(ctx context.Context, g *graph.Graph, path string, live bool, client *http.Client, apiURL string, now time.Time) (*DB, error) {
	switch {
	case path != "":
		return Load(path)
	case live:
		return Live(ctx, client, apiURL, Packages(g), now)
	}
	def, err := DefaultPath()
	if err != nil {
		return nil, fmt.Errorf("%w: no user cache dir (%v)", ErrNoData, err)
	}
	if _, err := os.Stat(def); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: no local copy at %s", ErrNoData, def)
	}
	return Load(def)
}
