package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// pagedOSV serves querybatch one advisory ID per page: a result with more
// IDs left carries next_page_token, and the query must come back with it as
// page_token. With loop set, every page of a package returns the same token.
func pagedOSV(t *testing.T, byPkg map[string][]string, loop bool) (*httptest.Server, *[][]string) {
	t.Helper()
	var mu sync.Mutex
	var requests [][]string // per request: name#token of each query
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		var q struct {
			Queries []struct {
				Package   Package `json:"package"`
				PageToken string  `json:"page_token"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns         []vuln `json:"vulns,omitempty"`
			NextPageToken string `json:"next_page_token,omitempty"`
		}
		var out struct {
			Results []result `json:"results"`
		}
		var seen []string
		for _, qq := range q.Queries {
			seen = append(seen, qq.Package.Name+"#"+qq.PageToken)
			all := byPkg[qq.Package.Name]
			page := 0
			if qq.PageToken != "" {
				n, err := strconv.Atoi(strings.TrimPrefix(qq.PageToken, "p"))
				if err != nil {
					http.Error(w, "bad token", http.StatusBadRequest)
					return
				}
				page = n
			}
			var res result
			if page < len(all) {
				res.Vulns = []vuln{{all[page]}}
			}
			switch {
			case loop:
				res.NextPageToken = "p1"
			case page+1 < len(all):
				res.NextPageToken = "p" + strconv.Itoa(page+1)
			}
			out.Results = append(out.Results, res)
		}
		mu.Lock()
		requests = append(requests, seen)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

// queryBatch follows next_page_token until every package's advisory list ends,
// and re-sends only the queries that have more pages.
func TestQueryBatchFollowsPageTokens(t *testing.T) {
	byPkg := map[string][]string{
		"acme-actions/deploy": {"GHSA-aaaa-0001", "GHSA-aaaa-0002", "GHSA-aaaa-0003"},
		"acme-actions/setup":  {"GHSA-bbbb-0001"},
	}
	srv, requests := pagedOSV(t, byPkg, false)
	ids, err := queryBatch(context.Background(), srv.Client(), srv.URL, []string{"acme-actions/deploy", "acme-actions/setup"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for id := range ids {
		got = append(got, id)
	}
	sort.Strings(got)
	want := []string{"GHSA-aaaa-0001", "GHSA-aaaa-0002", "GHSA-aaaa-0003", "GHSA-bbbb-0001"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ids %v, want %v", got, want)
	}
	wantReq := [][]string{
		{"acme-actions/deploy#", "acme-actions/setup#"},
		{"acme-actions/deploy#p1"},
		{"acme-actions/deploy#p2"},
	}
	if !reflect.DeepEqual(*requests, wantReq) {
		t.Errorf("requests %v, want %v", *requests, wantReq)
	}
}

// A token that never ends is an error, not a silent partial list or a hang.
func TestQueryBatchTokenLoop(t *testing.T) {
	srv, _ := pagedOSV(t, map[string][]string{"acme-actions/deploy": {"GHSA-aaaa-0001", "GHSA-aaaa-0002"}}, true)
	_, err := queryBatch(context.Background(), srv.Client(), srv.URL, []string{"acme-actions/deploy"})
	if err == nil || !strings.Contains(err.Error(), "do not end") {
		t.Errorf("err %v", err)
	}
}
