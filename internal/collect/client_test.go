package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc, maxAttempts int) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientOptions{BaseURL: srv.URL, Token: testToken, MaxAttempts: maxAttempts})
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	return c, &waits
}

func TestClientRetries502(t *testing.T) {
	var n int32
	c, waits := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(502)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}, 3)
	var out struct{ OK bool }
	if err := c.GetJSON(context.Background(), "/x", &out); err != nil || !out.OK {
		t.Fatalf("GetJSON = %v, %+v", err, out)
	}
	if n != 2 || len(*waits) != 1 {
		t.Errorf("requests=%d waits=%v, want 2 and 1", n, *waits)
	}
}

func TestClientMaxAttempts(t *testing.T) {
	var n int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(503)
	}, 4)
	err := c.GetJSON(context.Background(), "/x", nil)
	if err == nil || StatusOf(err) != 503 || !strings.Contains(err.Error(), "gave up after 4 attempts") {
		t.Fatalf("err = %v", err)
	}
	if n != 4 {
		t.Errorf("requests = %d, want 4", n)
	}
}

func TestClientRateLimits(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   time.Duration
	}{
		{"429 retry-after", 429, map[string]string{"Retry-After": "7"}, `{}`, 7 * time.Second},
		{"403 secondary retry-after", 403, map[string]string{"Retry-After": "3"}, `{"message":"You have exceeded a secondary rate limit"}`, 3 * time.Second},
		{"403 secondary no header", 403, nil, `{"message":"You have exceeded a secondary rate limit"}`, time.Minute},
		{"403 primary reset", 403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1000010"}, `{}`, 11 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n int32
			c, waits := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&n, 1) == 1 {
					for k, v := range tc.header {
						w.Header().Set(k, v)
					}
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
					return
				}
				fmt.Fprint(w, `{}`)
			}, 3)
			c.now = func() time.Time { return time.Unix(1000000, 0) }
			if err := c.GetJSON(context.Background(), "/x", nil); err != nil {
				t.Fatal(err)
			}
			if len(*waits) != 1 || (*waits)[0] != tc.want {
				t.Errorf("waits = %v, want [%s]", *waits, tc.want)
			}
		})
	}
}

func TestClientRateLimitTooLong(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(429)
	}, 3)
	err := c.GetJSON(context.Background(), "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds max wait") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientPlain403NotRetried(t *testing.T) {
	var n int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(403)
		fmt.Fprint(w, `{"message":"Must have admin rights"}`)
	}, 3)
	err := c.GetJSON(context.Background(), "/x", nil)
	if !IsForbidden(err) || n != 1 {
		t.Fatalf("err=%v requests=%d", err, n)
	}
}

func TestClientPagination(t *testing.T) {
	var base string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		if page < 3 {
			w.Header().Set("Link", fmt.Sprintf(`<%s/items?page=%d>; rel="next", <%s/items?page=3>; rel="last"`, base, page+1, base))
		}
		json.NewEncoder(w).Encode([]int{page*10 + 1, page*10 + 2})
	}, 3)
	base = c.base.String()
	var all []int
	err := c.GetPages(context.Background(), "/items", func(p []byte) error {
		var b []int
		if err := json.Unmarshal(p, &b); err != nil {
			return err
		}
		all = append(all, b...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(all) != "[11 12 21 22 31 32]" {
		t.Errorf("items = %v", all)
	}
}

func TestClientRefusesForeignNextLink(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://elsewhere.example/items?page=2>; rel="next"`)
		fmt.Fprint(w, `[]`)
	}, 3)
	err := c.GetPages(context.Background(), "/items", func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "off the API host") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientErrorsCarryNoToken(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprintf(w, `{"message":"Bad credentials"}`)
	}, 3)
	err := c.GetJSON(context.Background(), "/x", nil)
	if err == nil || strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), "Bad credentials") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientGraphQLPartialErrors(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `{"data":{"organization":{"name":"x","ipAllowListEnabledSetting":null}},
			"errors":[{"type":"FORBIDDEN","path":["organization","ipAllowListEnabledSetting"],"message":"no"}]}`)
	}, 3)
	var out struct {
		Organization struct{ Name string } `json:"organization"`
	}
	errs, err := c.GraphQL(context.Background(), "query{}", nil, &out)
	if err != nil || !errs.HasType("FORBIDDEN") || out.Organization.Name != "x" {
		t.Fatalf("errs=%v err=%v out=%+v", errs, err, out)
	}
}

func TestClientContextCanceled(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }, 5)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	if err := c.GetJSON(ctx, "/x", nil); err != context.Canceled {
		t.Fatalf("err = %v", err)
	}
}

func TestParseLinkNext(t *testing.T) {
	h := `<https://api.example/x?page=1>; rel="prev", <https://api.example/x?page=3>; rel="next"`
	if got := parseLinkNext(h); got != "https://api.example/x?page=3" {
		t.Errorf("got %q", got)
	}
	if parseLinkNext("") != "" {
		t.Error("empty header should have no next")
	}
}
