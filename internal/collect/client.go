// Package collect reads a GitHub Enterprise through the REST and GraphQL APIs
// and builds gop's evidence graph.
package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public GitHub REST API root.
	DefaultBaseURL = "https://api.github.com"

	defaultMaxAttempts = 5
	defaultMaxWait     = 5 * time.Minute
	defaultTimeout     = 60 * time.Second
	maxBodyBytes       = 32 << 20
	maxBackoff         = 30 * time.Second
)

// ClientOptions configures a Client. Only Token is required.
type ClientOptions struct {
	// BaseURL is the REST API root (default https://api.github.com; for GHES
	// "https://HOST/api/v3").
	BaseURL string
	// GraphQLURL defaults to BaseURL + "/graphql" (GHES: "https://HOST/api/graphql").
	GraphQLURL string
	Token      string
	HTTPClient *http.Client
	// MaxAttempts caps tries per request, including the first (default 5).
	MaxAttempts int
	// MaxWait is the longest single rate-limit wait the client accepts before
	// giving up (default 5m).
	MaxWait time.Duration
	// Timeout per HTTP attempt when HTTPClient is nil (default 60s).
	Timeout time.Duration
	// Logf, when set, receives progress lines. It never receives the token.
	Logf func(format string, args ...any)
}

// Client is a small, sequential GitHub API client.
type Client struct {
	base        *url.URL
	graphqlURL  string
	token       string
	http        *http.Client
	maxAttempts int
	maxWait     time.Duration
	logf        func(string, ...any)
	sleep       func(ctx context.Context, d time.Duration) error
	now         func() time.Time
}

// NewClient builds a Client from options.
func NewClient(o ClientOptions) (*Client, error) {
	if o.Token == "" {
		return nil, errors.New("collect: token is required")
	}
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	base, err := url.Parse(strings.TrimRight(o.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("collect: invalid base URL %q", o.BaseURL)
	}
	if o.GraphQLURL == "" {
		o.GraphQLURL = base.String() + "/graphql"
	}
	hc := o.HTTPClient
	if hc == nil {
		t := o.Timeout
		if t <= 0 {
			t = defaultTimeout
		}
		hc = &http.Client{Timeout: t}
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = defaultMaxAttempts
	}
	if o.MaxWait <= 0 {
		o.MaxWait = defaultMaxWait
	}
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Client{
		base:        base,
		graphqlURL:  o.GraphQLURL,
		token:       o.Token,
		http:        hc,
		maxAttempts: o.MaxAttempts,
		maxWait:     o.MaxWait,
		logf:        logf,
		sleep:       sleepCtx,
		now:         time.Now,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// APIError is a non-retryable (or exhausted) HTTP error. It never contains the token.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Message    string
	// header holds the response headers, for callers that inspect
	// X-GitHub-SSO or rate-limit headers through ResponseHeader. It is never
	// printed: header values are not part of Error().
	header http.Header
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("github api %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("github api %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

// StatusOf returns the HTTP status of an *APIError in err's chain, or 0.
func StatusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode
	}
	return 0
}

// ResponseHeader returns the response headers of an *APIError in err's
// chain, or nil.
func ResponseHeader(err error) http.Header {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.header
	}
	return nil
}

// IsNotFound reports whether err is an HTTP 404.
func IsNotFound(err error) bool { return StatusOf(err) == http.StatusNotFound }

// IsForbidden reports whether err is an HTTP 401 or 403.
func IsForbidden(err error) bool {
	s := StatusOf(err)
	return s == http.StatusForbidden || s == http.StatusUnauthorized
}

// redactedPath returns the request path and query for messages.
func redactedPath(u *url.URL) string {
	if u.RawQuery == "" {
		return u.Path
	}
	return u.Path + "?" + u.RawQuery
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends one logical request with retries for 5xx, network errors and rate limits.
func (c *Client) do(ctx context.Context, method string, u *url.URL, body []byte) (*response, error) {
	var lastErr error
	backoff := time.Second
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return nil, fmt.Errorf("github api %s %s: %w", method, redactedPath(u), err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "gop-collector")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Transport errors (timeouts, resets) are retried. The URL carries no secret.
			lastErr = fmt.Errorf("github api %s %s: transport error: %w", method, redactedPath(u), unwrapURLError(err))
			if attempt < c.maxAttempts {
				if err := c.sleep(ctx, backoff); err != nil {
					return nil, err
				}
				backoff = nextBackoff(backoff)
			}
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()
		if rerr != nil {
			lastErr = fmt.Errorf("github api %s %s: reading body: %w", method, redactedPath(u), rerr)
			continue
		}
		r := &response{status: resp.StatusCode, header: resp.Header, body: data}
		if r.status >= 200 && r.status < 300 {
			return r, nil
		}
		apiErr := &APIError{Method: method, Path: redactedPath(u), StatusCode: r.status, Message: errorMessage(data), header: r.header}
		if wait, limited := c.rateLimitWait(r); limited {
			lastErr = apiErr
			if wait > c.maxWait {
				return nil, fmt.Errorf("%w (rate limited; wait %s exceeds max wait %s)", apiErr, wait.Round(time.Second), c.maxWait)
			}
			if attempt < c.maxAttempts {
				c.logf("collect: rate limited on %s, waiting %s", redactedPath(u), wait.Round(time.Second))
				if err := c.sleep(ctx, wait); err != nil {
					return nil, err
				}
			}
			continue
		}
		if r.status >= 500 {
			lastErr = apiErr
			if attempt < c.maxAttempts {
				c.logf("collect: HTTP %d on %s, retrying", r.status, redactedPath(u))
				if err := c.sleep(ctx, backoff); err != nil {
					return nil, err
				}
				backoff = nextBackoff(backoff)
			}
			continue
		}
		return nil, apiErr
	}
	return nil, fmt.Errorf("gave up after %d attempts: %w", c.maxAttempts, lastErr)
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// rateLimitWait detects primary and secondary rate limits and returns how long to wait.
func (c *Client) rateLimitWait(r *response) (time.Duration, bool) {
	if r.status != http.StatusTooManyRequests && r.status != http.StatusForbidden {
		return 0, false
	}
	if ra := r.header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
		if t, err := http.ParseTime(ra); err == nil {
			return clampWait(t.Sub(c.now())), true
		}
	}
	if r.header.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(r.header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return clampWait(time.Unix(reset, 0).Sub(c.now()) + time.Second), true
		}
		return time.Minute, true
	}
	if r.status == http.StatusTooManyRequests ||
		strings.Contains(strings.ToLower(string(r.body)), "secondary rate limit") {
		// GitHub asks clients to wait at least one minute without a header.
		return time.Minute, true
	}
	return 0, false
}

func clampWait(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d
}

func errorMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return truncate(m.Message, 200)
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// resolve turns an API path ("/orgs/x/repos?type=all") into a URL under BaseURL.
func (c *Client) resolve(path string) (*url.URL, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.Parse(c.base.String() + path)
	if err != nil {
		return nil, fmt.Errorf("collect: bad path %q: %w", path, err)
	}
	return u, nil
}

// GetJSON fetches one REST resource and decodes it into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	_, err := c.GetJSONHeader(ctx, path, out)
	return err
}

// GetJSONHeader is GetJSON that also returns the response headers. On an
// HTTP error the headers are available through ResponseHeader(err).
func (c *Client) GetJSONHeader(ctx context.Context, path string, out any) (http.Header, error) {
	u, err := c.resolve(path)
	if err != nil {
		return nil, err
	}
	r, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			return r.header, fmt.Errorf("github api GET %s: decoding response: %w", redactedPath(u), err)
		}
	}
	return r.header, nil
}

// GetPages fetches a REST collection, following Link rel="next" headers, and
// calls fn with each page's raw JSON body. Next links must stay on the
// BaseURL's scheme and host so the token is never sent elsewhere.
func (c *Client) GetPages(ctx context.Context, path string, fn func(page []byte) error) error {
	u, err := c.resolve(path)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for u != nil {
		if seen[u.String()] {
			return fmt.Errorf("github api GET %s: pagination loop", redactedPath(u))
		}
		seen[u.String()] = true
		r, err := c.do(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		if err := fn(r.body); err != nil {
			return err
		}
		next := parseLinkNext(r.header.Get("Link"))
		if next == "" {
			return nil
		}
		nu, err := u.Parse(next)
		if err != nil {
			return fmt.Errorf("github api GET %s: bad next link: %w", redactedPath(u), err)
		}
		if nu.Scheme != c.base.Scheme || nu.Host != c.base.Host {
			return fmt.Errorf("github api GET %s: next link points off the API host, refusing to follow", redactedPath(u))
		}
		u = nu
	}
	return nil
}

// parseLinkNext returns the rel="next" target of an RFC 8288 Link header.
func parseLinkNext(h string) string {
	for _, part := range strings.Split(h, ",") {
		segs := strings.Split(part, ";")
		if len(segs) < 2 {
			continue
		}
		target := strings.TrimSpace(segs[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, p := range segs[1:] {
			p = strings.TrimSpace(p)
			if strings.EqualFold(p, `rel="next"`) || strings.EqualFold(p, "rel=next") {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}

// GraphQLError is one entry of a GraphQL "errors" array.
type GraphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Path    []any  `json:"path"`
}

// GraphQLErrors is a list of field-level GraphQL errors returned with partial data.
type GraphQLErrors []GraphQLError

func (e GraphQLErrors) Error() string {
	if len(e) == 0 {
		return "graphql: no errors"
	}
	types := make([]string, 0, len(e))
	for _, x := range e {
		t := x.Type
		if t == "" {
			t = truncate(x.Message, 120)
		}
		types = append(types, t)
	}
	return "graphql errors: " + strings.Join(types, ", ")
}

// HasType reports whether any error has the given type (e.g. "FORBIDDEN").
func (e GraphQLErrors) HasType(t string) bool {
	for _, x := range e {
		if x.Type == t {
			return true
		}
	}
	return false
}

// GraphQL runs a query. Data (possibly partial) is decoded into out; field
// errors are returned as GraphQLErrors alongside a nil error. Transport and
// HTTP failures are returned as error.
func (c *Client) GraphQL(ctx context.Context, query string, vars map[string]any, out any) (GraphQLErrors, error) {
	u, err := url.Parse(c.graphqlURL)
	if err != nil {
		return nil, fmt.Errorf("collect: invalid GraphQL URL: %w", err)
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		r, err := c.do(ctx, http.MethodPost, u, payload)
		if err != nil {
			return nil, err
		}
		var env struct {
			Data   json.RawMessage `json:"data"`
			Errors GraphQLErrors   `json:"errors"`
		}
		if err := json.Unmarshal(r.body, &env); err != nil {
			return nil, fmt.Errorf("graphql: decoding response: %w", err)
		}
		if env.Errors.HasType("RATE_LIMITED") && attempt < c.maxAttempts {
			wait, ok := c.rateLimitWait(&response{status: http.StatusTooManyRequests, header: r.header, body: r.body})
			if !ok {
				wait = time.Minute
			}
			if wait > c.maxWait {
				return nil, fmt.Errorf("graphql: rate limited; wait %s exceeds max wait", wait.Round(time.Second))
			}
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
			if err := json.Unmarshal(env.Data, out); err != nil {
				return env.Errors, fmt.Errorf("graphql: decoding data: %w", err)
			}
		}
		return env.Errors, nil
	}
}
