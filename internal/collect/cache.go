package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// The response cache (Config.CacheDir) stores REST GET responses on disk so
// a re-run can send conditional requests (If-None-Match / If-Modified-Since)
// and an interrupted run can resume (Config.Resume). It is off by default.
//
// The cache holds API responses: repository lists, workflow contents and
// settings, the same sensitive data as graph.json. It never holds the token
// or any request header: the key is a hash that includes a token fingerprint,
// and an entry stores only the redacted path, validators, status, the Link
// header and the body. Directories are 0700 and files 0600.

const (
	cacheRunFile = "run.json"
	cacheDirMode = 0o700
)

// cacheEntry is one cached response, stored as <dir>/<key[:2]>/<key>.json.
type cacheEntry struct {
	URLRedacted  string    `json:"url_redacted"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Status       int       `json:"status"`
	Link         string    `json:"link,omitempty"`
	Body         []byte    `json:"body"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// response rebuilds the client response of a cached entry. Only the Link
// header is kept, for pagination.
func (e *cacheEntry) response() *response {
	h := http.Header{}
	if e.Link != "" {
		h.Set("Link", e.Link)
	}
	return &response{status: e.Status, header: h, body: e.Body}
}

// cacheRun is <dir>/run.json, written when a run starts and removed when it
// succeeds. Its presence means the last run with this cache was interrupted.
type cacheRun struct {
	StartedAt  time.Time `json:"started_at"`
	Enterprise string    `json:"enterprise"`
	Orgs       []string  `json:"orgs"`
}

// CacheStats counts how cached GET requests were answered.
type CacheStats struct {
	// Hits were answered 304 Not Modified and served from the cache.
	Hits int
	// Fetched were downloaded (no entry, or the entry changed).
	Fetched int
	// Resumed were served from entries of the interrupted run without a request.
	Resumed int
}

// responseCache is the on-disk cache shared by every copy of a Client.
type responseCache struct {
	dir string
	// resumeSince, when set, makes entries fetched after it usable without
	// revalidation (Config.Resume after an interrupted run).
	resumeSince time.Time

	mu    sync.Mutex
	stats CacheStats
	// warned is set after the first write error is logged.
	warned bool
}

// openCache creates (or opens) the cache directory. An existing directory
// that other users can read is refused, since the cache holds API responses.
func openCache(dir string) (*responseCache, error) {
	if dir == "" {
		return nil, errors.New("collect: cache directory is empty")
	}
	if err := os.MkdirAll(dir, cacheDirMode); err != nil {
		return nil, fmt.Errorf("collect: creating cache directory: %w", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("collect: cache directory: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("collect: cache path %s is not a directory", dir)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("collect: cache directory %s is accessible by other users (mode %04o); run chmod 700 on it", dir, st.Mode().Perm())
	}
	return &responseCache{dir: dir}, nil
}

// tokenFingerprint is the first 16 hex digits of sha256(token). It keeps
// responses for different tokens apart without storing the token.
func tokenFingerprint(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])[:16]
}

// cacheKey derives the entry key from the request method, the absolute URL
// (scheme, host, path and query), the Accept media type and the token
// fingerprint.
func cacheKey(method string, u *url.URL, accept, tok string) string {
	s := sha256.Sum256([]byte(method + " " + u.String() + "\x00" + accept + "\x00" + tokenFingerprint(tok)))
	return hex.EncodeToString(s[:])
}

func (rc *responseCache) entryPath(key string) string {
	return filepath.Join(rc.dir, key[:2], key+".json")
}

// load returns the entry for key, or nil when there is none or it is unreadable.
func (rc *responseCache) load(key string) *cacheEntry {
	data, err := os.ReadFile(rc.entryPath(key))
	if err != nil {
		return nil
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil || e.Status != http.StatusOK {
		return nil
	}
	return &e
}

// store writes the entry for key atomically.
func (rc *responseCache) store(key string, e *cacheEntry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(rc.dir, key[:2]), key+".json", data)
}

// resumable reports whether an entry was fetched by the interrupted run and
// can be used without a request.
func (rc *responseCache) resumable(e *cacheEntry) bool {
	return !rc.resumeSince.IsZero() && e.FetchedAt.After(rc.resumeSince)
}

func (rc *responseCache) count(f func(*CacheStats)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	f(&rc.stats)
}

// Stats returns the counts so far.
func (rc *responseCache) Stats() CacheStats {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.stats
}

// warnOnce reports whether a write error should be logged (the first one only).
func (rc *responseCache) warnOnce() bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.warned {
		return false
	}
	rc.warned = true
	return true
}

// writeFileAtomic writes dir/name with mode 0600 through a temp file and a
// rename, creating dir with mode 0700.
func writeFileAtomic(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, cacheDirMode); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	ok = true
	return nil
}

// normOrgs returns the lower-cased, sorted org list for run.json comparison.
func normOrgs(orgs []string) []string {
	out := make([]string, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, strings.ToLower(strings.TrimSpace(o)))
	}
	sort.Strings(out)
	return out
}

// beginRun reads an interrupted run's run.json and writes this run's. With
// resume set and a run.json for the same enterprise and orgs, entries fetched
// after that run started are reused without revalidation, and its start time
// is kept so a second interruption still resumes everything since then.
// resumed reports whether entries will be reused.
func (rc *responseCache) beginRun(enterprise string, orgs []string, resume bool, now time.Time) (resumed bool, err error) {
	path := filepath.Join(rc.dir, cacheRunFile)
	want := cacheRun{StartedAt: now.UTC(), Enterprise: enterprise, Orgs: normOrgs(orgs)}
	if data, rerr := os.ReadFile(path); rerr == nil && resume {
		var prev cacheRun
		if json.Unmarshal(data, &prev) == nil && !prev.StartedAt.IsZero() &&
			prev.Enterprise == want.Enterprise && strings.Join(prev.Orgs, ",") == strings.Join(want.Orgs, ",") {
			rc.resumeSince = prev.StartedAt
			return true, nil
		}
	} else if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return false, fmt.Errorf("collect: reading %s: %w", cacheRunFile, rerr)
	}
	data, err := json.Marshal(want)
	if err != nil {
		return false, err
	}
	if err := writeFileAtomic(rc.dir, cacheRunFile, data); err != nil {
		return false, fmt.Errorf("collect: writing %s: %w", cacheRunFile, err)
	}
	return false, nil
}

// endRun removes run.json after a successful run.
func (rc *responseCache) endRun() error {
	err := os.Remove(filepath.Join(rc.dir, cacheRunFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// observedTracker remembers when the body of the last response was fetched,
// when it came from the cache without a new download. Copies of a Client
// share it, like the rate tracker.
type observedTracker struct {
	mu sync.Mutex
	at time.Time // zero: the last response was observed now
}

func (o *observedTracker) set(t time.Time) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.at = t
	o.mu.Unlock()
}

// servedAt returns the fetch time of the last response when it was served
// from the cache without revalidation, or the zero time when it was observed
// by this run (downloaded, or confirmed by a 304).
func (c *Client) servedAt() time.Time {
	if c.observed == nil {
		return time.Time{}
	}
	c.observed.mu.Lock()
	defer c.observed.mu.Unlock()
	return c.observed.at
}

// withCache returns a copy of c that uses rc for GET requests.
func (c *Client) withCache(rc *responseCache) *Client {
	cp := *c
	cp.cache = rc
	return &cp
}

// cacheable reports whether a request may use the cache: GET only, never
// the App JWT client (onlyPrefix) and never without a cache.
func (c *Client) cacheable(method string) bool {
	return c.cache != nil && method == http.MethodGet && c.onlyPrefix == ""
}

// cacheRevalidated handles a 304 for ent: the body is current, so the entry's
// fetched_at moves to now (a resumed run then skips it too) and the cached
// body is returned.
func (c *Client) cacheRevalidated(key string, ent *cacheEntry) *response {
	c.cache.count(func(s *CacheStats) { s.Hits++ })
	ent.FetchedAt = c.now().UTC()
	if err := c.cache.store(key, ent); err != nil && c.cache.warnOnce() {
		c.logf("collect: cache: writing an entry failed, continuing without it: %v", err)
	}
	return ent.response()
}

// cacheStore saves a fresh response when it is a 200 with a validator.
// Errors, other 2xx statuses and responses without ETag or Last-Modified are
// never stored.
func (c *Client) cacheStore(key string, u *url.URL, r *response) {
	c.cache.count(func(s *CacheStats) { s.Fetched++ })
	etag, lm := r.header.Get("ETag"), r.header.Get("Last-Modified")
	if r.status != http.StatusOK || (etag == "" && lm == "") || key == "" {
		return
	}
	e := &cacheEntry{
		URLRedacted: redactedPath(u), ETag: etag, LastModified: lm, Status: r.status,
		Link: r.header.Get("Link"), Body: r.body, FetchedAt: c.now().UTC(),
	}
	if err := c.cache.store(key, e); err != nil && c.cache.warnOnce() {
		c.logf("collect: cache: writing an entry failed, continuing without it: %v", err)
	}
}

// observedAt is the ObservedAt of an edge built now: the run time, or the
// fetch time of the last response when it was served from the cache of an
// interrupted run without a request. Collection is sequential and edges are
// built from the response just read, so the last response is the edge's
// source.
func (k *collector) observedAt() time.Time {
	if t := k.c.servedAt(); !t.IsZero() && t.Before(k.now) {
		return t.UTC()
	}
	return k.now
}
