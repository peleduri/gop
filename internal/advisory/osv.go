// Package advisory matches the action refs in a gop graph against OSV
// advisories for the "GitHub Actions" ecosystem (https://osv.dev): action
// versions that were compromised outright (a hijacked tag that shipped code
// stealing secrets) or that carry another published vulnerability.
//
// Data comes from a local copy of the ecosystem export (all.zip, written by
// gop advisories update, or a zip or directory the user points at) or, when
// asked, from the OSV query API. Loading and matching are offline; only Live
// and Download make requests, and never to GitHub.
//
// A ref is matched as a tag against the advisory's ranges and versions, and
// as a full commit SHA against the versions and the commits the advisory
// lists. A ref gop cannot place (a branch, a SHA the advisory does not list, a
// tag that only some affected versions share) is reported as unknown, never
// as safe.
package advisory

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Ecosystem is the OSV ecosystem name for GitHub Actions.
const Ecosystem = "GitHub Actions"

// Limits on local data: one record and the whole export.
const (
	maxRecordBytes = 4 << 20
	maxRecords     = 200_000
	// MaxZipBytes bounds all.zip, downloaded or supplied.
	MaxZipBytes = 512 << 20
)

// Record is the part of an OSV record gop reads.
type Record struct {
	ID               string           `json:"id"`
	Modified         string           `json:"modified,omitempty"`
	Withdrawn        string           `json:"withdrawn,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	Summary          string           `json:"summary,omitempty"`
	Affected         []Affected       `json:"affected"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific,omitempty"`
}

// DatabaseSpecific holds the GitHub advisory severity
// (CRITICAL, HIGH, MODERATE, LOW).
type DatabaseSpecific struct {
	Severity string `json:"severity,omitempty"`
}

// Affected is one affected package of a record.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package names an action: owner/repo or owner/repo/path.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is an OSV range: ECOSYSTEM or SEMVER over versions, GIT over commits.
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Event is one range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// DB is a set of GitHub Actions advisories indexed by package name.
type DB struct {
	// Source says where the data came from: a file path, or the API URL.
	Source string
	// AsOf is when the data was fetched: the file's modification time, or
	// the time of the live query.
	AsOf time.Time
	// Records counts the advisories loaded (withdrawn ones are dropped).
	Records int
	byName  map[string][]*Record
}

// NewDB indexes records. Withdrawn records and affected entries of other
// ecosystems are dropped.
func NewDB(source string, asOf time.Time, recs []Record) *DB {
	db := &DB{Source: source, AsOf: asOf, byName: map[string][]*Record{}}
	seen := map[string]bool{}
	for i := range recs {
		r := &recs[i]
		if r.ID == "" || r.Withdrawn != "" || seen[r.ID] {
			continue
		}
		keep := false
		names := map[string]bool{}
		for _, a := range r.Affected {
			if a.Package.Ecosystem != Ecosystem || a.Package.Name == "" {
				continue
			}
			n := strings.ToLower(a.Package.Name)
			if !names[n] {
				names[n] = true
				db.byName[n] = append(db.byName[n], r)
			}
			keep = true
		}
		if keep {
			seen[r.ID] = true
			db.Records++
		}
	}
	return db
}

// Load reads a zip of OSV JSON records (the ecosystem's all.zip) or a
// directory of *.json records.
func Load(path string) (*DB, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return loadDir(path, st.ModTime())
	}
	if st.Size() > MaxZipBytes {
		return nil, fmt.Errorf("%s: %d bytes is more than the %d byte limit", path, st.Size(), MaxZipBytes)
	}
	f, err := os.Open(path) // #nosec G304 -- the user names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	recs, err := readZip(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return NewDB(path, st.ModTime().UTC(), recs), nil
}

func readZip(r io.ReaderAt, size int64) ([]Record, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("not a zip of OSV records: %w", err)
	}
	var recs []Record
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(f.Name), ".json") {
			continue
		}
		if len(recs) >= maxRecords {
			return nil, fmt.Errorf("more than %d records", maxRecords)
		}
		if f.UncompressedSize64 > maxRecordBytes {
			return nil, fmt.Errorf("%s: record larger than %d bytes", f.Name, maxRecordBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		rec, err := decode(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func loadDir(dir string, mod time.Time) (*DB, error) {
	var recs []Record
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".json") {
			return nil
		}
		if len(recs) >= maxRecords {
			return fmt.Errorf("more than %d records", maxRecords)
		}
		f, err := os.Open(p) // #nosec G304 -- under the directory the user names
		if err != nil {
			return err
		}
		rec, err := decode(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		recs = append(recs, rec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return NewDB(dir, mod.UTC(), recs), nil
}

func decode(r io.Reader) (Record, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxRecordBytes+1))
	if err != nil {
		return Record{}, err
	}
	if len(b) > maxRecordBytes {
		return Record{}, fmt.Errorf("record larger than %d bytes", maxRecordBytes)
	}
	var rec Record
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("not an OSV record: %w", err)
	}
	return rec, nil
}

// ErrNoData is returned by DefaultPath's callers when no local copy exists.
var ErrNoData = errors.New("no advisory data")

// CacheFile is the file name of the local copy under the cache dir.
const CacheFile = "osv-github-actions.zip"

// DefaultPath is where gop advisories update writes the export:
// <user cache dir>/gop/osv-github-actions.zip.
func DefaultPath() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "gop", CacheFile), nil
}

// lookup returns the records for an action, most specific package name
// first: owner/repo/path, then owner/repo.
func (db *DB) lookup(owner, repo, path string) []*Record {
	if db == nil {
		return nil
	}
	base := strings.ToLower(owner + "/" + repo)
	var out []*Record
	seen := map[string]bool{}
	add := func(name string) {
		for _, r := range db.byName[name] {
			if !seen[r.ID] {
				seen[r.ID] = true
				out = append(out, r)
			}
		}
	}
	if path != "" {
		add(base + "/" + strings.ToLower(strings.Trim(path, "/")))
	}
	add(base)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
