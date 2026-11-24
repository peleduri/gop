package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/peleduri/gop/internal/advisory"
	"github.com/peleduri/gop/internal/graph"
)

const advisoriesUsage = "OSV GitHub Actions advisories: a zip (all.zip) or a directory of OSV JSON records. " +
	"Default: the copy gop advisories update keeps in the user cache dir; without one the check is skipped (see coverage)"

const advisoriesLiveUsage = "query the OSV API (api.osv.dev) for the advisories of the graph's actions instead of a local copy. " +
	"Sends the action package names (owner/repo[/path]) only"

// advisoryFlags are --advisories and --advisories-live on collect and enrich.
type advisoryFlags struct {
	path *string
	live *bool
}

func addAdvisoryFlags(fs *flag.FlagSet) advisoryFlags {
	return advisoryFlags{
		path: fs.String("advisories", "", advisoriesUsage),
		live: fs.Bool("advisories-live", false, advisoriesLiveUsage),
	}
}

func (f advisoryFlags) set() bool { return *f.path != "" || *f.live }

func (f advisoryFlags) check(cmd string) error {
	if *f.path != "" && *f.live {
		return usagef("%s: use --advisories or --advisories-live, not both", cmd)
	}
	return nil
}

func (a *app) httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: a.transport}
}

func (a *app) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// applyAdvisories matches g's action refs against advisory data. It never
// fails the run: with no data, or data that cannot be read, it records a
// skipped coverage entry and says so on stderr.
func (a *app) applyAdvisories(ctx context.Context, cmd string, g *graph.Graph, f advisoryFlags) {
	path := *f.path
	if path == "" && !*f.live {
		if a.advisoryPath != nil {
			if def, err := a.advisoryPath(); err == nil {
				if _, err := os.Stat(def); err == nil {
					path = def
				}
			}
		}
		if path == "" {
			advisory.Skip(g, "no advisory data (run gop advisories update, or pass --advisories or --advisories-live)")
			fmt.Fprintf(a.stderr, "gop %s: advisories: skipped, no advisory data (run gop advisories update)\n", cmd)
			return
		}
	}
	var (
		db  *advisory.DB
		err error
	)
	if path != "" {
		db, err = advisory.Load(path)
	} else {
		db, err = advisory.Live(ctx, a.httpClient(2*time.Minute), a.osvAPIURL, advisory.Packages(g), a.clock())
	}
	if err != nil {
		reason := "advisory data could not be read: " + err.Error()
		if errors.Is(err, context.Canceled) {
			reason = "interrupted"
		}
		advisory.Skip(g, reason)
		fmt.Fprintf(a.stderr, "gop %s: advisories: skipped: %v\n", cmd, err)
		return
	}
	st := advisory.Annotate(g, db)
	fmt.Fprintf(a.stderr, "gop %s: advisories: %d advisories from %s (as of %s): %d of %d action refs affected, %d unknown (see coverage)\n",
		cmd, db.Records, db.Source, db.AsOf.UTC().Format(time.RFC3339), st.Affected, st.Actions, st.Unknown)
}

// cmdAdvisories is gop advisories update: download the OSV export.
func (a *app) cmdAdvisories(args []string) error {
	if len(args) == 0 || args[0] != "update" {
		return usagef("advisories: want gop advisories update [--out PATH]")
	}
	fs := a.flags("advisories update")
	out := fs.String("out", "", "where to write the export (default: <user cache dir>/gop/"+advisory.CacheFile+", where collect and enrich look)")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	dest := *out
	if dest == "" {
		if a.advisoryPath == nil {
			return usagef("advisories update: --out is required")
		}
		var err error
		if dest, err = a.advisoryPath(); err != nil {
			return fmt.Errorf("no user cache dir: %w (pass --out)", err)
		}
	}
	zipURL := a.osvZipURL
	if zipURL == "" {
		zipURL = advisory.DefaultZipURL
	}
	n, err := advisory.Download(context.Background(), a.httpClient(10*time.Minute), zipURL, dest)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "gop advisories: wrote %d GitHub Actions advisories from %s to %s\n", n, zipURL, dest)
	return nil
}
