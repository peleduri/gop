package collect

import (
	"slices"
	"strconv"
	"strings"
)

// notVisibleTally counts the per-repository errors of one org and one fact
// (for example "collaborators") by HTTP status, so the default log prints one
// summary line per org instead of one line per repository. The coverage
// entries are written separately and do not depend on it.
type notVisibleTally struct {
	repos    int
	byStatus map[int]int // HTTP status (0 when the error has none) -> repos
}

// repoNotVisible records that fact could not be read on repo. With
// Config.Verbose it logs the per-repository line right away; otherwise the
// error is counted and logged by flushNotVisible at the end of the org.
func (k *collector) repoNotVisible(o *orgState, fact, repoID string, err error) {
	if k.cfg.Verbose {
		k.logf("collect: %s: %s not visible: %v", repoID, fact, err)
	}
	if o.notVisible == nil {
		o.notVisible = map[string]*notVisibleTally{}
	}
	t := o.notVisible[fact]
	if t == nil {
		t = &notVisibleTally{byStatus: map[int]int{}}
		o.notVisible[fact] = t
	}
	t.repos++
	t.byStatus[StatusOf(err)]++
}

// flushNotVisible logs one line per fact counted for o by repoNotVisible, for
// example "org acme-actions: collaborators not visible on 27 repos (HTTP 404:
// 26, HTTP 403: 1); see coverage", and resets the counts. Verbose runs already
// printed every repository, so they only get the summary too.
func (k *collector) flushNotVisible(o *orgState) {
	facts := make([]string, 0, len(o.notVisible))
	for f := range o.notVisible {
		facts = append(facts, f)
	}
	slices.Sort(facts)
	for _, f := range facts {
		k.logf("collect: %s", notVisibleLine(o.login, f, o.notVisible[f]))
	}
	o.notVisible = nil
}

// notVisibleLine renders one summary line. Statuses are listed by count,
// highest first, then by status; errors without an HTTP status count as "other".
func notVisibleLine(org, fact string, t *notVisibleTally) string {
	statuses := make([]int, 0, len(t.byStatus))
	for s := range t.byStatus {
		statuses = append(statuses, s)
	}
	slices.SortFunc(statuses, func(a, b int) int {
		if t.byStatus[a] != t.byStatus[b] {
			return t.byStatus[b] - t.byStatus[a]
		}
		return a - b
	})
	parts := make([]string, 0, len(statuses))
	for _, s := range statuses {
		label := "other"
		if s != 0 {
			label = "HTTP " + strconv.Itoa(s)
		}
		parts = append(parts, label+": "+strconv.Itoa(t.byStatus[s]))
	}
	noun := "repos"
	if t.repos == 1 {
		noun = "repo"
	}
	return "org " + org + ": " + fact + " not visible on " + strconv.Itoa(t.repos) + " " + noun +
		" (" + strings.Join(parts, ", ") + "); see coverage"
}
