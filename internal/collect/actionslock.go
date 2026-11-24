package collect

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/peleduri/gop/internal/graph"
)

// The GitHub Actions dependency lockfile, written by gh actions-lock. The
// format follows github/actions-lockfile (schema v0.0.3, parser reads v0.0.1
// to v0.0.3); docs/actions-lock.md names the upstream commits read.
//
//	version: 'v0.0.3'
//	workflows:                      # workflow path -> flat, transitive pin keys
//	  '.github/workflows/ci.yml':
//	    - 'actions/checkout@v4'
//	dependencies:                   # pin key -> resolved metadata
//	  'actions/checkout@v4':
//	    ref: 'v4'
//	    commit: 'sha1-<40 hex>'
//	    owner_id: 1
//	    repo_id: 1
//	    uses: ['owner/repo@ref']    # composite actions only
//
// A pin key is OWNER/REPO@REF: owner and repo lowercased, the ref as written,
// no sub-action path (actions/cache/save@v4 is locked as actions/cache@v4).
const (
	actionsLockName = "actions.lock"
	actionsLockPath = ".github/workflows/" + actionsLockName
	// maxActionsLockSize matches the upstream parser's MaxParseSize.
	maxActionsLockSize = 1 << 20
)

// actionsLockVersions are the schema versions the upstream parser reads.
var actionsLockVersions = map[string]bool{"v0.0.1": true, "v0.0.2": true, "v0.0.3": true}

// actionsLock is a parsed lockfile.
type actionsLock struct {
	workflows map[string]map[string]bool // workflow path -> pin keys
	commits   map[string]string          // pin key -> lowercase commit hex
}

// parseActionsLock parses a lockfile. Any shape the upstream parser would
// reject that gop relies on (an unknown version, a bad pin key or commit) is
// an error: gop then treats the repo's refs as not locked.
func parseActionsLock(data []byte) (*actionsLock, error) {
	if len(data) > maxActionsLockSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", actionsLockName, maxActionsLockSize)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
	}
	w := &yamlWalk{}
	root, err := w.mapping(rootMap(&doc), "lockfile")
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
	}
	vn, err := w.resolve(field(root, "version"))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
	}
	version := ""
	if vn != nil && vn.Kind == yaml.ScalarNode {
		version = vn.Value
	}
	if !actionsLockVersions[version] {
		return nil, fmt.Errorf("%s version %q is not one gop reads (v0.0.1 to v0.0.3)", actionsLockName, version)
	}
	v001 := version == "v0.0.1"
	l := &actionsLock{workflows: map[string]map[string]bool{}, commits: map[string]string{}}

	deps, err := w.mapping(field(root, "dependencies"), "dependencies")
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
	}
	for _, key := range deps.keys {
		pin, ok := lockPinKey(key, v001)
		if !ok {
			return nil, fmt.Errorf("%s: dependency key %q is not owner/repo@ref", actionsLockName, key)
		}
		dm, err := w.mapping(field(deps, key), "dependency")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
		}
		cn, err := w.resolve(field(dm, "commit"))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
		}
		commit := ""
		if cn != nil && cn.Kind == yaml.ScalarNode {
			commit, ok = lockCommit(cn.Value)
		}
		if commit == "" || !ok {
			return nil, fmt.Errorf("%s: dependency %q has no valid commit (want sha1-<hex> or sha256-<hex>)", actionsLockName, key)
		}
		l.commits[pin] = commit
	}

	wfs, err := w.mapping(field(root, "workflows"), "workflows")
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
	}
	for _, path := range wfs.keys {
		items, err := w.sequence(field(wfs, path), "[]pin")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
		}
		set := map[string]bool{}
		for _, it := range items {
			n, err := w.resolve(it)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", actionsLockName, err)
			}
			if n == nil || n.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s: workflow %q lists a non-string pin", actionsLockName, path)
			}
			pin, ok := lockPinKey(n.Value, v001)
			if !ok {
				return nil, fmt.Errorf("%s: workflow %q pin %q is not owner/repo@ref", actionsLockName, path, n.Value)
			}
			set[pin] = true
		}
		l.workflows[path] = set
	}
	return l, nil
}

// lockPinKey canonicalizes a pin key like the upstream ParsePin: split at the
// first "@", exactly one "/" before it, owner and repo lowercased, the ref
// kept as written. v0.0.1 keys may end in ":<algo>-<hex>", which is dropped.
func lockPinKey(s string, v001 bool) (string, bool) {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return "", false
	}
	nwo, ref := s[:at], s[at+1:]
	if v001 {
		if c := strings.LastIndexByte(ref, ':'); c > 0 {
			if _, ok := lockCommit(ref[c+1:]); ok {
				ref = ref[:c]
			}
		}
	}
	owner, repo, ok := strings.Cut(nwo, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") || ref == "" {
		return "", false
	}
	return strings.ToLower(owner) + "/" + strings.ToLower(repo) + "@" + ref, true
}

// lockCommit returns the hex digest of "sha1-<40 hex>" or "sha256-<64 hex>",
// lowercased.
func lockCommit(s string) (string, bool) {
	algo, hex, ok := strings.Cut(s, "-")
	if !ok {
		return "", false
	}
	want := map[string]int{"sha1": 40, "sha256": 64}[algo]
	if want == 0 || len(hex) != want {
		return "", false
	}
	for _, c := range hex {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return "", false
		}
	}
	return strings.ToLower(hex), true
}

// usePinKey is the lockfile pin key of an action_ref node: owner/repo@ref,
// without a sub-action path.
func usePinKey(n *graph.Node) string {
	return strings.ToLower(n.Attrs["owner"]+"/"+n.Attrs["repo"]) + "@" + n.Attrs["ref"]
}

// errLockNotFile is the read error of an actions.lock that is not a regular file.
var errLockNotFile = errors.New("actions.lock is not a regular file")

// noteActionsLock records the result of reading one repo's lockfile:
// data, or err when it was listed but could not be read or parsed.
func (k *collector) noteActionsLock(repo *graph.Node, data []byte, err error) {
	full := strings.TrimPrefix(repo.ID, "repo:")
	if err == nil {
		var l *actionsLock
		if l, err = parseActionsLock(data); err == nil {
			if k.locks == nil {
				k.locks = map[string]*actionsLock{}
			}
			k.locks[repo.ID] = l
			setAttr(repo, graph.AttrActionsLock, "true", graph.Live)
			return
		}
		setAttr(repo, graph.AttrActionsLock, "unknown", graph.Live)
		k.cover(repo.ID, graph.AttrActionsLock, err.Error()+"; its refs count as not locked",
			"fix "+actionsLockPath+" in "+full+" (rerun gh actions-lock)")
		return
	}
	setAttr(repo, graph.AttrActionsLock, "unknown", graph.NotVisible)
	fix := "read access to contents on " + full
	if errors.Is(err, errLockNotFile) || errors.Is(err, errTooLarge) {
		fix = "review " + actionsLockPath + " in " + full + " by hand"
	} else {
		fix = k.fixFor(err, fix)
	}
	k.cover(repo.ID, graph.AttrActionsLock, "could not read "+actionsLockPath+": "+err.Error()+"; its refs count as not locked", fix)
}

// applyActionsLocks marks every workflow USES edge of a repo with a lockfile
// actions_lock=locked (with locked_sha) or stale. It runs after
// expandNested, so it can check that the lockfile pins the nested refs gop
// saw under a locked action too. Remote reusable workflows are skipped: gh
// actions-lock does not lock them.
func (k *collector) applyActionsLocks() {
	if len(k.locks) == 0 {
		return
	}
	nested := map[string][]string{}
	var keys []string
	for key, e := range k.edges {
		if e.Kind != graph.Uses {
			continue
		}
		if strings.HasPrefix(e.From, "action:") {
			nested[e.From] = append(nested[e.From], e.To)
		} else {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		e := k.edges[key]
		wn, an := k.nodes[e.From], k.nodes[e.To]
		if wn == nil || an == nil || wn.Kind != graph.KindWorkflow || an.Attrs["reusable_workflow"] == "true" {
			continue
		}
		l := k.locks["repo:"+wn.Attrs["repo"]]
		if l == nil {
			continue
		}
		path := wn.Attrs["path"]
		pins, listed := l.workflows[path]
		pin := usePinKey(an)
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		if commit, ok := l.commits[pin]; listed && pins[pin] && ok {
			missing := k.lockMissing(e.To, pins, nested)
			if len(missing) == 0 {
				e.Attrs[graph.AttrActionsLock] = graph.LockLocked
				e.Attrs[graph.AttrLockedSHA] = commit
				continue
			}
			e.Attrs[graph.AttrActionsLock] = graph.LockStale
			e.Attrs[graph.AttrLockMissing] = strings.Join(missing, ",")
			k.cover(e.From, graph.AttrActionsLock+":"+pin,
				actionsLockName+" pins "+pin+" but not the nested "+strings.Join(missing, ", ")+": the lock is stale, so the use counts as unpinned",
				"rerun gh actions-lock in "+wn.Attrs["repo"])
			continue
		}
		e.Attrs[graph.AttrActionsLock] = graph.LockStale
		var reason string
		if !listed {
			reason = actionsLockName + " has no entry for " + path
		} else {
			same := lockSameRepo(pins, pin)
			if len(same) > 0 {
				e.Attrs[graph.AttrLockEntry] = strings.Join(same, ",")
				reason = actionsLockName + " pins " + strings.Join(same, ", ") + " but the workflow uses " + pin
			} else {
				reason = actionsLockName + " does not pin " + pin + " for " + path
			}
		}
		k.cover(e.From, graph.AttrActionsLock+":"+pin, reason+": the lock is stale, so the use counts as unpinned",
			"rerun gh actions-lock in "+wn.Attrs["repo"])
	}
}

// lockMissing lists, sorted, the nested refs under action (as collected)
// whose pin key the workflow's lockfile entry does not hold.
func (k *collector) lockMissing(action string, pins map[string]bool, nested map[string][]string) []string {
	seen := map[string]bool{action: true}
	queue := []string{action}
	var missing []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, to := range nested[cur] {
			if seen[to] {
				continue
			}
			seen[to] = true
			queue = append(queue, to)
			n := k.nodes[to]
			if n == nil {
				continue
			}
			if p := usePinKey(n); !pins[p] && !slices.Contains(missing, p) {
				missing = append(missing, p)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// lockSameRepo lists, sorted, the pins for the same owner/repo as pin.
func lockSameRepo(pins map[string]bool, pin string) []string {
	prefix := pin[:strings.IndexByte(pin, '@')+1]
	var out []string
	for p := range pins {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
