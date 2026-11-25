// Package summary builds gop.summary/v1: a small, versioned JSON summary of
// one graph that is safe to send off the machine that collected it (to the
// optional gop Cloud service, see docs/cloud.md). It carries counts and
// coverage, never the graph: no tokens, emails, secret values, member logins
// or IP lists. Findings are identified by a stable hash by default; names of
// repos, workflows and orgs are added only when Options.Names is set.
package summary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/peleduri/gop/internal/graph"
	"github.com/peleduri/gop/internal/sanitize"
	"github.com/peleduri/gop/internal/sarif"
)

// Version is the schema of the summary document.
const Version = "gop.summary/v1"

// MaxBytes caps the serialized summary. Build drops top findings, last
// first, until the document fits, and sets Truncated.
const MaxBytes = 64 * 1024

// DefaultTop is the number of top findings kept when Options.Top is 0.
const DefaultTop = 20

// MaxTop is the largest Options.Top accepted.
const MaxTop = 500

// IDLength is the number of hex characters of a finding ID.
const IDLength = 16

// Options tune Build.
type Options struct {
	// Version is the gop version written to gop_version.
	Version string
	// Names adds repo, workflow and org names to the top findings. Off by
	// default: findings carry only their hash ID.
	Names bool
	// Top is the number of top findings to keep (0 means DefaultTop).
	Top int
}

// Summary is the gop.summary/v1 document.
type Summary struct {
	Schema     string    `json:"schema"`
	Enterprise string    `json:"enterprise"`
	GopVersion string    `json:"gop_version"`
	RunAt      time.Time `json:"run_at"`
	// Names says whether top findings carry names (--names).
	Names      bool         `json:"names"`
	Coverage   Coverage     `json:"coverage"`
	Headline   Headline     `json:"headline"`
	Pairs      Pairs        `json:"pairs"`
	Severities Severities   `json:"severities"`
	Rules      []RuleCount  `json:"rules"`
	Findings   int          `json:"findings"`
	Top        []TopFinding `json:"top"`
	// Truncated says Top was cut to keep the document under MaxBytes.
	Truncated bool `json:"truncated"`
}

// Coverage is what the collection could read.
type Coverage struct {
	// OrgsRead is the number of org nodes in the graph.
	OrgsRead int `json:"orgs_read"`
	// Partial and PartialReason repeat the graph's fields: the collection
	// stopped early.
	Partial       bool   `json:"partial"`
	PartialReason string `json:"partial_reason"`
	// NotVisible counts the nodes and edges with evidence not_visible.
	NotVisible int `json:"not_visible"`
	// CoverageEntries is the number of coverage entries (facts gop could
	// not read, each with the access that would fix it).
	CoverageEntries int `json:"coverage_entries"`
}

// Headline holds the headline numbers of the report.
type Headline struct {
	// NonHumanActors and the Merge counts are graph.NonHuman.
	NonHumanActors             int `json:"non_human_actors"`
	MergeWithoutHuman          int `json:"merge_without_human"`
	MergeWithoutHumanConfirmed int `json:"merge_without_human_confirmed"`
	MergeWithoutHumanPossible  int `json:"merge_without_human_possible"`
	// OutsiderTriggerableAgents counts confirmed AI agent workflows people
	// without push access can start (agent_exposure outsiders).
	OutsiderTriggerableAgents int `json:"outsider_triggerable_agents"`
	// DangerousModeAgents counts confirmed AI agent workflows run with their
	// approval or sandbox removed (graph.AgentUnrestricted).
	DangerousModeAgents int `json:"dangerous_mode_agents"`
}

// Pairs are the confirmed and possible (principal, repo) pair totals.
type Pairs struct {
	Confirmed int `json:"confirmed"`
	Possible  int `json:"possible"`
}

// Severities counts findings by severity.
type Severities struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func (s *Severities) add(sev string) {
	switch sev {
	case sarif.SeverityCritical:
		s.Critical++
	case sarif.SeverityHigh:
		s.High++
	case sarif.SeverityMedium:
		s.Medium++
	default:
		s.Low++
	}
}

// RuleCount counts the findings of one SARIF rule. Confirmed findings are
// counted by severity; Possible ones (a hop is not visible) only in total.
type RuleCount struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Confirmed  int        `json:"confirmed"`
	Possible   int        `json:"possible"`
	Severities Severities `json:"severities"`
}

// TopFinding is one of the most severe findings.
type TopFinding struct {
	// ID is FindingID of the rule and the finding's edge endpoints.
	ID       string `json:"id"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Possible bool   `json:"possible"`
	// ReachRemovedPct is the share of confirmed pairs the fix removes.
	ReachRemovedPct float64 `json:"reach_removed_pct"`
	// Repository, Workflow and Org are set only with Options.Names,
	// sanitized and capped.
	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Org        string `json:"org,omitempty"`
}

// FindingID is the stable ID of a finding: the first IDLength hex characters
// of the SHA-256 of the rule ID and the node IDs, NUL separated. It has no
// salt, so it is the same on every run; it hides names from a casual reader
// but a guessable name can be confirmed by hashing it (see docs/cloud.md).
func FindingID(rule string, nodes ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(append([]string{rule}, nodes...), "\x00")))
	return hex.EncodeToString(sum[:])[:IDLength]
}

// moreSuffix is the "(+N more)" a grouped SARIF edge ends with.
var moreSuffix = regexp.MustCompile(` \(\+\d+ more\)$`)

var edgeKinds = []graph.EdgeKind{graph.CanPush, graph.Uses, graph.ResolvesTo, graph.DefinedIn, graph.ExecutesWith,
	graph.MemberOf, graph.CanTrigger, graph.CanAssume, graph.CanMergeViaBot}

// endpoints splits a SARIF result's edge text ("<from> KIND <to>") into its
// node IDs.
func endpoints(edge string) (from, to string) {
	edge = moreSuffix.ReplaceAllString(edge, "")
	for _, k := range edgeKinds {
		if f, t, ok := strings.Cut(edge, " "+string(k)+" "); ok {
			return f, t
		}
	}
	return edge, ""
}

// Build computes the summary of g.
func Build(g *graph.Graph, opts Options) (*Summary, error) {
	top := opts.Top
	switch {
	case top < 0 || top > MaxTop:
		return nil, fmt.Errorf("top must be between 0 and %d, got %d", MaxTop, top)
	case top == 0:
		top = DefaultTop
	}
	log, err := sarif.Build(g, sarif.Options{Version: opts.Version, IncludePossible: true})
	if err != nil {
		return nil, err
	}
	ix := graph.NewIndex(g)
	s := &Summary{
		Schema: Version, Enterprise: sanitize.Truncate(g.Enterprise, sanitize.MaxValue),
		GopVersion: sanitize.Truncate(opts.Version, 64), RunAt: g.CollectedAt.UTC(), Names: opts.Names,
		Top: []TopFinding{},
	}

	s.Coverage = Coverage{Partial: g.Partial, PartialReason: sanitize.Truncate(g.PartialReason, 64), CoverageEntries: len(g.Coverage)}
	for _, n := range g.Nodes {
		if n.Kind == graph.KindOrg {
			s.Coverage.OrgsRead++
		}
		if n.Evidence == graph.NotVisible {
			s.Coverage.NotVisible++
		}
	}
	for _, e := range g.Edges {
		if e.Evidence == graph.NotVisible {
			s.Coverage.NotVisible++
		}
	}

	nh := ix.NonHuman()
	s.Headline = Headline{NonHumanActors: nh.Actors, MergeWithoutHuman: nh.Merge,
		MergeWithoutHumanConfirmed: nh.MergeConfirmed, MergeWithoutHumanPossible: nh.MergePossible}
	for _, id := range ix.AgentWorkflows() {
		n, ok := ix.Node(id)
		if !ok || !graph.AgentConfirmed(n) {
			continue
		}
		if n.Attrs[graph.AttrAgentExposure] == graph.ExposureOutsiders {
			s.Headline.OutsiderTriggerableAgents++
		}
		if len(graph.AgentUnrestricted(n)) > 0 {
			s.Headline.DangerousModeAgents++
		}
	}

	t := ix.Totals()
	s.Pairs = Pairs{Confirmed: t.ConfirmedPairs, Possible: t.PossiblePairs}

	rules := sarif.Rules()
	s.Rules = make([]RuleCount, len(rules))
	for i, r := range rules {
		s.Rules[i] = RuleCount{ID: r.ID, Name: r.Name}
	}
	seen := map[string]bool{}
	results := log.Runs[0].Results
	s.Findings = len(results)
	for _, r := range results {
		rc := &s.Rules[r.RuleIndex]
		if r.Properties.Possible {
			rc.Possible++
		} else {
			rc.Confirmed++
			rc.Severities.add(r.Properties.Severity)
			s.Severities.add(r.Properties.Severity)
		}
		from, to := endpoints(r.Properties.Edge)
		id := FindingID(r.RuleID, from, to)
		if seen[id] || len(s.Top) >= top {
			continue
		}
		seen[id] = true
		f := TopFinding{ID: id, Rule: r.RuleID, Severity: r.Properties.Severity, Possible: r.Properties.Possible,
			ReachRemovedPct: r.Properties.ReachRemovedPct}
		if opts.Names {
			f.Repository = name(r.Properties.Repository)
			f.Org = name(r.Properties.Org)
			for _, n := range []string{from, to} {
				if graph.KindFromID(n) == graph.KindWorkflow {
					f.Workflow = name(strings.TrimPrefix(n, "workflow:"))
					break
				}
			}
		}
		s.Top = append(s.Top, f)
	}
	return s, nil
}

// name is a GitHub-written name made safe for the summary: unsafe
// characters escaped, capped at sanitize.MaxValue runes.
func name(s string) string { return sanitize.Truncate(s, sanitize.MaxValue) }

// Marshal serializes s as indented JSON with a trailing newline. When the
// document is over MaxBytes it drops top findings, last first, until it fits
// and sets Truncated (s is changed). Unsafe runes are escaped
// (sanitize.JSON).
func Marshal(s *Summary) ([]byte, error) {
	b, err := encode(s)
	if err != nil || len(b) <= MaxBytes {
		return b, err
	}
	all := s.Top
	s.Truncated = true
	// The largest prefix of all that fits, by binary search on its length.
	lo, hi := 0, len(all)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		s.Top = all[:mid]
		b, err := encode(s)
		if err != nil {
			return nil, err
		}
		if len(b) <= MaxBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	s.Top = all[:lo]
	b, err = encode(s)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("summary is %d bytes with no top findings, over the %d byte cap", len(b), MaxBytes)
	}
	return b, nil
}

func encode(s *Summary) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return sanitize.JSON(buf.Bytes()), nil
}
