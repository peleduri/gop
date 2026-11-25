package graph

import (
	"fmt"
	"sort"
)

// DefaultOwnerThreshold is the number of owned orgs from which ReduceOwners
// removes an account's standing org ownership, unless a caller sets another.
const DefaultOwnerThreshold = 5

// MinOwnersPerOrg is how many owners ReduceOwners always leaves in each org.
const MinOwnersPerOrg = 2

// OwnedOrgs lists the orgs a principal owns: the orgs of its verified
// via=org_owner CAN_PUSH edges, sorted. An org without repos has no such
// edge, so the graph cannot show its owners.
func (ix *Index) OwnedOrgs(principal string) []string {
	set := map[string]bool{}
	for _, e := range ix.out[principal] {
		if e.Kind == CanPush && e.Attrs[AttrVia] == ViaOrgOwner && ix.EdgeVerified(e) {
			if o := OrgOf(e.To); o != "" {
				set[o] = true
			}
		}
	}
	return sortedKeys(set)
}

// orgOwners maps each org to its owners and each owner to the orgs it owns,
// from verified via=org_owner CAN_PUSH edges.
func (ix *Index) orgOwners() (byOrg, byOwner map[string][]string) {
	orgSet, ownerSet := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, e := range ix.g.Edges {
		if e.Kind != CanPush || e.Attrs[AttrVia] != ViaOrgOwner || !ix.EdgeVerified(e) {
			continue
		}
		o := OrgOf(e.To)
		if o == "" {
			continue
		}
		if orgSet[o] == nil {
			orgSet[o] = map[string]bool{}
		}
		if ownerSet[e.From] == nil {
			ownerSet[e.From] = map[string]bool{}
		}
		orgSet[o][e.From] = true
		ownerSet[e.From][o] = true
	}
	byOrg, byOwner = map[string][]string{}, map[string][]string{}
	for o, s := range orgSet {
		byOrg[o] = sortedKeys(s)
	}
	for p, s := range ownerSet {
		byOwner[p] = sortedKeys(s)
	}
	return byOrg, byOwner
}

// OwnerBucket is one bar of the ownership histogram: the accounts that own
// between Min and Max orgs (Max 0: no upper bound).
type OwnerBucket struct {
	Label    string   `json:"label"`
	Min      int      `json:"min"`
	Max      int      `json:"max,omitempty"`
	Accounts int      `json:"accounts"`
	Members  []string `json:"members"`
}

// OrgOwnership is how concentrated standing org ownership is: how many orgs
// each account owns, bucketed, and how much confirmed reach depends on it.
// Counts come from verified via=org_owner CAN_PUSH edges.
type OrgOwnership struct {
	// Owners is the number of accounts that own at least one org.
	Owners  int           `json:"owners"`
	Buckets []OwnerBucket `json:"buckets"`
	// OwnerPairs is the confirmed (principal, repo) pairs, summed over the
	// scoring principals, that go away when every org_owner grant is
	// removed; ConfirmedPairs the baseline; OwnerPct the share, 0..100.
	OwnerPairs     int     `json:"owner_pairs"`
	ConfirmedPairs int     `json:"confirmed_pairs"`
	OwnerPct       float64 `json:"owner_pct"`
}

// ownerBuckets are the histogram's bars: 1, 2-4, 5-9 and 10 or more orgs.
var ownerBuckets = []OwnerBucket{{Label: "1 org", Min: 1, Max: 1}, {Label: "2-4 orgs", Min: 2, Max: 4},
	{Label: "5-9 orgs", Min: 5, Max: 9}, {Label: "10+ orgs", Min: 10}}

// Ownership measures OrgOwnership. ok is false when no account owns an org
// in this graph.
func (ix *Index) Ownership() (OrgOwnership, bool) {
	_, byOwner := ix.orgOwners()
	if len(byOwner) == 0 {
		return OrgOwnership{}, false
	}
	out := OrgOwnership{Owners: len(byOwner)}
	for _, b := range ownerBuckets {
		b.Members = []string{}
		out.Buckets = append(out.Buckets, b)
	}
	owners := make([]string, 0, len(byOwner))
	for p := range byOwner {
		owners = append(owners, p)
	}
	sort.Strings(owners)
	var all []OwnerCut
	for _, p := range owners {
		n := len(byOwner[p])
		for i := range out.Buckets {
			b := &out.Buckets[i]
			if n >= b.Min && (b.Max == 0 || n <= b.Max) {
				b.Accounts++
				b.Members = append(b.Members, p)
			}
		}
		for _, o := range byOwner[p] {
			all = append(all, OwnerCut{Principal: p, Org: o})
		}
	}
	// WhatIf(ReduceOwners{all}) pair totals, counted without paths.
	before, after := ix.confirmedPairs([]Fix{ReduceOwners{Cuts: all}})
	out.ConfirmedPairs = before
	out.OwnerPairs = before - after
	if out.ConfirmedPairs > 0 {
		out.OwnerPct = 100 * float64(out.OwnerPairs) / float64(out.ConfirmedPairs)
	}
	return out, true
}

// OwnerCut is one standing org ownership ReduceOwners removes.
type OwnerCut struct {
	Principal string `json:"principal"`
	Org       string `json:"org"`
}

// ReduceOwners removes standing org ownership from every account that owns
// Threshold or more orgs, keeping at least MinOwnersPerOrg owners in each
// org: it removes the via=org_owner CAN_PUSH edges of each cut (account,
// org) pair. Build it with Index.ReduceOwners, which picks the cuts.
type ReduceOwners struct {
	Threshold int `json:"threshold"`
	// Cuts are the (account, org) ownerships removed, sorted.
	Cuts []OwnerCut `json:"cuts"`
	// Kept are the ownerships of accounts at or over the threshold that stay
	// so that no org is left with fewer than MinOwnersPerOrg owners.
	Kept []OwnerCut `json:"kept,omitempty"`
}

func (f ReduceOwners) ID() string { return fmt.Sprintf("reduce_owners:>=%d", f.Threshold) }

func (f ReduceOwners) apply(fs *fixSet) {
	for _, c := range f.Cuts {
		setFlag(&fs.unowned, ownerKey(c.Principal, c.Org))
	}
}

func (f ReduceOwners) edges(ix *Index) []Edge {
	cut := map[string]bool{}
	for _, c := range f.Cuts {
		cut[ownerKey(c.Principal, c.Org)] = true
	}
	var out []Edge
	for _, e := range ix.g.Edges {
		if e.Kind == CanPush && e.Attrs[AttrVia] == ViaOrgOwner && cut[ownerKey(e.From, OrgOf(e.To))] {
			out = append(out, e)
		}
	}
	return out
}

// Accounts lists the accounts that lose at least one ownership, sorted.
func (f ReduceOwners) Accounts() []string {
	set := map[string]bool{}
	for _, c := range f.Cuts {
		set[c.Principal] = true
	}
	return sortedKeys(set)
}

func ownerKey(principal, org string) string { return principal + "\x00" + org }

// ReduceOwners picks the cuts for a threshold (DefaultOwnerThreshold when
// threshold <= 0). An account that owns threshold or more orgs loses its
// ownership of every org, except where the org would keep fewer than
// MinOwnersPerOrg owners: owners under the threshold always stay, and the org
// keeps as many of the accounts over it as it needs to reach
// MinOwnersPerOrg, those that own the most orgs first (ties by ID).
func (ix *Index) ReduceOwners(threshold int) ReduceOwners {
	if threshold <= 0 {
		threshold = DefaultOwnerThreshold
	}
	f := ReduceOwners{Threshold: threshold, Cuts: []OwnerCut{}}
	byOrg, byOwner := ix.orgOwners()
	orgs := make([]string, 0, len(byOrg))
	for o := range byOrg {
		orgs = append(orgs, o)
	}
	sort.Strings(orgs)
	for _, o := range orgs {
		var heavy []string
		light := 0
		for _, p := range byOrg[o] {
			if len(byOwner[p]) >= threshold {
				heavy = append(heavy, p)
			} else {
				light++
			}
		}
		sort.SliceStable(heavy, func(i, j int) bool {
			if a, b := len(byOwner[heavy[i]]), len(byOwner[heavy[j]]); a != b {
				return a > b
			}
			return heavy[i] < heavy[j]
		})
		keep := max(0, MinOwnersPerOrg-light)
		for i, p := range heavy {
			if i < keep {
				f.Kept = append(f.Kept, OwnerCut{Principal: p, Org: o})
			} else {
				f.Cuts = append(f.Cuts, OwnerCut{Principal: p, Org: o})
			}
		}
	}
	less := func(s []OwnerCut) func(i, j int) bool {
		return func(i, j int) bool {
			if s[i].Principal != s[j].Principal {
				return s[i].Principal < s[j].Principal
			}
			return s[i].Org < s[j].Org
		}
	}
	sort.Slice(f.Cuts, less(f.Cuts))
	sort.Slice(f.Kept, less(f.Kept))
	return f
}
