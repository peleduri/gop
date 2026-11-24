package collect

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/peleduri/gop/internal/graph"
)

// policyProbes are the paths a CODEOWNERS rule is checked against for each
// policy file: a directory (.cursor/rules) is owned when a file inside it is.
var policyProbes = map[string]string{".cursor/rules": ".cursor/rules/gop.mdc"}

// policyExprs are the batched object expressions for graph.PolicyFiles.
// They are read shallow: gop only needs to know whether each one exists.
func policyExprs() []string {
	out := make([]string, len(graph.PolicyFiles))
	for i, p := range graph.PolicyFiles {
		out[i] = "HEAD:" + p
	}
	return out
}

// applyPolicyObjs records which policy files exist from the batched objects
// (nil: no such path).
func (k *collector) applyPolicyObjs(repo *graph.Node, objs []*gqlObject) {
	found := []string{}
	for i, obj := range objs {
		if i < len(graph.PolicyFiles) && obj != nil && (obj.Typename == "Blob" || obj.Typename == "Tree") {
			found = append(found, graph.PolicyFiles[i])
		}
	}
	k.policy[repo.ID] = found
}

// collectPolicyFiles sets the policy file facts on the repos where a bot can
// approve or merge (review_bypass), the only case they matter, once the
// bypass is known. The batch already listed them; repos it did not cover
// (REST mode, a failed batch) are read over REST. Both modes give the same
// graph.
func (k *collector) collectPolicyFiles(ctx context.Context) error {
	for _, o := range k.orgs {
		for _, repo := range o.repos {
			if repo.Attrs[graph.AttrArchived] == "true" || !graph.ReviewBypassed(*repo) {
				continue
			}
			found, ok := k.policy[repo.ID]
			if !ok {
				var unknown string
				var err error
				found, unknown, err = k.restPolicyFiles(ctx, o, repo)
				if err != nil {
					return err
				}
				if unknown != "" {
					setAttr(repo, graph.AttrPolicyFiles, "unknown", graph.NotVisible)
					setAttr(repo, graph.AttrPolicyFilesUnowned, "unknown", graph.NotVisible)
					k.cover(repo.ID, graph.FactPolicyFiles, "could not read "+unknown,
						"read access to contents on "+strings.TrimPrefix(repo.ID, "repo:"))
					continue
				}
			}
			k.setPolicy(repo, found)
		}
	}
	return nil
}

// setPolicy sets policy_files and policy_files_unowned from the files found
// and the repo's CODEOWNERS.
func (k *collector) setPolicy(repo *graph.Node, found []string) {
	sort.Strings(found)
	if len(found) == 0 {
		setAttr(repo, graph.AttrPolicyFiles, "none", graph.Live)
		return
	}
	setAttr(repo, graph.AttrPolicyFiles, strings.Join(found, ","), graph.Live)
	switch repo.Attrs[graph.AttrCodeowners] {
	case "unknown", "":
		setAttr(repo, graph.AttrPolicyFilesUnowned, "unknown", graph.NotVisible)
		return
	}
	co := k.codeowners[repo.ID] // zero value (no rules) when there is no CODEOWNERS
	var unowned []string
	for _, p := range found {
		probe := p
		if pp, ok := policyProbes[p]; ok {
			probe = pp
		}
		if !co.Owns(probe) {
			unowned = append(unowned, p)
		}
	}
	if len(unowned) == 0 {
		setAttr(repo, graph.AttrPolicyFilesUnowned, "none", graph.Live)
		return
	}
	setAttr(repo, graph.AttrPolicyFilesUnowned, strings.Join(unowned, ","), graph.Live)
}

// restPolicyFiles checks each policy path with one contents GET: 200 (a
// file or a directory listing) means it exists, 404 that it does not.
// unknown names the first path that could not be read.
func (k *collector) restPolicyFiles(ctx context.Context, o *orgState, repo *graph.Node) (found []string, unknown string, err error) {
	name := repoName(o, repo)
	for _, p := range graph.PolicyFiles {
		var raw json.RawMessage
		gerr := k.cl(o.login).GetJSON(ctx, contentsPath(o.login, name, p, ""), &raw)
		switch {
		case gerr == nil:
			found = append(found, p)
		case ctx.Err() != nil:
			return nil, "", ctx.Err()
		case IsNotFound(gerr):
		default:
			return nil, p + ": " + gerr.Error(), nil
		}
	}
	return found, "", nil
}
