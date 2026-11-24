# Actions lockfile (actions.lock)

[`gh actions-lock`](https://github.com/github/gh-actions-lock) pins every
action a repo's workflows use, direct and nested (composite actions), to a
verified commit and records the pins in `.github/workflows/actions.lock`. A
workflow that still says `uses: actions/checkout@v4` then runs the locked
commit. gop reads that file so it does not report such repos as unpinned.

## Upstream version followed

gop's reader follows these upstream commits (read-only, through the GitHub
API, on 2026-11-24):

| Repository | Commit | What was read |
|---|---|---|
| [github/gh-actions-lock](https://github.com/github/gh-actions-lock) | [`d8e1ae3518e8ae47f38c291c1ebe68c10fcee346`](https://github.com/github/gh-actions-lock/tree/d8e1ae3518e8ae47f38c291c1ebe68c10fcee346) (2026-11-19) | `README.md`, its own `.github/workflows/actions.lock`, `cmd/gh-actions-lock/testdata/golden-json/`, `internal/lockfile/state_marshal.go`, `internal/dep/dependency.go`, `internal/uses/uses.go` |
| [github/actions-lockfile](https://github.com/github/actions-lockfile) | [`54969dc7fee8b1e0e22b06bd4b591c44232f831c`](https://github.com/github/actions-lockfile/tree/54969dc7fee8b1e0e22b06bd4b591c44232f831c) (2026-10-27) | `README.md`, `schema/lockfile-v0.0.3.json`, `go/pkg/lockfile/lockfile.go`, `pin.go`, `compat.go` |

`github/actions-lockfile` is the authoritative format definition and Go
parser; `gh actions-lock` is its producer. gop does not import the parser: it
reads the few fields it needs with its own YAML walker (the same one that
reads workflow files, which bounds work on attacker-written files), following
the rules below. Re-check them when the schema version moves past `v0.0.3`.

## Format

```yaml
version: 'v0.0.3'
workflows:                     # workflow path -> flat, transitive list of pin keys
  '.github/workflows/ci.yml':
    - 'actions/checkout@v4'
    - 'acme-actions/deploy@main'
    - 'acme-actions/setup@main'   # nested: deploy@main runs it
dependencies:                  # pin key -> resolved metadata
  'acme-actions/deploy@main':
    ref: 'main'
    commit: 'sha1-<40 hex>'
    owner_id: 1
    repo_id: 2
    uses:
      - 'acme-actions/setup@main'
```

- Path: `.github/workflows/actions.lock` (`lockfile.Path`).
- `version`: gop reads `v0.0.1`, `v0.0.2` and `v0.0.3`, the versions the
  upstream parser reads. Any other version is not read (see below).
- A pin key is `OWNER/REPO@REF`: split at the first `@`, exactly one `/`
  before it, owner and repo lowercased, the ref kept as written, no sub-action
  path (`actions/cache/save@v4` is locked as `actions/cache@v4`, since the
  runner downloads per repo and commit). v0.0.1 keys may end in
  `:<algo>-<hex>`, which is dropped.
- `commit` is `sha1-<40 hex>` or `sha256-<64 hex>`.
- `workflows` lists, for each workflow, every pin key it depends on, nested
  ones included.
- Remote reusable workflows (`jobs.<id>.uses`) are not locked upstream yet
  (gh-actions-lock issue #179), and local `./` actions are never locked.

## How gop uses it

`gop collect` reads the file from the `.github/workflows` listing it already
makes: on the batched GraphQL path the lockfile text comes back with the
workflow files at no extra cost; over REST it is one contents `GET`, made
only when the listing has the file (so a missing file costs nothing and a
404 means none). Both paths go through the response cache when
`--cache-dir` is set.

For each `uses:` in a workflow of a repo with a lockfile (not reusable
workflows), gop computes the pin key of the reference and marks the
`workflow -USES-> action` edge:

- `actions_lock=locked`, `locked_sha=<commit>` when the workflow's
  `workflows` entry lists the key, `dependencies` has a commit for it, and
  every nested ref gop collected under the action (enterprise composite
  actions it expanded) is listed for the workflow too. A nested action that
  no workflow file pins, but the lockfile does, is covered this way.
- `actions_lock=stale` otherwise: the workflow is not in the lockfile, the
  lockfile pins another ref of the same repo (`lock_entry`), or a nested ref
  is missing (`lock_missing`). A coverage entry on the workflow
  (`actions_lock:<pin>`) says which, with "rerun gh actions-lock" as the fix.
  A stale entry counts as unpinned.

The repo gets `actions_lock=true`. A lockfile that is listed but can't be
read, isn't a regular file, is too large (over 1 MiB, the upstream limit) or
doesn't parse leaves `actions_lock=unknown` with a coverage entry, and none of
the repo's refs count as locked: gop does not assume a pin it could not read.

## Effect

- Reach: the engine drops the control hop of a `locked` edge. Whoever can
  change the action, or anything nested under it, no longer reaches that
  workflow through it. Other workflows using the same action are unaffected.
- Pinned counts: the report's Coverage section and the MCP summary
  (`action_pins`) split workflow `uses:` lines into pinned in the workflow
  file (a commit SHA), pinned by actions.lock, stale actions.lock entry and
  unpinned, whenever the graph has a lockfile fact.
- Fixes: `suggest_fixes` does not propose pinning an action every use of
  which is locked, and the report does not list such an action under
  "Pinned, still reachable". `fix_plan` and `gop pin` never rewrite a
  `uses:` line a lockfile governs: they list it as governed (locked) or stale
  and point at `gh actions-lock`. gop never writes the lockfile.

## Limits

- gop does not check provenance (owner and repo IDs, whether the locked
  commit is still on the ref); `gh actions-lock --verify` and the runner do.
- Whether the runner enforces the lockfile is an org setting gop does not
  read; gop treats a locked entry as what the workflow runs.
- Nested refs are only checked where gop expanded the action (enterprise
  composite actions and reusable workflows); an external action's nested refs
  are taken from the lockfile as is.
