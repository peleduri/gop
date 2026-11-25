# gop brand

This is the single source of truth for how gop looks and sounds, on every surface: the site, the HTML and Markdown reports, the README and docs, CLI text, MCP tool descriptions, plugin listings and icons, the GitHub Action, the social preview, SARIF rules and the CHANGELOG.

The machine-readable half lives in [`brand/`](brand/):

- [`brand/tokens.json`](brand/tokens.json): the source. Colors (light and dark), fonts, type scale, spacing, radius, evidence and reach line styles, node shapes.
- [`brand/tokens.css`](brand/tokens.css) and [`site/brand.css`](site/brand.css): the same tokens as CSS custom properties (`--gop-*`). Generated; do not edit by hand.
- `brand.CSS()` in the [`brand`](brand/brand.go) Go package: the same CSS for the HTML report (the report inlines one hashed `<style>` block, so it reads the CSS from Go, not from a file).
- [`brand/logo/`](brand/logo/): the mark and the logo lockup (SVG) and PNG exports.
- [`brand/graph-language.svg`](brand/graph-language.svg): the node shapes and line styles on one sheet.

After editing `tokens.json`, run `go run ./brand/gen` from the repository root. `go test ./brand/` fails if a generated copy is stale, if any declared color pair falls below WCAG AA in either theme, if two evidence levels share a line style or glyph, if two node kinds share a shape, or if this file's color table drifts from the JSON.

## Name

- The name is **gop**, always lowercase, also at the start of a sentence and in titles: "gop reads...", "# gop report". Never "GOP", "Gop" or "G.O.P.".
- Write it in code style (`gop`) only when you mean the command or binary: "run `gop collect`".
- The expansion "GitHub Enterprise Org Posture" explains where the name came from. Use it at most once per surface, in an About or description field, never as the headline.
- gop is not a GitHub product. Do not use GitHub's logo, the Octocat, or GitHub's own color palette as gop's identity.

## Tagline and description

Tagline (one line, use it as the headline everywhere a headline fits):

> Which AI agents and people can make code run where.

Description (25 words, for listings, About fields, `og:description`, manifests that allow it):

> gop reads a GitHub Enterprise read-only and shows which AI agents and people can make code run where, with evidence per hop and fixes ranked.

Short form for fields capped near 100 characters (server.json, MCPB): "Read-only evidence graph of which AI agents and people can make code run where in a GitHub Enterprise." Trim "in a GitHub Enterprise" first if the cap demands it.

Lowercase sentence form inside prose: "gop shows which AI agents and people can make code run where".

## Voice

gop is evidence-first. Say what was observed, how, and what to change.

- Plain English, short sentences, active voice. One idea per sentence.
- Always name the evidence level when stating a fact: **live**, **inferred**, **audit**, **supplied** or **not_visible**. Never turn not_visible into "off", "none" or "safe". Say "not visible to this token".
- Keep **confirmed** reach (every hop observed) and **possible** reach (a hop not visible) apart, in every sentence and every count.
- Numbers come with their unit and scope: "3 repos across 2 orgs (confirmed)".
- Name the fix as an action: "Pin `acme-actions/deploy` to a full commit SHA."
- No em dashes. Use a colon, a comma, parentheses or a new sentence.
- No hype. gop never says: "AI-powered", "revolutionary", "next-gen", "seamless", "blazing fast", "military-grade", "zero risk", "fully secure", "guaranteed", "best-in-class", "game-changing". gop finds AI agents; it does not market itself as AI.
- No fear-selling. Say "can push to" rather than "is compromised". Say "anyone on the internet can start it with a comment" rather than "critical breach".
- Synthetic examples only: `acme`, `acme-actions`, `acme-app`, `alice`, `bob`.
- CLI errors start with `gop: `, are lowercase after the prefix, say what failed and what to do next, and never print a token.
- CHANGELOG entries start with what a user can now do or see, in the past or present tense, and name the flag or tool.

## Color

Two themes, light and dark, selected by `prefers-color-scheme` (screen only: print always uses light). Every text pair below passes WCAG 2 AA (4.5:1), and `line-strong` passes 3:1 for UI boundaries; `go test ./brand/` checks every pair listed in `tokens.json`.

| Token | Light | Dark | Role |
|---|---|---|---|
| `bg` | `#f6f7f9` | `#0e1116` | Page background |
| `surface` | `#ffffff` | `#161a21` | Cards, tables, panels |
| `sunken` | `#eef1f4` | `#1d222a` | Code chips, table header, inset areas |
| `fg` | `#15181d` | `#e8ecf1` | Body text, identity nodes |
| `muted` | `#545c68` | `#9ba4b0` | Secondary text, code-side nodes (repo, workflow) |
| `line` | `#cfd5dd` | `#353c47` | Card and table borders (decorative) |
| `line-subtle` | `#e4e8ed` | `#252b33` | Row dividers (decorative) |
| `line-strong` | `#7d8592` | `#6f7886` | Input borders and not_visible outlines (3:1) |
| `accent` | `#3a46c9` | `#9aa5ff` | Path and reach: confirmed edges, links, focus ring, primary button |
| `accent-bg` | `#e8eafc` | `#1f2552` | Accent tint behind accent text |
| `on-accent` | `#ffffff` | `#0e1116` | Text on an accent fill |
| `danger` | `#b42318` | `#ff8a80` | Danger: attacker-controlled input, dangerous mode, critical verdict |
| `danger-bg` | `#fdecea` | `#3b1618` | Danger banner and badge tint |
| `danger-solid` | `#b42318` | `#e5484d` | Solid danger fill (rare: one critical badge per view) |
| `on-danger` | `#ffffff` | `#0e1116` | Text on danger-solid |
| `ok` | `#1a6e3c` | `#5fd394` | Cut or fixed: removed reach, passing checks |
| `ok-bg` | `#e2f3e8` | `#10291b` | OK tint |
| `possible` | `#8a5300` | `#f0b84f` | Possible reach: a hop not seen, inferred risk |
| `possible-bg` | `#fcf1dc` | `#33240a` | Possible tint |
| `neutral` | `#5c6470` | `#9ba4b0` | not_visible, unknown, empty states |
| `neutral-bg` | `#eceff3` | `#242a33` | Neutral tint |
| `ev-live` | `#3a46c9` | `#9aa5ff` | Evidence badge: live |
| `ev-live-bg` | `#e8eafc` | `#1f2552` | Tint behind the badge text above |
| `ev-inferred` | `#3a46c9` | `#9aa5ff` | Evidence badge: inferred (dashed border) |
| `ev-inferred-bg` | `#f3f4fd` | `#181c38` | Tint behind the badge text above |
| `ev-audit` | `#6f3bbf` | `#c7a4ff` | Evidence badge: audit |
| `ev-audit-bg` | `#f1eafc` | `#2a1e47` | Tint behind the badge text above |
| `ev-supplied` | `#0b6a74` | `#55d0d8` | Evidence badge: supplied |
| `ev-supplied-bg` | `#e0f3f4` | `#0f2b2e` | Tint behind the badge text above |
| `ev-not-visible` | `#5c6470` | `#9ba4b0` | Evidence badge: not_visible (dashed border) |
| `ev-not-visible-bg` | `#eceff3` | `#242a33` | Tint behind the badge text above |
| `target` | `#a3245f` | `#f48fbd` | Targets, the "where": secret, oidc, cloud_target, runner nodes |
| `target-bg` | `#fbe9f1` | `#3a1528` | Target tint |

### Semantic roles

| Role | Token | Meaning | Paired with (never color alone) |
|---|---|---|---|
| Path, reach | `accent` | A confirmed hop or path: who can make code run where | Solid line, ✓ glyph |
| Danger | `danger` | Attacker-controlled input (anyone on the internet, a fork, a comment), dangerous mode, a critical verdict | ▲ glyph, heavier 3px line, the word "danger" or "dangerous mode" |
| Cut, fixed | `ok` | Reach a fix removes, a passing check | ✕ cross bar on the line, ✓ in text, the word "cut" or "fixed" |
| Possible, inferred risk | `possible` | Reach through a hop gop could not see | Dashed line (6 4), ? glyph, the word "possible" |
| Not visible | `neutral` | A fact the token could not read | Dotted line (2 4), dashed outline, ? glyph, the words "not visible" |
| Target | `target` | The "where": secrets, OIDC trust, cloud roles, self-hosted runners | Node shape (square, shield, stadium, barred square) |

Severity in verdicts maps onto these roles: critical uses `danger`, high uses `danger` with the outline (tint) style, medium uses `possible`, ok uses `ok`, unknown uses `neutral` with a dashed border. The verdict word is always printed.

### Grayscale and color blindness

The semantic colors have similar luminance on purpose (they all pass AA as text), so they do **not** separate in grayscale or for red/green color blindness. Every role is therefore paired with a line style, a glyph and a word, and every node kind with a shape. `go test ./brand/` fails if two evidence levels share a dash pattern or glyph, two reach states share a glyph or line style, or two node kinds share a shape. Never ship a legend, chart or badge where color is the only difference.

### Evidence badges

| Evidence | Text and border | Fill | Glyph | Border | Edge dash |
|---|---|---|---|---|---|
| live | `ev-live` | `ev-live-bg` | ✓ | none | solid |
| inferred | `ev-inferred` | `ev-inferred-bg` | ≈ | 1px dashed | `10 3` |
| audit | `ev-audit` | `ev-audit-bg` | ↺ | none | `6 4` |
| supplied | `ev-supplied` | `ev-supplied-bg` | ≡ | 1px solid | `12 3 2 3` |
| not_visible | `ev-not-visible` | `ev-not-visible-bg` | ? | 1px dashed | `2 4` |

A stale audit fact counts as not_visible: draw it with the not_visible style and say "audit, stale". The label text uses the evidence value with the underscore replaced by a space ("not visible").

## Typography

System font stacks only. No web font downloads, no `@font-face`, no `url()`: the report must work offline and under its CSP.

- Sans (UI and prose): `system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif` (`--gop-font-sans`)
- Mono (identifiers: logins, repos, workflow paths, action refs, SHAs, flags, commands, evidence values in tables): `ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace` (`--gop-font-mono`)
- Scale: `xs` .72rem (badges, tags), `sm` .85rem (meta, notes), `base` 1rem, `lg` 1.2rem (section headings), `xl` 1.6rem (page headings), `xxl` 2.4rem (site hero). Body is 15px in the report and 16px on the site, line height 1.55.
- Weights: 400 body, 600 labels and badges, 700 headings and the wordmark. Use `font-variant-numeric: tabular-nums` for counts.
- Uppercase only for short labels (badges, kickers), with .04em to .08em letter spacing.

## Logo

The mark is a path: a person (filled circle) reaches through a step (ring) to a target (rounded square), drawn as one orthogonal line. It is original to gop and must not be changed to resemble any other company's or tool's logo.

| File | Use |
|---|---|
| [`brand/logo/gop-mark.svg`](brand/logo/gop-mark.svg) | Primary mark on its dark tile. Favicon, app and plugin icons, avatars. |
| [`brand/logo/gop-mark-color.svg`](brand/logo/gop-mark-color.svg) | Mark without the tile, accent colored, adapts to light and dark. Inline in pages. |
| [`brand/logo/gop-mark-mono.svg`](brand/logo/gop-mark-mono.svg) | Single color (`currentColor`). Print, embossing, one-color contexts. |
| [`brand/logo/gop-logo.svg`](brand/logo/gop-logo.svg) | Lockup: tile mark plus the "gop" wordmark in the mono stack, bold. Headers, slides. |
| [`brand/logo/png/`](brand/logo/png/) | `gop-mark-{16,32,48,64,180,192,512,1024}.png` from `gop-mark.svg`. |

Sizes: favicon uses the SVG (`gop-mark.svg`) with a 32px PNG fallback; Apple touch icon 180; web manifest 192 and 512; the Claude plugin directory wants a square PNG between 512 and 2048 px under 2 MB (`.claude-plugin/icon.png`, use the 1024); the Cursor marketplace logo uses the same 1024; MCPB `icons` take `{src, size}` entries (ship 512 and 1024). Regenerate PNGs with `rsvg-convert -w N -h N brand/logo/gop-mark.svg -o brand/logo/png/gop-mark-N.png`.

Rules: keep clear space of one quarter of the tile width on every side. Minimum size 16px. Do not recolor the mark outside the accent, fg and mono variants, do not rotate it, add effects or gradients, or put it inside another shape. The wordmark is always lowercase.

## Graph visual language

See [`brand/graph-language.svg`](brand/graph-language.svg). Node kinds follow `internal/graph/types.go`; "agent" is a workflow whose `agent` attribute is set.

| Kind | Shape | Color |
|---|---|---|
| enterprise | hexagon | `fg` |
| org | folder tab | `fg` |
| org_members | double circle | `fg` |
| identity | circle | `fg` |
| external | ringed circle | `danger` |
| repo | rounded rectangle | `muted` |
| workflow | diamond | `muted` |
| agent | diamond with a hole | `accent` |
| action_ref | hollow diamond | `muted` |
| secret | square | `target` |
| oidc | shield | `target` |
| cloud_target | stadium | `target` |
| runner | square with a bar | `target` |

People are round, code is angular (diamonds and rectangles), targets are tinted `target`. Edges take the evidence style of the fact behind them; the path a finding is about is drawn on top with its reach style (`reach` in `tokens.json`: confirmed 2.5px solid accent, possible 2px dashed `possible`, danger 3px solid `danger`, cut 2px `ok` with a ✕ cross bar).

**Dangerous mode** (an AI agent running with permission checks off, for example `--dangerously-skip-permissions`, or started by anyone on the internet while it holds a write token or secrets): the agent node gets a 2.5px `danger` ring, a ▲ glyph and the visible label "dangerous mode". In text and tables, use a `danger` banner (see Components). Never signal it with color alone.

## Spacing and radius

- Spacing: `half` 4px, `1` 8px, `2` 16px, `3` 24px, `4` 32px, `6` 48px, `8` 72px (`--gop-space-*`). Gaps inside a component use half to 2; between components 3 to 4; between page sections 6 to 8.
- Radius: `sm` 6px (badges' square variant, tags, code chips, buttons), `md` 10px (cards, tables, banners), `lg` 14px (hero, figures), `pill` 999px (evidence badges, verdict chips).
- Content width: 1200px max for the report, 1120px for the site, 16px side gutter, 80ch max for prose.

## Components

- **Badge:** pill, `xs` text, weight 600, glyph then label. Evidence badges follow the table above. Reach badges: "✓ confirmed" in accent, "? possible" in possible with a dashed border.
- **Tag:** `sm` radius, uppercase `xs` label, accent-bg with accent text; `danger-bg` with `danger` text for warnings.
- **Card:** `surface` fill, 1px `line` border, `md` radius, `space-3` padding, no heavy shadows (at most a 1px hairline).
- **Table:** `sunken` header row, 1px `line-subtle` row dividers, identifiers in mono, numbers right aligned with tabular numerals, evidence as badges in their own column.
- **Banner:** full width inside the content column, `md` radius, a 4px left border in the role color, a tint fill (`danger-bg`, `possible-bg`, `neutral-bg`), a glyph (▲, ?, i) and a bold first phrase that says what happened. Partial collection, demo data and dangerous mode use banners.
- **Verdict:** a pill with the verdict word in uppercase plus a 4px top rule on the hero card in the role color; unknown uses a dashed rule.
- **Links and focus:** `accent`, underlined (1px, 2px offset); a 2px `accent` focus ring on every interactive element.
- **Code and commands:** mono, `sunken` chip, `sm` radius. Terminal blocks use the dark theme tokens in both themes.

## Surfaces

| Surface | Source of truth used |
|---|---|
| Site (`site/`) | Inline `site/brand.css` into the single hashed `<style>` block and map existing variables to `--gop-*`. |
| HTML report (`internal/report`) | Prepend `brand.CSS()` to the report's style constant; the CSP hash is computed from the served bytes. |
| Markdown report, README, docs, CHANGELOG, SARIF, CLI, MCP | Name, tagline, description and voice rules; evidence glyphs where text allows. |
| Plugin and MCPB icons, favicon, social preview | `brand/logo/` files and the dark theme tokens. |
| GitHub Action (`action/action.yml`) | `branding.icon: share-2`, `branding.color: purple` (the closest of GitHub's fixed Action colors to `accent`). |

## Audit: where surfaces differ today

Recorded when this file was written, for the stage that applies it. Remove an item once its surface follows this file.

- **Headline.** README says "gop: GitHub Enterprise Org Posture"; the site title, plugin `displayName`, `server.json` title, MCPB `display_name` and the Markdown report heading say "gop: who can make code run where"; the HTML report title says "gop report"; the README lede and site description use "Which AI agents and people can make code run where". At least six other variants of "who can make code run where ..." appear across docs, manifests and the MCP server instructions.
- **Palette.** The site and the HTML report both copy GitHub's own Primer colors (`#0969da`, `#1a7f37`, `#cf222e`, `#0d1117`), which makes gop read as a GitHub product. The README site badge also uses `0969da`. The social preview uses amber (`#f2a33a`) for the hot path, which this system reserves for possible reach.
- **Evidence colors.** In the report, live evidence and "good/fixed" share one green, so "observed" and "fixed" look the same; audit shares the medium-severity amber; supplied borrows the accent; the badge glyph for audit is the generic ✓. Edge dashes differ from the site's hero path (the site's `inferred` badge uses the live green with a dashed border).
- **Logo.** Four different marks: the site favicon and the report and site header `.mark` are a bold mono "g" on a dark tile; the Claude and Cursor plugin icon (1024px) is a "g" under a blue graph arc on a gradient tile; the social preview uses a "gop" wordmark with an amber graph; the Action uses the generic `shield` icon in `gray-dark`.
- **Social preview.** `docs/assets/social-preview.png` exists but the site has no `og:image`, `og:title` or `twitter:card` tags.
- **Name casing.** "gop" is lowercase on every surface checked. The expansion "GitHub Enterprise Org Posture" appears in the README H1 and `llms.txt`.
- **Punctuation.** One user-visible em dash: the empty coverage value in `internal/report/view.go` renders an em dash (U+2014).
- **Fonts.** Already system stacks everywhere (good); the mono stack differs slightly between the report, site and social preview (`"Liberation Mono"` missing).
