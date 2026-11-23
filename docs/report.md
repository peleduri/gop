# The HTML report: `gop report`

```sh
gop report --graph graph.json --out report.html
gop report --graph new.json --previous old.json --out report.html   # opens with what changed
```

The report is one self-contained HTML file: an inline style, the embedded graph data and one inline script, all pinned by a Content Security Policy (`default-src 'none'` plus the SHA-256 of the style and of the script, computed from the constants in `internal/report/assets.go`). It loads nothing from the network and works offline. Every section is server-rendered, so it reads the same with JavaScript off; the script adds the filters and the per-org views. `--format md` writes the same content as Markdown.

## What changed: `--previous`

With `--previous old.json`, gop runs the same comparison as `gop diff old.json new.json` and puts a "What changed" banner at the top:

- the dates of the two snapshots and `gop diff`'s own one-sentence summary, verbatim;
- the top principal's score before and after;
- one group per kind of change, each with an exact count and up to 10 items:
  - **New confirmed paths**: `added` pairs whose new path is confirmed, plus `upgraded` (possible → confirmed) pairs.
  - **Removed paths**: `removed` pairs, each marked with what it was (confirmed or possible).
  - **New possible paths**: `added` pairs with a hop that is not visible.
  - **Setting changes**: settings that changed or became visible.
  - **Lost visibility**: paths that lost visibility or were downgraded to possible, settings that are no longer visible, and coverage gaps that opened. These are unknown, not fixed.

Each path item links to the filtered view for its principal (for example `#ev=confirmed&kind=oidc&q=identity%3Abob`), and each setting or coverage item links to its org view (`#/org/acme-app`). The links need JavaScript. `gop diff` lists every change, including the edge changes the banner leaves out.

`--previous` refuses the snapshots `gop diff` refuses: another enterprise or another major schema version (exit 2). Without `--previous` the report has no banner.

The GitHub Action passes `--previous` when `fail-on-reach-increase` downloaded a baseline. If the baseline cannot be compared, the Action writes the report without the banner.

## Accessibility

The report must work with a screen reader and a keyboard, and must never say "confirmed" or "possible" with color alone: that difference is the core of gop.

| Check | How the report meets it | Tested by |
|---|---|---|
| Landmarks | One `header` (the `h1` and the snapshot line), one `nav` labelled "Report sections", one `main`, one `footer`, and a "Skip to the report" link. | `TestA11yStructure` |
| Headings | Exactly one `h1`; headings never skip a level going down (`h1` → `h2` → `h3` → `h4`), in the static report, the banner and the org views. | `TestA11yStructure` |
| Tables | Every table has a `caption` (visually hidden when a heading already names it) and `th scope="col"` headers. Tables built by the script go through one helper that adds both. | `TestA11yStructure`, `TestScriptRendersAccessibleMarkup`, `TestInlineScriptInNode` |
| Form controls | Every filter (the selects, the principal search box, the org checkboxes) is inside a `label`; the org checkboxes are grouped in a `fieldset` with a `legend`. | `TestA11yStructure` |
| Keyboard | Only native links, buttons, form controls and `details` are interactive, there is no positive `tabindex`, and focus has a visible `:focus-visible` outline in both themes. Following a banner link moves focus to the filtered paths; opening an org view moves focus to its heading. | `TestA11yStructure`, `TestInlineScriptInNode` |
| Evidence not by color | Every evidence badge is text plus an icon hidden from screen readers: `✓ confirmed`, `? possible: a hop is not visible`, `✓ live`, `✓ audit`, `≡ supplied file`, `? not visible`, `? unknown`. | `TestA11yStructure`, `TestInlineScriptInNode` |
| Contrast | Every text color on every background it is used on is at least 4.5:1 (WCAG AA) in the light theme and in the dark theme (`prefers-color-scheme: dark`). | `TestContrastAA` |
| Live results | The filter result count ("12 paths match (9 confirmed, 3 possible) ...") is a `role="status"` region with `aria-live="polite"`, so screen readers announce it after each filter change. | `TestA11yStructure` |
| Graph image | The report has no SVG graph; paths are listed as text. A test fails if an SVG is added, as a reminder that it then needs a text alternative listing the paths. | `TestA11yStructure` |

The tests parse the rendered HTML with `golang.org/x/net/html` (`internal/report/a11y_test.go`, `internal/report/banner_test.go`). For a manual check, open a report in a browser and run axe DevTools or the Lighthouse accessibility audit, in both color schemes.
