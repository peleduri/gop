"""The scorecard: per-case results and per-group pass rates, as JSON and Markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

GROUPS = ["correctness", "no_overclaiming", "refusal", "injection"]


def _rate(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-group and overall rates. A case passes when every deterministic check
    passed and, if the judge ran, every metric passed. hard_pass_rate counts the
    deterministic checks alone."""
    groups = {}
    for g in GROUPS + sorted({r["group"] for r in rows} - set(GROUPS)):
        rs = [r for r in rows if r["group"] == g]
        if not rs:
            continue
        metric_names = sorted({m for r in rs for m in r.get("metrics", {})})
        groups[g] = {
            "cases": len(rs),
            "hard_pass_rate": _rate(sum(r["hard_pass"] for r in rs), len(rs)),
            "pass_rate": _rate(sum(r["pass"] for r in rs), len(rs)),
            "metrics": {m: round(sum(r["metrics"][m]["score"] for r in rs if m in r["metrics"])
                                 / max(1, sum(m in r["metrics"] for r in rs)), 3) for m in metric_names},
        }
    return {
        "cases": len(rows),
        "hard_pass_rate": _rate(sum(r["hard_pass"] for r in rows), len(rows)),
        "pass_rate": _rate(sum(r["pass"] for r in rows), len(rows)),
        "groups": groups,
    }


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x * 100:.0f}%"


def markdown(card: dict[str, Any]) -> str:
    s = card["summary"]
    out = [f"# gop agent eval: {card['mode']}", ""]
    for k in ("model", "judge_model", "skill_variant", "gop_version"):
        if card.get(k):
            out.append(f"- {k.replace('_', ' ')}: `{card[k]}`")
    dry = any("expect_failed" in r for r in card["cases"])
    if dry:
        match = sum(r["failed_checks"] == r["expect_failed"] for r in card["cases"])
        out += ["", f"{match} of {s['cases']} recorded transcripts fail exactly the checks they are recorded to fail "
                    "(good-* transcripts none, bad-* ones the rule they break). The rates below count the "
                    "transcripts, bad ones included.", ""]
    else:
        out += ["", f"Overall: {_pct(s['pass_rate'])} of {s['cases']} cases pass "
                    f"({_pct(s['hard_pass_rate'])} pass the deterministic checks).", ""]
    out += ["| Group | Cases | Deterministic checks | Pass | Metric means |", "|---|---|---|---|---|"]
    for g, v in s["groups"].items():
        means = ", ".join(f"{m} {x:.2f}" for m, x in v["metrics"].items()) or "-"
        out.append(f"| {g} | {v['cases']} | {_pct(v['hard_pass_rate'])} | {_pct(v['pass_rate'])} | {means} |")
    if dry:
        out += ["", "| Transcript | Group | Graph | Failed checks | Recorded to fail | Match |", "|---|---|---|---|---|---|"]
        for r in card["cases"]:
            out.append(f"| {r['id']} | {r['group']} | {r['graph']} | {', '.join(r['failed_checks']) or '-'} | "
                       f"{', '.join(r['expect_failed']) or '-'} | "
                       f"{'yes' if r['failed_checks'] == r['expect_failed'] else 'NO'} |")
    else:
        out += ["", "| Case | Group | Graph | Pass | Failed checks | Failed metrics |", "|---|---|---|---|---|---|"]
        for r in card["cases"]:
            fm = ", ".join(m for m, v in r.get("metrics", {}).items() if not v["passed"]) or "-"
            out.append(f"| {r['id']} | {r['group']} | {r['graph']} | {'yes' if r['pass'] else 'no'} | "
                       f"{', '.join(r['failed_checks']) or '-'} | {fm} |")
    if card.get("notes"):
        out += [""] + [f"- {n}" for n in card["notes"]]
    return "\n".join(out) + "\n"


def write(out_dir: Path, card: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scorecard.json").write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    (out_dir / "scorecard.md").write_text(markdown(card), encoding="utf-8")
