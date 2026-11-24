"""Run the gop agent-behaviour eval (docs/evals.md).

Live:  python -m evals.run --model <id> [--judge-model <id>] [--skill-variant real]
Dry:   python -m evals.run --dry

A live run asks a model every case through `gop serve` and scores the answers.
A dry run needs no model and no API key: it reads the expected values from gop
for every case and runs the deterministic checks on the recorded transcripts
in evals/recorded/, failing if any check's outcome differs from the one the
transcript records. Both write <out>/scorecard.json and <out>/scorecard.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from . import checks, scorecard
from .expected import _resolve_args, expected_for
from .gop import EVALS, GRAPHS, gop_binary, serve
from .skill import VARIANTS, skill_text

CASES = EVALS / "cases.yaml"
RECORDED = EVALS / "recorded"


def load_cases(only: list[str] | None = None, groups: list[str] | None = None) -> list[dict[str, Any]]:
    cases = yaml.safe_load(CASES.read_text(encoding="utf-8"))["cases"]
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("cases.yaml: duplicate case id")
    for c in cases:
        if c["graph"] not in GRAPHS or c["group"] not in scorecard.GROUPS:
            raise SystemExit(f"cases.yaml: {c['id']}: unknown graph or group")
    if only:
        cases = [c for c in cases if c["id"] in only]
    if groups:
        cases = [c for c in cases if c["group"] in groups]
    return cases


def by_graph(cases: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for c in cases:
        out.setdefault(c["graph"], []).append(c)
    return out


def version(binary: str) -> str:
    try:
        return subprocess.run([binary, "version"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def row(case: dict[str, Any], results: dict[str, Any], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    failed = checks.failed(results)
    metrics = metrics or {}
    return {"id": case["id"], "group": case["group"], "graph": case["graph"], "checks": results,
            "failed_checks": failed, "hard_pass": not failed, "metrics": metrics,
            "pass": not failed and all(m["passed"] for m in metrics.values())}


# --- dry run ----------------------------------------------------------------


async def dry(binary: str, cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Expected values for every case, and the checks on every recorded transcript."""
    index = {c["id"]: c for c in load_cases()}
    recorded = []
    for path in sorted(RECORDED.glob("*.json")):
        rec = json.loads(path.read_text(encoding="utf-8"))
        rec["file"] = path.name
        if rec["case"] not in index:
            raise SystemExit(f"{path.name}: unknown case {rec['case']!r}")
        recorded.append(rec)
    wanted = {c["id"] for c in cases}
    recorded = [r for r in recorded if r["case"] in wanted]
    expected: dict[str, Any] = {}
    rows, problems = [], []
    for graph, cs in by_graph(cases).items():
        async with serve(binary, graph) as gop:
            for case in cs:
                exp = await expected_for(gop, case)
                expected[case["id"]] = exp
            for rec in [r for r in recorded if index[r["case"]]["graph"] == graph]:
                case = index[rec["case"]]
                exp = expected[case["id"]]
                calls = []
                for c in rec["tool_calls"]:
                    args = _resolve_args(graph, c.get("arguments") or {}, exp.subject)
                    res = await gop.call(c["name"], args)
                    if res.is_error and c["name"] in checks.READ_ONLY_TOOLS:
                        problems.append(f"{rec['file']}: replayed {c['name']} failed: {res.text[:200]}")
                    calls.append({"name": c["name"], "arguments": args, "text": res.text})
                results = checks.run_checks(checks.Transcript(calls, rec["answer"]), exp)
                got, want = checks.failed(results), sorted(rec.get("expect_failed", []))
                if got != want:
                    problems.append(f"{rec['file']}: failed checks {got}, recorded {want}: "
                                    + "; ".join(f"{k}: {results[k]['detail']}" for k in sorted(set(got) ^ set(want))))
                r = row(case, results)
                r["id"] = f"{rec['file'].removesuffix('.json')}"
                r["expect_failed"] = want
                rows.append(r)
    return rows, {k: v.to_dict() for k, v in expected.items()}, problems


# --- live run ---------------------------------------------------------------


async def live_agent(binary: str, cases: list[dict[str, Any]], args: argparse.Namespace,
                     out_dir: Path) -> list[tuple[dict[str, Any], Any, dict[str, Any], dict[str, Any], list[Any]]]:
    from openai import OpenAI

    from .agent import run_agent

    client = OpenAI(base_url=args.base_url) if args.base_url else OpenAI()
    system = skill_text(args.skill_variant)
    done = []
    tdir = out_dir / "transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    for graph, cs in by_graph(cases).items():
        async with serve(binary, graph) as gop:
            prompt = system + ("\n\n# Server instructions\n\n" + gop.instructions if args.server_instructions else "")
            for case in cs:
                exp = await expected_for(gop, case)
                try:
                    run = await run_agent(client, args.model, prompt, case["question"], gop)
                except Exception as err:  # noqa: BLE001 - one failed request fails one case
                    run = {"tool_calls": [], "answer": "", "turns": 0, "error": f"{type(err).__name__}: {err}"}
                results = checks.run_checks(checks.Transcript(run["tool_calls"], run["answer"]), exp)
                if run["error"]:
                    results["agent_answered"] = {"passed": False, "detail": run["error"][:300]}
                print(f"{case['id']}: failed checks {checks.failed(results) or 'none'}", file=sys.stderr)
                (tdir / f"{case['id']}.json").write_text(json.dumps({
                    "case": case["id"], "graph": graph, "question": case["question"],
                    "tool_calls": [{k: v for k, v in c.items() if k != "raw"} for c in run["tool_calls"]],
                    "answer": run["answer"], "error": run["error"], "turns": run["turns"],
                    "expected": exp.to_dict(), "checks": results}, indent=2) + "\n", encoding="utf-8")
                done.append((case, exp, run, results, gop.tools))
    return done


def live(binary: str, cases: list[dict[str, Any]], args: argparse.Namespace, out_dir: Path) -> list[dict[str, Any]]:
    done = asyncio.run(live_agent(binary, cases, args, out_dir))
    if args.no_judge:
        return [row(case, results) for case, _, _, results, _ in done]
    from . import metrics as m

    judge = m.judge(args.judge_model, args.judge_base_url)
    rows = []
    for case, exp, run, results, tools in done:
        scores = m.score(m.test_case(case, exp, run, tools), judge)
        rows.append(row(case, results, scores))
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.run", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry", action="store_true", help="no model: check expected values and recorded transcripts")
    p.add_argument("--model", help="agent model ID on the OpenAI-compatible endpoint (live run)")
    p.add_argument("--base-url", help="OpenAI-compatible endpoint for the agent (default: $OPENAI_BASE_URL or OpenAI)")
    p.add_argument("--judge-model", help="DeepEval judge model (default: DeepEval's configured model)")
    p.add_argument("--judge-base-url", help="OpenAI-compatible endpoint for the judge")
    p.add_argument("--no-judge", action="store_true", help="live run with the deterministic checks only")
    p.add_argument("--skill-variant", default="real", choices=sorted(VARIANTS),
                   help="the skill as given (real) or with one rule removed, to show the eval catches it")
    p.add_argument("--server-instructions", action="store_true",
                   help="append gop's MCP server instructions to the system prompt, as most clients do")
    p.add_argument("--case", action="append", dest="only", help="run only this case ID (repeatable)")
    p.add_argument("--group", action="append", dest="groups", choices=scorecard.GROUPS, help="run only this group")
    p.add_argument("--gop", help="gop binary (default: $GOP_BIN, else go build of this checkout)")
    p.add_argument("--out", type=Path, default=EVALS / "out", help="output directory (default evals/out)")
    p.add_argument("--fail-under", type=float, default=1.0,
                   help="exit 1 when the share of cases passing the deterministic checks is below this (live run)")
    args = p.parse_args(argv)
    for k in ("base_url", "judge_base_url", "judge_model", "model"):
        if not getattr(args, k):  # an empty workflow variable means unset
            setattr(args, k, None)
    if os.environ.get("OPENAI_BASE_URL") == "":
        del os.environ["OPENAI_BASE_URL"]
    if not args.dry and not args.model:
        p.error("--model is required (or pass --dry)")
    cases = load_cases(args.only, args.groups)
    if not cases:
        p.error("no cases selected")
    binary = gop_binary(args.gop, args.out)
    card: dict[str, Any] = {"gop_version": version(binary), "notes": []}
    if args.dry:
        for v in VARIANTS:
            skill_text(v)  # every broken variant still applies to the current skill
        rows, expected, problems = asyncio.run(dry(binary, cases))
        card.update(mode="dry (recorded transcripts, no model)", cases=rows, summary=scorecard.summarize(rows),
                    expected=expected)
        card["notes"] = [f"expected values read from gop for {len(expected)} cases",
                         f"{len(rows)} recorded transcripts checked"] + [f"MISMATCH {x}" for x in problems]
        scorecard.write(args.out, card)
        print(scorecard.markdown(card))
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        return 0
    rows = live(binary, cases, args, args.out)
    summary = scorecard.summarize(rows)
    card.update(mode="live", model=args.model, judge_model=args.judge_model or ("none" if args.no_judge else "default"),
                skill_variant=args.skill_variant, cases=rows, summary=summary)
    scorecard.write(args.out, card)
    print(scorecard.markdown(card))
    return 1 if (summary["hard_pass_rate"] or 0) < args.fail_under else 0


if __name__ == "__main__":
    sys.exit(main())
