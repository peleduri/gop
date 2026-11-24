"""Compare two scorecards: the real skill must score clearly higher than a broken variant.

python -m evals.compare evals/out/real/scorecard.json evals/out/no-sum-rule/scorecard.json --min-gap 0.1

Exits 1 when the real skill's overall pass rate is not at least min-gap above
the broken one's, which would mean the eval cannot tell them apart.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.compare", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("real", type=Path)
    p.add_argument("broken", type=Path)
    p.add_argument("--min-gap", type=float, default=0.1)
    p.add_argument("--markdown", type=Path, help="also write the comparison as Markdown here")
    args = p.parse_args(argv)
    real, broken = (json.loads(f.read_text(encoding="utf-8"))["summary"] for f in (args.real, args.broken))
    lines = ["| Group | Real skill | Broken skill |", "|---|---|---|"]
    for g in real["groups"]:
        b = broken["groups"].get(g, {}).get("pass_rate")
        lines.append(f"| {g} | {real['groups'][g]['pass_rate']} | {b} |")
    gap = (real["pass_rate"] or 0) - (broken["pass_rate"] or 0)
    lines += ["", f"Overall: real {real['pass_rate']}, broken {broken['pass_rate']}, gap {gap:.3f} "
                  f"(minimum {args.min_gap})."]
    text = "\n".join(lines) + "\n"
    print(text)
    if args.markdown:
        args.markdown.write_text("# Real skill vs broken variant\n\n" + text, encoding="utf-8")
    if gap < args.min_gap:
        print("evals.compare: the broken skill variant does not score clearly lower", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
