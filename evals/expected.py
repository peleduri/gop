"""Expected values, read from gop itself.

For each case, run the same check_answerable call and the same query the
agent should run, on the same graph, and keep the confirmed and possible
counts, answerable and missing facts. Nothing here is hand-written, so the
expected values cannot drift from the engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .gop import Gop, resolve_id

# The unit each query's headline number counts, as an answer would write it.
UNITS = {
    "who_can_reach": r"principals?|accounts?|identities|identity|users?|members?",
    "blast_radius": r"repos?|repositories|repository",
    "top_risks": r"repos?|repositories|repository",
    "what_if": r"pairs?",
    "fix_plan": r"pairs?",
}


@dataclass
class Expected:
    case_id: str
    graph: str
    kind: str
    subject: str  # resolved node ID, "" for the whole enterprise
    answerable: str  # yes | partial | no
    missing: list[dict[str, str]]
    tool: str
    unit: str  # regex of the unit the counts are in, "" when the tool has none
    confirmed: list[int] = field(default_factory=list)  # every confirmed figure, headline first
    possible: list[int] = field(default_factory=list)  # the possible figure of each confirmed one, same order
    summary: str = ""  # the query's summary line

    @property
    def headline_confirmed(self) -> int | None:
        return self.confirmed[0] if self.confirmed else None

    def facts_text(self) -> str:
        """The expected facts in words, for the judge's expected_output."""
        lines = [f"check_answerable({self.kind}, {self.subject or 'enterprise'}) = {self.answerable}."]
        if self.confirmed:
            lines.append(f"Confirmed figures ({self.tool}): {self.confirmed}; possible figures: {self.possible}.")
        if self.summary:
            lines.append(f"gop summary: {self.summary}")
        for m in self.missing:
            lines.append(f"Not visible: {m.get('fact')} on {m.get('scope')} ({m.get('reason', '')}).")
        if self.answerable == "no":
            lines.append("The agent must not answer; it asks for the missing access.")
        elif self.answerable == "partial":
            lines.append("The answer is a lower bound; findings that rest on missing facts need validation.")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _resolve_args(graph: str, args: Any, subject: str) -> Any:
    if isinstance(args, dict):
        return {k: _resolve_args(graph, v, subject) for k, v in args.items()}
    if isinstance(args, list):
        return [_resolve_args(graph, v, subject) for v in args]
    if args == "$subject":
        return subject
    if isinstance(args, str) and ":" in args:
        try:
            return resolve_id(graph, args)
        except ValueError:
            return args
    return args


def _numbers(tool: str, out: dict[str, Any]) -> tuple[list[int], list[int]]:
    if tool == "who_can_reach":
        return [len(out.get("confirmed") or [])], [len(out.get("possible") or [])]
    if tool == "blast_radius":
        s = out["score"]
        return [s["confirmed"]["repos"]], [s["possible"]["repos"]]
    if tool == "top_risks":
        rows = out.get("risks") or []
        return [r["confirmed"]["repos"] for r in rows], [r["possible"]["repos"] for r in rows]
    if tool == "what_if":
        d = out["delta"]
        return ([d["before"]["confirmed_pairs"], d["after"]["confirmed_pairs"]],
                [d["before"]["possible_pairs"], d["after"]["possible_pairs"]])
    if tool == "fix_plan":
        d = out["plan"]["removes"]
        b, a = d["before"], d["after"]
        return ([b["confirmed_pairs"], a["confirmed_pairs"], b["confirmed_pairs"] - a["confirmed_pairs"]],
                [b["possible_pairs"], a["possible_pairs"], 0])
    return [], []


async def expected_for(gop: Gop, case: dict[str, Any]) -> Expected:
    """Run the case's check_answerable call and query on gop and keep the results."""
    facts = case["facts"]
    graph = case["graph"]
    subject = resolve_id(graph, facts["subject"]) if facts.get("subject") else ""
    ca_args = {"question_kind": facts["kind"]}
    if subject:
        ca_args["subject"] = subject
    ca = await gop.call("check_answerable", ca_args)
    if ca.is_error:
        raise RuntimeError(f"{case['id']}: check_answerable failed: {ca.text}")
    tool = facts["tool"]
    res = await gop.call(tool, _resolve_args(graph, facts.get("args") or {}, subject))
    if res.is_error:
        raise RuntimeError(f"{case['id']}: {tool} failed: {res.text}")
    confirmed, possible = _numbers(tool, res.structured)
    return Expected(
        case_id=case["id"], graph=graph, kind=facts["kind"], subject=subject,
        answerable=ca.structured["answerable"],
        missing=[{k: str(v) for k, v in m.items()} for m in ca.structured.get("missing") or []],
        tool=tool, unit=UNITS.get(tool, ""), confirmed=confirmed, possible=possible,
        summary=res.text.split("\n", 1)[0],
    )
