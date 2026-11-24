"""The skill text the agent gets as its system prompt, and broken variants of it.

A broken variant removes one rule from skills/gop/SKILL.md. Running the eval
with it must score clearly lower than with the real skill (evals.compare):
that shows the eval detects a regression in the skill.
"""

from __future__ import annotations

from .gop import ROOT

SKILL = ROOT / "skills" / "gop" / "SKILL.md"

# Each variant is a list of exact passages removed from SKILL.md. A passage
# that is no longer in the skill is an error, so a variant can never silently
# become the real skill.
VARIANTS: dict[str, list[str]] = {
    "real": [],
    # The "never add possible to confirmed" rule.
    "no-sum-rule": [
        "- Never add possible counts to confirmed counts, in a total or a headline. Lead\n"
        "  with confirmed numbers; give possible numbers on their own line.\n",
    ],
    # The "check before concluding" step and the unknown-is-not-absent rules.
    "no-check": [
        "2. Call `check_answerable(question_kind=top_risks)` for the enterprise, and\n"
        "   again with `question_kind` and `subject` for each specific claim you make\n"
        "   later (for example `question_kind=paths`, `subject=members:acme-actions`).\n"
        "   - `yes`: every required fact was visible.\n"
        "   - `partial`: the answer is a lower bound. Say so and name what is missing.\n"
        "   - `no`: do not answer. Ask for the missing access instead.\n",
        "- Never call a setting off, absent or safe when it is `not_visible`. Write\n"
        "  \"unknown (not visible)\" and name the access that would make it visible.\n",
    ],
}


def body(text: str) -> str:
    """SKILL.md without its YAML front matter."""
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end >= 0:
            return text[end + 5:].lstrip()
    return text


def skill_text(variant: str = "real") -> str:
    """The system prompt for variant."""
    if variant not in VARIANTS:
        raise SystemExit(f"unknown skill variant {variant!r}; one of {', '.join(VARIANTS)}")
    text = SKILL.read_text(encoding="utf-8")
    for passage in VARIANTS[variant]:
        if passage not in text:
            raise SystemExit(f"skill variant {variant}: passage no longer in {SKILL}: {passage[:60]!r}")
        text = text.replace(passage, "")
    return body(text)
