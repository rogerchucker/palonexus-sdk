"""A minimal plain-Python PaloNexus agent."""

from typing import cast

from palonexus.developer.context import AgentContext


def review_release(
    change: dict[str, object], context: AgentContext
) -> dict[str, object]:
    """Submit one descriptor-declared action through the parent guard."""
    risk = str(change["risk"])
    score = {"low": 0.2, "medium": 0.5, "high": 0.9}[risk]
    outcome = context.actions.invoke(
        "release.assessment.publish",
        "release/demo",
        {"assessment": {"risk": risk, "score": score}},
    )
    return cast(dict[str, object], outcome.result)
