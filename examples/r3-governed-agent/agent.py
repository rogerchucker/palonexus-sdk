"""R3 demo agent: one exact MCP call or one intentionally ungranted action."""

from __future__ import annotations

from typing import Any

MCP_SCHEMA_DIGEST = (
    "93c5c52c6762a21b1b35dea92835f8385a29c7c9da3ecb4f1b4c0faa3937132b"
)
RESOURCE = "release:2026.08.30"


def assess_release(command: dict[str, Any], context: Any) -> dict[str, Any]:
    release = command["release"]
    if command["scenario"] == "mcp_approval":
        return context.mcp.call(
            server="change-control-mcp",
            tool="assess_release",
            schema_digest=MCP_SCHEMA_DIGEST,
            resource=RESOURCE,
            arguments={"release": release},
        ).result
    return context.actions.invoke(
        "release.assessment.publish",
        RESOURCE,
        {"release": release},
    ).result
