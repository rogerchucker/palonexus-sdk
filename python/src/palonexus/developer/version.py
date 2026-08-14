# SPDX-License-Identifier: MIT
from __future__ import annotations

import re
from importlib import import_module, metadata

try:
    SOURCE_REVISION: object = getattr(
        import_module("palonexus._build"), "SOURCE_REVISION"
    )
except ImportError:
    SOURCE_REVISION = ""


def version_metadata() -> dict[str, str | None]:
    version = metadata.version("palonexus")
    source_revision = (
        SOURCE_REVISION
        if isinstance(SOURCE_REVISION, str)
        and re.fullmatch(r"[0-9a-f]{40}", SOURCE_REVISION)
        else None
    )
    return {
        "version": version,
        "source_revision": source_revision,
    }
