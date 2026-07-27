# SPDX-License-Identifier: MIT
"""Deterministically vendor the reviewed reference canonicalizer."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).parents[1]
REFERENCE = ROOT / "protocol" / "reference" / "canonicalize.py"
PACKAGE = ROOT / "python" / "src" / "palonexus" / "_canonicalize.py"
REFERENCE_VECTOR_PATH = (
    'VECTORS = Path(__file__).parents[1] / "test-vectors" / "canonicalization"'
)
# The emitted statement is one line: it fits the project's 88-column limit, and a
# wrapped form makes `ruff format` reject the vendored output. It is written here as
# two concatenated parts only to keep this source line within the same limit.
PACKAGE_VECTOR_PATH = (
    'VECTORS = Path(__file__).parents[3] / "protocol"'
    ' / "test-vectors" / "canonicalization"'
)


def generated_bytes() -> bytes:
    source = REFERENCE.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    text = source.decode("utf-8")
    text = text.replace(
        "# SPDX-License-Identifier: MIT\n",
        "# SPDX-License-Identifier: MIT\n"
        "# Generated from protocol/reference/canonicalize.py\n"
        f"# Source-SHA256: {digest}\n",
        1,
    )
    text = text.replace(REFERENCE_VECTOR_PATH, PACKAGE_VECTOR_PATH, 1)
    return text.encode("utf-8")


def main() -> int:
    expected = generated_bytes()
    if PACKAGE.read_bytes() == expected:
        return 0
    PACKAGE.write_bytes(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
