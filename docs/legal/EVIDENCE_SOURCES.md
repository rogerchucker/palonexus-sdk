# Host evidence sources

Gate 0 records factual observations and locally authored test structure. It does
not copy or relicense Claude Code, npm packages, or Anthropic documentation.

| Input | Upstream | Material retained | Legal disposition |
| --- | --- | --- | --- |
| Claude Code executable | Anthropic native installer | Version, SHA-256, operating system, architecture, and origin label | Factual compatibility and integrity metadata; executable is not distributed |
| `@anthropic-ai/claude-code` | npm registry / Anthropic | Package name, stable dist-tag version, and registry integrity value | Factual registry metadata; package is not distributed |
| Claude Code hooks reference | Anthropic | URL, retrieval timestamp, SHA-256, and a short factual contract summary | Upstream prose is not copied; digest supports reproducibility |
| Claude Code changelog | Anthropic GitHub repository | Immutable commit URL, commit ID, SHA-256, and factual version evidence | Upstream changelog is not copied or redistributed |
| `PreToolUse` payloads | Claude Code executable output | Strictly allowlisted field names and non-sensitive fixture values | Factual interoperability records; PaloNexus authors the selection, sanitization, and JSON arrangement |

The repository's MIT license applies to PaloNexus-authored scripts, tests,
selection, and arrangement. It does not alter ownership of third-party
software, documentation, trademarks, or any copyrightable upstream material.
Superseded observations are explicitly claim-excluded and cannot establish
compatibility.
