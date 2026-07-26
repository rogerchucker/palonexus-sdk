# PreToolUse fixture status

JSON payloads in this directory are derived only from trusted cells. Their
presence records the observed payload shape; it does not mean Gate 0 is
complete or that every blocking scenario passed. The `capture.cell` field links
each payload to its nonce-bound source evidence under `../cells/`.

`foundation_tests/test_codex_gate0.py` validates the payload input fingerprint,
invocation count, and linked scenario evidence. Gate completeness is reported
separately in `../expected-capabilities.json`.
