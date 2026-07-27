# Asynchronous Python example

This fully offline example provides async parity for the synthetic inventory
workflow. It demonstrates deny, approval-required, explicit approval, fresh
authorization on resume, exactly one execution after allow, and correlated
authorization/approval audit IDs.
It inspects the recorded request sequence to prove the fresh resume decision
and demonstrates that the prepared execution envelope cannot be replayed.

From the repository root:

```bash
uv run python examples/python-async/main.py
```

The `ScriptedEngine` and `AsyncFakeTransport` are explicit testing utilities
for deterministic examples. Applications should inject their production async
authorization and approval transports instead.
