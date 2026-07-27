# Synchronous Python example

This fully offline example governs a synthetic inventory update with the
synchronous PaloNexus client. It demonstrates a denied request, a separate
approval-required request, explicit approval, fresh authorization on resume,
one execution after allow, and correlated authorization/approval audit IDs.

From the repository root:

```bash
uv run python examples/python-basic/main.py
```

The `ScriptedEngine` and `FakeTransport` are explicit testing utilities used to
make the example deterministic. Applications should inject their production
authorization and approval transports instead.
