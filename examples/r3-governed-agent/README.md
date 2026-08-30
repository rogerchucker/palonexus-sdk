# R3 governed MCP and subagent walkthrough

This one registered agent drives all three acceptance scenarios. It declares two
commands but requests authority only for the exact MCP tool. That distinction is
intentional: declaration says what the program can attempt; the approved ceiling and
run grant say what PaloNexus can authorize.

```bash
cd examples/r3-governed-agent
pnxs login
pnxs agents init
pnxs agents register
pnxs agents request-authority
pnxs run agent.py --input input-mcp-approval.json --detach --json
```

Approve the exact action in Operations Center, then resume the original process state:

```bash
pnxs actions resume ACTION_ID --json
```

The completed response contains the bounded MCP result and the target receipt. To prove
that a human approval cannot manufacture missing authority, run:

```bash
pnxs run agent.py --input input-capability-denied.json --json
```

That command exits with terminal `capability_denied`; no approval request, credential,
target call, effect, or receipt is created.

The third scenario is directly runnable and restart-safe:

```bash
pnxs run agent.py --input input-subagent-denied.json --detach --json
# Deny the pending spawn in Operations Center.
pnxs subagents resume SPAWN_REQUEST_ID --json
```

The descriptor's reviewed subagent template is part of the registered artifact. The CLI
retains the prospective key only in local encrypted custody and resumes the same server
request; it never creates a replacement request after restart.

`deep_agent.py` also shows the framework host wiring. Pass a
`GovernedSubagentRuntime` as `spawn_runtime`. The middleware intercepts Deep Agents'
public `task` tool before its handler. A pending spawn interrupts the durable graph; a
human denial resumes it as `spawn_denied` without calling the child handler. An allowed
spawn proves possession of the prospective key, provisions and activates the child
identity, and only then permits Deep Agents to execute the child.
