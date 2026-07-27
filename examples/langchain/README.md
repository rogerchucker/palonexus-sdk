# LangChain integration

Install the optional integration with:

```bash
uv add "palonexus[langchain]"
```

`PaloNexusLangChainMiddleware` is provider-neutral and supports LangChain 1.x.
Register every permitted tool and model with an explicit service and side-effect
classification; an unregistered or malformed call fails closed. Pass a
`LangChainAuthorizationContext` as the agent runtime context. Tool calls may
also receive the same object at
`config["configurable"]["palonexus"]`. Model middleware cannot read
`RunnableConfig` in LangChain 1.x, so model calls require runtime context.

The middleware authorizes before calling LangChain's model or tool handler.
Consequently no streaming chunk is emitted before an allow. LangChain exposes
no separate middleware hook for per-chunk authorization; once allowed, stream
lifecycle and cleanup remain LangChain's responsibility. Cancellation is
propagated without retrying the handler.

`LangChainApprovalRequired` is a safe pre-execution exception. It may be
rendered or routed by LangChain's human-in-the-loop middleware, but that
middleware is not a substitute for PaloNexus approval creation, immutable-scope
validation, or resume authorization. Use the PaloNexus LangGraph integration
for durable checkpoint-and-resume workflows.

Run the fully offline example:

```bash
uv run --all-extras python examples/langchain/main.py
```
