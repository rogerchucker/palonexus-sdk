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
`RunnableConfig` in LangChain 1.x, so model calls require runtime context and
an application-owned `model_policy_key`. Each model policy also binds that key
to the exact application-supplied `BaseChatModel` object; a distinct backend
object fails closed even if it advertises the same public name.
`create_authorized_agent` likewise binds every configured tool policy to the
exact supplied `BaseTool` object. A replacement tool with the same name fails
closed before authorization or execution.

Use `create_authorized_agent`, not a raw `create_agent` middleware list.
LangChain executes middleware in onion order: the first entry is outermost and
the last is innermost. The helper validates exactly one PaloNexus middleware
and places it last, after middleware that may modify the model or tool request.
The raw middleware class is an advanced API; if used directly, validate the
complete list with `validate_authorized_middleware_stack`.

The middleware authorizes before calling LangChain's model or tool handler.
Consequently no streaming chunk is emitted before an allow. LangChain exposes
no separate middleware hook for per-chunk authorization; once allowed, stream
lifecycle and cleanup remain LangChain's responsibility. Cancellation is
propagated without retrying the handler.

By default authorization scope contains only the registered policy key,
service, and static tool/model identity. Tool argument values, argument keys,
prompts, and unsalted hashes of those values are not serialized. Argument-
sensitive authorization is intentionally deferred until an explicit safe
resource-projection contract is available.

## Compatibility matrix

| Surface | Sync | Async | Configuration and limit |
| --- | --- | --- | --- |
| Tool call | enforced | enforced | Runtime context or `RunnableConfig`; arguments omitted from scope |
| Model call | enforced | enforced | Runtime context only; policy key plus exact bound model object |
| Agent stream | pre-start gate | pre-start gate | No chunk precedes allow; LangChain owns post-allow cleanup |
| Durable approval resume | no | no | Use the PaloNexus LangGraph integration |
| Target-mutating middleware | enforced with helper | enforced with helper | PaloNexus must be last/innermost |

`LangChainApprovalRequired` is a safe pre-execution exception. It may be
rendered or routed by LangChain's human-in-the-loop middleware, but that
middleware is not a substitute for PaloNexus approval creation, immutable-scope
validation, or resume authorization. Use the PaloNexus LangGraph integration
for durable checkpoint-and-resume workflows.

Run the fully offline example:

```bash
uv run --all-extras python examples/langchain/main.py
```
