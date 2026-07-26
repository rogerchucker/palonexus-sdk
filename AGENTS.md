# Repository instructions

- Use `uv`, never `pip`, for Python environments, builds, and publishing.
- New behavior is developed test-first.
- The protocol schemas and golden vectors are the cross-language source of truth.
- Host plugins stay thin: normalize, call the local guard, and render the verdict.
- Policy, credentials, identity derivation, and caches do not belong in plugins.
- Missing identity, malformed protocol data, and unavailable authorization fail closed.
