# Generated protocol runtime version 1

The generated Python and Go structural runtimes enforce bounded JSON parsing at
their public wire boundary. Each document is limited to 64 KiB, nesting to 32
containers, decoded collections to 1,024 entries, decoded strings to 8,192
UTF-8 bytes, numeric tokens to 512 bytes, and the aggregate decoded tree to
4,096 nodes. Invalid UTF-8, unpaired escaped surrogates, duplicate object keys
at every depth, and limit violations are rejected before schema traversal.

JSON numbers remain exact across generated runtimes. Python wire parsing uses
`int` for integer tokens and `decimal.Decimal` for decimal or exponent tokens;
direct Python mappings must likewise use `int` or `Decimal`, never a binary
`float`. Go retains `json.Number` in extension trees. Schema `integer` fields
accept mathematically integral spellings such as `1.0` and `1e0`, then normalize
them to the target integer type after range validation. Serialization may
normalize a number's spelling but preserves its exact mathematical value.

Generator input patterns are limited to 512 Unicode scalar values. Generator
version 2 records SHA-256 digests for every immutable Task 5–8 pattern that has
received Python and Go RE2 portability and complexity review. A changed complex
pattern has a different digest, fails closed, and requires an explicit generator
policy review before its digest can be added.

New, unreviewed patterns are limited to a deliberately simple common grammar:
anchors, explicit ASCII or Unicode scalar literals, approved literal escapes,
character classes, and finite `{m}` or `{m,n}` quantifiers applied to one literal
or class. Bounds are parsed as decimal integers, ordered, and capped at the
runtime string ceiling. Groups, alternation, open-ended or malformed braces,
lookaround, backreferences, inline flags, conditionals, named groups,
Unicode-sensitive shorthand classes, locale or Unicode property classes,
unsupported escapes, and variable `?`, `*`, or `+` quantifiers all require
reviewed-pattern approval and otherwise fail closed.

Every patterned string is bounded by the 8,192-byte runtime string ceiling; an
explicit schema `maxLength` cannot exceed that ceiling. Wire parsing enforces the
byte ceiling before any regular expression runs.

Reference-cycle review uses the complete local schema graph. Direct references
and composition applicators do not consume document structure, while
`properties`, `items`, `prefixItems`, `additionalProperties`, and equivalent
container keywords do. A cycle made only of non-consuming edges is rejected.
Recursive extension schemas remain valid only when every cycle crosses a
structure-consuming edge and runtime nesting remains bounded.
