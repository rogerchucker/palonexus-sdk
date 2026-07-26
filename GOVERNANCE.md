# Governance

PaloNexus SDK is maintainer-led. The repository owner, `@rogerchucker`, appoints
maintainers, reviews governance changes, and has final responsibility for
releases, security response, and repository administration. Maintainers seek
technical consensus in public issues and pull requests; when consensus is not
possible, the repository owner decides and records the rationale.

## Ownership and changes

`CODEOWNERS` identifies areas requiring owner review. Protocol schemas and
golden vectors are normative across all implementations. A protocol proposal
must describe motivation, compatibility, migration, security consequences, and
test-vector changes. Approval from the protocol owner is required. Released
protocol majors are stable; incompatible semantics require a new major version.

Security-sensitive guard code, host plugins, release workflows, and security
policy require owner review. Maintainers may expedite a private security fix
and document the decision after coordinated disclosure.

## Releases and trademarks

Only maintainers may create releases. Release support follows `SECURITY.md`,
and user-visible changes are recorded in `CHANGELOG.md`.

The source is MIT-licensed. The PaloNexus names, logos, and other brand assets
remain trademarks; the license does not grant permission to imply endorsement
or use those marks to identify a derived product.
