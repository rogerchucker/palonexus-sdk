# Relicensing record

## Owner attestation

The committed [`OWNER_AUTHORIZATION.md`](OWNER_AUTHORIZATION.md) is the public,
DCO-signed authorization artifact for this extraction.

The PaloNexus repository owner/controller of the GitHub account
`rogerchucker`, acting in that capacity and representing that they control the
rights necessary for the covered PaloNexus-owned material, selected MIT on
2026-07-25 and reaffirmed authorization to execute the public extraction on
2026-07-26. The required authorization date for this extraction is therefore
2026-07-26.

This attestation is traceable to the private Codex task conversation in which
the repository design, MIT choice, and subsequent execution approval were
recorded. The private conversation is not distributed because it may contain
private repository context; repository history, this record, and
`PROVENANCE.csv` are the durable public evidence.

The authorized extraction source is `rogerchucker/palonexus-platform` at commit
`e5ebb21fc960f57a529f262c52c6d69c20fcf2f8`. That repository remains subject to
its own license. This authorization applies only to material deliberately
entered in `PROVENANCE.csv` and released from `rogerchucker/palonexus-sdk`.

## Conditions

- A file derived from the source repository must have a provenance row before
  it enters this repository.
- A `port` or `rewrite` row must identify the exact source path and extraction
  commit, confirm that contributor history was reviewed, and reference a
  path-plus-SHA-256 entry in `SOURCE_TREE.txt`.
- Clean-room work is recorded as `new`. Reproducible output is recorded as
  `generated`.
- Every destination is reviewed for compatibility with the MIT License. The
  repository-level `LICENSE` file is the controlling license for accepted
  contributions unless a file explicitly and validly states otherwise.
- Third-party dependencies and bundled material follow `THIRD_PARTY.md`; owner
  authorization does not relicense third-party work.
- Contributor-owned material not covered by the owner's representation requires
  independent rights-holder review and authorization before migration.

## Provenance coverage and exemptions

The verifier inventories distributable/runtime source, build and release
tooling, examples, protocol and packaging inputs, plugin instructions and
manifests, executable fixture/testdata helpers, root package metadata, and legal
evidence. Vendor directories are not exempt.

Only generated caches, virtual environments, dependency installation trees,
ordinary source build outputs, release output directories, and inert captured
fixture/testdata records (`.json`, `.yaml`, `.yml`, `.xml`, `.txt`, `.out`, and
`.golden`) and captured archives named exactly `payload.zip` are exempt. A
recognized plugin/package manifest remains covered even in a fixture directory,
and code or executable helpers in fixtures and testdata remain covered.

`SOURCE_TREE.txt` is deliberately an eligible-migration manifest, not an
inventory of the private source repository. It starts empty. A maintainer adds
only the source path and content hash for a reviewed file at the moment that a
public `port` or `rewrite` provenance row is added. Unrelated private paths are
never published.

This record is durable project evidence, not a general representation about
the licensing of any other PaloNexus repository. It records project process and
is not legal advice.
