# Third-party review policy

PaloNexus accepts a dependency only after a maintainer verifies its identity,
source, resolved version or build constraint, SPDX license expression, notices,
obligations, and compatibility with distribution under MIT. Manifest and
lockfile changes must update the inventory below in the same pull request. The
verifier reconciles direct build/development requirements and every registry
package resolved in `uv.lock`; verification is local and does not use the
network.

An unreviewed dependency is release-blocking and must not be distributed.
Dependencies with a forbidden license or an unknown license are rejected.
Reviewers must also reject material whose license obligations cannot be met by
the repository's source and binary release process. Approval records must use
`reviewed`; no blank, pending, unreviewed, or exception state is accepted.

Generated software bills of materials and license reports are release evidence,
not substitutes for this review.

## External compatibility evidence

Gate 0 records facts about Codex releases and public host contracts from
OpenAI's official documentation, GitHub releases, immutable source-schema
permalinks, and release-archive digests. The repository stores only URLs,
timestamps, digests, version identifiers, and short factual summaries. It does
not redistribute OpenAI documentation, schemas, binaries, or release notes.
Those external materials are capture inputs and verification evidence, not
MIT-licensed contents of this repository.

## Dependency review inventory

Versions are exact resolutions in `uv.lock`, including the Python build and
development dependency closure. “Retain notices” means preserving the
dependency's copyright and license text when its code is redistributed.
“Include supplied NOTICE” applies when an upstream Apache NOTICE file is
present.

`python/pyproject.toml` lists the complete Hatchling and hatch-vcs dependency
closure as exact reviewed requirements. PEP 517 permits additional
build-system requirements; listing the closure directly constrains isolated
build environments so their resolver cannot float a transitive build tool.
The verifier derives that closure from `uv.lock` and requires every member to
be present as an exact build requirement.

Verification runs `uv lock --check --offline`, checks every manifest constraint
against the locked version, requires the canonical PyPI registry and
`files.pythonhosted.org` artifact host, and requires SHA-256 hashes for every
locked distribution without contacting the network.

<!-- dependency-inventory:start -->
| Dependency | Version | License | Review status | Obligations | Notice | Source |
| --- | --- | --- | --- | --- | --- | --- |
| colorama | 0.4.6 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| hatch-vcs | 0.5.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| hatchling | 1.31.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| iniconfig | 2.3.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| pathspec | 1.1.1 | MPL-2.0 | reviewed | Retain notices; disclose modifications to covered files | None identified | PyPI |
| pluggy | 1.6.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| pygments | 2.20.0 | BSD-2-Clause | reviewed | Retain notices | None identified | PyPI |
| pytest | 9.1.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| ruff | 0.16.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools | 83.0.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools-scm | 10.2.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| trove-classifiers | 2026.6.1.19 | Apache-2.0 | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| vcs-versioning | 2.2.2 | MIT | reviewed | Retain notices | None identified | PyPI |
<!-- dependency-inventory:end -->
