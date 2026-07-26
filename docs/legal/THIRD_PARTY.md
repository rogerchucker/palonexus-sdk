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

Protocol type generation uses the Python standard library, the reviewed and
locked JSON Schema validator for Draft 2020-12 meta-schema checks, the reviewed
and locked Ruff formatter, and `gofmt` from the Go 1.25 baseline declared in
`go.mod`. The generated Python and Go DTOs add no runtime package dependency.
Their stable headers bind each output to the generator version and the SHA-256
digest of all source schemas.

The protocol version 1 canonicalization reference pins `unicodedata2` so Python
3.12, Python 3.13, and later runtimes use the same Unicode 15.1.0 normalization
tables. It pins `idna` for strict IDNA2008 A-label validation without UTS 46
mapping. The exact package versions and supplied licenses were reviewed; the
reference otherwise uses the Python standard library.

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
| attrs | 26.1.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| colorama | 0.4.6 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| hatch-vcs | 0.5.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| hatchling | 1.31.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| idna | 3.18 | BSD-3-Clause | reviewed | Retain license and notices | None supplied | PyPI |
| iniconfig | 2.3.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| jsonschema | 4.26.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| jsonschema-specifications | 2025.9.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| pathspec | 1.1.1 | MPL-2.0 | reviewed | Retain notices; disclose modifications to covered files | None identified | PyPI |
| pluggy | 1.6.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| pygments | 2.20.0 | BSD-2-Clause | reviewed | Retain notices | None identified | PyPI |
| pytest | 9.1.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| referencing | 0.37.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| rpds-py | 2026.6.3 | MIT | reviewed | Retain notices | None identified | PyPI |
| ruff | 0.16.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools | 83.0.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools-scm | 10.2.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| trove-classifiers | 2026.6.1.19 | Apache-2.0 | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| typing-extensions | 4.16.0 | PSF-2.0 | reviewed | Retain notices | None identified | PyPI |
| unicodedata2 | 15.1.0 | Apache-2.0 | reviewed | Retain license and notices | None supplied | PyPI |
| vcs-versioning | 2.2.2 | MIT | reviewed | Retain notices | None identified | PyPI |
<!-- dependency-inventory:end -->
