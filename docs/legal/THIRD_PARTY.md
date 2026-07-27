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
and locked Ruff formatter, and `gofmt` from the security-patched Go 1.25.12
toolchain declared in `go.mod`. The module retains the Go 1.25.0 language
baseline while verification rejects any selected build toolchain other than
Go 1.25.12. The generated Python and Go DTOs add no runtime package dependency.
Their stable headers bind each output to the generator version and the SHA-256
digest of all source schemas.

The protocol version 1 canonicalizer used by the Python SDK and vector
reference pins `unicodedata2` so Python 3.12, Python 3.13, and later runtimes
use the same Unicode 15.1.0 normalization tables. It pins `idna` for strict
IDNA2008 A-label validation without UTS 46 mapping. The exact package versions
and supplied licenses were reviewed; the implementation otherwise uses the
Python standard library.

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

After one explicit `uv sync --frozen`, verification runs
`uv lock --check --offline`; every `uv run` uses
`--frozen --offline --no-sync`. It checks every manifest constraint against the
locked version, requires the canonical PyPI registry and
`files.pythonhosted.org` artifact host, and requires SHA-256 hashes for every
locked distribution without contacting the network.

<!-- dependency-inventory:start -->
| Dependency | Version | License | Review status | Obligations | Notice | Source |
| --- | --- | --- | --- | --- | --- | --- |
| annotated-types | 0.8.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| anyio | 4.14.2 | MIT | reviewed | Retain notices | None identified | PyPI |
| ast-serialize | 0.6.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| attrs | 26.1.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| certifi | 2026.7.22 | MPL-2.0 | reviewed | Retain notices; disclose modifications to covered files | None identified | PyPI |
| cffi | 2.1.0 | MIT-0 | reviewed | Retain supplied license | None supplied | PyPI |
| charset-normalizer | 3.4.9 | MIT | reviewed | Retain notices | None identified | PyPI |
| colorama | 0.4.6 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause | reviewed | Retain supplied licenses | None supplied | PyPI |
| distro | 1.9.0 | Apache-2.0 | reviewed | Retain supplied license | None supplied | PyPI |
| hatch-vcs | 0.5.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| hatchling | 1.31.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| h11 | 0.16.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| httpcore | 1.0.9 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| httpx | 0.28.1 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| idna | 3.18 | BSD-3-Clause | reviewed | Retain license and notices | None supplied | PyPI |
| iniconfig | 2.3.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| jsonschema | 4.26.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| jsonschema-specifications | 2025.9.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| jsonpatch | 1.33 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| jsonpointer | 3.1.1 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| langchain | 1.3.14 | MIT | reviewed | Retain notices | None identified | PyPI |
| langchain-core | 1.5.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| langchain-protocol | 0.0.18 | MIT | reviewed | Retain notices | None identified | PyPI |
| langgraph | 1.2.9 | MIT | reviewed | Retain notices | None identified | PyPI |
| langgraph-checkpoint | 4.1.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| langgraph-prebuilt | 1.1.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| langgraph-sdk | 0.4.2 | MIT | reviewed | Retain notices | None identified | PyPI |
| langsmith | 0.10.10 | MIT | reviewed | Retain notices | None identified | PyPI |
| librt | 0.13.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| mypy | 2.3.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| mypy-extensions | 1.1.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| orjson | 3.11.9 | MPL-2.0 AND (Apache-2.0 OR MIT) | reviewed | Retain supplied licenses; disclose modifications to covered files | None supplied | PyPI |
| ormsgpack | 1.12.2 | Apache-2.0 OR MIT | reviewed | Retain supplied licenses | None supplied | PyPI |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| pathspec | 1.1.1 | MPL-2.0 | reviewed | Retain notices; disclose modifications to covered files | None identified | PyPI |
| pluggy | 1.6.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| pydantic | 2.13.4 | MIT | reviewed | Retain notices | None identified | PyPI |
| pydantic-core | 2.46.4 | MIT | reviewed | Retain notices | None identified | PyPI |
| pycparser | 3.0 | BSD-3-Clause | reviewed | Retain supplied license | None supplied | PyPI |
| pygments | 2.20.0 | BSD-2-Clause | reviewed | Retain notices | None identified | PyPI |
| pytest | 9.1.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| pyyaml | 6.0.3 | MIT | reviewed | Retain notices | None identified | PyPI |
| referencing | 0.37.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| requests | 2.34.2 | Apache-2.0 | reviewed | Retain supplied license and notices | Include supplied NOTICE | PyPI |
| requests-toolbelt | 1.0.0 | Apache-2.0 | reviewed | Retain supplied license | None supplied | PyPI |
| rpds-py | 2026.6.3 | MIT | reviewed | Retain notices | None identified | PyPI |
| ruff | 0.16.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools | 83.0.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| setuptools-scm | 10.2.1 | MIT | reviewed | Retain notices | None identified | PyPI |
| sniffio | 1.3.1 | MIT OR Apache-2.0 | reviewed | Retain supplied licenses | None supplied | PyPI |
| tenacity | 9.1.4 | Apache-2.0 | reviewed | Retain supplied license | None supplied | PyPI |
| trove-classifiers | 2026.6.1.19 | Apache-2.0 | reviewed | Retain notices | Include supplied NOTICE | PyPI |
| typing-extensions | 4.16.0 | PSF-2.0 | reviewed | Retain notices | None identified | PyPI |
| typing-inspection | 0.4.2 | MIT | reviewed | Retain notices | None identified | PyPI |
| unicodedata2 | 15.1.0 | Apache-2.0 | reviewed | Retain license and notices | None supplied | PyPI |
| urllib3 | 2.7.0 | MIT | reviewed | Retain notices | None identified | PyPI |
| uuid-utils | 0.17.0 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| vcs-versioning | 2.2.2 | MIT | reviewed | Retain notices | None identified | PyPI |
| websockets | 15.0.1 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
| xxhash | 3.8.1 | BSD-2-Clause | reviewed | Retain notices | None identified | PyPI |
| zstandard | 0.25.0 | BSD-3-Clause | reviewed | Retain notices | None identified | PyPI |
<!-- dependency-inventory:end -->

## CI-only tools and actions

CI does not distribute its tools with PaloNexus artifacts. GitHub-hosted actions
are restricted to the `actions`, `astral-sh`, and `github` organizations,
pinned to full immutable commit IDs, and annotated with their reviewed release
versions in each workflow. Dependency caches are disabled for untrusted pull
request execution.

Secret scanning runs the MIT-licensed Gitleaks module at the exact
`github.com/zricethezav/gitleaks/v8@v8.30.1` version through Go's authenticated
module mechanism. The repository does not use the separately licensed
`gitleaks-action` bundle. Historical false positives are suppressed only by
exact commit/path/rule/line fingerprints in `.gitleaksignore`; no path or regex
allowlist is used. The CodeQL analysis action is a GitHub-provided service
integration and its results are not distributed in release artifacts.
