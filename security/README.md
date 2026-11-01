# AppSec boundary matrix CI

This is a local, source-linked CI gate for the Go/Gin RealWorld backend. It uses
the [catalog](matrices/catalog.json) based on upstream commit
`626c372d259472148d93303f74aa9b9a1cdcef24` plus local hardening changes.
Only synthetic users and a temporary SQLite database are used. Nine security
rules that were previously held are now explicit in [POLICY.md](POLICY.md).

## What is enforced now

- `matrix_ci.py` validates 30 matrix definitions, 160 planned variant IDs,
  source references, route coverage, bindings, and change-to-matrix mapping.
- `matrix_runtime.py` runs all 160 variants in 30 bound matrices against the
  real local HTTP server. Each variant gets a fresh SQLite database with
  synthetic users; write checks compare HTTP and DB state.
- `matrix_sensitivity.py` builds 30 disposable source mutants. Each matrix has
  a probe that must notice a controlled regression. Production source is not
  changed by the sensitivity run. One representative variant is probed per
  matrix; this does not independently confirm every failing variant.
- `test_matrix_gate.py` checks that dependency and new-source changes cannot
  silently skip the matrix set, and that missing runtime or sensitivity
  evidence makes the report fail.
- `matrix_report.py` fails CI on a new or changed bound check failure, a missing result from
  either group, a runner error, missing sensitivity evidence, or an unmapped
  production file. The only exception is an exact, reviewed local failure in
  `matrices/accepted_failures.json`: both its variant ID and stable observation
  fingerprint must match. New failures and changed fingerprints fail CI; a
  repaired variant also fails until its stale baseline entry is removed. The
  report keeps accepted failures visible as `KNOWN_FAIL`.

The full local run before the pagination experiment completed 159 variants:
153 passed and 6 matched the reviewed known-failure baseline. The experiment
adds `RW-RESOURCE-01-P02`; its result is recorded in CI evidence. The six
baseline failures are in four
matrices (`AUTH-02`, `USER-01`, `ARTICLE-04`, `ARTICLE-07`); they remain visible
as `KNOWN_FAIL` and are not fixed. All nine formerly held policy matrices
passed their variants and their individual source-mutation probes. A green
report does not mean the remaining known failures were fixed. See the generated
matrix status and per-variant JSON evidence.

The remaining known failures cover malformed JWT claims or nonexistent users,
registration uniqueness and long-password handling, duplicate article titles,
and article list `body` compatibility. These are local observations, not claims
about a deployed service. The 2024-08-16 RealWorld response format excludes
article `body` from list responses; this is an API compatibility mismatch.

The nine local policy rows are blocking: token handling (`AUTH-03`), JWT key
source (`CONFIG-01`), atomic tag writes (`ARTICLE-05`, `TAG-01`), nested comment
identity (`COMMENT-03`), query handling (`QUERY-01`), resource limits
(`RESOURCE-01`), public error details (`ERROR-01`), and read-only GET behavior
(`READ-01`). The previous filtered GET delay disappeared after read paths
stopped creating database rows.

## Change selection

On PRs and pushes, the workflow compares changed files with the base commit.
Any production Go file, Go dependency manifest, matrix catalog, or CI script
selects all 30 matrices. A new production Go file without a catalog mapping
fails selection. Documentation-only and Go test-only changes do not run this
matrix job's runtime cases; the repository's other test jobs still run.

`ci_watch_seed` is a source ownership map, not a selective-execution shortcut.
Running the full matrix set for production changes avoids missing transitive
dependencies that the seed map does not yet describe.

## Local reproduction

Run on Linux with Go 1.23+, a C compiler for SQLite/CGO, and Python 3.11+:

Set `JWT_SECRET` to a local test value before manually running the application
in `GIN_MODE=release`. The matrix runner supplies its own synthetic test key.

```sh
python3 security/matrix_ci.py validate
python3 security/matrix_ci.py select --output /tmp/matrix-selection.json
CGO_ENABLED=1 go build -o /tmp/realworld-app .
python3 security/matrix_runtime.py --binary /tmp/realworld-app --selection /tmp/matrix-selection.json --output /tmp/matrix-runtime.json
python3 security/matrix_sensitivity.py --binary /tmp/realworld-app --selection /tmp/matrix-selection.json --output /tmp/matrix-sensitivity.json
python3 security/matrix_report.py --selection /tmp/matrix-selection.json --runtime /tmp/matrix-runtime.json --sensitivity /tmp/matrix-sensitivity.json --json-out /tmp/matrix-status.json --markdown-out /tmp/matrix-status.md
```

The existing `.github/workflows/ci.yml` still runs its Go, lint, scanner,
and API jobs. The new `matrix-appsec` job adds this matrix gate. This
repository has no deployment workflow, so a deploy gate can be connected to
the same job when a release/deployment pipeline exists. The GitHub-hosted job
has not been run because these changes have not been pushed.
