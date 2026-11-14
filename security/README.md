# AppSec boundary matrix CI

This is a local, source-linked CI gate for the Go/Gin RealWorld backend. It uses
the [catalog](matrices/catalog.json) based on upstream commit
`626c372d259472148d93303f74aa9b9a1cdcef24` plus local hardening changes.
Only synthetic users and a temporary SQLite database are used. Nine security
rules that were previously held are now explicit in [POLICY.md](POLICY.md).

## What is enforced now

- `matrix_ci.py` validates 30 matrix definitions, 159 planned variant IDs,
  source references, route coverage, bindings, and change-to-matrix mapping.
  It also inventories every non-test Go file: each must have a matrix watch
  or an explicit full-run classification before CI can proceed.
- `matrix_runtime.py` runs the selected matrices' variants against the real
  local HTTP server (159 variants across all 30 matrices in a full run). Each
  variant gets a fresh SQLite database with
  synthetic users; write checks compare HTTP and DB state.
- `matrix_sensitivity.py` builds one disposable source mutant per selected
  matrix (30 in a full run). Each matrix has
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

The latest local runtime run completed all 159 variants: 153 passed and 6
matched the reviewed known-failure baseline. The six failures are in four
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
Changes to article routers, serializers, or validators select all matrices that
reach an article or tag route (currently 23), including cross-cutting auth,
input, and route checks. Article models, shared/user/startup Go code, Go
dependencies, and CI/security files select all 30 because they can affect
other routes or the gate itself. A new production Go file without a matrix
watch or an explicit full-run classification fails validation before selection.
Existing shared database code, compiled test helpers, and package documentation
are explicitly classified for a full run. The catalog validator also fails if
any production Go file lacks a classification, even when that file was not
changed in the current PR.
Non-Go documentation-only and Go test-only changes do not run this matrix job's
runtime cases; the repository's other test jobs still run.

Each selected matrix runs its runtime variants and one representative source
mutation probe. A weekly Sunday 03:00 UTC schedule and manual workflow
dispatch select all 30. The selector uses `ci_watch_seed` to require source
ownership; it does not assume that file-level ownership covers transitive
dependencies. Shared code therefore keeps the full-run fallback.

## Reviewing changes inside Go files

The PR gate also compares named functions, route registrations, and top-level
declarations at the merge base and PR head. It writes `boundary-change-impact.json`
and `boundary-review.json`, plus a short Markdown review summary. Changed
functions are linked to **candidate** matrix IDs and variant IDs using source
references inside their current span; file watches are a broader fallback.
Route candidates use method/path suffixes, then file watches. These links are
review prompts, not evidence that a new security rule is already tested.

- Every code change inside a named function, every changed route registration,
  and every top-level code change needs an explicit decision in
  `matrices/code_decisions.json` before the gate passes. The decision is per
  changed region, not per edited line. Formatting and ordinary comment edits
  are ignored; the gate does not require a new matrix for every code edit.
- The decision is `existing_rule`, `add_variant`, `new_matrix`, or
  `not_security`, with a short reason. Security decisions name real matrix and
  variant IDs. The decision's `fingerprint` is the changed item's `after_hash`
  from `boundary-change-impact.json`, or `before_hash` for a removal. This
  binds the decision to the exact changed code or route registration.
- An `add_variant` decision must name a variant newly added relative to the
  PR base catalog. A `new_matrix` decision must name a newly added matrix.
  Reusing an old ID with either label fails review. Top-level changes use
  `kind: "top_level"` and `symbol: "(outside named functions)"`.
- The reviewer checks whether the existing test really reaches the changed
  behavior. If the same rule has a new case, add a variant and its executable
  binding. If there is a new obligation, add a matrix and executable tests.
  CI validates IDs and results; it cannot decide the meaning of a code change
  on its own. An ambiguous scanner input fails rather than silently omitting
  the change.

Example decision shape (replace IDs and fingerprint with those from the actual
change and catalog):

```json
{
  "kind": "function",
  "path": "articles/routers.go",
  "symbol": "ArticleCommentDelete",
  "fingerprint": "<64-character after_hash>",
  "decision": "existing_rule",
  "matrix_ids": ["RW-COMMENT-03"],
  "variant_ids": ["RW-COMMENT-03-N01"],
  "reason": "The existing case checks that a comment belongs to the selected article."
}
```

This is the second layer of source review. It does not narrow the existing
23/30 matrix selector, and a passing gate does not imply that every new
security obligation was automatically discovered. The development review
starts at the changed behavior, maps it back to a rule and test, and records
whether to reuse a matrix, add a case, or add a matrix.

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

The existing `.github/workflows/ci.yml` runs its Go, lint, scanner, and API
jobs alongside `matrix-appsec`. The [default-branch CI run](https://github.com/Sera5imSec/realworld-appsec-private/actions/runs/41345271013)
passed. The isolated [pagination experiment](https://github.com/Sera5imSec/realworld-appsec-private/actions/runs/41346717675)
also passed with 160 scenarios. A [controlled tag-limit regression](https://github.com/Sera5imSec/realworld-appsec-private/actions/runs/41478246898)
failed the matrix gate, and its [revert](https://github.com/Sera5imSec/realworld-appsec-private/actions/runs/41478756085)
passed. This repository has no deployment workflow; the existing gate can be
connected to a deployment pipeline when one is added.
