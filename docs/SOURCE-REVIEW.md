# Source review with a local assistant

When source review stops CI, send the PR URL and intended behavior to an
assistant that can access the repository and Actions. The assistant follows
`AGENTS.md`, reads the changed source and actual executable assertions, implements
the coverage decision and tests it. No automatic cloud-agent integration is used.

```text
Missing decision -> FAIL before build -> give PR to assistant
  -> inspect source, impact, rules, tests and accepted observations
  -> existing_rule / add_variant / new_matrix / not_security
  -> implement, test and record exact generated fingerprints
  -> authorized commit to the same PR branch -> new CI run
  -> runtime checks -> maintainer review and merge
```

## What to send

```text
Review PR <URL> using AGENTS.md and docs/SOURCE-REVIEW.md.
Use its actual base SHA and inspect the source-review artifacts.
Implement justified coverage decisions, executable checks and bindings where
needed. Preserve policies, matrix scenarios and exact accepted-failure evidence.
Run normal checks and report their real results. Keep changes on this PR branch.
Do not merge, deploy or run source mutations. Commit/push within my authorization.
```

The journal is `security/matrices/code_decisions.json`. Its `fingerprint` is the
impact report's `after_hash`, or `before_hash` for a removed symbol. Decisions
are per `kind` (`function`, `route`, `top_level`), path and symbol. Top-level
declarations use `(outside named functions)` as the symbol. Re-running identical
committed source does not require a new decision.

| Decision | Implementation |
| --- | --- |
| `existing_rule` | Existing executable variants demonstrably cover this behavior; record IDs and rationale |
| `add_variant` | Add a scenario to the catalog and its executable Python binding |
| `new_matrix` | Add an independent obligation, oracle, controls, cases and bindings |
| `not_security` | Record a precise scope reason, with empty matrix/variant arrays |

`add_variant` and `new_matrix` must introduce a scenario/matrix relative to the
base catalog. Changing a label or copying a previous fingerprint is insufficient.
Do not automatically refresh hashes or classify a security-relevant block as
`not_security`. An adequate decision permits runtime testing; it cannot override
an actual rule failure.

## Commands

Use Linux with Go 1.23, Node 20+, Python 3.11+ and SQLite/CGO build tools for full
runtime verification. Use the actual PR base SHA. The Go impact parser compares
committed snapshots, so uncommitted Go edits are not included in its report.

```sh
# Coverage only. Writes reports before returning 0 (PASS) or 1 (FAIL).
python3 security/matrix_ci.py review --base BASE_COMMIT_SHA

# Normal integrity and admission checks; no source-mutation suite.
python3 -m unittest discover -s security -p 'test_matrix_gate.py'
node --test security/test_change_impact.mjs security/test_boundary_review.mjs
python3 -m unittest discover -s delivery -p 'test_*.py'

# Use selection produced by the passing source review.
CGO_ENABLED=1 go build -o /tmp/realworld-app .
python3 security/matrix_runtime.py --binary /tmp/realworld-app --selection artifacts/matrix-selection.json --output artifacts/matrix-runtime.json
python3 security/matrix_report.py --selection artifacts/matrix-selection.json --runtime artifacts/matrix-runtime.json --json-out artifacts/matrix-status.json --markdown-out artifacts/matrix-status.md
```

Stop after any failed command. `review --full` validates the catalog and whole
production Go file classification and selects all matrices; it explicitly skips
a PR symbol diff. It is not a substitute for reviewing an actual PR base.

## Reports and outcomes

Reports default to `artifacts/`. CI uses `$RUNNER_TEMP` and uploads them in
`matrix-appsec-evidence` with `if: always()`.

| File | Meaning |
| --- | --- |
| `catalog-validation.json` | Catalog, bindings, routes and production Go file classification |
| `boundary-change-impact.json` | Added/modified/removed committed Go units and exact before/after hashes |
| `boundary-review.json` / `.md` | Candidate checks, recorded decisions, blocking items and errors |
| `source-review.json` / `.md` | Pre-build verdict and instructions for the local-assistant handoff |
| `matrix-selection.json` | Selected checks, or `blocked` after a failed review |
| `matrix-runtime.json` | `NOT_RUN` before build; observed per-variant results after runtime |
| `matrix-status.json` / `.md` | Source-review failure or the actual runtime gate result |

Parser, base and tool errors are reported explicitly and replace stale success
artifacts. No parser result is invented when parsing failed. A source-review
`REVIEW_REQUIRED` is different from a runtime failure or missing runtime evidence.
Exact accepted observations remain `KNOWN_FAIL`; new/changed failures block CI.
Passing normal CI does not claim those accepted deviations were repaired.

Source sensitivity remains in its separate manual workflow. Local CD follows
successful main CI and has separate deployment/install observations. HTTP/SQLite
test evidence does not by itself establish a deployed application's behavior.
