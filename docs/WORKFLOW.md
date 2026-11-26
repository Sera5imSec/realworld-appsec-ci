# RealWorld boundary matrix workflow

The source, catalog, executable HTTP/SQLite checks and CI live in this repository.
The catalog contains 32 matrices and 164 scenarios. A matrix describes a rule;
independent observations determine whether the rule holds. Existing accepted
deviations remain visible as `KNOWN_FAIL` rather than being reported as fixed.

## Development

```text
Inspect the actual source and affected callers
  -> identify the trust boundary and obligation
  -> define an observation distinguishing correct behavior from a violation
  -> implement controls and negative cases in the catalog and Python runner
  -> link Go files, functions/routes and matrix scenarios
  -> reverse-review source rules and record exact coverage decisions
  -> validate the catalog and run normal checks
  -> submit the scoped change for review
```

Source mutation sensitivity remains a separate optional manual operation. It is
not a stage of each PR, push or scheduled normal run.

## Normal CI and agent handoff

```text
PR opened/updated, push to main, manual run or weekly normal CI
  -> checkout source and install tools
  -> review catalog, bindings and classification of production Go files
  -> compare committed Go symbols/routes/top-level code against the PR base
  -> match exact fingerprint decisions and write handoff artifacts
     -> missing/invalid coverage: FAIL at SOURCE_REVIEW before building
        -> maintainer gives the PR link to a local assistant
        -> assistant reads AGENTS.md, diff, artifacts, rules and executable checks
        -> assistant implements justified decisions and missing scenarios/matrices
        -> scoped commit/push to the same PR branch when authorized
        -> new CI run starts from checkout
     -> coverage current: continue
  -> gate and source-review integrity tests
  -> select affected matrices
  -> build the Go server
  -> run selected HTTP/SQLite controls and negative scenarios
  -> enforce runtime results and exact accepted-failure observations
  -> upload reports, including when source review fails
  -> maintainer reviews and merges according to repository rules
  -> successful main CI permits the separate Local CD workflow
```

A source-review failure ends the job. The assistant is requested separately; a
running CI job does not wait for a person or automatically invoke an agent. The
authorizing request and final merge review follow the repository/user's rules;
there is no Copilot subscription dependency or fixed number of approvals.

Normal Go, lint, API, scanner and delivery admission jobs remain parallel jobs.
Source-review success only permits the build; it is not a runtime PASS.

## Selection and review scope

- Article routers, serializers and validators select the 23 matrices reaching
  article/tag routes, including cross-cutting rules.
- Shared/user/startup/model code, dependencies and gate/catalog changes select
  all 32. Manual and scheduled normal runs also select all 32.
- The decision journal does not broaden selection by itself. Decisions are
  still validated and changed Go code still determines the selected checks.
- Documentation-only and Go-test-only changes select zero matrix runtime cases;
  the catalog/inventory review and other test jobs still apply.

File classification checks every current non-test Go file. Function, route and
top-level decisions are evaluated for the committed PR diff. The existing Go
parser does not inspect uncommitted source edits. A full/no-base run explicitly
records that no PR diff was analyzed; it must not be presented as a new review
of every function. A candidate matrix link does not prove semantic completeness.

See [the source review guide](SOURCE-REVIEW.md), [matrix documentation](../security/README.md),
[policy](../security/POLICY.md) and [Local CD](LOCAL-CD.md).
