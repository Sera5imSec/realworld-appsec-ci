# Reverse source-to-matrix audit

Scope: the 16 non-`*_test.go` Go files in this backend checkout. This audit
starts with source behavior, then checks the catalog, executable case, and
representative sensitivity probe. A file watch or a selected full gate is **not**
evidence that every rule in that file has an executable oracle.

## Inventory

| Source | Existing direct matrix families | Reverse-audit decision |
| --- | --- | --- |
| `hello.go` | ROUTE, AUTH-03, CONFIG; now DB-01 | Route/auth/JWT startup are tested; migration failure handling is not. |
| `common/database.go` | None before this audit; now DB-01 | Configured DB path and failed open needed their own startup check. |
| `common/utils.go` | AUTH, CONFIG, INPUT, RESOURCE, ERROR | Publicly reachable uses have direct scenarios; random helpers have Go unit tests and are not a separate trust boundary here. |
| `common/test_helpers.go` | None | Test utilities are compiled but not called by production routes; no AppSec matrix is justified for them. |
| `users/middlewares.go` | ROUTE, AUTH, CONFIG | Token extraction and request identity have direct cases; malformed/deleted-user failures are already recorded, not missing matrices. |
| `users/models.go` | USER, PROFILE, FOLLOW, FEED | Password/identity/follow outcomes have HTTP and DB cases; the long-password failure is already recorded. |
| `users/validators.go` | USER, INPUT | Registration/update/login validation has direct cases. |
| `users/routers.go` | ROUTE, USER, PROFILE, FOLLOW, QUERY, ERROR | Public, optional and protected handlers have route and behavior cases. |
| `users/serializers.go` | USER, PROFILE, ARTICLE | Field allowlists and viewer identity have response cases. |
| `articles/models.go` | ARTICLE, FEED, TAG, COMMENT, FAVORITE, QUERY, RESOURCE, READ | Main write/read boundaries have cases; filter combinations and deletion relations need an explicit contract decision before a new rule is claimed. |
| `articles/validators.go` | ARTICLE, COMMENT, INPUT, RESOURCE | Payload validation, ownership and tag limit have direct cases. |
| `articles/routers.go` | ROUTE, ARTICLE, COMMENT, FAVORITE, TAG, QUERY, RESOURCE, ERROR | Registered handlers have route and behavior cases. |
| `articles/serializers.go` | ARTICLE, COMMENT, FAVORITE, TAG, READ | Public field exposure and viewer-specific fields have response cases. |
| `doc.go`, `users/doc.go`, `articles/doc.go` | None | Package documentation only; the file inventory still classifies changes. |

## Gaps and decisions

1. **DB startup — executable row added (`RW-DB-01`).** Earlier, changing
   `common/database.go` selected all matrices, but none tested DB opening.
   New control checks the configured SQLite file and migrated schema; negative
   case points `DB_PATH` at a directory and requires startup to stop. Its
   disposable source mutation ignores the path. In [PR #7's first CI run](https://github.com/Sera5imSec/realworld-appsec-ci/actions/runs/43715210087),
   both `RW-DB-01` variants passed and the path-ignoring mutation was detected.
   The artifact records 31 selected matrices, 161 runtime rows, 31 sensitivity
   probes, 27 `BOUND_PASS` and four matrices with accepted `KNOWN_FAIL` cases.
2. **Migration errors — uncovered candidate.** `hello.go:Migrate` and
   `users/models.go:AutoMigrate` discard migration errors. Existing tests check
   the happy schema through fixtures, but none supplies a failing migration and
   checks that the HTTP listener stays closed. This is a distinct obligation
   from DB opening; it needs a fixture, an error-propagating implementation and
   a sensitivity check before it can become a blocking matrix.
3. **Combined article filters and soft-delete relations — contract questions.**
   `FindManyArticle` uses `if/else if` for tag, author and favorited, so multiple
   filters do not compose. `ArticleDelete` soft-deletes the article without an
   explicit assertion about its old comment, favorite and tag relationships.
   Current catalog tests individual filters and delete authorization. The
   RealWorld contract and desired cleanup semantics need to be fixed before
   adding a blocking rule; source inspection alone is not a finding.
4. **Six accepted failures — already covered, not blind spots.** AUTH-02 has
   two; USER-01 two; ARTICLE-04 one; ARTICLE-07 one. The gate reports these as
   reviewed `KNOWN_FAIL` observations. Do not count them as missing matrices or
   as repaired behavior.

The source inventory and within-file review catch *future unclassified edits*.
This audit addresses existing behavior. Neither a green catalog validation nor
one representative mutant per matrix proves completeness of every variant.
