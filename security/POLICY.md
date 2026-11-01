# Local AppSec policy for the RealWorld matrix gate

These rules apply to this checkout's CI and local test server. They are project
hardening decisions, not claims about every RealWorld implementation or a
deployed service. The catalog's API-spec checks remain separate.

| Matrix | Required behavior |
| --- | --- |
| `RW-AUTH-03` | `Authorization` takes priority. In release mode, a query `access_token` never authenticates. URL token values are redacted before access logging. The legacy query path is available only in development mode. |
| `RW-CONFIG-01` | Release mode requires `JWT_SECRET`. Signing and verification use that configured value; a key change immediately invalidates tokens signed with the old key. The source fallback is development-only. |
| `RW-ARTICLE-05` | Article and tag creation/update occur in one transaction. A rejected article operation leaves no tag or join-table changes. |
| `RW-TAG-01` | Public tag output reflects completed article operations. Parallel use of one tag does not create duplicate active tags or orphan article-tag links. |
| `RW-COMMENT-03` | Deleting a comment through a nested article route requires the comment's article ID to match the route's slug. A wrong or missing slug leaves the comment intact. |
| `RW-QUERY-01` | Client-supplied username, slug, and filter strings are query values. Special characters cannot broaden selection or mutate data. |
| `RW-RESOURCE-01` | Article page size defaults to 20 and is capped at 100; negative page size/offset normalize to the defaults and offset is capped at 10000. An article accepts at most 32 tags, and JSON bodies above 64 KiB receive a controlled client error without database changes. |
| `RW-ERROR-01` | Public database errors use a generic message. Malformed JSON receives structured 4xx; responses do not include SQL, table names, local paths, keys, or stack traces. |
| `RW-READ-01` | GET handlers and serializers do not create or update domain rows. A missing viewer-specific row stays missing during reads. |

All nine rows are blocking only after their normal and negative variants pass
and a disposable source mutation is detected for each row. A CI pass still
reports any separately accepted known failures; those are not remediated by
this policy.
