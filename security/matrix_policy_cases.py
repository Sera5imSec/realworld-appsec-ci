"""Local HTTP/SQLite checks for the project-specific AppSec policy rows.

Every variant reaches the HTTP/server boundary. PASS/FAIL describes the
approved local rule on this checkout. These rows block CI through bindings.
"""

from __future__ import annotations

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, urlencode

from matrix_cases import (article, count, create_article, legacy_source_key, need, rows, signup,
                          token_for, user)


ROOT = Path(__file__).resolve().parents[1]


class PolicyObservation(Exception):
    """A measured result without an approved pass/fail threshold."""


def auth_03(app, f, vid):
    query = urlencode({"access_token": f["bobby"]})
    path = "/api/user?" + query
    if vid.endswith("P01"):
        status, data = app.call("GET", path, token=f["alice"])
        need(status == 200 and data["user"]["username"] == "alice",
             f"header did not outrank query token: HTTP {status}")
    elif vid.endswith("N01"):
        status, data = app.call("GET", path)
        log = (Path(app.tmp.name) / "app.log").read_text(encoding="utf-8", errors="replace")
        identity = data.get("user", {}).get("username") if isinstance(data, dict) else None
        need(status == 401 and identity is None and f["bobby"] not in log,
             f"query token accepted or logged: HTTP {status}, identity={identity}, token_in_log={f['bobby'] in log}")
    else:
        status, data = app.call("GET", path, headers={"Authorization": "Token invalid"})
        need(status == 401 and "bobby@example.test" not in json.dumps(data),
             f"valid query token replaced invalid header: HTTP {status}")
    return "Authorization header priority held"


def config_01(local_app_type, binary, vid):
    key_a, key_b = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    if vid.endswith("P01"):
        with local_app_type(binary, {"JWT_SECRET": key_a}) as app:
            signup(app, "alice")
            signed = token_for({"id": user(app, "alice")[0], "exp": int(time.time()) + 3600}, key_a)
            status, data = app.call("GET", "/api/user", token=signed)
            need(status == 200 and data["user"]["username"] == "alice",
                 f"configured JWT key ignored: HTTP {status}")
    elif vid.endswith("N01"):
        with local_app_type(binary, {"JWT_SECRET": key_b}) as app:
            signup(app, "alice")
            signed = token_for({"id": user(app, "alice")[0], "exp": int(time.time()) + 3600}, key_a)
            status, _ = app.call("GET", "/api/user", token=signed)
            need(status == 401, f"token under old key accepted after rotation: HTTP {status}")
    else:
        with local_app_type(binary, {"JWT_SECRET": key_a}) as app:
            signup(app, "alice")
            known_source_key_token = token_for({
                "id": user(app, "alice")[0], "exp": int(time.time()) + 3600,
            }, legacy_source_key())
            status, _ = app.call("GET", "/api/user", token=known_source_key_token)
            need(status == 401, f"source fallback key accepted with configured key: HTTP {status}")
    return "JWT key followed configured value"


def article_05(app, f, vid):
    if vid.endswith("P01"):
        item = create_article(app, f["alice"], "Matrix tagged article", tags=["matrix-new-tag"])
        tag = rows(app, "SELECT id FROM tag_models WHERE tag=? AND deleted_at IS NULL", ("matrix-new-tag",))
        article_row = article(app, item["slug"])
        links = rows(app, "SELECT * FROM article_tags")
        need(article_row and len(tag) == 1 and links and "matrix-new-tag" in item["tagList"],
             "article/tag/link were not created together")
    elif vid.endswith("N01"):
        before = app.snapshot()
        status, _ = app.call("POST", "/api/articles", {"article": {
            "title": "Alpha article", "description": "Colliding title", "body": "Body",
            "tagList": ["orphan-create-tag"],
        }}, token=f["alice"])
        after = app.snapshot()
        need(status == 422 and after["article_models"] == before["article_models"]
             and after["tag_models"] == before["tag_models"]
             and after["article_tags"] == before["article_tags"],
             f"rejected article left tag/link rows: HTTP {status}, tags_delta={len(after['tag_models'])-len(before['tag_models'])}")
    else:
        before = app.snapshot()
        status, _ = app.call("PUT", f"/api/articles/{f['alpha_slug']}", {"article": {
            "title": "Bravo article", "tagList": ["orphan-update-tag"],
        }}, token=f["alice"])
        after = app.snapshot()
        need(status == 422 and after["article_models"] == before["article_models"]
             and after["tag_models"] == before["tag_models"]
             and after["article_tags"] == before["article_tags"],
             f"rejected update left tag/link rows: HTTP {status}, tags_delta={len(after['tag_models'])-len(before['tag_models'])}")
    return "article and tag state moved atomically"


def tag_01(app, f, vid):
    if vid.endswith("P01"):
        create_article(app, f["alice"], "Shared Alice article", tags=["shared-matrix-tag"])
        create_article(app, f["bobby"], "Shared Bobby article", tags=["shared-matrix-tag"])
        status, data = app.call("GET", "/api/tags")
        active = count(app, "tag_models", "tag=? AND deleted_at IS NULL", ("shared-matrix-tag",))
        need(status == 200 and data["tags"].count("shared-matrix-tag") == 1 and active == 1,
             f"shared tag duplicated: HTTP {status}, active={active}")
    elif vid.endswith("N01"):
        before = count(app, "tag_models", "tag=? AND deleted_at IS NULL", ("orphan-tag-list",))
        status, _ = app.call("POST", "/api/articles", {"article": {
            "title": "Alpha article", "description": "Collision", "body": "Body",
            "tagList": ["orphan-tag-list"],
        }}, token=f["alice"])
        _, data = app.call("GET", "/api/tags")
        active = count(app, "tag_models", "tag=? AND deleted_at IS NULL", ("orphan-tag-list",))
        need(status == 422 and active == before and "orphan-tag-list" not in data["tags"],
             f"rejected article exposed orphan tag: HTTP {status}, active={active}")
    else:
        titles = ("Parallel Alice article", "Parallel Bobby article")
        def make_item(item):
            token, title = item
            return app.call("POST", "/api/articles", {"article": {
                "title": title, "description": "Concurrent tag", "body": "Body",
                "tagList": ["parallel-matrix-tag"],
            }}, token=token)[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(make_item, (
                (f["alice"], titles[0]),
                (f["bobby"], titles[1]),
            )))
        active = count(app, "tag_models", "tag=? AND deleted_at IS NULL", ("parallel-matrix-tag",))
        created = count(app, "article_models", "title IN (?, ?) AND deleted_at IS NULL", titles)
        links = rows(app, """SELECT a.title FROM article_tags AS at
            JOIN article_models AS a ON a.id = at.article_model_id
            JOIN tag_models AS t ON t.id = at.tag_model_id
            WHERE t.tag = ? AND a.title IN (?, ?)""", ("parallel-matrix-tag", *titles))
        need(all(status in (201, 422) for status in statuses)
             and created == statuses.count(201) and len(links) == created
             and active == (1 if created else 0),
             f"parallel tag state inconsistent: statuses={statuses}, active={active}, created={created}, links={links}")
        return "parallel tag writes had no duplicate or orphan links"
    return "tag list matched completed articles"


def comment_03(app, f, vid):
    path = f"/api/articles/{f['alpha_slug']}/comments/{f['comment_a_id']}"
    before = count(app, "comment_models", "id=? AND deleted_at IS NULL", (f["comment_a_id"],))
    need(before == 1, "comment fixture missing")
    if vid.endswith("P01"):
        status, _ = app.call("DELETE", path, token=f["alice"])
        active = count(app, "comment_models", "id=? AND deleted_at IS NULL", (f["comment_a_id"],))
        need(status == 200 and active == 0, f"correct nested deletion: HTTP {status}, active={active}")
    else:
        wrong_slug = "bravo-article" if vid.endswith("N01") else "no-such-article"
        status, _ = app.call("DELETE", f"/api/articles/{wrong_slug}/comments/{f['comment_a_id']}", token=f["alice"])
        active = count(app, "comment_models", "id=? AND deleted_at IS NULL", (f["comment_a_id"],))
        need(status in (403, 404) and active == 1,
             f"wrong nested slug deleted comment: HTTP {status}, active={active}")
    return "comment ID remained bound to article slug"


def query_01(app, f, vid):
    tagged = create_article(app, f["alice"], "Exact query article", tags=["exact-matrix-tag"])
    before = app.snapshot()
    if vid.endswith("P01"):
        profile_status, profile = app.call("GET", "/api/profiles/bobby")
        article_status, item = app.call("GET", f"/api/articles/{tagged['slug']}")
        list_status, listing = app.call("GET", "/api/articles?tag=exact-matrix-tag")
        need(profile_status == article_status == list_status == 200
             and profile["profile"]["username"] == "bobby"
             and item["article"]["slug"] == tagged["slug"]
             and {x["slug"] for x in listing["articles"]} == {tagged["slug"]}
             and app.snapshot() == before, "exact query returned wrong object or changed DB")
    else:
        suffix = "' OR '1'='1" if vid.endswith("N01") else "é%雪"
        bad_user = quote("bobby" + suffix, safe="")
        bad_slug = quote(tagged["slug"] + suffix, safe="")
        bad_tag = urlencode({"tag": "exact-matrix-tag" + suffix})
        profile_status, _ = app.call("GET", f"/api/profiles/{bad_user}")
        article_status, _ = app.call("GET", f"/api/articles/{bad_slug}")
        list_status, listing = app.call("GET", f"/api/articles?{bad_tag}")
        need(profile_status == 404 and article_status == 404
             and list_status == 200 and listing["articles"] == []
             and listing["articlesCount"] == 0 and app.snapshot() == before,
             f"special query broadened selection: profile={profile_status}, article={article_status}, list={listing}")
    return "query values stayed bound to exact records"


def make_resource_fixture(app, fixture, total=25):
    for index in range(total - 2):
        create_article(app, fixture["alice"], f"Resource matrix article {index:02d}")
    need(count(app, "article_models", "deleted_at IS NULL") == total,
         f"resource fixture did not create {total} articles")


def resource_01(app, f, vid):
    if vid.endswith("N02"):
        before = app.snapshot()
        tags = [f"resource-matrix-tag-{i:02d}" for i in range(64)]
        status, _ = app.call("POST", "/api/articles", {"article": {
            "title": "Resource tag list", "description": "Description", "body": "Body",
            "tagList": tags,
        }}, token=f["alice"])
        need(status == 422 and app.snapshot() == before,
             f"oversized tagList changed state: HTTP {status}")
        return "64 tags were rejected without database changes"
    if vid.endswith("N03"):
        before = app.snapshot()
        status, _ = app.call("POST", "/api/articles", {"article": {
            "title": "Oversized request", "description": "Description", "body": "Body",
            "padding": "X" * 70000,
        }}, token=f["alice"])
        need(400 <= status < 500 and app.snapshot() == before,
             f"oversized JSON changed state or returned HTTP {status}")
        return "oversized JSON was rejected without database changes"
    if vid.endswith("P01"):
        make_resource_fixture(app, f)
        status, data = app.call("GET", "/api/articles?limit=20")
        need(status == 200 and len(data["articles"]) == 20 and data["articlesCount"] == 25,
             f"ordinary limit=20 response: HTTP {status}, size={len(data.get('articles', []))}")
        return "ordinary limit=20 returned 20 of 25 articles"
    if vid.endswith("P02"):
        make_resource_fixture(app, f)
        before = app.snapshot()
        plain_status, plain = app.call("GET", "/api/articles?limit=5&offset=2")
        spaced_status, spaced = app.call("GET", "/api/articles?limit=%205%20&offset=%202%20")
        need(plain_status == spaced_status == 200
             and plain["articlesCount"] == spaced["articlesCount"] == 25
             and len(plain["articles"]) == len(spaced["articles"]) == 5
             and [item["slug"] for item in plain["articles"]] ==
                 [item["slug"] for item in spaced["articles"]]
             and app.snapshot() == before,
             f"spaced pagination differed from numeric control: plain={plain_status}/{len(plain.get('articles', []))}, spaced={spaced_status}/{len(spaced.get('articles', []))}")
        return "spaced limit and offset matched the numeric control without database changes"
    make_resource_fixture(app, f, total=105)
    large_status, large = app.call("GET", "/api/articles?limit=1000000&offset=0")
    negative_status, negative = app.call("GET", "/api/articles?limit=-1&offset=-1")
    need(large_status == negative_status == 200
         and len(large["articles"]) == 100 and large["articlesCount"] == 105
         and len(negative["articles"]) == 20 and negative["articlesCount"] == 105,
         f"pagination was not capped: large={large_status}/{len(large.get('articles', []))}, negative={negative_status}/{len(negative.get('articles', []))}")
    return "limit was capped at 100 and negative pagination normalized"


def error_01(app, f, vid):
    if vid.endswith("P01"):
        status, data = signup(app, "diana", password="short")
        need(status == 422 and isinstance(data, dict) and isinstance(data.get("errors"), dict)
             and "Password" in data["errors"], f"validation error shape: HTTP {status}, body={data}")
    elif vid.endswith("N01"):
        status, data = signup(app, "diana", email="alice@example.test")
        body = json.dumps(data).lower()
        forbidden = ("unique constraint", "user_models", "select ", "insert ", "/tmp/", "traceback")
        need(status == 422 and isinstance(data, dict) and "errors" in data
             and not any(marker in body for marker in forbidden),
             f"database details exposed in public error: HTTP {status}, markers={[x for x in forbidden if x in body]}")
    else:
        status, data = app.call("POST", "/api/users", "{")
        need(400 <= status < 500 and isinstance(data, dict) and "errors" in data,
             f"malformed JSON returned uncontrolled response: HTTP {status}")
    return "public error class/body matched proposed policy"


def read_01(local_app_type, binary, vid):
    with local_app_type(binary) as app:
        bob_status, bob = signup(app, "bobby")
        alice_status, alice = signup(app, "alice")
        need(bob_status == alice_status == 201, "reader fixture registration failed")
        item = create_article(app, bob["user"]["token"], "Public read article")
        alice_id = user(app, "alice")[0]
        need(count(app, "article_user_models", "user_model_id=?", (alice_id,)) == 0,
             "reader fixture already has ArticleUserModel")
        before = app.snapshot()
        if vid.endswith("P01"):
            status, _ = app.call("GET", f"/api/articles/{item['slug']}", token=alice["user"]["token"])
            need(status == 200 and app.snapshot() == before,
                 f"GET article wrote domain state: HTTP {status}")
        elif vid.endswith("N01"):
            try:
                list_status, _ = app.call("GET", "/api/articles?author=alice", token=alice["user"]["token"])
            except TimeoutError as exc:
                raise AssertionError("filtered GET did not respond within 5 seconds") from exc
            article_status, _ = app.call("GET", f"/api/articles/{item['slug']}", token=alice["user"]["token"])
            need(list_status == article_status == 200 and app.snapshot() == before,
                 f"filtered/article GET wrote domain state: list={list_status}, article={article_status}")
        else:
            for _ in range(3):
                status, _ = app.call("GET", f"/api/articles/{item['slug']}", token=alice["user"]["token"])
                need(status == 200, f"repeated GET failed: HTTP {status}")
            need(app.snapshot() == before, "repeated GET wrote domain state")
        return "GET did not mutate domain rows"


OBSERVED_CASES = {
    "RW-AUTH-03": auth_03,
    "RW-ARTICLE-05": article_05,
    "RW-TAG-01": tag_01,
    "RW-COMMENT-03": comment_03,
    "RW-QUERY-01": query_01,
    "RW-RESOURCE-01": resource_01,
    "RW-ERROR-01": error_01,
}


def run_policy_case(local_app_type, binary, matrix_id, variant_id):
    if matrix_id == "RW-CONFIG-01":
        return config_01(local_app_type, binary, variant_id)
    if matrix_id == "RW-READ-01":
        return read_01(local_app_type, binary, variant_id)
    with local_app_type(binary) as app:
        fixture = app.bootstrap()
        return OBSERVED_CASES[matrix_id](app, fixture, variant_id)


OBSERVED_CASES.update({"RW-CONFIG-01": config_01, "RW-READ-01": read_01})
