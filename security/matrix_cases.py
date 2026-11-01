"""Additional source-linked RealWorld matrix cases.

Each case starts a fresh local server and SQLite database. Assertions use HTTP
results plus direct DB checks where a write or identity boundary is involved.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
TEST_JWT_SECRET = "realworld-matrix-local-key-never-for-deployment"


def legacy_source_key():
    source = (ROOT / "common/utils.go").read_text(encoding="utf-8")
    return re.search(r'const JWTSecret = "([^"]+)"', source).group(1)


def need(ok, detail):
    if not ok:
        raise AssertionError(detail)


def rows(app, query, params=()):
    with sqlite3.connect(app.db) as db:
        return db.execute(query, params).fetchall()


def count(app, table, where="1=1", params=()):
    return rows(app, f'SELECT COUNT(*) FROM "{table}" WHERE {where}', params)[0][0]


def user(app, name):
    return rows(app, "SELECT id, username, email, password, bio, image FROM user_models WHERE username=?", (name,))[0]


def article(app, slug):
    found = rows(app, "SELECT id, slug, title, author_id FROM article_models WHERE slug=? AND deleted_at IS NULL", (slug,))
    return found[0] if found else None


def active_follows(app, follower, target):
    return count(app, "follow_models", "followed_by_id=? AND following_id=? AND deleted_at IS NULL", (follower, target))


def active_favorites(app, article_id, user_id):
    return count(app, "favorite_models", "favorite_id=? AND favorite_by_id=? AND deleted_at IS NULL", (article_id, user_id))


def signup(app, name, email=None, password="SafePassword123"):
    return app.call("POST", "/api/users", {"user": {
        "username": name, "email": email or f"{name}@example.test", "password": password,
    }})


def login(app, email, password):
    return app.call("POST", "/api/users/login", {"user": {"email": email, "password": password}})


def create_article(app, token, title, *, tags=None):
    status, data = app.call("POST", "/api/articles", {"article": {
        "title": title, "description": "Matrix description", "body": "Matrix body",
        "tagList": tags or [],
    }}, token=token)
    need(status == 201 and isinstance(data, dict) and "article" in data,
         f"article fixture failed: {status} {data}")
    return data["article"]


def create_comment(app, token, slug, body):
    status, data = app.call("POST", f"/api/articles/{slug}/comments",
                            {"comment": {"body": body}}, token=token)
    need(status == 201 and isinstance(data, dict) and "comment" in data,
         f"comment fixture failed: {status} {data}")
    return data["comment"]


def token_for(claims, key=None):
    if key is None:
        key = TEST_JWT_SECRET
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")
    message = encode({"alg": "HS256", "typ": "JWT"}) + b"." + encode(claims)
    signature = base64.urlsafe_b64encode(hmac.new(key.encode(), message, hashlib.sha256).digest()).rstrip(b"=")
    return (message + b"." + signature).decode()


def private_keys_absent(value):
    forbidden = {"email", "token", "password", "password_hash", "passwordhash",
                 "author_id", "user_model_id", "favorite_by_id"}
    if isinstance(value, dict):
        need(not forbidden.intersection(value), f"private key in response: {forbidden.intersection(value)}")
        for child in value.values():
            private_keys_absent(child)
    elif isinstance(value, list):
        for child in value:
            private_keys_absent(child)


def auth_01(app, f, vid):
    token = f["alice"]
    if vid.endswith("N01"):
        parts = token.split(".")
        signature = parts[2]
        parts[2] = ("A" if signature[0] != "A" else "B") + signature[1:]
        token = ".".join(parts)
    elif vid.endswith("N02"):
        token = token_for({"id": user(app, "alice")[0], "exp": int(time.time()) - 60})
    status, data = app.call("GET", "/api/user", token=token)
    if vid.endswith("P01"):
        need(status == 200 and data["user"]["username"] == "alice", f"valid signed token: {status} {data}")
    else:
        need(status == 401, f"invalid signed token accepted: {status} {data}")
    return f"token identity/status {status}"


def auth_02(app, f, vid):
    alice_id = user(app, "alice")[0]
    if vid.endswith("P01"):
        status, data = app.call("GET", "/api/user", token=f["alice"])
        need(status == 200 and data["user"]["username"] == "alice", f"valid claims: {status} {data}")
        again, body = app.call("GET", "/api/user", token=data["user"]["token"])
        need(again == 200 and body["user"]["username"] == "alice", "renewed token changed identity")
    elif vid.endswith("N01"):
        for claims in ({"exp": int(time.time()) + 3600},
                       {"id": str(alice_id), "exp": int(time.time()) + 3600}):
            status, data = app.call("GET", "/api/user", token=token_for(claims))
            need(status == 401, f"invalid id claim returned {status}: {data}")
    else:
        bad = token_for({"id": 999999, "exp": int(time.time()) + 3600})
        before = count(app, "article_models")
        status, data = app.call("GET", "/api/user", token=bad)
        need(status == 401, f"missing user id returned {status}: {data}")
        status, data = app.call("POST", "/api/articles", {"article": {
            "title": "Ghost article", "description": "Description", "body": "Body"}}, token=bad)
        need(status == 401 and count(app, "article_models") == before,
             f"missing user created article or returned {status}: {data}")
    return "JWT claims bound to existing user"


def user_01(app, f, vid):
    if vid.endswith("P01"):
        alice = user(app, "alice")
        status, data = login(app, "alice@example.test", "SafePassword123")
        need(status == 200 and alice[3] and alice[3] != "SafePassword123"
             and "SafePassword123" not in json.dumps(data)
             and alice[3] not in json.dumps(data), f"password storage/login: {status} {data}")
    elif vid.endswith("N01"):
        before = rows(app, "SELECT id, username, email, password FROM user_models ORDER BY id")
        status, _ = signup(app, "diana", "alice@example.test")
        need(status == 422 and rows(app, "SELECT id, username, email, password FROM user_models ORDER BY id") == before,
             f"duplicate email: status={status}")
    elif vid.endswith("N02"):
        before = count(app, "user_models")
        for password in ("", "short"):
            status, _ = signup(app, "diana", password=password)
            need(status == 422 and count(app, "user_models") == before,
                 f"short password: status={status}")
    elif vid.endswith("N03"):
        before = count(app, "user_models", "username='alice'")
        status, _ = signup(app, "alice", "diana@example.test")
        need(status == 422 and count(app, "user_models", "username='alice'") == before,
             f"duplicate username: status={status}")
    else:
        long_password = "A" * 100
        before = count(app, "user_models")
        status, data = signup(app, "diana", password=long_password)
        if status == 201:
            diana = user(app, "diana")
            logged, _ = login(app, "diana@example.test", long_password)
            need(bool(diana[3]) and logged == 200,
                 f"long password created unusable hash: hash={bool(diana[3])}, login={logged}")
        else:
            need(status == 422 and count(app, "user_models") == before,
                 f"long password invalid handling: {status} {data}")
    return "registration/password DB and HTTP oracle matched"


def user_03(app, f, vid):
    if vid.endswith("P01"):
        status, data = app.call("GET", "/api/user", token=f["alice"])
        need(status == 200 and data["user"]["email"] == "alice@example.test"
             and data["user"]["username"] == "alice" and data["user"]["token"],
             f"Alice self: {status} {data}")
        need(set(data["user"]) == {"username", "email", "bio", "image", "token"}, "self response fields changed")
    elif vid.endswith("N01"):
        status, data = app.call("GET", "/api/user", token=f["bobby"])
        need(status == 200 and data["user"]["email"] == "bobby@example.test"
             and data["user"]["token"] != f["alice"]
             and "alice@example.test" not in json.dumps(data), "Bob read Alice's self data")
    else:
        status, data = app.call("GET", "/api/user")
        need(status == 401 and "alice@example.test" not in json.dumps(data), f"anonymous self: {status} {data}")
    return "self identity/field boundary matched"


def user_04(app, f, vid):
    before = rows(app, "SELECT id,username,email,password,bio,image FROM user_models ORDER BY id")
    if vid.endswith("P01"):
        status, data = app.call("PUT", "/api/user", {"user": {
            "bio": "Alice matrix bio", "image": "https://example.test/alice.png"}}, token=f["alice"])
        after = rows(app, "SELECT id,username,email,password,bio,image FROM user_models ORDER BY id")
        need(status == 200 and after[0][:4] == before[0][:4]
             and after[0][4:] == ("Alice matrix bio", "https://example.test/alice.png")
             and after[1:] == before[1:], f"self update: {status} {data}")
    elif vid.endswith("N01"):
        bob_id = user(app, "bobby")[0]
        status, _ = app.call("PUT", "/api/user", {"user": {
            "id": bob_id, "password_hash": "forged", "email": "bobby@example.test"}}, token=f["alice"])
        after = rows(app, "SELECT id,username,email,password,bio,image FROM user_models ORDER BY id")
        need(status in (200, 422) and after == before, f"forged update affected system/other user: {status}")
    elif vid.endswith("N02"):
        status, _ = app.call("PUT", "/api/user", {"user": {"bio": "anonymous edit"}})
        after = rows(app, "SELECT id,username,email,password,bio,image FROM user_models ORDER BY id")
        need(status == 401 and after == before, f"anonymous update: {status}")
    else:
        status, _ = app.call("PUT", "/api/user", {"user": {"password": "NewPassword123"}}, token=f["alice"])
        old_status, _ = login(app, "alice@example.test", "SafePassword123")
        new_status, _ = login(app, "alice@example.test", "NewPassword123")
        after = rows(app, "SELECT id,username,email,password,bio,image FROM user_models ORDER BY id")
        need(status == 200 and old_status == 401 and new_status == 200
             and after[0][3] != before[0][3] and bool(after[0][3])
             and after[1:] == before[1:], f"password update: {status}, old={old_status}, new={new_status}")
    return "user update was scoped to current identity"


def profile_01(app, f, vid):
    if vid.endswith("P01"):
        status, _ = app.call("POST", "/api/profiles/bobby/follow", token=f["alice"])
        need(status == 200, f"follow fixture: {status}")
        a_status, a = app.call("GET", "/api/profiles/bobby", token=f["alice"])
        n_status, n = app.call("GET", "/api/profiles/bobby")
        need(a_status == n_status == 200 and a["profile"]["following"] is True
             and n["profile"]["following"] is False,
             f"viewer-specific following: {a_status} {a} / {n_status} {n}")
    elif vid.endswith("N01"):
        for token in (f["bobby"], None):
            status, data = app.call("GET", "/api/profiles/alice", token=token)
            need(status == 200 and set(data["profile"]) == {"username", "bio", "image", "following"},
                 f"profile field set: {status} {data}")
            private_keys_absent(data)
    else:
        status, data = app.call("GET", "/api/profiles/no-such-user")
        need(status == 404 and "alice@example.test" not in json.dumps(data), f"missing profile: {status} {data}")
    return "public profile field/viewer oracle matched"


def follow_01(app, f, vid):
    aid, bid, cid = (user(app, name)[0] for name in ("alice", "bobby", "charlie"))
    if vid.endswith("P01"):
        status, _ = app.call("POST", "/api/profiles/bobby/follow", token=f["alice"])
        need(status == 200 and active_follows(app, aid, bid) == 1, f"follow did not create one Alice->Bob: {status}")
        status, _ = app.call("DELETE", "/api/profiles/bobby/follow", token=f["alice"])
        need(status == 200 and active_follows(app, aid, bid) == 0, f"unfollow did not remove Alice->Bob: {status}")
    elif vid.endswith("N01"):
        status, _ = app.call("POST", "/api/profiles/bobby/follow",
                             {"follower": bid, "following": cid, "id": cid}, token=f["alice"])
        need(status == 200 and active_follows(app, aid, bid) == 1
             and active_follows(app, bid, cid) == 0, f"body redirected follow: {status}")
    elif vid.endswith("N02"):
        for _ in range(2):
            status, _ = app.call("POST", "/api/profiles/bobby/follow", token=f["alice"])
            need(status == 200, f"repeat follow: {status}")
        need(active_follows(app, aid, bid) == 1, "duplicate active Alice->Bob follow")
        before = rows(app, "SELECT id,following_id,followed_by_id,deleted_at FROM follow_models ORDER BY id")
        for method in ("POST", "DELETE"):
            status, _ = app.call(method, "/api/profiles/bobby/follow")
            need(status == 401 and rows(app, "SELECT id,following_id,followed_by_id,deleted_at FROM follow_models ORDER BY id") == before,
                 f"anonymous follow mutation: {method} {status}")
    else:
        before = count(app, "follow_models")
        status, _ = app.call("POST", "/api/profiles/no-such-user/follow", token=f["alice"])
        need(status == 404 and count(app, "follow_models") == before, f"missing profile follow: {status}")
    return "follow relation matched actor and target"


def article_01(app, f, vid):
    before = count(app, "article_models")
    if vid.endswith("P01"):
        item = create_article(app, f["alice"], "Matrix new article")
        row = article(app, item["slug"])
        linked_user = rows(app, "SELECT user_model_id FROM article_user_models WHERE id=?", (row[3],))[0][0]
        need(row is not None and linked_user == user(app, "alice")[0]
             and item["author"]["username"] == "alice", "article author did not bind token")
    elif vid.endswith("N01"):
        bob_id = user(app, "bobby")[0]
        status, data = app.call("POST", "/api/articles", {"article": {
            "title": "Spoof author article", "description": "Description", "body": "Body",
            "author": "bobby", "author_id": bob_id}}, token=f["alice"])
        need(status == 201, f"spoof fixture: {status} {data}")
        row = article(app, data["article"]["slug"])
        linked_user = rows(app, "SELECT user_model_id FROM article_user_models WHERE id=?", (row[3],))[0][0]
        need(linked_user == user(app, "alice")[0] and data["article"]["author"]["username"] == "alice",
             "client selected article author")
    else:
        for bad in ({"title": "Missing body", "description": "Description"},
                    {"title": "Wrong type", "description": "Description", "body": ["not string"]}):
            status, _ = app.call("POST", "/api/articles", {"article": bad}, token=f["alice"])
            need(status == 422 and count(app, "article_models") == before,
                 f"invalid article created or returned {status}")
    return "article author/validation matched DB oracle"


def article_04(app, f, vid):
    a, b = article(app, f["alpha_slug"]), article(app, "bravo-article")
    need(a and b, "fixture articles missing")
    if vid.endswith("P01"):
        need(a[0] != b[0] and a[1] != b[1] and a[3] != b[3], "different article identities collided")
        for row, username in ((a, "alice"), (b, "bobby")):
            status, data = app.call("GET", f"/api/articles/{row[1]}")
            need(status == 200 and data["article"]["author"]["username"] == username,
                 f"slug lookup mismatched {username}")
    elif vid.endswith("N01"):
        first = create_article(app, f["alice"], "Identical Matrix Title")
        status, second = app.call("POST", "/api/articles", {"article": {
            "title": "Identical Matrix Title", "description": "Description", "body": "Body"}}, token=f["bobby"])
        need(status == 201 and first["slug"] != second["article"]["slug"],
             f"equal titles did not get distinct slugs: {status} {second}")
        for slug, owner in ((first["slug"], "alice"), (second["article"]["slug"], "bobby")):
            got, data = app.call("GET", f"/api/articles/{slug}")
            need(got == 200 and data["article"]["author"]["username"] == owner,
                 f"duplicate title slug mapped wrong owner: {slug}")
    else:
        before = article(app, "bravo-article")
        status, _ = app.call("PUT", f"/api/articles/{f['alpha_slug']}",
                             {"article": {"title": "Bravo article"}}, token=f["alice"])
        after = article(app, "bravo-article")
        need(status in (200, 422) and before == after,
             f"rename overwrote another author's slug: {status} {before} -> {after}")
    return "article slug identity/collision oracle matched"


def article_06(app, f, vid):
    red = create_article(app, f["alice"], "Red filter article", tags=["red-matrix"])
    blue = create_article(app, f["bobby"], "Blue filter article", tags=["blue-matrix"])
    status, _ = app.call("POST", f"/api/articles/{blue['slug']}/favorite", token=f["alice"])
    need(status == 200, f"favorite fixture: {status}")

    def listing(query, expected, total):
        status, data = app.call("GET", "/api/articles?" + urlencode(query))
        actual = {a["slug"] for a in data.get("articles", [])} if isinstance(data, dict) else None
        need(status == 200 and actual == set(expected) and data["articlesCount"] == total,
             f"list {query}: status={status}, slugs={actual}, count={data.get('articlesCount') if isinstance(data, dict) else data}")

    if vid.endswith("P01"):
        listing({"tag": "red-matrix"}, {red["slug"]}, 1)
        listing({"author": "bobby"}, {"bravo-article", blue["slug"]}, 2)
        listing({"favorited": "alice"}, {blue["slug"]}, 1)
        status, page = app.call("GET", "/api/articles?" + urlencode({"author": "bobby", "limit": 1, "offset": 1}))
        need(status == 200 and len(page["articles"]) == 1 and page["articlesCount"] == 2,
             f"filtered page: {status} {page}")
    elif vid.endswith("N01"):
        for query in ({"author": "no-such-user"}, {"tag": "no-such-tag"},
                      {"favorited": "no-such-user"}):
            listing(query, set(), 0)
    else:
        listing({"tag": "red-matrix", "offset": 99}, set(), 1)
    return "list filters/count/page matched independent fixtures"


def feed_01(app, f, vid):
    charlie = create_article(app, f["charlie"], "Charlie feed article")
    status, _ = app.call("POST", "/api/profiles/bobby/follow", token=f["alice"])
    need(status == 200, f"follow fixture: {status}")
    if vid.endswith("P01"):
        status, data = app.call("GET", "/api/articles/feed", token=f["alice"])
        slugs = {a["slug"] for a in data.get("articles", [])} if isinstance(data, dict) else None
        need(status == 200 and slugs == {"bravo-article"} and data["articlesCount"] == 1
             and charlie["slug"] not in slugs, f"Alice feed: {status} {data}")
    elif vid.endswith("N01"):
        status, data = app.call("GET", "/api/articles/feed", token=f["charlie"])
        need(status == 200 and data["articles"] == [] and data["articlesCount"] == 0,
             f"Charlie empty feed: {status} {data}")
    else:
        status, _ = app.call("GET", "/api/articles/feed")
        bob_status, bob = app.call("GET", "/api/articles/feed", token=f["bobby"])
        alice_status, alice = app.call("GET", "/api/articles/feed", token=f["alice"])
        need(status == 401 and bob_status == alice_status == 200
             and bob["articlesCount"] == 0
             and {a["slug"] for a in alice["articles"]} == {"bravo-article"},
             f"feed identity boundary: anon={status}, bob={bob}, alice={alice}")
    return "feed contained only followed authors"


def article_07(app, f, vid):
    slug = "bravo-article"
    if vid.endswith("P01"):
        need(app.call("POST", "/api/profiles/bobby/follow", token=f["alice"])[0] == 200,
             "follow fixture failed")
        need(app.call("POST", f"/api/articles/{slug}/favorite", token=f["alice"])[0] == 200,
             "favorite fixture failed")
        seen = []
        for token in (None, f["alice"], f["bobby"]):
            status, data = app.call("GET", f"/api/articles/{slug}", token=token)
            need(status == 200, f"article retrieve: {status} {data}")
            seen.append(data["article"])
        common = lambda a: {k: v for k, v in a.items() if k not in {"favorited", "author"}}
        need(common(seen[0]) == common(seen[1]) == common(seen[2])
             and [a["favorited"] for a in seen] == [False, True, False]
             and [a["author"]["following"] for a in seen] == [False, True, False],
             f"viewer-specific article fields: {seen}")
    elif vid.endswith("N01"):
        for path in (f"/api/articles/{slug}", "/api/articles"):
            status, data = app.call("GET", path)
            need(status == 200, f"public article: {status}")
            private_keys_absent(data)
            items = [data["article"]] if "article" in data else data["articles"]
            for item in items:
                need("id" not in item and set(item["author"]) == {"username", "bio", "image", "following"},
                     f"internal article/profile key: {item}")
    else:
        status, data = app.call("GET", "/api/articles")
        need(status == 200 and all("body" not in item for item in data["articles"]),
             f"list exposes body contrary to catalog contract: {status} {data}")
    return "article response matched field/viewer contract"


def comment_01(app, f, vid):
    bob_article = article(app, "bravo-article")
    before = count(app, "comment_models")
    if vid.endswith("P01"):
        item = create_comment(app, f["alice"], "bravo-article", "Alice on Bob article")
        link = rows(app, "SELECT article_id,author_id FROM comment_models WHERE id=?", (item["id"],))[0]
        author_user = rows(app, "SELECT user_model_id FROM article_user_models WHERE id=?", (link[1],))[0][0]
        need(link[0] == bob_article[0] and author_user == user(app, "alice")[0]
             and item["author"]["username"] == "alice",
             f"comment linked wrong article/author: {link}")
    elif vid.endswith("N01"):
        status, data = app.call("POST", "/api/articles/bravo-article/comments",
                                {"comment": {"body": "Spoofed author", "author_id": user(app, "bobby")[0]}},
                                token=f["alice"])
        need(status == 201, f"spoof comment fixture: {status} {data}")
        link = rows(app, "SELECT article_id,author_id FROM comment_models WHERE id=?", (data["comment"]["id"],))[0]
        author_user = rows(app, "SELECT user_model_id FROM article_user_models WHERE id=?", (link[1],))[0][0]
        need(link[0] == bob_article[0] and author_user == user(app, "alice")[0],
             f"client changed comment author/article: {link}")
    else:
        for path, body, expected in (("/api/articles/no-such-article/comments", {"comment": {"body": "X"}}, 404),
                                     ("/api/articles/bravo-article/comments", {"comment": {"body": ""}}, 422)):
            status, _ = app.call("POST", path, body, token=f["alice"])
            need(status == expected and count(app, "comment_models") == before,
                 f"invalid comment created or returned {status}")
    return "comment article/author linked to path and token"


def comment_04(app, f, vid):
    second = create_comment(app, f["bobby"], "bravo-article", "Bob comment on B")
    if vid.endswith("P01"):
        status, data = app.call("GET", f"/api/articles/{f['alpha_slug']}/comments")
        ids = {item["id"] for item in data.get("comments", [])} if isinstance(data, dict) else None
        need(status == 200 and ids == {f["comment_a_id"]} and second["id"] not in ids,
             f"cross-article comment listing: {status} {data}")
    elif vid.endswith("N01"):
        status, data = app.call("GET", "/api/articles/no-such-article/comments")
        need(status == 404 and str(second["body"]) not in json.dumps(data),
             f"unknown article comment list: {status} {data}")
    else:
        status, data = app.call("GET", f"/api/articles/{f['alpha_slug']}/comments")
        need(status == 200, f"public comment list: {status}")
        private_keys_absent(data)
        for item in data["comments"]:
            need(set(item) == {"id", "body", "createdAt", "updatedAt", "author"}
                 and set(item["author"]) == {"username", "bio", "image", "following"},
                 f"comment fields: {item}")
    return "public comment list scoped to article"


def favorite_01(app, f, vid):
    slug = "bravo-article"
    article_id = article(app, slug)[0]
    alice_id, bob_id = (rows(app, "SELECT id FROM article_user_models WHERE user_model_id=?",
                             (user(app, name)[0],))[0][0] for name in ("alice", "bobby"))
    path = f"/api/articles/{slug}/favorite"
    if vid.endswith("P01"):
        status, data = app.call("POST", path, token=f["alice"])
        _, b = app.call("GET", f"/api/articles/{slug}", token=f["bobby"])
        need(status == 200 and data["article"]["favorited"] is True
             and b["article"]["favorited"] is False and data["article"]["favoritesCount"] == 1
             and active_favorites(app, article_id, alice_id) == 1, f"favorite add/viewer: {status} {data} {b}")
        status, data = app.call("DELETE", path, token=f["alice"])
        need(status == 200 and data["article"]["favoritesCount"] == 0
             and active_favorites(app, article_id, alice_id) == 0, f"favorite remove: {status} {data}")
    elif vid.endswith("N01"):
        for token in (f["alice"], f["bobby"]):
            need(app.call("POST", path, token=token)[0] == 200, "favorite fixture failed")
        status, data = app.call("DELETE", path, token=f["alice"])
        need(status == 200 and data["article"]["favoritesCount"] == 1
             and active_favorites(app, article_id, alice_id) == 0
             and active_favorites(app, article_id, bob_id) == 1,
             f"unfavorite removed another user's relation: {status} {data}")
    elif vid.endswith("N02"):
        for _ in range(2):
            need(app.call("POST", path, token=f["alice"])[0] == 200,
                 "sequential repeat favorite failed")
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: app.call("POST", path, token=f["alice"])[0], range(2)))
        status, data = app.call("GET", f"/api/articles/{slug}", token=f["alice"])
        need(all(s in (200, 422) for s in statuses) and status == 200
             and active_favorites(app, article_id, alice_id) == 1
             and data["article"]["favoritesCount"] == 1,
             f"duplicate favorite: concurrent={statuses}, count={data}")
    else:
        before = count(app, "favorite_models")
        status, _ = app.call("POST", "/api/articles/no-such-article/favorite", token=f["alice"])
        need(status == 404 and count(app, "favorite_models") == before,
             f"missing article favorite: {status}")
    return "favorite relation/count matched actor and article"


INPUT_ROUTES = {
    "R01": ("POST", "/api/users", None,
            {"user": {"username": "diana", "email": "diana@example.test", "password": "SafePassword123"}},
            {"user": {"username": "diana", "email": "diana@example.test", "password": ""}}, 201, "user_models"),
    "R02": ("POST", "/api/users/login", None,
            {"user": {"email": "alice@example.test", "password": "SafePassword123"}},
            {"user": {"email": "alice@example.test", "password": ""}}, 200, None),
    "R03": ("PUT", "/api/user", "alice",
            {"user": {"bio": "input valid bio"}},
            {"user": {"password": "short"}}, 200, "user_models"),
    "R04": ("POST", "/api/articles", "alice",
            {"article": {"title": "Input test title", "description": "Description", "body": "Body"}},
            {"article": {"title": "Bad", "description": "Description", "body": ""}}, 201, "article_models"),
    "R05": ("PUT", "/api/articles/alpha-article", "alice",
            {"article": {"description": "Input valid description"}},
            {"article": {"title": "X"}}, 200, "article_models"),
    "R06": ("POST", "/api/articles/alpha-article/comments", "alice",
            {"comment": {"body": "Input valid comment"}},
            {"comment": {"body": ""}}, 201, "comment_models"),
}


def input_01(app, f, vid):
    route = re.search(r"-R(\d\d)-", vid).group(0)[1:4]
    method, path, actor, good, bad, good_status, table = INPUT_ROUTES[route]
    token = f[actor] if actor else None
    before = app.snapshot()
    if vid.endswith("-P"):
        status, data = app.call(method, path, good, token=token)
        need(status == good_status, f"valid {route} request: {status} {data}")
        if table:
            need(app.snapshot()[table] != before[table], f"valid {route} did not affect {table}")
        else:
            need(app.snapshot() == before, "login changed DB")
    else:
        payload = "{" if vid.endswith("-N1") else bad
        status, data = app.call(method, path, payload, token=token)
        expected = 400 <= status < 500 if vid.endswith("-N1") else status == 422
        need(expected, f"invalid {route} request was not controlled 4xx: {status} {data}")
        need(app.snapshot() == before, f"invalid {route} request changed DB")
    return f"input route {route} validation/status/DB matched"


CASES = {
    "RW-AUTH-01": auth_01,
    "RW-AUTH-02": auth_02,
    "RW-USER-01": user_01,
    "RW-USER-03": user_03,
    "RW-USER-04": user_04,
    "RW-PROFILE-01": profile_01,
    "RW-FOLLOW-01": follow_01,
    "RW-ARTICLE-01": article_01,
    "RW-ARTICLE-04": article_04,
    "RW-ARTICLE-06": article_06,
    "RW-FEED-01": feed_01,
    "RW-ARTICLE-07": article_07,
    "RW-COMMENT-01": comment_01,
    "RW-COMMENT-04": comment_04,
    "RW-FAVORITE-01": favorite_01,
    "RW-INPUT-01": input_01,
}


def run_case(local_app_type, binary, matrix_id, variant_id):
    with local_app_type(binary) as app:
        fixture = app.bootstrap()
        return CASES[matrix_id](app, fixture, variant_id)
