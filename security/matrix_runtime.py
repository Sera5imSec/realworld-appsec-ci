#!/usr/bin/env python3
"""Run bound and policy-observation variants against a local build."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from matrix_cases import CASES, TEST_JWT_SECRET, run_case
from matrix_policy_cases import OBSERVED_CASES, PolicyObservation, run_policy_case


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "security" / "matrices" / "catalog.json"
_BINDINGS = json.loads((ROOT / "security" / "matrices" / "bindings.json").read_text(encoding="utf-8"))
BOUND = set(_BINDINGS["bound_matrices"])
OBSERVED = set(_BINDINGS["observed_matrices"])


def http(base: str, method: str, path: str, body=None, token: str | None = None,
         headers: dict | None = None) -> tuple[int, object]:
    payload = None if body is None else (
        body.encode("utf-8") if isinstance(body, str)
        else json.dumps(body).encode("utf-8")
    )
    req_headers = dict(headers or {})
    if token is not None:
        req_headers["Authorization"] = "Token " + token
    if payload is not None:
        req_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        base + path, data=payload, method=method, headers=req_headers
    )
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read().decode("utf-8", errors="replace")
        try:
            return response.status, json.loads(raw)
        except json.JSONDecodeError:
            return response.status, raw


class LocalApp:
    def __init__(self, binary: Path, env_overrides: dict | None = None):
        self.binary = binary.resolve()
        self.env_overrides = env_overrides or {}
        self.tmp = None
        self.process = None
        self.log = None

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="realworld-matrix-")
        self.db = Path(self.tmp.name) / "test.db"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, PORT=str(port), DB_PATH=str(self.db), GIN_MODE="release",
                   JWT_SECRET=TEST_JWT_SECRET)
        env.update(self.env_overrides)
        self.log = open(Path(self.tmp.name) / "app.log", "wb")
        self.process = subprocess.Popen(
            [str(self.binary)], cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                code = self.process.returncode
                self.__exit__()
                raise RuntimeError(f"app exited {code} during startup")
            try:
                if http(self.base, "GET", "/api/ping/")[0] == 200:
                    return self
            except (OSError, TimeoutError):
                pass
            time.sleep(0.05)
        self.__exit__()
        raise RuntimeError("app did not start within 15 seconds")

    def __exit__(self, *_):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()
        if self.tmp is not None:
            self.tmp.cleanup()

    def call(self, method: str, path: str, body=None, token=None, headers=None):
        return http(self.base, method, path, body, token, headers)

    def snapshot(self) -> dict:
        with sqlite3.connect(self.db) as db:
            tables = [
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            return {
                table: db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                for table in tables
            }

    def bootstrap(self) -> dict:
        users = {}
        for username in ("alice", "bobby", "charlie"):
            status, body = self.call("POST", "/api/users", {
                "user": {
                    "username": username,
                    "email": f"{username}@example.test",
                    "password": "SafePassword123",
                }
            })
            require(status == 201 and isinstance(body, dict) and "user" in body,
                    f"fixture registration failed for {username}: {status} {body}")
            users[username] = body["user"]["token"]
        status, body = self.call("POST", "/api/articles", {
            "article": {"title": "Alpha article", "description": "A description", "body": "A body"}
        }, token=users["alice"])
        require(status == 201, f"fixture article A failed: {status} {body}")
        alpha = body["article"]["slug"]
        status, body = self.call("POST", "/api/articles", {
            "article": {"title": "Bravo article", "description": "B description", "body": "B body"}
        }, token=users["bobby"])
        require(status == 201, f"fixture article B failed: {status} {body}")
        status, body = self.call("POST", f"/api/articles/{alpha}/comments", {
            "comment": {"body": "Alice test comment"}
        }, token=users["alice"])
        require(status == 201, f"fixture comment failed: {status} {body}")
        return {**users, "alpha_slug": alpha, "comment_a_id": body["comment"]["id"]}


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def materialize_request(request: dict, fixture: dict) -> tuple:
    path = request["path"].replace("alpha-article", fixture["alpha_slug"])
    path = path.replace("{{comment_a_id}}", str(fixture["comment_a_id"]))
    headers = {
        key: value.replace("{{alice_token}}", fixture["alice"])
        for key, value in request.get("headers", {}).items()
    }
    return request["method"], path, request.get("body"), headers


def prepare_route(app: LocalApp, route: str, fixture: dict):
    if route == "DELETE /api/profiles/:username/follow" or route == "GET /api/articles/feed":
        status, body = app.call("POST", "/api/profiles/bobby/follow", token=fixture["alice"])
        require(status == 200, f"follow fixture failed: {status} {body}")
    if route == "DELETE /api/articles/:slug/favorite":
        status, body = app.call(
            "POST", f"/api/articles/{fixture['alpha_slug']}/favorite", token=fixture["alice"]
        )
        require(status == 200, f"favorite fixture failed: {status} {body}")


def run_route_variant(binary: Path, variant: dict) -> str:
    with LocalApp(binary) as app:
        fixture = app.bootstrap()
        prepare_route(app, variant["route"], fixture)
        method, path, body, headers = materialize_request(variant["request"], fixture)
        mode = "protected" if "Missing Authorization" in variant["scenario_and_expected"] else None
        before = app.snapshot()
        status, response = app.call(method, path, body, headers=headers)
        if variant["kind"] == "CONTROL":
            expected = int(re.search(r"returns (\d+)", variant["scenario_and_expected"]).group(1))
            require(status == expected, f"{method} {path}: expected {expected}, got {status}: {response}")
        elif mode == "protected":
            require(status == 401, f"{method} {path}: missing token returned {status}")
            require(app.snapshot() == before, f"{method} {path}: unauthorized request changed DB")
        else:
            require(status == 200, f"{method} {path}: optional invalid token returned {status}")
            anon_status, anon = app.call(method, path)
            require(anon_status == 200 and response == anon,
                    f"{method} {path}: invalid token did not behave as anonymous")
        return f"HTTP {status}; route={method} {path}"


def run_article_update(binary: Path, variant_id: str) -> str:
    with LocalApp(binary) as app:
        f = app.bootstrap()
        path = f"/api/articles/{f['alpha_slug']}"
        if variant_id.endswith("P01"):
            with sqlite3.connect(app.db) as db:
                original = db.execute(
                    "SELECT id, author_id FROM article_models WHERE slug = ?",
                    (f["alpha_slug"],),
                ).fetchone()
            status, _ = app.call("PUT", path, {"article": {"title": "Updated alpha title"}}, f["alice"])
            require(status == 200, f"author update returned {status}")
            status, article = app.call("GET", "/api/articles/updated-alpha-title")
            with sqlite3.connect(app.db) as db:
                updated = db.execute(
                    "SELECT id, author_id FROM article_models WHERE slug = ?",
                    ("updated-alpha-title",),
                ).fetchone()
            require(status == 200 and article["article"]["author"]["username"] == "alice"
                    and original is not None and updated == original,
                    "author update did not preserve article identity")
        elif variant_id.endswith("N01"):
            before = app.snapshot()
            status, _ = app.call("PUT", path, {"article": {"title": "Bobby takeover"}}, f["bobby"])
            require(status == 403 and app.snapshot() == before,
                    f"non-author update: status={status}, db_unchanged={app.snapshot()==before}")
        else:
            before = app.snapshot()
            for p in (path, path + "/"):
                status, _ = app.call("PUT", p, {"article": {"title": "Anonymous takeover"}})
                require(status == 401 and app.snapshot() == before,
                        f"anonymous update on {p}: {status}")
        return "article update auth and DB oracle matched"


def run_article_delete(binary: Path, variant_id: str) -> str:
    with LocalApp(binary) as app:
        f = app.bootstrap()
        path = f"/api/articles/{f['alpha_slug']}"
        if variant_id.endswith("P01"):
            status, _ = app.call("DELETE", path, token=f["alice"])
            after_status, _ = app.call("GET", path)
            with sqlite3.connect(app.db) as db:
                deleted = db.execute(
                    "SELECT deleted_at FROM article_models WHERE slug = ?",
                    (f["alpha_slug"],),
                ).fetchone()
            require(status == 200 and after_status == 404
                    and deleted is not None and deleted[0] is not None,
                    f"author delete: status={status}, post_get={after_status}")
        else:
            before = app.snapshot()
            token = f["bobby"] if variant_id.endswith("N01") else None
            expected = 403 if token else 401
            status, _ = app.call("DELETE", path, token=token)
            require(status == expected and app.snapshot() == before,
                    f"forbidden delete: status={status}, db_unchanged={app.snapshot()==before}")
        return "article delete auth and DB oracle matched"


def run_comment_delete(binary: Path, variant_id: str) -> str:
    with LocalApp(binary) as app:
        f = app.bootstrap()
        path = f"/api/articles/{f['alpha_slug']}/comments/{f['comment_a_id']}"
        if variant_id.endswith("P01"):
            status, _ = app.call("DELETE", path, token=f["alice"])
            list_status, body = app.call("GET", f"/api/articles/{f['alpha_slug']}/comments")
            ids = [c["id"] for c in body["comments"]]
            with sqlite3.connect(app.db) as db:
                deleted = db.execute(
                    "SELECT deleted_at FROM comment_models WHERE id = ?",
                    (f["comment_a_id"],),
                ).fetchone()
            require(status == 200 and list_status == 200 and f["comment_a_id"] not in ids
                    and deleted is not None and deleted[0] is not None,
                    f"author comment delete: {status}, remaining={ids}")
        else:
            before = app.snapshot()
            if variant_id.endswith("N01"):
                token, expected = f["bobby"], 403
            elif variant_id.endswith("N02"):
                token, expected = None, 401
            else:
                token, expected = f["alice"], 404
                path = f"/api/articles/{f['alpha_slug']}/comments/not-a-number"
            status, _ = app.call("DELETE", path, token=token)
            require(status == expected and app.snapshot() == before,
                    f"comment delete: status={status}, db_unchanged={app.snapshot()==before}")
        return "comment delete auth and DB oracle matched"


def run_login(binary: Path, variant_id: str) -> str:
    with LocalApp(binary) as app:
        f = app.bootstrap()
        before = app.snapshot()
        email = "alice@example.test"
        password = "SafePassword123"
        if variant_id.endswith("N01"):
            password = "WrongPassword123"
        elif variant_id.endswith("N02"):
            email = "missing@example.test"
        status, body = app.call("POST", "/api/users/login",
                                {"user": {"email": email, "password": password}})
        if variant_id.endswith("P01"):
            require(status == 200 and isinstance(body, dict) and body["user"]["token"],
                    f"valid login failed: {status} {body}")
            self_status, self_body = app.call("GET", "/api/user", token=body["user"]["token"])
            require(self_status == 200 and self_body["user"]["username"] == "alice",
                    "login token did not bind Alice")
        else:
            require(status == 401 and "token" not in json.dumps(body).lower()
                    and app.snapshot() == before,
                    f"invalid login exposed token or returned {status}")
            if variant_id.endswith("N02"):
                wrong_status, wrong_body = app.call(
                    "POST", "/api/users/login",
                    {"user": {"email": "alice@example.test", "password": "WrongPassword123"}},
                )
                require(wrong_status == 401 and wrong_body == body,
                        "unknown email and wrong password have different public responses")
        return f"login HTTP {status}; token binding checked"


RUNNERS = {
    "RW-ARTICLE-02": run_article_update,
    "RW-ARTICLE-03": run_article_delete,
    "RW-COMMENT-02": run_comment_delete,
    "RW-USER-02": run_login,
}


def run_bound_variant(binary: Path, matrix_id: str, variant: dict) -> str:
    if matrix_id == "RW-ROUTE-01":
        return run_route_variant(binary, variant)
    if matrix_id in RUNNERS:
        return RUNNERS[matrix_id](binary, variant["id"])
    if matrix_id in CASES:
        return run_case(LocalApp, binary, matrix_id, variant["id"])
    if matrix_id in OBSERVED_CASES:
        return run_policy_case(LocalApp, binary, matrix_id, variant["id"])
    raise KeyError(f"no runtime runner for {matrix_id}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    selected = set(json.loads(args.selection.read_text(encoding="utf-8"))["selected"]) if args.selection else BOUND | OBSERVED
    results = []
    for matrix in catalog["matrices"]:
        mid = matrix["id"]
        if mid not in BOUND | OBSERVED or mid not in selected:
            continue
        for variant in matrix["variants"]:
            vid = variant["id"]
            try:
                detail = run_bound_variant(args.binary, mid, variant)
                result = "PASS"
            except PolicyObservation as exc:
                result, detail = "OBSERVED", str(exc)
            except AssertionError as exc:
                result, detail = "FAIL", str(exc)
            except Exception as exc:
                result, detail = "ERROR", f"{type(exc).__name__}: {exc}"
            results.append({"matrix_id": mid, "variant_id": vid,
                            "result": result, "detail": detail,
                            "sensitivity": "NOT_RUN"})
            print(f"{result} {vid}: {detail}")
    args.output.write_text(json.dumps({"results": results}, indent=2) + "\n", encoding="utf-8")
    return 1 if any(r["result"] == "ERROR" or
                    (r["result"] == "FAIL" and r["matrix_id"] in BOUND)
                    for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
