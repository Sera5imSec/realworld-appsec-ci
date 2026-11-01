#!/usr/bin/env python3
"""Prove that bound matrix probes notice controlled source regressions.

Mutations are made only in a disposable copy; the working checkout is untouched.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from matrix_runtime import CATALOG, ROOT, run_bound_variant


PROBES = {
    "RW-ROUTE-01": ("hello.go", None,
                    "v1.Use(users.AuthMiddleware(true))",
                    "v1.Use(users.AuthMiddleware(false))",
                    "RW-ROUTE-01-R03-N"),
    "RW-USER-02": ("users/routers.go", "UsersLogin",
                    "if userModel.checkPassword(loginValidator.User.Password) != nil {",
                    "if userModel.checkPassword(loginValidator.User.Password) != nil && false {",
                    "RW-USER-02-N01"),
    "RW-ARTICLE-02": ("articles/routers.go", "ArticleUpdate",
                       "if articleModel.AuthorID != articleUserModel.ID {",
                       "if articleModel.AuthorID != articleUserModel.ID && false {",
                       "RW-ARTICLE-02-N01"),
    "RW-ARTICLE-03": ("articles/routers.go", "ArticleDelete",
                       "if articleModel.AuthorID != articleUserModel.ID {",
                       "if articleModel.AuthorID != articleUserModel.ID && false {",
                       "RW-ARTICLE-03-N01"),
    "RW-COMMENT-02": ("articles/routers.go", "ArticleCommentDelete",
                       "if commentModel.AuthorID != articleUserModel.ID {",
                       "if commentModel.AuthorID != articleUserModel.ID && false {",
                       "RW-COMMENT-02-N01"),
    "RW-AUTH-01": ("users/middlewares.go", "AuthMiddleware",
                   "if err != nil {", "if err != nil && false {",
                   "RW-AUTH-01-N01"),
    "RW-AUTH-02": ("users/routers.go", "UserRetrieve",
                   "c.JSON(http.StatusOK, gin.H{\"user\": serializer.Response()})",
                   "c.JSON(http.StatusUnauthorized, gin.H{\"user\": serializer.Response()})",
                   "RW-AUTH-02-P01"),
    "RW-USER-01": ("users/routers.go", "UsersRegistration",
                   "if err := userModelValidator.Bind(c); err != nil {",
                   "if err := userModelValidator.Bind(c); err != nil && false {",
                   "RW-USER-01-N02"),
    "RW-USER-03": ("users/serializers.go", "(self *UserSerializer) Response",
                   "Email:    myUserModel.Email,", "Email:    \"mutant@example.test\",",
                   "RW-USER-03-P01"),
    "RW-USER-04": ("users/routers.go", "UserUpdate",
                   "myUserModel.Update(userModelValidator.userModel)",
                   "myUserModel.Update(UserModel{Bio: \"mutant\"})",
                   "RW-USER-04-P01"),
    "RW-FOLLOW-01": ("users/routers.go", "ProfileFollow",
                     "err = myUserModel.following(userModel)",
                     "err = myUserModel.following(myUserModel)",
                     "RW-FOLLOW-01-P01"),
    "RW-PROFILE-01": ("users/serializers.go", None,
                      "ID        uint   `json:\"-\"`",
                      "ID        uint   `json:\"id\"`",
                      "RW-PROFILE-01-N01"),
    "RW-ARTICLE-01": ("articles/serializers.go", "(s *ArticleSerializer) Response",
                      "Author:         authorSerializer.Response(),",
                      "Author:         users.ProfileResponse{Username: authorSerializer.Response().Username + \"-mutant\"},",
                      "RW-ARTICLE-01-N01"),
    "RW-ARTICLE-04": ("articles/routers.go", "ArticleRetrieve",
                      "FindOneArticle(&ArticleModel{Slug: slug})",
                      "FindOneArticle(&ArticleModel{Slug: \"alpha-article\" + slug[:0]})",
                      "RW-ARTICLE-04-P01"),
    "RW-ARTICLE-06": ("articles/routers.go", "ArticleList",
                      "tag := c.Query(\"tag\")", "tag := \"\"",
                      "RW-ARTICLE-06-P01"),
    "RW-FEED-01": ("articles/models.go", "(self *ArticleUserModel) GetArticleFeed",
                   "followings := self.UserModel.GetFollowings()",
                   "followings := []users.UserModel{}",
                   "RW-FEED-01-P01"),
    "RW-COMMENT-01": ("articles/serializers.go", "(s *CommentSerializer) Response",
                      "Author:    authorSerializer.Response(),",
                      "Author:    users.ProfileResponse{Username: authorSerializer.Response().Username + \"-mutant\"},",
                      "RW-COMMENT-01-P01"),
    "RW-COMMENT-04": ("articles/routers.go", "ArticleCommentList",
                      "err = articleModel.getComments()", "err = nil",
                      "RW-COMMENT-04-P01"),
    "RW-ARTICLE-07": ("users/serializers.go", None,
                      "ID        uint   `json:\"-\"`",
                      "ID        uint   `json:\"id\"`",
                      "RW-ARTICLE-07-N01"),
    "RW-FAVORITE-01": ("articles/routers.go", "ArticleFavorite",
                       "articleModel.favoriteBy(GetArticleUserModel(myUserModel))",
                       "articleModel.unFavoriteBy(GetArticleUserModel(myUserModel))",
                       "RW-FAVORITE-01-P01"),
    "RW-INPUT-01": ("common/utils.go", "NewValidatorError",
                    "res.Errors = make(map[string]interface{})",
                    "panic(\"mutant validation error\")",
                    "RW-INPUT-01-R01-N2"),
    "RW-AUTH-03": ("users/middlewares.go", "extractToken",
                   "if gin.Mode() == gin.ReleaseMode {",
                   "if gin.Mode() == gin.DebugMode {",
                   "RW-AUTH-03-N01"),
    "RW-CONFIG-01": ("common/utils.go", "JWTSigningKey",
                     "return []byte(key), nil",
                     "return []byte(JWTSecret), nil",
                     "RW-CONFIG-01-P01"),
    "RW-ARTICLE-05": ("articles/models.go", "SaveArticleWithTags",
                       "if err := model.setTagsUsing(tx, tags); err != nil {",
                       "if err := model.setTagsUsing(common.GetDB(), tags); err != nil {",
                       "RW-ARTICLE-05-N01"),
    "RW-TAG-01": ("articles/models.go", "SaveArticleWithTags",
                   "if err := model.setTagsUsing(tx, tags); err != nil {",
                   "if err := model.setTagsUsing(common.GetDB(), tags); err != nil {",
                   "RW-TAG-01-N01"),
    "RW-COMMENT-03": ("articles/routers.go", "ArticleCommentDelete",
                      "if commentModel.ArticleID != articleModel.ID {",
                      "if commentModel.ArticleID != articleModel.ID && false {",
                      "RW-COMMENT-03-N01"),
    "RW-QUERY-01": ("articles/models.go", "FindOneArticle",
                    "Where(condition).First(&model).Error",
                    "Where(&ArticleModel{}).First(&model).Error",
                    "RW-QUERY-01-P01"),
    "RW-RESOURCE-01": ("articles/models.go", None,
                       "const maxArticlePageSize = 100",
                       "const maxArticlePageSize = 1000000",
                       "RW-RESOURCE-01-N01"),
    "RW-ERROR-01": ("common/utils.go", "NewError",
                    "res.Errors[key] = \"operation failed\"",
                    "res.Errors[key] = err.Error()",
                    "RW-ERROR-01-N01"),
    "RW-READ-01": ("articles/models.go", "FindArticleUserModel",
                   "common.GetDB().Where(\"user_model_id = ?\", userModel.ID).First(&articleUserModel)",
                   "common.GetDB().Where(\"user_model_id = ?\", userModel.ID).FirstOrCreate(&articleUserModel)",
                   "RW-READ-01-P01"),
}


def mutate(source: Path, relative: str, function: str | None, old: str, new: str):
    file = source / relative
    text = file.read_text(encoding="utf-8")
    if function:
        start = text.index(f"func {function}(")
        next_func = text.find("\nfunc ", start + 5)
        end = len(text) if next_func < 0 else next_func
        section = text[start:end]
        if section.count(old) != 1:
            raise RuntimeError(f"expected one guard in {relative}:{function}")
        text = text[:start] + section.replace(old, new, 1) + text[end:]
    else:
        if text.count(old) != 1:
            raise RuntimeError(f"expected one guard in {relative}")
        text = text.replace(old, new, 1)
    file.write_text(text, encoding="utf-8")


def run_probe(binary: Path, matrix_id: str, variant_id: str, catalog: dict) -> str:
    matrix = next(m for m in catalog["matrices"] if m["id"] == matrix_id)
    variant = next(v for v in matrix["variants"] if v["id"] == variant_id)
    return run_bound_variant(binary, matrix_id, variant)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--matrix", action="append", help="run one named matrix probe (repeatable)")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    selected = set(json.loads(args.selection.read_text(encoding="utf-8"))["selected"]) if args.selection else set(PROBES)
    if args.matrix:
        selected &= set(args.matrix)
    results = []
    for matrix_id, (file, function, old, new, variant_id) in PROBES.items():
        if matrix_id not in selected:
            continue
        row = {"matrix_id": matrix_id, "variant_id": variant_id,
               "mutation": f"{file}:{function or 'router registration'}"}
        try:
            run_probe(args.binary.resolve(), matrix_id, variant_id, catalog)
            row["baseline"] = "PASS"
            with tempfile.TemporaryDirectory(prefix="realworld-mutant-") as tmp:
                source = Path(tmp) / "source"
                shutil.copytree(
                    ROOT, source,
                    ignore=shutil.ignore_patterns(".git", "app", "data", "matrix-results.json",
                                                  "matrix-run.log", "__pycache__"),
                )
                mutate(source, file, function, old, new)
                mutant = Path(tmp) / "mutant-app"
                env = dict(os.environ, CGO_ENABLED="1")
                build = subprocess.run(
                    [args.go, "build", "-o", str(mutant), "."], cwd=source, env=env,
                    capture_output=True, text=True, timeout=180, check=False,
                )
                if build.returncode:
                    raise RuntimeError("mutant build failed: " + build.stderr[-1500:])
                try:
                    run_probe(mutant, matrix_id, variant_id, catalog)
                except AssertionError as exc:
                    row["sensitivity"] = "DETECTED"
                    row["detail"] = str(exc)
                else:
                    row["sensitivity"] = "MISSED"
                    row["detail"] = "negative probe passed after guard was disabled"
        except (OSError, ValueError, RuntimeError, AssertionError, subprocess.TimeoutExpired) as exc:
            row["sensitivity"] = "ERROR"
            row["detail"] = str(exc)
        results.append(row)
        print(f"{row['sensitivity']} {matrix_id}: {row.get('detail', '')}")
    args.output.write_text(json.dumps({"results": results}, indent=2) + "\n", encoding="utf-8")
    return 1 if any(r["sensitivity"] != "DETECTED" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
