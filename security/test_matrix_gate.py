"""Fail-closed checks for change selection and the matrix evidence gate."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import matrix_ci


ROOT = Path(__file__).resolve().parents[1]
CATALOG = matrix_ci.load_catalog()
BY_ID = {matrix["id"]: matrix for matrix in CATALOG["matrices"]}


def report_for(matrix_id: str, results: list[str], sensitivity: list[dict]):
    variants = BY_ID[matrix_id]["variants"]
    runtime_rows = []
    for variant, item in zip(variants, results):
        result, detail = item if isinstance(item, tuple) else (item, "")
        runtime_rows.append({
            "matrix_id": matrix_id, "variant_id": variant["id"],
            "result": result, "detail": detail,
        })
    runtime = {"results": runtime_rows}
    with tempfile.TemporaryDirectory(prefix="matrix-gate-test-") as tmp:
        directory = Path(tmp)
        inputs = {
            "selection": {"selected": [matrix_id], "unmapped_production_files": []},
            "runtime": runtime,
            "sensitivity": {"results": sensitivity},
        }
        for name, payload in inputs.items():
            (directory / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")
        command = [
            sys.executable, str(ROOT / "security/matrix_report.py"),
            "--selection", str(directory / "selection.json"),
            "--runtime", str(directory / "runtime.json"),
            "--sensitivity", str(directory / "sensitivity.json"),
            "--json-out", str(directory / "status.json"),
            "--markdown-out", str(directory / "status.md"),
        ]
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        report = json.loads((directory / "status.json").read_text(encoding="utf-8"))
        return run.returncode, report


class MatrixGateTest(unittest.TestCase):
    def test_selection_keeps_shared_code_full_and_article_routes_scoped(self):
        all_count = len(BY_ID)
        for path in ("go.mod", "go.sum", "users/routers.go", "common/utils.go",
                     "articles/models.go", "hello.go"):
            with self.subTest(path=path):
                self.assertEqual(len(matrix_ci.select(CATALOG, [path])["selected"]), all_count)
        article = matrix_ci.select(CATALOG, ["articles/routers.go"])
        self.assertEqual(len(article["selected"]), 23)
        self.assertIn("RW-COMMENT-03", article["selected"])
        self.assertIn("RW-AUTH-01", article["selected"])
        self.assertNotIn("RW-USER-01", article["selected"])
        self.assertEqual(matrix_ci.select(CATALOG, ["articles/validators.go"])["selected"],
                         article["selected"])
        self.assertEqual(len(matrix_ci.select(CATALOG, ["articles/routers.go", "users/models.go"])["selected"]),
                         all_count)
        new_source = matrix_ci.select(CATALOG, ["newpkg/guard.go"])
        self.assertEqual(len(new_source["selected"]), all_count)
        self.assertEqual(new_source["unmapped_production_files"], ["newpkg/guard.go"])
        mixed = matrix_ci.select(CATALOG, ["security/matrix_ci.py", "newpkg/guard.go"])
        self.assertEqual(mixed["unmapped_production_files"], ["newpkg/guard.go"])
        self.assertEqual(matrix_ci.select(CATALOG, ["README.md"])["selected"], [])
        self.assertEqual(len(matrix_ci.select(CATALOG, ["README.md"], full=True)["selected"]), all_count)

    def test_bound_matrix_needs_every_result_and_valid_sensitivity(self):
        matrix_id = "RW-AUTH-01"
        variants = BY_ID[matrix_id]["variants"]
        sensitivity = [{
            "matrix_id": matrix_id,
            "variant_id": variants[0]["id"],
            "mutation": "users/middlewares.go:AuthMiddleware",
            "baseline": "PASS",
            "sensitivity": "DETECTED",
        }]
        code, report = report_for(matrix_id, ["PASS"] * len(variants), sensitivity)
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("BOUND_PASS"), 1)

        code, report = report_for(matrix_id, ["FAIL"] + ["PASS"] * (len(variants) - 1), sensitivity)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("FAIL"), 1)

        code, report = report_for(matrix_id, ["PASS"] * (len(variants) - 1), sensitivity)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("INCOMPLETE"), 1)

        sensitivity[0]["baseline"] = "ERROR"
        code, report = report_for(matrix_id, ["PASS"] * len(variants), sensitivity)
        self.assertEqual(code, 1)
        self.assertTrue(any("baseline" in error for error in report["errors"]))

    def test_promoted_policy_difference_and_missing_result_block(self):
        matrix_id = "RW-READ-01"
        variants = BY_ID[matrix_id]["variants"]
        sensitivity = [{
            "matrix_id": matrix_id,
            "variant_id": variants[0]["id"],
            "mutation": "articles/models.go:FindArticleUserModel",
            "baseline": "PASS",
            "sensitivity": "DETECTED",
        }]
        code, report = report_for(matrix_id, ["PASS"] * len(variants), sensitivity)
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("BOUND_PASS"), 1)
        code, report = report_for(matrix_id, ["FAIL"] * len(variants), sensitivity)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("FAIL"), 1)
        code, report = report_for(matrix_id, ["FAIL"] * (len(variants) - 1), sensitivity)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("INCOMPLETE"), 1)
        code, report = report_for(matrix_id, ["ERROR"] + ["PASS"] * (len(variants) - 1), sensitivity)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("TEST_ERROR"), 1)

    def test_known_failure_is_visible_and_only_exact_observation_is_accepted(self):
        matrix_id = "RW-AUTH-02"
        variants = BY_ID[matrix_id]["variants"]
        sensitivity = [{
            "matrix_id": matrix_id,
            "variant_id": variants[0]["id"],
            "mutation": "users/routers.go:UserRetrieve",
            "baseline": "PASS",
            "sensitivity": "DETECTED",
        }]
        known = [
            "PASS",
            ("FAIL", "invalid id claim returned 500: "),
            ("FAIL", "missing user id returned 200: {'user': {'username': ''}}"),
        ]
        code, report = report_for(matrix_id, known, sensitivity)
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("KNOWN_FAIL"), 1)
        self.assertEqual(len(report["accepted_failure_variants"]), 2)

        changed = known.copy()
        changed[1] = ("FAIL", "invalid id claim returned 403")
        code, report = report_for(matrix_id, changed, sensitivity)
        self.assertEqual(code, 1)
        self.assertTrue(any("fingerprint changed" in error for error in report["errors"]))

        changed = known.copy()
        changed[0] = ("FAIL", "new regression")
        code, report = report_for(matrix_id, changed, sensitivity)
        self.assertEqual(code, 1)
        self.assertTrue(any("new runtime failure" in error for error in report["errors"]))

        changed = known.copy()
        changed[1] = "PASS"
        code, report = report_for(matrix_id, changed, sensitivity)
        self.assertEqual(code, 1)
        self.assertTrue(any("remove its baseline entry" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
