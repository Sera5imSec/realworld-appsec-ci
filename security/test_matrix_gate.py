"""Fail-closed checks for change selection and the matrix evidence gate."""

from __future__ import annotations

import json
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from pathlib import Path

import matrix_ci


ROOT = Path(__file__).resolve().parents[1]
CATALOG = matrix_ci.load_catalog()
BY_ID = {matrix["id"]: matrix for matrix in CATALOG["matrices"]}


def report_for(matrix_id: str, results: list[str]):
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
        }
        for name, payload in inputs.items():
            (directory / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")
        command = [
            sys.executable, str(ROOT / "security/matrix_report.py"),
            "--selection", str(directory / "selection.json"),
            "--runtime", str(directory / "runtime.json"),
            "--json-out", str(directory / "status.json"),
            "--markdown-out", str(directory / "status.md"),
        ]
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        report = json.loads((directory / "status.json").read_text(encoding="utf-8"))
        return run.returncode, report


class MatrixGateTest(unittest.TestCase):
    def test_source_review_cli_handoff_for_a_committed_added_helper(self):
        archive = subprocess.check_output(["git", "archive", "--format=zip", "HEAD"], cwd=ROOT)
        with tempfile.TemporaryDirectory(prefix="realworld-source-review-") as tmp:
            fixture = Path(tmp)
            with zipfile.ZipFile(io.BytesIO(archive)) as files:
                files.extractall(fixture)
            for name in ("matrix_ci.py", "change_impact.mjs", "boundary_review.mjs"):
                (fixture / "security" / name).write_bytes((ROOT / "security" / name).read_bytes())

            def git(*arguments):
                return subprocess.check_output(["git", "-c", "user.name=Source Review Fixture",
                                                "-c", "user.email=source-review@example.invalid",
                                                *arguments], cwd=fixture, stderr=subprocess.PIPE, text=True).strip()

            git("init", "--quiet")
            git("add", ".")
            git("commit", "--quiet", "-m", "Source review control")
            base = git("rev-parse", "HEAD")
            source = fixture / "articles/serializers.go"
            with source.open("a", encoding="utf-8") as stream:
                stream.write("\nfunc CoverageReviewPracticeOnly() {}\n")
            git("add", "articles/serializers.go")
            git("commit", "--quiet", "-m", "Add unused review fixture helper")
            output = fixture / "artifacts"
            command = [sys.executable, str(fixture / "security/matrix_ci.py"), "review", "--base", base]
            first = subprocess.run(command, cwd=fixture, capture_output=True, text=True, check=False)
            self.assertEqual(first.returncode, 1, first.stdout + first.stderr)
            report = json.loads((output / "source-review.json").read_text())
            self.assertEqual(report["coverage_status"], "REVIEW_REQUIRED")
            self.assertEqual(report["oracle_execution"], "NOT_RUN")
            impact = json.loads((output / "boundary-change-impact.json").read_text())
            helper = next(row for row in impact["changed_functions"] if row["symbol"] == "CoverageReviewPracticeOnly")
            self.assertEqual(helper["status"], "added")
            self.assertIsNone(helper["before_hash"])
            self.assertEqual(len(helper["after_hash"]), 64)
            journal_path = fixture / "security/matrices/code_decisions.json"
            journal = json.loads(journal_path.read_text())
            journal["decisions"].append({
                "kind": "function", "path": helper["path"], "symbol": helper["symbol"],
                "fingerprint": helper["after_hash"], "decision": "not_security", "matrix_ids": [], "variant_ids": [],
                "reason": "This isolated fixture adds an empty, uncalled helper with no state, I/O or security behavior."
            })
            journal_path.write_text(json.dumps(journal), encoding="utf-8")
            git("add", "security/matrices/code_decisions.json")
            git("commit", "--quiet", "-m", "Record exact fixture decision")
            second = subprocess.run(command, cwd=fixture, capture_output=True, text=True, check=False)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertEqual(json.loads((output / "source-review.json").read_text())["status"], "PASS")
            self.assertEqual(json.loads((output / "matrix-runtime.json").read_text())["status"], "NOT_RUN")
            self.assertEqual(len(json.loads((output / "matrix-selection.json").read_text())["selected"]), 23)

    def test_source_review_is_enforced_before_build_and_evidence_survives_failure(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        review = ci.split("- name: Review source coverage before building", 1)[1].split("- name:", 1)[0]
        self.assertNotIn("continue-on-error", review)
        self.assertIn("id: source_review", review)
        self.assertLess(ci.index("- name: Review source coverage before building"), ci.index("- name: Build local test server"))
        publish = ci.split("- name: Publish matrix status and enforce bound results", 1)[1].split("- name:", 1)[0]
        self.assertIn("steps.source_review.outcome == 'success'", publish)
        upload = ci.split("- name: Upload matrix evidence", 1)[1]
        self.assertIn("if: always()", upload)
        self.assertIn("source-review.json", upload)

    def run_source_review(self, directory, *, blocked=False, parser_error=False, catalog_errors=None):
        impact = {"schema_version": 1, "analysis_skipped": False, "base": "a" * 40, "head": "b" * 40,
                  "changed_files": ["articles/routers.go"], "changed_routes": [], "changed_top_level": [],
                  "changed_functions": [{"path": "articles/routers.go", "symbol": "NewHandler", "status": "added"}]}
        review = {"schema_version": 1, "rows": [{"symbol": "NewHandler", "decision": None if blocked else "existing_rule"}],
                  "blocking": ["articles/routers.go:NewHandler: changed function needs a coverage decision"] if blocked else [], "errors": []}

        def command(command, **kwargs):
            if command[1].endswith("change_impact.mjs") and parser_error:
                return subprocess.CompletedProcess(command, 1, "", "invalid Go source")
            destination = Path(command[command.index("--output") + 1])
            payload = impact if command[1].endswith("change_impact.mjs") else review
            destination.write_text(json.dumps(payload), encoding="utf-8")
            if "--markdown-out" in command:
                Path(command[command.index("--markdown-out") + 1]).write_text("# Boundary change review\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 1 if payload.get("blocking") else 0, "review output", "")

        with patch.object(matrix_ci, "load_catalog", return_value=CATALOG), \
                patch.object(matrix_ci, "validate", return_value=catalog_errors or []), \
                patch.object(matrix_ci, "changed_paths", return_value=["articles/routers.go"]), \
                patch.object(matrix_ci.subprocess, "run", side_effect=command) as invoked, \
                patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": str(directory / "summary.md")}):
            report = matrix_ci.review_source(base="a" * 40, full=False, output=directory)
        return report, invoked

    def test_missing_decision_writes_handoff_without_a_runtime_verdict(self):
        with tempfile.TemporaryDirectory(prefix="source-review-") as tmp:
            output = Path(tmp)
            report, invoked = self.run_source_review(output, blocked=True)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["coverage_status"], "REVIEW_REQUIRED")
            self.assertEqual(report["oracle_execution"], "NOT_RUN")
            self.assertEqual(invoked.call_count, 2)
            self.assertTrue(json.loads((output / "matrix-selection.json").read_text())["blocked"])
            self.assertEqual(json.loads((output / "matrix-runtime.json").read_text())["status"], "NOT_RUN")
            self.assertIn("NewHandler", (output / "summary.md").read_text())
            for name in ("catalog-validation.json", "boundary-change-impact.json", "boundary-review.json", "source-review.json", "source-review.md"):
                self.assertTrue((output / name).is_file(), name)

    def test_parser_error_replaces_stale_success_and_is_not_an_empty_change(self):
        with tempfile.TemporaryDirectory(prefix="source-review-") as tmp:
            output = Path(tmp)
            for name in ("source-review.json", "matrix-status.json", "boundary-change-impact.json"):
                (output / name).write_text(json.dumps({"status": "PASS", "stale": True}))
            report, invoked = self.run_source_review(output, parser_error=True)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["coverage_status"], "ERROR")
            self.assertIsNone(report["analysis_skipped"])
            self.assertEqual(invoked.call_count, 1)
            impact = json.loads((output / "boundary-change-impact.json").read_text())
            self.assertEqual(impact["status"], "ERROR")
            self.assertNotIn("stale", impact)
            self.assertIn("invalid Go source", (output / "source-review.md").read_text())

    def test_catalog_failure_is_saved_before_source_review_stops(self):
        with tempfile.TemporaryDirectory(prefix="source-review-") as tmp:
            output = Path(tmp)
            report, _ = self.run_source_review(output, catalog_errors=["production Go source has no CI coverage decision: forgotten.go"])
            self.assertEqual(report["status"], "FAIL")
            self.assertIn("forgotten.go", (output / "source-review.md").read_text())
            self.assertEqual(json.loads((output / "matrix-status.json").read_text())["phase"], "SOURCE_REVIEW")

    def test_passing_source_review_selects_checks_but_does_not_run_them(self):
        with tempfile.TemporaryDirectory(prefix="source-review-") as tmp:
            output = Path(tmp)
            report, _ = self.run_source_review(output)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["changed_units"], 1)
            self.assertEqual(len(json.loads((output / "matrix-selection.json").read_text())["selected"]), 23)
            self.assertEqual(json.loads((output / "matrix-status.json").read_text())["status"], "NOT_RUN")

    def test_source_mutations_are_manual_only(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        manual = (ROOT / ".github/workflows/matrix-sensitivity.yml").read_text(encoding="utf-8")
        self.assertNotIn("matrix_sensitivity.py", ci)
        self.assertNotIn("--sensitivity", ci)
        self.assertIn("workflow_dispatch:", manual)
        for trigger in ("pull_request:", "push:", "schedule:"):
            self.assertNotIn(trigger, manual)

    def test_source_inventory_blocks_unclassified_and_stale_go_files(self):
        self.assertEqual(matrix_ci.source_inventory_errors(CATALOG), [])
        with tempfile.TemporaryDirectory(prefix="matrix-source-inventory-") as tmp:
            root = Path(tmp)
            catalog = {"matrices": [{"ci_watch_seed": ["covered.go"]}]}
            (root / "covered.go").write_text("package sample\n", encoding="utf-8")
            self.assertEqual(matrix_ci.source_inventory_errors(catalog, root, {}), [])
            (root / "unclassified.go").write_text("package sample\n", encoding="utf-8")
            self.assertIn("production Go source has no CI coverage decision: unclassified.go",
                          matrix_ci.source_inventory_errors(catalog, root, {}))
            (root / "covered.go").unlink()
            self.assertIn("stale CI source classification: covered.go",
                          matrix_ci.source_inventory_errors(catalog, root, {}))

    def test_selection_keeps_shared_code_full_and_article_routes_scoped(self):
        all_count = len(BY_ID)
        for path in ("go.mod", "go.sum", "users/routers.go", "common/utils.go",
                     "articles/models.go", "hello.go", *matrix_ci.FULL_RUN_SOURCE_FILES):
            with self.subTest(path=path):
                selected = matrix_ci.select(CATALOG, [path])
                self.assertEqual(len(selected["selected"]), all_count)
                self.assertEqual(selected["unmapped_production_files"], [])
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

    def test_decision_journal_does_not_broaden_matrix_selection(self):
        decisions = matrix_ci.REVIEW_DECISIONS_FILE
        self.assertEqual(matrix_ci.select(CATALOG, [decisions])["selected"], [])
        self.assertEqual(matrix_ci.select(CATALOG, ["articles/routers.go", decisions])["selected"],
                         matrix_ci.select(CATALOG, ["articles/routers.go"])["selected"])
        self.assertEqual(len(matrix_ci.select(CATALOG, ["security/matrix_ci.py", decisions])["selected"]), len(BY_ID))

    def test_bound_matrix_needs_every_runtime_result(self):
        matrix_id = "RW-AUTH-01"
        variants = BY_ID[matrix_id]["variants"]
        code, report = report_for(matrix_id, ["PASS"] * len(variants))
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("BOUND_PASS"), 1)
        self.assertNotIn("sensitivity_detected", report)

        code, report = report_for(matrix_id, ["FAIL"] + ["PASS"] * (len(variants) - 1))
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("FAIL"), 1)

        code, report = report_for(matrix_id, ["PASS"] * (len(variants) - 1))
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("INCOMPLETE"), 1)

    def test_manual_sensitivity_rejects_unknown_matrix(self):
        with tempfile.TemporaryDirectory(prefix="matrix-sensitivity-test-") as tmp:
            command = [
                sys.executable, str(ROOT / "security/matrix_sensitivity.py"),
                "--binary", str(Path(tmp) / "unused-app"),
                "--matrix", "RW-DOES-NOT-EXIST",
                "--output", str(Path(tmp) / "results.json"),
            ]
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("unknown matrix ID", run.stderr)

    def test_promoted_policy_difference_and_missing_result_block(self):
        matrix_id = "RW-READ-01"
        variants = BY_ID[matrix_id]["variants"]
        code, report = report_for(matrix_id, ["PASS"] * len(variants))
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("BOUND_PASS"), 1)
        code, report = report_for(matrix_id, ["FAIL"] * len(variants))
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("FAIL"), 1)
        code, report = report_for(matrix_id, ["FAIL"] * (len(variants) - 1))
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("INCOMPLETE"), 1)
        code, report = report_for(matrix_id, ["ERROR"] + ["PASS"] * (len(variants) - 1))
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"].get("TEST_ERROR"), 1)

    def test_known_failure_is_visible_and_only_exact_observation_is_accepted(self):
        matrix_id = "RW-AUTH-02"
        variants = BY_ID[matrix_id]["variants"]
        known = [
            "PASS",
            ("FAIL", "invalid id claim returned 500: "),
            ("FAIL", "missing user id returned 200: {'user': {'username': ''}}"),
        ]
        code, report = report_for(matrix_id, known)
        self.assertEqual(code, 0)
        self.assertEqual(report["counts"].get("KNOWN_FAIL"), 1)
        self.assertEqual(len(report["accepted_failure_variants"]), 2)

        changed = known.copy()
        changed[1] = ("FAIL", "invalid id claim returned 403")
        code, report = report_for(matrix_id, changed)
        self.assertEqual(code, 1)
        self.assertTrue(any("fingerprint changed" in error for error in report["errors"]))

        changed = known.copy()
        changed[0] = ("FAIL", "new regression")
        code, report = report_for(matrix_id, changed)
        self.assertEqual(code, 1)
        self.assertTrue(any("new runtime failure" in error for error in report["errors"]))

        changed = known.copy()
        changed[1] = "PASS"
        code, report = report_for(matrix_id, changed)
        self.assertEqual(code, 1)
        self.assertTrue(any("remove its baseline entry" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
