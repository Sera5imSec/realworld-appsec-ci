#!/usr/bin/env python3
"""Combine matrix selection, runtime evidence, and sensitivity evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--sensitivity", required=True, type=Path)
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--markdown-out", required=True, type=Path)
    args = parser.parse_args()
    try:
        catalog = read_json(ROOT / "security/matrices/catalog.json")
        bindings = read_json(ROOT / "security/matrices/bindings.json")
        accepted = read_json(ROOT / "security/matrices/accepted_failures.json")
        selection = read_json(args.selection)
        runtime = read_json(args.runtime)
        sensitivity = read_json(args.sensitivity)
    except (OSError, ValueError) as exc:
        print(f"ERROR: incomplete matrix evidence: {exc}", file=sys.stderr)
        return 1

    by_id = {m["id"]: m for m in catalog["matrices"]}
    selected = set(selection["selected"])
    bound = set(bindings["bound_matrices"])
    observed_matrices = set(bindings["observed_matrices"])
    try:
        accepted_rows = accepted["accepted_failures"]
        accepted_by_variant = {r["variant_id"]: r for r in accepted_rows}
    except (KeyError, TypeError) as exc:
        print(f"ERROR: invalid accepted-failures baseline: {exc}", file=sys.stderr)
        return 1
    runtime_rows = runtime["results"]
    sensitivity_rows = sensitivity["results"]
    runtime_ids = [r["variant_id"] for r in runtime_rows]
    sensitivity_ids = [r["matrix_id"] for r in sensitivity_rows]
    errors = []
    accepted_runtime = []
    variant_parent = {v["id"]: m["id"] for m in catalog["matrices"] for v in m["variants"]}
    if accepted.get("schema_version") != 1 or accepted.get("target_commit") != catalog["project"]["commit"]:
        errors.append("accepted failures target a different source commit")
    if len(accepted_by_variant) != len(accepted_rows):
        errors.append("duplicate accepted failure variant")
    for vid, entry in accepted_by_variant.items():
        if variant_parent.get(vid) != entry.get("matrix_id") or entry["matrix_id"] not in bound:
            errors.append(f"{vid}: invalid accepted failure binding")
        details = entry.get("detail_contains")
        if not isinstance(details, list) or not details or any(not isinstance(part, str) or not part for part in details):
            errors.append(f"{vid}: missing failure fingerprint")
    for row in runtime_rows:
        if row["result"] not in {"PASS", "FAIL", "OBSERVED", "ERROR"}:
            errors.append(f"{row['variant_id']}: invalid runtime result")
        if variant_parent.get(row["variant_id"]) != row["matrix_id"]:
            errors.append(f"{row['variant_id']}: matrix ID does not match catalog")
    if len(runtime_ids) != len(set(runtime_ids)):
        errors.append("duplicate runtime variant")
    if len(sensitivity_ids) != len(set(sensitivity_ids)):
        errors.append("duplicate sensitivity matrix")
    if set(selection.get("unmapped_production_files", [])):
        errors.append("unmapped production source file")
    runtime_by_id = {r["variant_id"]: r for r in runtime_rows}
    sensitivity_by_id = {r["matrix_id"]: r for r in sensitivity_rows}
    expected_sensitivity = selected & bound
    if set(sensitivity_ids) != expected_sensitivity:
        errors.append("sensitivity matrix set differs from selected bound matrices")
    for mid in sorted(expected_sensitivity):
        if mid in sensitivity_by_id:
            probe = sensitivity_by_id[mid]
            if probe.get("baseline") != "PASS" or probe.get("sensitivity") != "DETECTED":
                errors.append(f"{mid}: baseline or source-mutation sensitivity was not demonstrated")
            if probe.get("variant_id") not in {v["id"] for v in by_id[mid]["variants"]}:
                errors.append(f"{mid}: sensitivity variant does not belong to matrix")
            if not probe.get("mutation"):
                errors.append(f"{mid}: missing source-mutation description")
    statuses = []
    for matrix in catalog["matrices"]:
        mid = matrix["id"]
        expected_variants = {v["id"] for v in matrix["variants"]}
        executed = expected_variants & runtime_by_id.keys()
        if mid not in selected:
            status = "NOT_IMPACTED"
        elif mid in observed_matrices:
            if executed != expected_variants:
                status = "INCOMPLETE"
                errors.append(f"{mid}: {len(expected_variants - executed)} observation results missing")
            elif any(runtime_by_id[vid]["result"] == "ERROR" for vid in executed):
                status = "TEST_ERROR"
                errors.append(f"{mid}: observation runner error")
            else:
                status = "HOLD_POLICY"
        elif mid not in bound:
            status = "GAP_NOT_RUN"
            errors.append(f"{mid}: no runtime binding")
        else:
            if executed != expected_variants:
                status = "INCOMPLETE"
                errors.append(f"{mid}: {len(expected_variants - executed)} variant results missing")
            elif any(runtime_by_id[vid]["result"] == "ERROR" for vid in executed):
                status = "TEST_ERROR"
                errors.append(f"{mid}: runtime runner error")
            else:
                differences = []
                matched = []
                for vid in sorted(expected_variants):
                    row = runtime_by_id[vid]
                    exception = accepted_by_variant.get(vid)
                    if exception and row["result"] == "FAIL" and isinstance(exception.get("detail_contains"), list) and exception["detail_contains"] and all(
                        isinstance(part, str) and part and part in row.get("detail", "")
                        for part in exception["detail_contains"]
                    ):
                        matched.append(vid)
                    elif exception and row["result"] == "PASS":
                        differences.append(f"{vid}: accepted failure now passes; remove its baseline entry")
                    elif exception and row["result"] == "FAIL":
                        differences.append(f"{vid}: failure fingerprint changed")
                    elif row["result"] != "PASS":
                        differences.append(f"{vid}: new runtime failure")
                accepted_runtime.extend(matched)
                if differences:
                    status = "FAIL"
                    errors.extend(differences)
                elif mid not in sensitivity_by_id or sensitivity_by_id[mid].get("baseline") != "PASS" or sensitivity_by_id[mid].get("sensitivity") != "DETECTED":
                    status = "INCOMPLETE"
                elif matched:
                    status = "KNOWN_FAIL"
                else:
                    status = "BOUND_PASS"
        statuses.append({
            "matrix_id": mid,
            "status": status,
            "planned_variants": len(expected_variants),
            "runtime_executed": len(executed),
            "runtime_passes": sum(
                runtime_by_id[vid]["result"] == "PASS"
                for vid in executed
            ),
            "runtime_failures": sum(runtime_by_id[vid]["result"] == "FAIL" for vid in executed),
            "runtime_observed": sum(runtime_by_id[vid]["result"] == "OBSERVED" for vid in executed),
            "runtime_errors": sum(runtime_by_id[vid]["result"] == "ERROR" for vid in executed),
        })
    unexpected = set(runtime_ids) - {
        v["id"] for m in catalog["matrices"] if m["id"] in selected & (bound | observed_matrices)
        for v in m["variants"]
    }
    if unexpected:
        errors.append(f"unexpected runtime variant: {sorted(unexpected)}")
    counts = Counter(item["status"] for item in statuses)
    report = {
        "base_commit": catalog["project"]["commit"],
        "source_state": "local working tree with AppSec changes",
        "selected": sorted(selected),
        "counts": dict(counts),
        "statuses": statuses,
        "sensitivity_detected": sum(r.get("sensitivity") == "DETECTED" and r.get("baseline") == "PASS" for r in sensitivity_rows),
        "accepted_failure_variants": sorted(accepted_runtime),
        "errors": errors,
        "meaning": "BOUND_PASS covers listed variants and a source mutation. KNOWN_FAIL preserves exact accepted local failures without claiming a pass.",
    }
    args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# RealWorld AppSec matrix CI",
        "",
        f"Selected matrices: **{len(selected)}**. Runtime variants: **{len(runtime_rows)}**.",
        f"Bound pass: **{counts['BOUND_PASS']}**; accepted known fail: **{counts['KNOWN_FAIL']}**; new or changed fail: **{counts['FAIL']}**; "
        f"test error: **{counts['TEST_ERROR']}**; incomplete: **{counts['INCOMPLETE']}**; "
        f"gap not run: **{counts['GAP_NOT_RUN']}**; policy hold: **{counts['HOLD_POLICY']}**; "
        f"not impacted: **{counts['NOT_IMPACTED']}**.",
        f"Policy observations: **{sum(r['runtime_executed'] for r in statuses if r['matrix_id'] in observed_matrices)}** variants "
        f"({sum(r['runtime_passes'] for r in statuses if r['matrix_id'] in observed_matrices)} match proposed rules, "
        f"{sum(r['runtime_failures'] for r in statuses if r['matrix_id'] in observed_matrices)} differ, "
        f"{sum(r['runtime_observed'] for r in statuses if r['matrix_id'] in observed_matrices)} measured without a threshold).",
        f"Representative source-mutation probes detected: **{sum(r.get('sensitivity') == 'DETECTED' and r.get('baseline') == 'PASS' for r in sensitivity_rows)} / {len(expected_sensitivity)}**. "
        "Each probe checks one selected variant; it does not independently confirm every failing variant.",
        f"Accepted local failure variants: **{len(accepted_runtime)}**. Their exact IDs and failure fingerprints remain visible in the uploaded evidence.",
        "",
        "| Matrix | Status | Executed / planned | Match | Differ | Measured |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    lines += [
        f"| `{s['matrix_id']}` | {s['status']} | {s['runtime_executed']} / {s['planned_variants']} | "
        f"{s['runtime_passes']} | {s['runtime_failures']} | {s['runtime_observed']} |"
        for s in statuses
    ]
    failed_variants = [r["variant_id"] for r in runtime_rows
                       if r["result"] in ("FAIL", "ERROR") and r["matrix_id"] in bound]
    if failed_variants:
        lines += ["", "## Observed bound failures", "", ", ".join(f"`{vid}`" for vid in failed_variants)]
    if accepted_runtime:
        lines += ["", "## Accepted local failures (tracked, non-blocking)", "",
                  ", ".join(f"`{vid}`" for vid in sorted(accepted_runtime))]
    held_differences = [r["variant_id"] for r in runtime_rows
                        if r["result"] == "FAIL" and r["matrix_id"] in observed_matrices]
    if held_differences:
        lines += ["", "## Proposed policy differences (non-blocking)", "",
                  ", ".join(f"`{vid}`" for vid in held_differences)]
    if errors:
        lines += ["", "## Gate errors", ""] + [f"- {error}" for error in errors]
    lines += [
        "",
        "A green job can include exact accepted local failures. It means no new failure, missing result, changed failure fingerprint, or missed sensitivity probe was found; it does not mean the known failures were fixed.",
        "",
    ]
    markdown = "\n".join(lines)
    args.markdown_out.write_text(markdown, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(markdown)
    print(markdown)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
