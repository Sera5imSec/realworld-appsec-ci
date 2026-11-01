#!/usr/bin/env python3
"""Validate and select source-linked AppSec matrices for CI.

This tool does not turn DESCRIBED variants into runtime evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "security" / "matrices" / "catalog.json"
BINDINGS = ROOT / "security" / "matrices" / "bindings.json"
ACCEPTED_FAILURES = ROOT / "security" / "matrices" / "accepted_failures.json"
CI_FILES = {"security/matrices/catalog.json", "security/matrix_ci.py", ".github/workflows/ci.yml"}
GO_DEPENDENCIES = {"go.mod", "go.sum", "go.work", "go.work.sum"}


def load_catalog() -> dict:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def production_go(path: str) -> bool:
    p = Path(path)
    return p.suffix == ".go" and not p.name.endswith("_test.go")


def validate(catalog: dict) -> list[str]:
    errors: list[str] = []
    if catalog.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    matrices = catalog.get("matrices", [])
    if not matrices:
        errors.append("no matrices")
    ids = [m.get("id") for m in matrices]
    if len(ids) != len(set(ids)):
        errors.append("duplicate matrix ID")
    variant_ids: list[str] = []
    routes = {r["route"] for r in catalog["route_inventory"]["canonical"]}
    known_routes = routes | {r["alias"] for r in catalog["route_inventory"]["aliases"]}
    known_routes |= {r["route"] for r in catalog["route_inventory"]["extra"]}
    for m in matrices:
        mid = m.get("id", "?")
        if m.get("readiness") != "DESCRIBED":
            errors.append(f"{mid}: catalog must not claim runtime readiness")
        if not m.get("obligation") or not m.get("independent_oracle") or not m.get("sensitivity_plan"):
            errors.append(f"{mid}: missing obligation, oracle, or sensitivity plan")
        if "PROPOSED_POLICY" in m.get("basis", []) and not m.get("policy_hold"):
            errors.append(f"{mid}: proposed policy has no hold")
        if m.get("policy_hold") and m.get("gate_status") != "HOLD_POLICY":
            errors.append(f"{mid}: policy hold/status mismatch")
        if not m.get("policy_hold") and m.get("gate_status") != "NOT_READY":
            errors.append(f"{mid}: unexpected gate status")
        if not m.get("reach") or not set(m["reach"]) <= known_routes:
            errors.append(f"{mid}: missing or unknown route")
        kinds = {v.get("kind") for v in m.get("variants", [])}
        if not {"CONTROL", "NEGATIVE"} <= kinds:
            errors.append(f"{mid}: control and negative variants required")
        for v in m.get("variants", []):
            variant_ids.append(v.get("id"))
            if v.get("execution") != "NOT_RUN":
                errors.append(f"{mid}: catalog cannot contain run results")
        source_paths: set[str] = set()
        for ref in m.get("source_refs", []):
            match = re.fullmatch(r"([A-Za-z0-9_/.-]+\.go):(\d+)", ref)
            if not match:
                errors.append(f"{mid}: invalid source ref {ref}")
                continue
            rel, line = match.group(1), int(match.group(2))
            file = ROOT / rel
            source_paths.add(rel)
            if not file.is_file() or not 1 <= line <= len(file.read_text(encoding="utf-8").splitlines()):
                errors.append(f"{mid}: stale source ref {ref}")
        if not source_paths <= set(m.get("ci_watch_seed", [])):
            errors.append(f"{mid}: source absent from CI watch seed")
    if len(variant_ids) != len(set(variant_ids)):
        errors.append("duplicate variant ID")
    coverage = {r["route"]: r["matrices"] for r in catalog.get("route_coverage", [])}
    if set(coverage) != routes or any(not coverage[r] for r in routes):
        errors.append("canonical route coverage is incomplete")
    route_pattern = r"\b[A-Za-z_][A-Za-z0-9_]*\.(?:GET|POST|PUT|DELETE)\("
    source_routes = sum(
        len(re.findall(route_pattern, (ROOT / rel).read_text(encoding="utf-8")))
        for rel in ("hello.go", "users/routers.go", "articles/routers.go")
    )
    recorded_routes = len(routes) + len(catalog["route_inventory"]["aliases"]) + len(catalog["route_inventory"]["extra"])
    if source_routes != recorded_routes:
        errors.append(f"route inventory drift: source={source_routes}, catalog={recorded_routes}")
    bound: set[str] = set()
    try:
        bindings = json.loads(BINDINGS.read_text(encoding="utf-8"))
        bound = bindings["bound_matrices"]
        if bindings.get("schema_version") != 1 or len(bound) != len(set(bound)):
            errors.append("invalid bindings schema or duplicate bound matrix")
        unknown = set(bound) - set(ids)
        if unknown:
            errors.append(f"unknown bound matrix: {sorted(unknown)}")
        held = {m["id"] for m in matrices if m.get("policy_hold")}
        if set(bound) & held:
            errors.append("policy-held matrix cannot be in blocking bindings")
        observed = bindings.get("observed_matrices", [])
        if len(observed) != len(set(observed)) or set(observed) != held:
            errors.append("observed matrices must equal the policy-held catalog rows")
        if set(observed) & set(bound):
            errors.append("a matrix cannot be both blocking and observed")
        for key in ("runner", "sensitivity_runner"):
            if not (ROOT / bindings[key]).is_file():
                errors.append(f"missing {key}: {bindings[key]}")
        from matrix_sensitivity import PROBES
        if set(PROBES) != set(bound):
            errors.append("sensitivity probes must cover exactly the bound matrices")
    except (OSError, ValueError, KeyError) as exc:
        errors.append(f"invalid bindings: {exc}")
    try:
        accepted = json.loads(ACCEPTED_FAILURES.read_text(encoding="utf-8"))
        if accepted.get("schema_version") != 1:
            errors.append("invalid accepted-failures schema")
        if accepted.get("target_commit") != catalog["project"]["commit"]:
            errors.append("accepted failures target a different source commit")
        parents = {v["id"]: m["id"] for m in matrices for v in m["variants"]}
        accepted_ids: list[str] = []
        for row in accepted["accepted_failures"]:
            vid, mid = row["variant_id"], row["matrix_id"]
            accepted_ids.append(vid)
            if parents.get(vid) != mid or mid not in bound:
                errors.append(f"{vid}: accepted failure is not a bound catalog variant")
            details = row.get("detail_contains")
            if not isinstance(details, list) or not details or any(not isinstance(part, str) or not part for part in details):
                errors.append(f"{vid}: missing stable failure fingerprint")
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                errors.append(f"{vid}: missing review reason")
        if len(accepted_ids) != len(set(accepted_ids)):
            errors.append("duplicate accepted failure variant")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"invalid accepted failures: {exc}")
    return errors


def changed_paths(base: str | None) -> list[str]:
    if not base or re.fullmatch(r"0{40}", base):
        return []
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git diff failed for {base}: {result.stderr.strip()}")
    return sorted(set(result.stdout.splitlines()))


def select(catalog: dict, changed: list[str]) -> dict:
    matrices = catalog["matrices"]
    all_ids = {m["id"] for m in matrices}
    selected: set[str] = set()
    unmapped: list[str] = []
    if not changed or any(p in CI_FILES or p in GO_DEPENDENCIES or p.startswith("security/") for p in changed):
        selected = all_ids
    else:
        for path in changed:
            if production_go(path):
                matched = {m["id"] for m in matrices if path in m["ci_watch_seed"]}
                if not matched:
                    unmapped.append(path)
                selected = all_ids
    by_id = {m["id"]: m for m in matrices}
    return {
        "changed_paths": changed,
        "selected": sorted(selected),
        "hold_policy": sorted(mid for mid in selected if by_id[mid]["policy_hold"]),
        "bound": sorted(mid for mid in selected if not by_id[mid]["policy_hold"]),
        "unmapped_production_files": unmapped,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate", "select"))
    parser.add_argument("--base", help="base commit for PR/push selection")
    parser.add_argument("--output", type=Path, help="write JSON selection")
    args = parser.parse_args()
    try:
        catalog = load_catalog()
        errors = validate(catalog)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        if args.command == "validate":
            print(f"VALID: {len(catalog['matrices'])} matrices, "
                  f"{sum(len(m['variants']) for m in catalog['matrices'])} planned variants")
            return 0
        selection = select(catalog, changed_paths(args.base))
        result = json.dumps(selection, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        print(result, end="")
        if selection["unmapped_production_files"]:
            print("ERROR: production source without matrix mapping", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
