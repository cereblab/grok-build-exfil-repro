"""Verify a run-level local evidence integrity manifest."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .models import EVIDENCE_MANIFEST_SCHEMA, sha256_file


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def verify_manifest(run_directory: Path) -> dict[str, Any]:
    """Recalculate every listed hash and report integrity anomalies."""

    run_directory = run_directory.resolve()
    manifest_path = run_directory / "evidence-manifest.json"
    result: dict[str, Any] = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA,
        "manifest": str(manifest_path),
        "valid": False,
        "missing_files": [],
        "modified_files": [],
        "duplicate_manifest_paths": [],
        "duplicate_content_groups": [],
        "unexpected_raw_files": [],
        "errors": [],
    }
    if not manifest_path.is_file():
        result["errors"].append("evidence-manifest.json is missing")
        return result

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        result["errors"].append(f"manifest could not be read: {type(exc).__name__}: {exc}")
        return result

    if manifest.get("schema_version") != EVIDENCE_MANIFEST_SCHEMA:
        result["errors"].append("unsupported or missing manifest schema_version")

    entries: list[dict[str, Any]] = []
    entries.extend(manifest.get("metadata_files", []))
    entries.extend(manifest.get("raw_evidence_files", []))
    addon = manifest.get("addon_file")
    if isinstance(addon, dict):
        entries.append(addon)

    paths = [str(entry.get("path", "")) for entry in entries]
    result["duplicate_manifest_paths"] = _duplicates(paths)
    content_paths: defaultdict[tuple[str, int], list[str]] = defaultdict(list)

    for entry in entries:
        relative = str(entry.get("path", ""))
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            result["errors"].append(f"unsafe manifest path: {relative!r}")
            continue
        path = run_directory / Path(relative)
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(run_directory)
        except (OSError, ValueError):
            result["missing_files"].append(relative)
            continue
        if not resolved.is_file():
            result["missing_files"].append(relative)
            continue
        actual_size = resolved.stat().st_size
        actual_hash = sha256_file(resolved)
        if actual_size != entry.get("size") or actual_hash != entry.get("sha256"):
            result["modified_files"].append(
                {
                    "path": relative,
                    "expected_size": entry.get("size"),
                    "actual_size": actual_size,
                    "expected_sha256": entry.get("sha256"),
                    "actual_sha256": actual_hash,
                }
            )
        content_paths[(actual_hash, actual_size)].append(relative)

    for (digest, size), duplicate_paths in sorted(content_paths.items()):
        if len(duplicate_paths) > 1:
            result["duplicate_content_groups"].append(
                {"sha256": digest, "size": size, "paths": sorted(duplicate_paths)}
            )

    expected_raw = {
        str(entry.get("path", "")) for entry in manifest.get("raw_evidence_files", [])
    }
    raw_root = run_directory / "raw"
    actual_raw = (
        {path.relative_to(run_directory).as_posix() for path in raw_root.rglob("*") if path.is_file()}
        if raw_root.is_dir()
        else set()
    )
    result["unexpected_raw_files"] = sorted(actual_raw - expected_raw)

    fatal_lists = (
        result["missing_files"],
        result["modified_files"],
        result["duplicate_manifest_paths"],
        result["unexpected_raw_files"],
        result["errors"],
    )
    result["valid"] = not any(fatal_lists)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    result = verify_manifest(args.run_directory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
