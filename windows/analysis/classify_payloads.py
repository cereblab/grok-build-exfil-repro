"""Classify exact canaries and candidate Git signatures in all evidence layers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .models import CANARIES, CLASSIFICATION_SCHEMA, sha256_bytes, write_json_atomic


BUNDLE_SIGNATURES = {
    "v2": b"# v2 git bundle\n",
    "v3": b"# v3 git bundle\n",
}
PACK_SIGNATURE = b"PACK"
INDEX_SIGNATURE = b"DIRC"
DIFF_SIGNATURES = (b"diff --git ", b"--- a/", b"+++ b/")
PATCH_SIGNATURES = (b"Subject: [PATCH", b"*** Begin Patch", b"From ")


def _all_offsets(data: bytes, marker: bytes) -> list[int]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(marker, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def _load_artifacts(
    run_directory: Path, derived_directory: Path
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    raw_root = run_directory / "raw"
    if raw_root.is_dir():
        for path in sorted(item for item in raw_root.rglob("*") if item.is_file()):
            relative = path.relative_to(run_directory).as_posix()
            artifacts.append(
                {
                    "path": relative,
                    "filesystem_path": path,
                    "layer": "raw",
                    "source_raw_file": relative,
                    "extraction_path": [relative],
                }
            )

    extraction_path = derived_directory / "extraction-result.json"
    if not extraction_path.is_file():
        return artifacts
    extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
    by_output = {item["output_file"]: item for item in extraction.get("artifacts", [])}
    path_cache: dict[str, list[str]] = {}

    def extraction_chain(output_file: str, active: set[str] | None = None) -> list[str]:
        if output_file in path_cache:
            return path_cache[output_file]
        active = set() if active is None else active
        if output_file in active:
            return ["cycle_detected"]
        active.add(output_file)
        artifact = by_output[output_file]
        relationship = artifact.get("relationships", [{}])[0]
        parent = relationship.get("parent_derived_artifact")
        if parent and parent in by_output:
            chain = extraction_chain(parent, active) + [
                relationship.get("extraction_operation", "unknown")
            ]
        else:
            chain = [
                relationship.get("source_raw_file", "unknown"),
                relationship.get("extraction_operation", "unknown"),
            ]
        path_cache[output_file] = chain
        return chain

    for output_file, artifact in sorted(by_output.items()):
        relationships = artifact.get("relationships", [])
        source_raw = relationships[0].get("source_raw_file") if relationships else None
        artifacts.append(
            {
                "path": output_file,
                "filesystem_path": derived_directory / output_file,
                "layer": "derived",
                "source_raw_file": source_raw,
                "extraction_path": extraction_chain(output_file),
            }
        )
    return artifacts


def classify_evidence(
    run_directory: Path, derived_directory: Path
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    derived_directory = derived_directory.resolve()
    result: dict[str, Any] = {
        "schema_version": CLASSIFICATION_SCHEMA,
        "canary_findings": [],
        "artifact_signatures": [],
        "git_candidates": [],
        "git_bundle_header_found": False,
        "git_pack_signature_found": False,
        "git_index_signature_found": False,
        "git_diff_marker_found": False,
        "git_patch_marker_found": False,
    }

    for artifact in _load_artifacts(run_directory, derived_directory):
        path = artifact["filesystem_path"]
        if not path.is_file():
            continue
        data = path.read_bytes()
        for canary_name, canary in CANARIES.items():
            for offset in _all_offsets(data, canary):
                context = data[max(0, offset - 32) : min(len(data), offset + len(canary) + 32)]
                result["canary_findings"].append(
                    {
                        "canary_name": canary_name,
                        "source_artifact": artifact["path"],
                        "byte_offset": offset,
                        "extraction_path": artifact["extraction_path"],
                        "layer": artifact["layer"],
                        "surrounding_context_sha256": sha256_bytes(context),
                    }
                )

        bundle_offsets: list[dict[str, Any]] = []
        for bundle_version, signature in BUNDLE_SIGNATURES.items():
            for offset in _all_offsets(data, signature):
                bundle_offsets.append({"version": bundle_version, "offset": offset})
                result["git_candidates"].append(
                    {
                        "candidate_type": "possible_git_bundle",
                        "source_artifact": artifact["path"],
                        "source_raw_file": artifact["source_raw_file"],
                        "layer": artifact["layer"],
                        "byte_offset": offset,
                        "signature_version": bundle_version,
                        "structurally_validated": False,
                    }
                )
        pack_offsets = _all_offsets(data, PACK_SIGNATURE)
        index_offsets = _all_offsets(data, INDEX_SIGNATURE)
        for offset in pack_offsets:
            result["git_candidates"].append(
                {
                    "candidate_type": "possible_git_pack",
                    "source_artifact": artifact["path"],
                    "source_raw_file": artifact["source_raw_file"],
                    "layer": artifact["layer"],
                    "byte_offset": offset,
                    "structurally_validated": False,
                }
            )
        diff_offsets = sorted(
            {offset for marker in DIFF_SIGNATURES for offset in _all_offsets(data, marker)}
        )
        patch_offsets = sorted(
            {offset for marker in PATCH_SIGNATURES for offset in _all_offsets(data, marker)}
        )
        if diff_offsets:
            result["git_candidates"].append(
                {
                    "candidate_type": "possible_git_diff",
                    "source_artifact": artifact["path"],
                    "source_raw_file": artifact["source_raw_file"],
                    "layer": artifact["layer"],
                    "byte_offsets": diff_offsets,
                    "structurally_validated": False,
                }
            )

        signature_record = {
            "source_artifact": artifact["path"],
            "layer": artifact["layer"],
            "git_bundle_header_found": bool(bundle_offsets),
            "git_bundle_header_offsets": bundle_offsets,
            "git_pack_signature_found": bool(pack_offsets),
            "git_pack_signature_offsets": pack_offsets,
            "git_index_signature_found": bool(index_offsets),
            "git_index_signature_offsets": index_offsets,
            "git_diff_marker_found": bool(diff_offsets),
            "git_diff_marker_offsets": diff_offsets,
            "git_patch_marker_found": bool(patch_offsets),
            "git_patch_marker_offsets": patch_offsets,
        }
        if any(
            signature_record[key]
            for key in (
                "git_bundle_header_found",
                "git_pack_signature_found",
                "git_index_signature_found",
                "git_diff_marker_found",
                "git_patch_marker_found",
            )
        ):
            result["artifact_signatures"].append(signature_record)
        result["git_bundle_header_found"] |= bool(bundle_offsets)
        result["git_pack_signature_found"] |= bool(pack_offsets)
        result["git_index_signature_found"] |= bool(index_offsets)
        result["git_diff_marker_found"] |= bool(diff_offsets)
        result["git_patch_marker_found"] |= bool(patch_offsets)

    result["canary_findings"].sort(
        key=lambda item: (item["canary_name"], item["source_artifact"], item["byte_offset"])
    )
    result["git_candidates"].sort(
        key=lambda item: (
            item["candidate_type"],
            item["source_artifact"],
            item.get("byte_offset", item.get("byte_offsets", [0])[0]),
        )
    )
    write_json_atomic(derived_directory / "classification.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("derived_directory", type=Path)
    args = parser.parse_args()
    result = classify_evidence(args.run_directory, args.derived_directory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
