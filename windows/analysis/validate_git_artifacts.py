"""Validate candidate Git artifacts in isolated temporary repositories."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from .models import GIT_VALIDATION_SCHEMA, sha256_bytes, write_json_atomic


OBJECT_ID_PATTERN = re.compile(r"\b([0-9a-f]{40}|[0-9a-f]{64})\b")


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def _run_git(arguments: Sequence[str], cwd: Path | None = None) -> dict[str, Any]:
    command = ["git", "-c", "core.hooksPath=NUL", *arguments]
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace"),
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
    }


def _require_git() -> str:
    result = _run_git(["--version"])
    if result["exit_code"] != 0:
        raise RuntimeError(f"Git is required: {result['stderr'].strip()}")
    return result["stdout"].strip()


def build_git_inventory(repository: Path) -> dict[str, Any]:
    """Create a deterministic inventory of refs and every local Git object."""

    repository = repository.resolve()
    refs_result = _run_git(
        ["-C", str(repository), "for-each-ref", "--format=%(refname)%00%(objectname)"]
    )
    if refs_result["exit_code"] != 0:
        raise RuntimeError(refs_result["stderr"].strip() or "git for-each-ref failed")
    refs: dict[str, str] = {}
    for line in refs_result["stdout"].splitlines():
        if not line:
            continue
        name, object_id = line.split("\x00", 1)
        refs[name] = object_id

    objects_result = _run_git(
        [
            "-C",
            str(repository),
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            "--batch-all-objects",
        ]
    )
    if objects_result["exit_code"] != 0:
        raise RuntimeError(objects_result["stderr"].strip() or "git cat-file failed")
    objects: list[dict[str, Any]] = []
    for line in objects_result["stdout"].splitlines():
        if not line:
            continue
        object_id, object_type, object_size = line.split(" ", 2)
        objects.append(
            {"object_id": object_id, "object_type": object_type, "object_size": int(object_size)}
        )
    objects.sort(key=lambda item: item["object_id"])

    return {
        "refs": dict(sorted(refs.items())),
        "branch_names": sorted(
            name.removeprefix("refs/heads/")
            for name in refs
            if name.startswith("refs/heads/")
        ),
        "tag_names": sorted(
            name.removeprefix("refs/tags/")
            for name in refs
            if name.startswith("refs/tags/")
        ),
        "object_count": len(objects),
        "objects": objects,
        "commit_ids": [
            item["object_id"] for item in objects if item["object_type"] == "commit"
        ],
        "tree_ids": [
            item["object_id"] for item in objects if item["object_type"] == "tree"
        ],
        "blob_ids": [
            item["object_id"] for item in objects if item["object_type"] == "blob"
        ],
    }


def _empty_inventory() -> dict[str, Any]:
    return {
        "refs": {},
        "branch_names": [],
        "tag_names": [],
        "object_count": 0,
        "objects": [],
        "commit_ids": [],
        "tree_ids": [],
        "blob_ids": [],
    }


def _compare_inventories(
    expected: dict[str, Any], recovered: dict[str, Any], *, structurally_valid: bool, fsck_passed: bool
) -> dict[str, Any]:
    expected_objects = {item["object_id"] for item in expected["objects"]}
    recovered_objects = {item["object_id"] for item in recovered["objects"]}
    expected_refs = expected["refs"]
    recovered_refs = recovered["refs"]

    def compare_ids(field: str) -> tuple[list[str], list[str]]:
        expected_ids = set(expected[field])
        recovered_ids = set(recovered[field])
        return sorted(expected_ids - recovered_ids), sorted(expected_ids & recovered_ids)

    missing_commits, recovered_commits = compare_ids("commit_ids")
    missing_trees, recovered_trees = compare_ids("tree_ids")
    missing_blobs, recovered_blobs = compare_ids("blob_ids")
    recovered_expected_refs = sorted(
        name for name, value in expected_refs.items() if recovered_refs.get(name) == value
    )
    missing_expected_refs = sorted(set(expected_refs) - set(recovered_expected_refs))
    recovered_expected_objects = expected_objects & recovered_objects
    complete_objects = expected_objects <= recovered_objects
    expected_refs_recovered = not missing_expected_refs
    return {
        "expected_object_count": len(expected_objects),
        "recovered_expected_object_count": len(recovered_expected_objects),
        "unexpected_recovered_object_count": len(recovered_objects - expected_objects),
        "missing_expected_refs": missing_expected_refs,
        "recovered_expected_refs": recovered_expected_refs,
        "missing_expected_commits": missing_commits,
        "recovered_expected_commits": recovered_commits,
        "missing_expected_trees": missing_trees,
        "recovered_expected_trees": recovered_trees,
        "missing_expected_blobs": missing_blobs,
        "recovered_expected_blobs": recovered_blobs,
        "partial_git_object_set_recovered": bool(recovered_expected_objects) and not complete_objects,
        "complete_expected_object_set_recovered": complete_objects,
        "expected_refs_recovered": expected_refs_recovered,
        "full_repository_reconstructed": bool(
            structurally_valid
            and fsck_passed
            and complete_objects
            and expected_refs_recovered
            and not missing_commits
            and not missing_trees
            and not missing_blobs
        ),
    }


def _source_path(
    candidate: dict[str, Any], run_directory: Path, derived_directory: Path
) -> Path:
    relative = Path(str(candidate["source_artifact"]))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe candidate source path: {relative}")
    root = run_directory if candidate.get("layer") == "raw" else derived_directory
    path = (root / relative).resolve()
    path.relative_to(root.resolve())
    return path


def _persist_candidate(
    candidate_bytes: bytes,
    candidate_type: str,
    sequence: int,
    derived_directory: Path,
) -> tuple[Path, str]:
    digest = sha256_bytes(candidate_bytes)
    extension = ".bundle" if candidate_type == "possible_git_bundle" else ".pack"
    directory = derived_directory / "git-candidates"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{sequence:04d}-{candidate_type}-{digest}{extension}"
    if path.exists():
        if path.read_bytes() != candidate_bytes:
            raise FileExistsError(f"Refusing to overwrite a different candidate: {path}")
    else:
        with path.open("xb") as handle:
            handle.write(candidate_bytes)
    return path, digest


def _validate_bundle(candidate_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], bool, bool]:
    commands: list[dict[str, Any]] = []
    recovered = _empty_inventory()
    with tempfile.TemporaryDirectory(prefix="egress-git-bundle-") as temporary:
        temporary_path = Path(temporary)
        verification_repo = temporary_path / "verification.git"
        init = _run_git(["init", "--bare", str(verification_repo)])
        commands.append(init)
        if init["exit_code"] != 0:
            return commands, recovered, False, False
        verify = _run_git(
            ["-C", str(verification_repo), "bundle", "verify", str(candidate_path)]
        )
        commands.append(verify)
        if verify["exit_code"] != 0:
            return commands, recovered, False, False

        recovered_repo = temporary_path / "recovered.git"
        clone = _run_git(["clone", "--bare", str(candidate_path), str(recovered_repo)])
        commands.append(clone)
        if clone["exit_code"] != 0:
            return commands, recovered, True, False
        fsck = _run_git(["-C", str(recovered_repo), "fsck", "--full"])
        commands.append(fsck)
        fsck_passed = fsck["exit_code"] == 0
        if fsck_passed:
            recovered = build_git_inventory(recovered_repo)
        return commands, recovered, True, fsck_passed


def _validate_pack(candidate_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], bool, bool]:
    commands: list[dict[str, Any]] = []
    recovered = _empty_inventory()
    with tempfile.TemporaryDirectory(prefix="egress-git-pack-") as temporary:
        temporary_path = Path(temporary)
        working_pack = temporary_path / "candidate.pack"
        shutil.copyfile(candidate_path, working_pack)
        index = _run_git(["index-pack", "--strict", str(working_pack)])
        commands.append(index)
        if index["exit_code"] != 0:
            return commands, recovered, False, False
        object_ids = OBJECT_ID_PATTERN.findall(index["stdout"] + "\n" + index["stderr"])
        if not object_ids:
            commands.append(
                {
                    "command": ["parse index-pack output"],
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "index-pack did not report a pack object ID",
                }
            )
            return commands, recovered, False, False
        pack_id = object_ids[-1]
        working_index = working_pack.with_suffix(".idx")
        if not working_index.is_file():
            commands.append(
                {
                    "command": ["locate generated pack index"],
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": f"missing generated index: {working_index}",
                }
            )
            return commands, recovered, False, False

        recovered_repo = temporary_path / "recovered.git"
        init = _run_git(["init", "--bare", str(recovered_repo)])
        commands.append(init)
        if init["exit_code"] != 0:
            return commands, recovered, True, False
        pack_directory = recovered_repo / "objects" / "pack"
        pack_directory.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(working_pack, pack_directory / f"pack-{pack_id}.pack")
        shutil.copyfile(working_index, pack_directory / f"pack-{pack_id}.idx")
        fsck = _run_git(
            ["-C", str(recovered_repo), "fsck", "--full", "--no-reflogs"]
        )
        commands.append(fsck)
        fsck_passed = fsck["exit_code"] == 0
        if fsck_passed:
            recovered = build_git_inventory(recovered_repo)
        return commands, recovered, True, fsck_passed


def validate_candidates(
    run_directory: Path,
    derived_directory: Path,
    expected_repository: Path,
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    derived_directory = derived_directory.resolve()
    git_version = _require_git()
    expected_inventory = build_git_inventory(expected_repository)
    write_json_atomic(derived_directory / "expected-git-inventory.json", expected_inventory)
    classification = json.loads(
        (derived_directory / "classification.json").read_text(encoding="utf-8")
    )
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    candidates = [
        item
        for item in classification.get("git_candidates", [])
        if item.get("candidate_type") in ("possible_git_bundle", "possible_git_pack")
    ]
    for sequence, candidate in enumerate(candidates, 1):
        source_path = _source_path(candidate, run_directory, derived_directory)
        source = source_path.read_bytes()
        offset = int(candidate["byte_offset"])
        candidate_bytes = source[offset:]
        candidate_type = str(candidate["candidate_type"])
        candidate_path, digest = _persist_candidate(
            candidate_bytes, candidate_type, sequence, derived_directory
        )
        identity = (candidate_type, digest)
        if identity in seen:
            continue
        seen.add(identity)

        if candidate_type == "possible_git_bundle":
            commands, recovered, validated, fsck_passed = _validate_bundle(candidate_path)
            bundle_validated = validated
            pack_validated = False
        else:
            commands, recovered, validated, fsck_passed = _validate_pack(candidate_path)
            bundle_validated = False
            pack_validated = validated
        comparison = _compare_inventories(
            expected_inventory,
            recovered,
            structurally_valid=validated,
            fsck_passed=fsck_passed,
        )
        results.append(
            {
                "candidate_type": candidate_type,
                "source_artifact": candidate["source_artifact"],
                "byte_offset": offset,
                "candidate_file": candidate_path.relative_to(derived_directory).as_posix(),
                "candidate_sha256": digest,
                "candidate_byte_length": len(candidate_bytes),
                "git_version": git_version,
                "commands": commands,
                "git_bundle_validated": bundle_validated,
                "git_pack_validated": pack_validated,
                "repository_integrity_checks_passed": fsck_passed,
                "recovered_inventory": recovered,
                **comparison,
            }
        )

    result = {
        "schema_version": GIT_VALIDATION_SCHEMA,
        "git_version": git_version,
        "expected_inventory_file": "expected-git-inventory.json",
        "validated_candidates": results,
        "git_bundle_validated": any(item["git_bundle_validated"] for item in results),
        "git_pack_validated": any(item["git_pack_validated"] for item in results),
        "partial_git_object_set_recovered": any(
            item["partial_git_object_set_recovered"] for item in results
        ),
        "complete_expected_object_set_recovered": any(
            item["complete_expected_object_set_recovered"] for item in results
        ),
        "expected_refs_recovered": any(item["expected_refs_recovered"] for item in results),
        "full_repository_reconstructed": any(
            item["full_repository_reconstructed"] for item in results
        ),
    }
    write_json_atomic(derived_directory / "git-validation.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("derived_directory", type=Path)
    parser.add_argument("expected_repository", type=Path)
    args = parser.parse_args()
    result = validate_candidates(
        args.run_directory, args.derived_directory, args.expected_repository
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
