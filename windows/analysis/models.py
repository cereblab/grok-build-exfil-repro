"""Shared data models and deterministic serialization helpers."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


EVIDENCE_MANIFEST_SCHEMA = "egress-evidence-manifest/v1"
EXTRACTION_SCHEMA = "egress-extraction/v1"
CLASSIFICATION_SCHEMA = "egress-classification/v1"
GIT_VALIDATION_SCHEMA = "egress-git-validation/v1"
REPORT_SCHEMA = "egress-report/v1"

CANARIES: dict[str, bytes] = {
    "current_tracked_canary": b"CANARY-CURRENT-TRACKED-7A9C2E",
    "never_read_tracked_canary": b"CANARY-TRACKED-DO-NOT-READ-5F1D8B",
    "historical_deleted_canary": b"CANARY-GIT-HISTORY-DELETED-2C6E4A",
    "ignored_untracked_canary": b"CANARY-IGNORED-UNTRACKED-9B3D7F",
    "non_ignored_untracked_canary": b"CANARY-UNTRACKED-NONIGNORED-4E8A1C",
    "second_branch_canary": b"CANARY-SECOND-BRANCH-6D2F9A",
    "env_canary": b"EGRESS_CANARY_ENV_TOKEN_8A4F1",
    "local_settings_canary": b"EGRESS_CANARY_SETTINGS_TOKEN_73C2B",
}


@dataclass(frozen=True)
class ExtractionLimits:
    """Hard limits applied before derived artifacts are persisted."""

    maximum_extraction_depth: int = 6
    maximum_total_expanded_bytes: int = 64 * 1024 * 1024
    maximum_derived_artifacts: int = 1_000
    maximum_size_per_derived_artifact: int = 16 * 1024 * 1024
    decompression_ratio_limit: float = 100.0
    base64_minimum_decoded_length: int = 12

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        integer_fields = (
            self.maximum_extraction_depth,
            self.maximum_total_expanded_bytes,
            self.maximum_derived_artifacts,
            self.maximum_size_per_derived_artifact,
            self.base64_minimum_decoded_length,
        )
        if any(value < 1 for value in integer_fields):
            raise ValueError("All extraction integer limits must be positive.")
        if self.decompression_ratio_limit <= 0:
            raise ValueError("decompression_ratio_limit must be positive.")


def deterministic_json_bytes(value: Any) -> bytes:
    """Return canonical UTF-8 JSON suitable for stable local manifests."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def write_json_atomic(path: Path, value: Any) -> None:
    """Atomically replace a derived JSON file with deterministic bytes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("xb") as handle:
        handle.write(deterministic_json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_file_record(root: Path, path: Path) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    return {
        "path": relative,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }
