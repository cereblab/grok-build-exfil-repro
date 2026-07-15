from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from unittest import mock

WINDOWS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WINDOWS_ROOT))

import brotli
import jsonschema

from analysis import validate_git_artifacts as git_validation
from analysis.classify_payloads import classify_evidence
from analysis.extract_payloads import extract_run
from analysis.generate_report import (
    MISSING_CANARY_LANGUAGE,
    PROHIBITED_CONCLUSIONS,
    generate_reports,
    render_markdown,
)
from analysis.models import (
    CANARIES,
    CLASSIFICATION_SCHEMA,
    EVIDENCE_MANIFEST_SCHEMA,
    EXTRACTION_SCHEMA,
    GIT_VALIDATION_SCHEMA,
    ExtractionLimits,
    evidence_file_record,
    sha256_bytes,
    write_json_atomic,
)


def _create_run(root: Path, payloads: list[dict[str, object]]) -> Path:
    run = root / "run"
    raw_directory = run / "raw" / "http"
    websocket_directory = run / "raw" / "websocket"
    provenance = run / "provenance"
    raw_directory.mkdir(parents=True)
    websocket_directory.mkdir(parents=True)
    provenance.mkdir(parents=True)
    records = []
    for sequence, spec in enumerate(payloads, 1):
        payload = bytes(spec["data"])
        digest = hashlib.sha256(payload).hexdigest()
        relative = f"raw/http/{sequence:08d}-{digest}.bin"
        (run / relative).write_bytes(payload)
        records.append(
            {
                "request_sequence_number": sequence,
                "raw_body_file": relative,
                "body_sha256": digest,
                "body_size": len(payload),
                "content_type": spec.get("content_type"),
                "content_encoding": spec.get("content_encoding"),
            }
        )
    (run / "requests.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in records),
        encoding="utf-8",
        newline="\n",
    )
    (run / "websockets.jsonl").write_bytes(b"")
    run_metadata = {
        "run_id": "test-run",
        "started_at_utc": "2024-01-01T00:00:00.000Z",
        "operating_system": "Windows test",
        "python_version": sys.version.split()[0],
        "mitmproxy_version": "test",
        "repository_commit_sha": "0" * 40,
    }
    write_json_atomic(run / "run.json", run_metadata)
    addon = provenance / "capture_requests.py"
    addon.write_bytes(b"# test addon snapshot\n")
    metadata_files = sorted(
        [
            evidence_file_record(run, run / "run.json"),
            evidence_file_record(run, run / "requests.jsonl"),
            evidence_file_record(run, run / "websockets.jsonl"),
        ],
        key=lambda item: item["path"],
    )
    raw_files = sorted(
        [evidence_file_record(run, path) for path in raw_directory.iterdir()],
        key=lambda item: item["path"],
    )
    manifest = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA,
        "run_id": "test-run",
        "capture_start_timestamp": "2024-01-01T00:00:00.000Z",
        "capture_stop_timestamp": "2024-01-01T00:01:00.000Z",
        "operating_system": "Windows test",
        "python_version": sys.version.split()[0],
        "mitmproxy_version": "test",
        "repository_commit_sha": "0" * 40,
        "addon_file": evidence_file_record(run, addon),
        "metadata_file_sha256": {
            item["path"]: item["sha256"] for item in metadata_files
        },
        "metadata_files": metadata_files,
        "raw_evidence_files": raw_files,
        "capture_ended_cleanly": True,
        "capture_error_count": 0,
        "integrity_scope": "local_integrity_only_not_cryptographic_nonrepudiation",
    }
    write_json_atomic(run / "evidence-manifest.json", manifest)
    return run


def _artifact_payloads(derived: Path, result: dict[str, object]) -> list[bytes]:
    return [
        (derived / item["output_file"]).read_bytes()
        for item in result["artifacts"]
    ]


def _run_git(arguments: list[str], *, input_data: bytes | None = None) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Phase 2 Test",
            "GIT_AUTHOR_EMAIL": "phase2@example.invalid",
            "GIT_COMMITTER_NAME": "Phase 2 Test",
            "GIT_COMMITTER_EMAIL": "phase2@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        ["git", *arguments],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


def _create_git_repository(root: Path) -> Path:
    repository = root / "source-repository"
    _run_git(["init", "--quiet", "--initial-branch=main", str(repository)])
    (repository / "canary.txt").write_bytes(CANARIES["current_tracked_canary"] + b"\n")
    _run_git(["-C", str(repository), "add", "canary.txt"])
    _run_git(["-C", str(repository), "commit", "--quiet", "-m", "test commit"])
    _run_git(["-C", str(repository), "branch", "canary/second-branch"])
    return repository


class ExtractionTests(unittest.TestCase):
    def test_http_gzip_zlib_raw_deflate_brotli_and_chain(self) -> None:
        original = b"decoded-content-" + CANARIES["env_canary"]
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw_deflate = compressor.compress(original) + compressor.flush()
        gzip_layer = gzip.compress(original, mtime=0)
        payloads = [
            {"data": gzip_layer, "content_encoding": "gzip"},
            {"data": zlib.compress(original), "content_encoding": "deflate"},
            {"data": raw_deflate, "content_encoding": "deflate"},
            {"data": brotli.compress(original), "content_encoding": "br"},
            {"data": brotli.compress(gzip_layer), "content_encoding": "gzip, br"},
        ]
        with tempfile.TemporaryDirectory(prefix="phase2-extract-") as temporary:
            root = Path(temporary)
            run = _create_run(root, payloads)
            derived = root / "derived"
            result = extract_run(run, derived)
            outputs = _artifact_payloads(derived, result)
            self.assertIn(original, outputs)
            operations = [item["extraction_operation"] for item in result["operations"]]
            self.assertIn("http_content_encoding:gzip", operations)
            self.assertIn("http_content_encoding:deflate", operations)
            self.assertIn("http_content_encoding:deflate_raw", operations)
            self.assertIn("http_content_encoding:br", operations)
            self.assertEqual([], result["unsupported_encodings"])

    def test_malformed_compression_unknown_encoding_and_expansion_limit(self) -> None:
        payloads = [
            {"data": b"not-gzip", "content_encoding": "gzip"},
            {"data": b"opaque", "content_encoding": "future-encoding"},
            {"data": gzip.compress(b"A" * 4096, mtime=0), "content_encoding": "gzip"},
        ]
        limits = ExtractionLimits(
            maximum_extraction_depth=4,
            maximum_total_expanded_bytes=1024,
            maximum_derived_artifacts=20,
            maximum_size_per_derived_artifact=128,
            decompression_ratio_limit=10.0,
            base64_minimum_decoded_length=12,
        )
        with tempfile.TemporaryDirectory(prefix="phase2-limits-") as temporary:
            root = Path(temporary)
            run = _create_run(root, payloads)
            result = extract_run(run, root / "derived", limits)
            self.assertGreaterEqual(len(result["extraction_failures"]), 3)
            self.assertEqual("future-encoding", result["unsupported_encodings"][0]["encoding"])
            self.assertTrue(result["processing_limits_reached"])

    def test_json_base64_nested_gzip_and_deduplication(self) -> None:
        marker = CANARIES["local_settings_canary"]
        nested = base64.b64encode(gzip.compress(marker, mtime=0)).decode("ascii")
        repeated = base64.b64encode(b"duplicate-derived-content").decode("ascii")
        body = json.dumps(
            {"nested": nested, "first": repeated, "second": repeated},
            sort_keys=True,
        ).encode("utf-8")
        with tempfile.TemporaryDirectory(prefix="phase2-json-") as temporary:
            root = Path(temporary)
            run = _create_run(root, [{"data": body, "content_type": "application/json"}])
            derived = root / "derived"
            result = extract_run(run, derived)
            outputs = _artifact_payloads(derived, result)
            self.assertIn(marker, outputs)
            duplicates = [
                item for item in result["operations"] if item.get("duplicate_content")
            ]
            self.assertTrue(duplicates)
            repeated_artifacts = [
                item
                for item in result["artifacts"]
                if (derived / item["output_file"]).read_bytes()
                == b"duplicate-derived-content"
            ]
            self.assertEqual(1, len(repeated_artifacts))
            self.assertEqual(2, len(repeated_artifacts[0]["relationships"]))

    def test_multipart_urlencoded_zip_tar_and_application_gzip(self) -> None:
        multipart_payload = b"multipart-" + CANARIES["ignored_untracked_canary"]
        boundary = "phase2-boundary"
        multipart = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x.bin\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("ascii") + multipart_payload + f"\r\n--{boundary}--\r\n".encode("ascii")
        url_value = b"url-" + CANARIES["non_ignored_untracked_canary"]
        urlencoded = urllib.parse.urlencode({"payload": url_value.decode("ascii")}).encode("ascii")

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("inside.txt", CANARIES["historical_deleted_canary"])
        tar_buffer = io.BytesIO()
        tar_content = CANARIES["second_branch_canary"]
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            info = tarfile.TarInfo("inside.txt")
            info.size = len(tar_content)
            archive.addfile(info, io.BytesIO(tar_content))

        payloads = [
            {
                "data": multipart,
                "content_type": f"multipart/form-data; boundary={boundary}",
            },
            {"data": urlencoded, "content_type": "application/x-www-form-urlencoded"},
            {"data": zip_buffer.getvalue(), "content_type": "application/zip"},
            {"data": tar_buffer.getvalue(), "content_type": "application/x-tar"},
            {"data": gzip.compress(b"application-gzip-value", mtime=0)},
        ]
        with tempfile.TemporaryDirectory(prefix="phase2-wrappers-") as temporary:
            root = Path(temporary)
            run = _create_run(root, payloads)
            derived = root / "derived"
            result = extract_run(run, derived)
            outputs = _artifact_payloads(derived, result)
            for expected in (
                multipart_payload,
                url_value,
                CANARIES["historical_deleted_canary"],
                tar_content,
                b"application-gzip-value",
            ):
                self.assertIn(expected, outputs)
            operations = [item["extraction_operation"] for item in result["operations"]]
            self.assertIn("multipart_part", operations)
            self.assertIn("urlencoded_field", operations)
            self.assertIn("zip_member", operations)
            self.assertIn("tar_member", operations)
            self.assertIn("application_gzip", operations)
            self.assertNotIn("http_content_encoding:gzip", operations)

    def test_malformed_base64_and_recursion_limit(self) -> None:
        nested = b"nested-base64-content"
        for _ in range(3):
            nested = base64.b64encode(nested)
        payloads = [
            {"data": b"this===is-not-base64"},
            {"data": nested},
        ]
        limits = ExtractionLimits(maximum_extraction_depth=1)
        with tempfile.TemporaryDirectory(prefix="phase2-recursion-") as temporary:
            root = Path(temporary)
            run = _create_run(root, payloads)
            result = extract_run(run, root / "derived", limits)
            self.assertTrue(result["processing_limits_reached"])
            self.assertFalse(
                any(
                    item.get("source_raw_file", "").startswith("raw/http/00000001")
                    and item.get("success")
                    for item in result["operations"]
                )
            )


class ClassificationTests(unittest.TestCase):
    def test_all_canaries_and_nonzero_git_signatures(self) -> None:
        payload = b"prefix-" + b"|".join(CANARIES.values())
        payload += (
            b"\nnoise# v2 git bundle\nmore-PACK-data-DIRC-index\n"
            b"diff --git a/a b/a\n--- a/a\n+++ b/a\nSubject: [PATCH test]\n"
        )
        with tempfile.TemporaryDirectory(prefix="phase2-classify-") as temporary:
            root = Path(temporary)
            run = _create_run(root, [{"data": payload}])
            derived = root / "derived"
            derived.mkdir()
            result = classify_evidence(run, derived)
            self.assertEqual(set(CANARIES), {item["canary_name"] for item in result["canary_findings"]})
            self.assertTrue(result["git_bundle_header_found"])
            self.assertTrue(result["git_pack_signature_found"])
            self.assertTrue(result["git_index_signature_found"])
            self.assertTrue(result["git_diff_marker_found"])
            self.assertTrue(result["git_patch_marker_found"])
            self.assertTrue(
                all(item.get("byte_offset", 1) > 0 for item in result["git_candidates"] if "byte_offset" in item)
            )
            self.assertTrue(
                all(not item["structurally_validated"] for item in result["git_candidates"])
            )


class GitValidationTests(unittest.TestCase):
    def test_valid_bundle_complete_reconstruction_and_valid_full_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase2-git-valid-") as temporary:
            root = Path(temporary)
            repository = _create_git_repository(root)
            bundle_path = root / "source.bundle"
            _run_git(["-C", str(repository), "bundle", "create", str(bundle_path), "--all"])
            run = _create_run(root / "bundle-case", [{"data": bundle_path.read_bytes()}])
            derived = root / "bundle-derived"
            derived.mkdir()
            classify_evidence(run, derived)
            bundle_result = git_validation.validate_candidates(run, derived, repository)
            self.assertTrue(bundle_result["git_bundle_validated"])
            self.assertTrue(bundle_result["full_repository_reconstructed"])

            pack = _run_git(["-C", str(repository), "pack-objects", "--all", "--stdout"])
            pack_run = _create_run(root / "pack-case", [{"data": pack}])
            pack_derived = root / "pack-derived"
            pack_derived.mkdir()
            classify_evidence(pack_run, pack_derived)
            pack_result = git_validation.validate_candidates(
                pack_run, pack_derived, repository
            )
            self.assertTrue(pack_result["git_pack_validated"])
            self.assertTrue(pack_result["complete_expected_object_set_recovered"])
            self.assertFalse(pack_result["expected_refs_recovered"])
            self.assertFalse(pack_result["full_repository_reconstructed"])

    def test_invalid_bundle_invalid_pack_and_false_positive_pack(self) -> None:
        payloads = [
            {"data": b"# v2 git bundle\ninvalid\n"},
            {"data": b"prefix-PACK-not-a-real-pack"},
        ]
        with tempfile.TemporaryDirectory(prefix="phase2-git-invalid-") as temporary:
            root = Path(temporary)
            repository = _create_git_repository(root)
            run = _create_run(root / "case", payloads)
            derived = root / "derived"
            derived.mkdir()
            classification = classify_evidence(run, derived)
            self.assertTrue(classification["git_pack_signature_found"])
            result = git_validation.validate_candidates(run, derived, repository)
            self.assertFalse(result["git_bundle_validated"])
            self.assertFalse(result["git_pack_validated"])
            self.assertFalse(result["full_repository_reconstructed"])

    def test_partial_pack_inventory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase2-git-partial-") as temporary:
            root = Path(temporary)
            repository = _create_git_repository(root)
            blob_id = _run_git(
                ["-C", str(repository), "rev-parse", "HEAD:canary.txt"]
            ).strip()
            pack = _run_git(
                ["-C", str(repository), "pack-objects", "--stdout"],
                input_data=blob_id + b"\n",
            )
            run = _create_run(root / "case", [{"data": pack}])
            derived = root / "derived"
            derived.mkdir()
            classify_evidence(run, derived)
            result = git_validation.validate_candidates(run, derived, repository)
            self.assertTrue(result["git_pack_validated"])
            self.assertTrue(result["partial_git_object_set_recovered"])
            self.assertFalse(result["complete_expected_object_set_recovered"])

    def test_repository_integrity_failure_blocks_full_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase2-git-fsck-") as temporary:
            root = Path(temporary)
            repository = _create_git_repository(root)
            run = _create_run(root / "case", [{"data": b"# v2 git bundle\nplaceholder"}])
            derived = root / "derived"
            derived.mkdir()
            classify_evidence(run, derived)
            recovered = git_validation.build_git_inventory(repository)
            fake_commands = [
                {"command": ["git", "fsck"], "exit_code": 1, "stdout": "", "stderr": "failure"}
            ]
            with mock.patch.object(
                git_validation,
                "_validate_bundle",
                return_value=(fake_commands, recovered, True, False),
            ):
                result = git_validation.validate_candidates(run, derived, repository)
            self.assertTrue(result["git_bundle_validated"])
            self.assertFalse(result["full_repository_reconstructed"])


class ReportingTests(unittest.TestCase):
    def test_json_schema_markdown_source_and_required_caveat(self) -> None:
        with tempfile.TemporaryDirectory(prefix="phase2-report-") as temporary:
            root = Path(temporary)
            run = _create_run(root, [{"data": b"ordinary test payload"}])
            derived = root / "derived"
            result = extract_run(run, derived)
            classify_evidence(run, derived)
            write_json_atomic(
                derived / "git-validation.json",
                {
                    "schema_version": GIT_VALIDATION_SCHEMA,
                    "validated_candidates": [],
                    "git_bundle_validated": False,
                    "git_pack_validated": False,
                    "partial_git_object_set_recovered": False,
                    "complete_expected_object_set_recovered": False,
                    "expected_refs_recovered": False,
                    "full_repository_reconstructed": False,
                },
            )
            json_path, markdown_path = generate_reports(run, derived)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            schema = json.loads(
                (WINDOWS_ROOT / "analysis" / "schema" / "report.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.validate(report, schema)
            self.assertEqual("NOT_EVALUATED", report["capture_status"])
            self.assertTrue(report["evidence_integrity"]["valid"])
            self.assertEqual(MISSING_CANARY_LANGUAGE, report["canary_summary"])
            self.assertEqual(render_markdown(report), markdown_path.read_text(encoding="utf-8"))
            combined = json_path.read_text(encoding="utf-8") + markdown_path.read_text(
                encoding="utf-8"
            )
            for phrase in PROHIBITED_CONCLUSIONS:
                self.assertNotIn(phrase, combined.lower())
            self.assertEqual(EXTRACTION_SCHEMA, result["schema_version"])


if __name__ == "__main__":
    unittest.main()
