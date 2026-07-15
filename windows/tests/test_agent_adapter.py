from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

WINDOWS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WINDOWS_ROOT))

from analysis.agent_runtime import (
    build_child_environment,
    gate_identity_changes,
    load_adapter,
    prepare_invocation,
    redact_text,
    reserve_run_directories,
    run_client,
    substitute,
    verify_client_version,
)
from analysis.generate_report import generate_reports
from analysis.models import (
    EVIDENCE_MANIFEST_SCHEMA,
    evidence_file_record,
    write_json_atomic,
)
from analysis.output_layout import prepare_output_layout
from analysis.validate_capture_coverage import calculate_capture_status
from analysis.reconcile_capture_outcome import calculate_final_outcome


ADAPTER_PATH = WINDOWS_ROOT / "adapters" / "codex.json"
SCHEMA_PATH = WINDOWS_ROOT / "adapters" / "schema" / "adapter.schema.json"


def _prepared(
    working_directory: Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 10,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "product": "Synthetic Client",
        "vendor": "Test",
        "client_surface": "CLI",
        "executable": sys.executable,
        "arguments": arguments,
        "redacted_command": "synthetic command",
        "environment_variables": environment or {},
        "prompt": "synthetic prompt",
        "working_directory": str(working_directory),
        "timeout_seconds": timeout_seconds,
        "model_identifier": None,
        "version_command": ["--version"],
    }


def _snapshot(root_pid: int) -> dict[str, object]:
    return {
        "processes": [
            {
                "ProcessId": root_pid,
                "ParentProcessId": os.getpid(),
                "ExecutablePath": sys.executable,
                "CreationDate": "2024-01-01T00:00:00Z",
            }
        ],
        "connections": [],
    }


def _create_empty_run(root: Path) -> Path:
    run = root / "run"
    (run / "raw" / "http").mkdir(parents=True)
    (run / "raw" / "websocket").mkdir(parents=True)
    (run / "provenance").mkdir()
    write_json_atomic(
        run / "run.json",
        {
            "run_id": "synthetic-codex-run",
            "started_at_utc": "2024-01-01T00:00:00.000Z",
            "operating_system": "Windows test",
            "python_version": sys.version.split()[0],
            "mitmproxy_version": "test",
            "repository_commit_sha": "0" * 40,
        },
    )
    (run / "requests.jsonl").write_bytes(b"")
    (run / "websockets.jsonl").write_bytes(b"")
    addon = run / "provenance" / "capture_requests.py"
    addon.write_bytes(b"# synthetic addon\n")
    metadata = [
        evidence_file_record(run, run / "run.json"),
        evidence_file_record(run, run / "requests.jsonl"),
        evidence_file_record(run, run / "websockets.jsonl"),
    ]
    write_json_atomic(
        run / "evidence-manifest.json",
        {
            "schema_version": EVIDENCE_MANIFEST_SCHEMA,
            "run_id": "synthetic-codex-run",
            "capture_start_timestamp": "2024-01-01T00:00:00.000Z",
            "capture_stop_timestamp": "2024-01-01T00:01:00.000Z",
            "operating_system": "Windows test",
            "python_version": sys.version.split()[0],
            "mitmproxy_version": "test",
            "repository_commit_sha": "0" * 40,
            "addon_file": evidence_file_record(run, addon),
            "metadata_file_sha256": {
                item["path"]: item["sha256"] for item in metadata
            },
            "metadata_files": metadata,
            "raw_evidence_files": [],
            "capture_ended_cleanly": True,
            "capture_error_count": 0,
            "integrity_scope": "local_integrity_only_not_cryptographic_nonrepudiation",
        },
    )
    return run


class AdapterValidationTests(unittest.TestCase):
    def test_codex_adapter_validates_against_schema(self) -> None:
        adapter = load_adapter(ADAPTER_PATH, SCHEMA_PATH)
        self.assertEqual("egress-adapter/v1", adapter["schema_version"])
        self.assertEqual("OpenAI Codex CLI", adapter["product_name"])
        self.assertNotIn("CODEX_ACCESS_TOKEN", adapter["environment_variables"])
        prepared = prepare_invocation(
            adapter,
            working_directory=WINDOWS_ROOT,
            prompt="test prompt",
            proxy_port=8080,
            ca_certificate=WINDOWS_ROOT / "test-ca.pem",
        )
        self.assertEqual(
            str(Path(adapter["executable"]).absolute()), prepared["executable"]
        )
        self.assertNotIn("WindowsApps", str(prepared["executable"]))

    def test_placeholder_substitution_and_preparation(self) -> None:
        self.assertEqual("port=8080", substitute("port={proxy_port}", {"proxy_port": 8080}))
        with tempfile.TemporaryDirectory(prefix="adapter-prepare-") as temporary:
            root = Path(temporary)
            ca = root / "ca.pem"
            ca.write_text("test", encoding="utf-8")
            adapter = load_adapter(ADAPTER_PATH, SCHEMA_PATH)
            prepared = prepare_invocation(
                adapter,
                working_directory=root,
                prompt="Reply only with OK.",
                proxy_port=8080,
                ca_certificate=ca,
            )
            self.assertNotIn("{prompt}", prepared["redacted_command"])
            self.assertIn("Reply only with OK.", prepared["arguments"])
            self.assertEqual(
                "http://127.0.0.1:8080",
                prepared["environment_variables"]["HTTPS_PROXY"],
            )

    def test_unknown_or_missing_placeholder_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            substitute("{prompt}-{missing}", {"prompt": "x"})


class ClientRuntimeTests(unittest.TestCase):
    def test_version_command_success_and_client_execution_receives_version(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-version-") as temporary:
            root = Path(temporary)
            prepared = _prepared(root, ["-c", "print('ok')"])
            completed = subprocess.CompletedProcess(
                [sys.executable, "--version"], 0, "codex-cli 0.144.4\n", ""
            )
            with mock.patch("analysis.agent_runtime.subprocess.run", return_value=completed):
                verification = verify_client_version(prepared)
            self.assertTrue(verification["verified"])
            self.assertEqual("codex-cli 0.144.4", verification["normalized_client_version"])
            result = run_client(
                prepared,
                root / "output",
                snapshot_provider=_snapshot,
                version_verification=verification,
            )
            saved = json.loads((root / "output" / "client-execution.json").read_text(encoding="utf-8"))
            self.assertEqual("codex-cli 0.144.4", result["client_version"])
            self.assertEqual(0, saved["version_exit_code"])
            self.assertEqual("codex-cli 0.144.4", saved["normalized_client_version"])

    def test_version_command_failure(self) -> None:
        prepared = {"executable": sys.executable, "version_command": ["--version"]}
        completed = subprocess.CompletedProcess([sys.executable], 7, "", "failed")
        with mock.patch("analysis.agent_runtime.subprocess.run", return_value=completed):
            result = verify_client_version(prepared)
        self.assertFalse(result["verified"])
        self.assertEqual(7, result["version_exit_code"])

    def test_gate_rejects_executable_or_version_change(self) -> None:
        saved = {"executable_path": "codex-a.exe", "normalized_client_version": "codex-cli 1"}
        self.assertEqual(
            ["executable_path"],
            gate_identity_changes(saved, {**saved, "executable_path": "codex-b.exe"}),
        )
        self.assertEqual(
            ["normalized_client_version"],
            gate_identity_changes(saved, {**saved, "normalized_client_version": "codex-cli 2"}),
        )

    def test_missing_executable_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-missing-") as temporary:
            root = Path(temporary)
            prepared = _prepared(root, [])
            prepared["executable"] = str(root / "does-not-exist.exe")
            result = run_client(prepared, root / "output", snapshot_provider=_snapshot)
            self.assertFalse(result["started"])
            self.assertIn("Executable not found", result["error"])

    def test_timeout_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-timeout-") as temporary:
            root = Path(temporary)
            result = run_client(
                _prepared(
                    root,
                    ["-c", "import time; time.sleep(5)"],
                    timeout_seconds=1,
                ),
                root / "output",
                snapshot_provider=_snapshot,
                monitor_interval_seconds=0.05,
            )
            self.assertTrue(result["started"])
            self.assertTrue(result["timed_out"])

    def test_subprocess_exit_code_is_captured(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-exit-") as temporary:
            root = Path(temporary)
            result = run_client(
                _prepared(root, ["-c", "raise SystemExit(7)"]),
                root / "output",
                snapshot_provider=_snapshot,
            )
            self.assertEqual(7, result["exit_code"])

    def test_environment_isolation_removes_credentials_and_proxy_poisoning(self) -> None:
        base = dict(os.environ)
        base.update(
            {
                "CODEX_API_KEY": "must-not-propagate",
                "HTTPS_PROXY": "http://poison.invalid:1",
                "PARENT_ONLY": "retained",
            }
        )
        child = build_child_environment(
            base,
            {
                "HTTPS_PROXY": "http://127.0.0.1:8080",
                "HARNESS_ONLY": "defined-by-adapter",
            },
        )
        self.assertNotIn("CODEX_API_KEY", child)
        self.assertEqual("http://127.0.0.1:8080", child["HTTPS_PROXY"])
        self.assertEqual("defined-by-adapter", child["HARNESS_ONLY"])
        self.assertNotIn("PARENT_ONLY", child)
        self.assertEqual("must-not-propagate", base["CODEX_API_KEY"])

    def test_sensitive_values_are_redacted(self) -> None:
        original = (
            "Authorization: Bearer secret-token\n"
            "email=user@example.com sk-abcdefghijklmnopqrstuvwxyz "
            '"session_id":"session-secret" org_abcdefghijk'
        )
        redacted = redact_text(original)
        for forbidden in (
            "secret-token",
            "user@example.com",
            "sk-abcdefghijklmnopqrstuvwxyz",
            "session-secret",
            "org_abcdefghijk",
        ):
            self.assertNotIn(forbidden, redacted)

    def test_unique_run_directories_are_reserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-runs-") as temporary:
            root = Path(temporary)
            first = reserve_run_directories(
                canary_root=root / "canary",
                capture_root=root / "capture",
                derived_root=root / "derived",
                test_id="A",
            )
            second = reserve_run_directories(
                canary_root=root / "canary",
                capture_root=root / "capture",
                derived_root=root / "derived",
                test_id="A",
            )
            self.assertNotEqual(first["run_id"], second["run_id"])
            self.assertFalse(Path(first["capture_directory"]).exists())
            self.assertTrue(Path(first["output_root"]).is_dir())
            self.assertEqual(
                {"control", "analysis", "report"},
                {
                    Path(first[key]).name
                    for key in (
                        "control_directory",
                        "analysis_directory",
                        "report_directory",
                    )
                },
            )
            Path(first["canary_repository"]).mkdir()
            resumed = reserve_run_directories(
                canary_root=root / "canary",
                capture_root=root / "capture",
                derived_root=root / "derived",
                test_id="A",
                run_id=first["run_id"],
                reuse=True,
            )
            self.assertEqual(first, resumed)

    def test_process_tree_and_pid_scoped_connections_are_recorded(self) -> None:
        def snapshot(root_pid: int) -> dict[str, object]:
            value = _snapshot(root_pid)
            value["connections"] = [
                {
                    "ProcessId": root_pid,
                    "LocalAddress": "127.0.0.1",
                    "LocalPort": 50000,
                    "RemoteAddress": "127.0.0.1",
                    "RemotePort": 8080,
                    "State": "Established",
                }
            ]
            return value

        with tempfile.TemporaryDirectory(prefix="adapter-process-") as temporary:
            root = Path(temporary)
            output = root / "output"
            result = run_client(
                _prepared(root, ["-c", "print('ok')"]),
                output,
                snapshot_provider=snapshot,
                monitor_interval_seconds=0.01,
            )
            tree = json.loads((output / "process-tree.json").read_text(encoding="utf-8"))
            connections = json.loads((output / "connections.json").read_text(encoding="utf-8"))
            self.assertEqual(result["parent_process_id"], tree["root_process_id"])
            self.assertTrue(tree["processes"])
            self.assertEqual(8080, connections["connections"][0]["remote_port"])

    def test_failed_authentication_is_detected_without_preserving_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-auth-") as temporary:
            root = Path(temporary)
            output = root / "output"
            result = run_client(
                _prepared(
                    root,
                    ["-c", "import sys; print('Authentication failed'); sys.exit(1)"],
                ),
                output,
                snapshot_provider=_snapshot,
            )
            self.assertTrue(result["authentication_failed"])
            self.assertEqual(1, result["exit_code"])


class CoverageAndReportTests(unittest.TestCase):
    def _status(self, **overrides: object) -> str:
        values: dict[str, object] = {
            "mitmproxy_started": True,
            "client_started": True,
            "client_exit_code": 0,
            "timed_out": False,
            "authentication_failed": False,
            "tls_error_observed": False,
            "direct_bypass_detected": False,
            "request_count": 1,
            "attributable_request": True,
            "decrypted_readable_request_body": True,
            "manifest_valid": True,
            "process_monitoring_complete": True,
        }
        values.update(overrides)
        return calculate_capture_status(**values)  # type: ignore[arg-type]

    def test_capture_status_calculation(self) -> None:
        self.assertEqual("CAPTURE_VALIDATED", self._status())
        self.assertEqual(
            "PARTIAL_CAPTURE", self._status(process_monitoring_complete=False)
        )

    def _final_outcome(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "proxy_started": True,
            "client_launched": True,
            "client_exit_code": 0,
            "timed_out": False,
            "authentication_failed": False,
            "tls_error_observed": False,
            "direct_bypass_status": "NOT_DETECTED",
            "http_request_count": 1,
            "websocket_message_count": 0,
            "attributable_decrypted_traffic": True,
            "manifest_valid": True,
            "launcher_exit_code": 0,
            "mitmdump_exit_code": 0,
            "launcher_final_status": "CAPTURE_COMPLETE",
            "capture_runtime_failure": False,
            "capture_completed_before_shutdown": True,
            "metadata_and_raw_files_flushed": True,
            "no_request_truncation": True,
            "shutdown_initiated_by_harness": True,
            "listener_released": True,
            "process_terminated_within_cleanup_bound": True,
            "lifecycle_history": [{"stage": "startup", "event": "completed"}],
        }
        values.update(overrides)
        return calculate_final_outcome(values)

    def test_authoritative_launcher_and_shutdown_outcomes(self) -> None:
        self.assertEqual("CAPTURE_VALIDATED", self._final_outcome()["final_status"])
        failed_launcher = self._final_outcome(
            launcher_exit_code=1,
            launcher_final_status="CAPTURE_FAILED",
            metadata_and_raw_files_flushed=False,
        )
        self.assertEqual("CAPTURE_FAILED", failed_launcher["final_status"])
        self.assertEqual("CAPTURE_FAILED", failed_launcher["launcher_final_status"])
        benign = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            launcher_final_status="CAPTURE_FAILED",
            capture_runtime_failure=True,
        )
        self.assertEqual("CAPTURE_VALIDATED", benign["final_status"])
        self.assertEqual("BENIGN_CONTROLLED_SHUTDOWN", benign["shutdown_error_classification"])
        partial = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            no_request_truncation=None,
        )
        self.assertEqual("PARTIAL_CAPTURE", partial["final_status"])
        self.assertEqual("BENIGN_NOT_ESTABLISHED", partial["shutdown_error_classification"])
        self.assertEqual([{"stage": "startup", "event": "completed"}], partial["lifecycle_history"])
        self.assertEqual(
            "TLS_INTERCEPTION_FAILED", self._status(tls_error_observed=True)
        )
        self.assertEqual(
            "NO_AGENT_TRAFFIC_OBSERVED", self._status(request_count=0)
        )
        self.assertEqual(
            "PARTIAL_CAPTURE",
            self._status(request_count=0, process_monitoring_complete=False),
        )

    def test_direct_bypass_takes_capture_specific_status(self) -> None:
        self.assertEqual(
            "DIRECT_BYPASS_DETECTED", self._status(direct_bypass_detected=True)
        )

    def test_capture_start_failure_and_client_execution_failure_are_distinct(self) -> None:
        self.assertEqual(
            "CLIENT_EXECUTION_FAILED", self._status(authentication_failed=True)
        )
        self.assertEqual(
            "CAPTURE_START_FAILED",
            self._status(mitmproxy_started=False, client_started=False),
        )
        self.assertEqual(
            "CAPTURE_FAILED",
            self._status(mitmproxy_started=False, client_started=True),
        )
        self.assertEqual(
            "CLIENT_EXECUTION_FAILED",
            self._status(client_started=True, client_exit_code=7),
        )

    def test_synthetic_codex_report_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-report-") as temporary:
            root = Path(temporary)
            run = _create_empty_run(root)
            layout = prepare_output_layout(root / "output-v1")
            analysis = layout.analysis
            control = layout.control
            write_json_atomic(
                analysis / "extraction-result.json",
                {
                    "raw_files_processed": [],
                    "artifacts": [],
                    "operations": [],
                    "extraction_failures": [],
                    "unsupported_encodings": [],
                    "processing_limits_reached": [],
                },
            )
            write_json_atomic(
                analysis / "classification.json",
                {"canary_findings": [], "git_candidates": []},
            )
            write_json_atomic(analysis / "git-validation.json", {})
            write_json_atomic(
                control / "client-execution.json",
                {
                    "product": "OpenAI Codex CLI",
                    "client_version": "test-version",
                    "normalized_client_version": "test-version",
                    "version_command": ["codex.exe", "--version"],
                    "version_stdout": "test-version\n",
                    "version_stderr": "",
                    "version_exit_code": 0,
                    "model_identifier": None,
                    "exit_code": 0,
                    "timed_out": False,
                    "authentication_failed": False,
                },
            )
            write_json_atomic(
                control / "coverage.json",
                {
                    "capture_status": "CAPTURE_VALIDATED",
                    "proxy_started": True,
                    "client_launched": True,
                    "monitoring_started": True,
                    "http_request_count": 1,
                    "websocket_message_count": 0,
                    "http_request_bytes": 42,
                    "websocket_message_bytes": 0,
                    "total_request_count": 1,
                    "total_websocket_message_count": 0,
                    "total_raw_request_bytes": 42,
                    "total_raw_websocket_bytes": 0,
                    "decrypted_readable_request_body": True,
                    "direct_bypass_status": "NOT_DETECTED",
                    "process_monitoring_complete": True,
                },
            )
            outcome = self._final_outcome()
            write_json_atomic(control / "capture-outcome.json", outcome)
            write_json_atomic(
                control / "reconciled-run.json",
                {"reconciled_final_state": outcome, "lifecycle_history": outcome["lifecycle_history"]},
            )
            json_path, markdown_path = generate_reports(
                run,
                analysis,
                "PARTIAL_CAPTURE",
                control_directory=control,
                report_directory=layout.report,
            )
            report = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertEqual("CAPTURE_VALIDATED", report["capture_status"])
            reconciled = json.loads((control / "reconciled-run.json").read_text(encoding="utf-8"))
            self.assertEqual(
                reconciled["reconciled_final_state"]["final_status"],
                report["capture_status"],
            )
            self.assertEqual("test-version", report["client_version"])
            self.assertEqual("OpenAI Codex CLI", report["client_execution"]["product"])
            self.assertEqual(1, report["http_request_count"])
            self.assertEqual(0, report["websocket_message_count"])
            self.assertEqual(42, report["http_request_bytes"])
            self.assertEqual(0, report["websocket_message_bytes"])
            self.assertTrue(report["client_launched"])
            self.assertTrue(report["proxy_started"])
            self.assertTrue(report["monitoring_started"])
            self.assertEqual(str(layout.output_root), report["output_layout"]["output_root"])
            self.assertEqual(layout.report, json_path.parent)
            self.assertIn("Client execution and capture coverage", markdown)

    def test_failed_start_report_has_zero_counts_and_no_client_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="failed-start-report-") as temporary:
            root = Path(temporary)
            run = _create_empty_run(root)
            derived = root / "derived"
            derived.mkdir()
            write_json_atomic(
                derived / "client-execution.json",
                {
                    "product": "Synthetic Client",
                    "started": False,
                    "exit_code": None,
                    "timed_out": False,
                    "authentication_failed": False,
                    "error": "Capture startup failed before client launch.",
                },
            )
            write_json_atomic(
                derived / "coverage.json",
                {
                    "capture_status": "CAPTURE_START_FAILED",
                    "proxy_started": False,
                    "client_launched": False,
                    "monitoring_started": False,
                    "http_request_count": 0,
                    "websocket_message_count": 0,
                    "http_request_bytes": 0,
                    "websocket_message_bytes": 0,
                    "total_request_count": 0,
                    "total_websocket_message_count": 0,
                    "total_raw_request_bytes": 0,
                    "total_raw_websocket_bytes": 0,
                    "decrypted_readable_request_body": False,
                    "direct_bypass_status": "MONITORING_NOT_STARTED",
                    "process_monitoring_complete": False,
                    "manifest_valid": True,
                    "limitations": ["The client was not launched."],
                },
            )
            json_path, markdown_path = generate_reports(
                run, derived, "CAPTURE_START_FAILED"
            )
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual("CAPTURE_START_FAILED", report["capture_status"])
            self.assertEqual(0, report["http_request_count"])
            self.assertEqual(0, report["websocket_message_count"])
            self.assertEqual(0, report["http_request_bytes"])
            self.assertEqual(0, report["websocket_message_bytes"])
            self.assertFalse(report["client_launched"])
            self.assertFalse(report["proxy_started"])
            self.assertFalse(report["monitoring_started"])
            self.assertTrue(report["evidence_integrity"]["valid"])
            self.assertTrue(markdown_path.is_file())


if __name__ == "__main__":
    unittest.main()
