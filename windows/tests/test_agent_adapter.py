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
    detect_authentication_failure,
    gate_identity_changes,
    load_adapter,
    prepare_invocation,
    reclassify_client_execution,
    redact_text,
    reserve_run_directories,
    run_client,
    substitute,
    verify_client_version,
    verify_authentication_selection,
    verify_inherited_secret_availability,
)
from analysis.generate_report import generate_reports
from analysis.models import (
    EVIDENCE_MANIFEST_SCHEMA,
    evidence_file_record,
    write_json_atomic,
)
from analysis.output_layout import prepare_output_layout
from analysis.validate_capture_coverage import calculate_capture_status
from analysis.reconcile_capture_outcome import (
    calculate_final_outcome,
    process_exit_code_for_final_status,
)


ADAPTER_PATH = WINDOWS_ROOT / "adapters" / "codex.json"
GEMINI_ADAPTER_PATH = WINDOWS_ROOT / "adapters" / "gemini.json"
CLAUDE_ADAPTER_PATH = WINDOWS_ROOT / "adapters" / "claude.json"
GROK_ADAPTER_PATH = WINDOWS_ROOT / "adapters" / "grok.json"
SCHEMA_PATH = WINDOWS_ROOT / "adapters" / "schema" / "adapter.schema.json"


def _prepared(
    working_directory: Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 10,
    environment: dict[str, str] | None = None,
    authentication_failure_patterns: list[str] | None = None,
    authentication_failure_classifications: list[dict[str, str]] | None = None,
    inherited_secret_environment_variables: list[str] | None = None,
) -> dict[str, object]:
    return {
        "product": "Synthetic Client",
        "vendor": "Test",
        "client_surface": "CLI",
        "authentication_mode": "synthetic authentication",
        "executable": sys.executable,
        "arguments": arguments,
        "redacted_command": "synthetic command",
        "environment_variables": environment or {},
        "inherited_secret_environment_variables": (
            inherited_secret_environment_variables or []
        ),
        "prompt": "synthetic prompt",
        "working_directory": str(working_directory),
        "timeout_seconds": timeout_seconds,
        "authentication_failure_patterns": authentication_failure_patterns or [],
        "authentication_failure_classifications": (
            authentication_failure_classifications or []
        ),
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
        self.assertEqual("never", adapter["approval_mode"])
        self.assertEqual("read-only", adapter["sandbox_mode"])
        self.assertIn('windows.sandbox="unelevated"', prepared["arguments"])

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

    def test_installed_gemini_adapter_uses_read_only_headless_template(self) -> None:
        adapter = load_adapter(GEMINI_ADAPTER_PATH, SCHEMA_PATH)
        self.assertEqual("Gemini CLI", adapter["product_name"])
        self.assertEqual("Google", adapter["vendor"])
        self.assertEqual("gemini.cmd", Path(adapter["executable"]).name)
        self.assertIn("plan", adapter["noninteractive_command_template"])
        self.assertIn("--skip-trust", adapter["noninteractive_command_template"])
        self.assertNotIn("--sandbox", adapter["noninteractive_command_template"])
        self.assertNotIn("--yolo", adapter["noninteractive_command_template"])
        self.assertTrue(adapter["authentication_failure_patterns"])
        self.assertEqual(
            "Gemini CLI 0.50.0, API-key mode", adapter["authentication_mode"]
        )
        self.assertEqual(
            ["GEMINI_API_KEY"],
            adapter["inherited_secret_environment_variables"],
        )
        self.assertEqual(
            "gemini-api-key",
            adapter["authentication_selection"]["expected_value"],
        )

    def test_authentication_selection_reads_only_declared_json_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-auth-selection-") as temporary:
            settings = Path(temporary) / "settings.json"
            settings.write_text(
                json.dumps(
                    {
                        "security": {"auth": {"selectedType": "gemini-api-key"}},
                        "account": {"email": "must-not-be-returned@example.invalid"},
                    }
                ),
                encoding="utf-8",
            )
            result = verify_authentication_selection(
                {
                    "authentication_selection": {
                        "settings_file": str(settings),
                        "json_path": ["security", "auth", "selectedType"],
                        "expected_value": "gemini-api-key",
                    }
                }
            )
            self.assertTrue(result["matches"])
            self.assertEqual("gemini-api-key", result["selected_value"])
            self.assertNotIn("must-not-be-returned", json.dumps(result))

    def test_authentication_selection_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-auth-selection-") as temporary:
            settings = Path(temporary) / "settings.json"
            settings.write_text(
                '{"security":{"auth":{"selectedType":"oauth-personal"}}}',
                encoding="utf-8",
            )
            result = verify_authentication_selection(
                {
                    "authentication_selection": {
                        "settings_file": str(settings),
                        "json_path": ["security", "auth", "selectedType"],
                        "expected_value": "gemini-api-key",
                    }
                }
            )
            self.assertFalse(result["matches"])

    def test_adapter_cannot_store_or_request_unsupported_secrets(self) -> None:
        adapter = load_adapter(GEMINI_ADAPTER_PATH, SCHEMA_PATH)
        stored = dict(adapter)
        stored["environment_variables"] = {
            **adapter["environment_variables"],
            "GEMINI_API_KEY": "not-allowed",
        }
        with self.assertRaises(ValueError):
            from analysis.agent_runtime import validate_adapter_semantics

            validate_adapter_semantics(stored)
        unsupported = dict(adapter)
        unsupported["inherited_secret_environment_variables"] = ["UNKNOWN_SECRET"]
        with self.assertRaises(ValueError):
            validate_adapter_semantics(unsupported)

    def test_installed_claude_adapter_limits_test_b_to_read_tool(self) -> None:
        adapter = load_adapter(CLAUDE_ADAPTER_PATH, SCHEMA_PATH)
        template = adapter["noninteractive_command_template"]
        self.assertEqual("Claude Code", adapter["product_name"])
        self.assertEqual("Anthropic", adapter["vendor"])
        self.assertEqual("claude.exe", Path(adapter["executable"]).name)
        self.assertIn("--safe-mode", template)
        self.assertIn("--strict-mcp-config", template)
        self.assertIn("--tools=Read", template)
        self.assertIn("--no-session-persistence", template)
        self.assertIn("plan", template)
        self.assertNotIn("--dangerously-skip-permissions", template)
        self.assertNotIn("--max-turns", template)
        self.assertNotIn("Bash", " ".join(template))
        self.assertNotIn("Edit", " ".join(template))
        self.assertNotIn("Glob", " ".join(template))
        self.assertNotIn("Grep", " ".join(template))
        self.assertTrue(adapter["authentication_failure_patterns"])
        self.assertNotIn("ANTHROPIC_API_KEY", adapter["environment_variables"])

    def test_installed_grok_adapter_limits_test_c_to_read_only_tools(self) -> None:
        adapter = load_adapter(GROK_ADAPTER_PATH, SCHEMA_PATH)
        template = adapter["noninteractive_command_template"]
        environment = adapter["environment_variables"]
        self.assertEqual("Grok Build", adapter["product_name"])
        self.assertEqual("xAI", adapter["vendor"])
        self.assertEqual("grok.exe", Path(adapter["executable"]).name)
        self.assertIn("--single", template)
        self.assertIn("--cwd", template)
        self.assertIn("--tools=read_file,list_dir", template)
        self.assertIn("--disable-web-search", template)
        self.assertIn("--no-memory", template)
        self.assertIn("--no-subagents", template)
        self.assertIn("--no-auto-update", template)
        self.assertIn("--verbatim", template)
        self.assertEqual("Agent", template[template.index("--disallowed-tools") + 1])
        denied = {
            template[index + 1]
            for index, value in enumerate(template)
            if value == "--deny"
        }
        self.assertEqual(
            {"Bash", "Edit", "Write", "Grep", "WebFetch", "WebSearch", "MCPTool"},
            denied,
        )
        self.assertEqual("default", template[template.index("--permission-mode") + 1])
        self.assertEqual("3", template[template.index("--max-turns") + 1])
        self.assertEqual("json", template[template.index("--output-format") + 1])
        self.assertNotIn("--always-approve", template)
        self.assertNotIn("--continue", template)
        self.assertNotIn("--resume", template)
        self.assertNotIn("--worktree", template)
        self.assertEqual("0", environment["GROK_MEMORY"])
        self.assertEqual("0", environment["GROK_SUBAGENTS"])
        self.assertEqual("0", environment["GROK_WEB_FETCH"])
        self.assertEqual("1", environment["GROK_DISABLE_AUTOUPDATER"])
        self.assertEqual(
            ["cli-chat-proxy.grok.com"], adapter["expected_vendor_hosts"]
        )
        self.assertTrue(adapter["authentication_failure_patterns"])

    def test_grok_adapter_prepares_generic_single_turn_command(self) -> None:
        adapter = load_adapter(GROK_ADAPTER_PATH, SCHEMA_PATH)
        with tempfile.TemporaryDirectory(prefix="grok-adapter-") as temporary:
            root = Path(temporary)
            prepared = prepare_invocation(
                adapter,
                working_directory=root,
                prompt="Reply only with OK.",
                proxy_port=8080,
                ca_certificate=root / "mitmproxy-ca-cert.pem",
            )
        self.assertEqual(str(root.resolve()), prepared["working_directory"])
        self.assertIn(str(root.resolve()), prepared["arguments"])
        self.assertIn("Reply only with OK.", prepared["arguments"])
        self.assertEqual(
            "http://127.0.0.1:8080",
            prepared["environment_variables"]["HTTPS_PROXY"],
        )
        self.assertEqual("0", prepared["environment_variables"]["GROK_MEMORY"])
        self.assertEqual([], prepared["inherited_secret_environment_variables"])


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
            self.assertEqual("synthetic authentication", saved["authentication_mode"])

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

    def test_declared_secret_is_passed_without_serialization(self) -> None:
        synthetic_secret = "AIzaSyntheticValueThatMustNeverBePersisted123"
        with tempfile.TemporaryDirectory(prefix="adapter-secret-") as temporary:
            root = Path(temporary)
            prepared = _prepared(
                root,
                [
                    "-c",
                    "import os; print(os.environ.get('GEMINI_API_KEY') is not None)",
                ],
                inherited_secret_environment_variables=["GEMINI_API_KEY"],
            )
            availability = verify_inherited_secret_availability(
                {"inherited_secret_environment_variables": ["GEMINI_API_KEY"]},
                {"GEMINI_API_KEY": synthetic_secret},
            )
            self.assertEqual(
                {"required_count": 1, "available_count": 1, "all_available": True},
                availability,
            )
            result = run_client(
                prepared,
                root / "output",
                base_environment={"GEMINI_API_KEY": synthetic_secret},
                snapshot_provider=_snapshot,
            )
            self.assertEqual(0, result["exit_code"])
            self.assertEqual("True\n", (root / "output" / "client-stdout.txt").read_text())
            persisted = "".join(
                path.read_text(encoding="utf-8")
                for path in (root / "output").iterdir()
                if path.is_file()
            )
            self.assertNotIn(synthetic_secret, persisted)
            self.assertNotIn(synthetic_secret, json.dumps(prepared))

    def test_missing_declared_secret_fails_before_client_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-secret-missing-") as temporary:
            root = Path(temporary)
            prepared = _prepared(
                root,
                ["-c", "print('must not run')"],
                inherited_secret_environment_variables=["GEMINI_API_KEY"],
            )
            availability = verify_inherited_secret_availability(
                {"inherited_secret_environment_variables": ["GEMINI_API_KEY"]},
                {},
            )
            self.assertFalse(availability["all_available"])
            result = run_client(
                prepared,
                root / "output",
                base_environment={},
                snapshot_provider=_snapshot,
            )
            self.assertFalse(result["started"])
            self.assertIn("required inherited secret", result["error"])

    def test_sensitive_values_are_redacted(self) -> None:
        original = (
            "Authorization: Bearer secret-token\n"
            "email=user@example.com sk-abcdefghijklmnopqrstuvwxyz "
            '"session_id":"session-secret" org_abcdefghijk\n'
            'GEMINI_API_KEY=AIzaSyntheticValueThatMustNeverBePersisted123'
        )
        redacted = redact_text(original)
        for forbidden in (
            "secret-token",
            "user@example.com",
            "sk-abcdefghijklmnopqrstuvwxyz",
            "session-secret",
            "org_abcdefghijk",
            "AIzaSyntheticValueThatMustNeverBePersisted123",
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

    def test_adapter_pattern_detects_vendor_authentication_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adapter-vendor-auth-") as temporary:
            root = Path(temporary)
            result = run_client(
                _prepared(
                    root,
                    [
                        "-c",
                        "import sys; print('Configure cloud identity before running'); sys.exit(41)",
                    ],
                    authentication_failure_patterns=[r"(?i)configure\s+cloud\s+identity"],
                ),
                root / "output",
                snapshot_provider=_snapshot,
            )
            self.assertTrue(result["authentication_failed"])
            self.assertEqual(41, result["exit_code"])

    def test_ineligible_tier_failure_records_observed_authentication_mode(self) -> None:
        corrected = reclassify_client_execution(
            {"exit_code": 1, "authentication_failed": False},
            stdout="Error authenticating: IneligibleTierError: UNSUPPORTED_CLIENT",
            stderr="",
            authentication_failure_patterns=[r"(?i)error\s+authenticating"],
            authentication_failure_classifications=[
                {
                    "pattern": r"(?i)IneligibleTierError|UNSUPPORTED_CLIENT",
                    "reason": "UNSUPPORTED_CLIENT",
                    "observed_authentication_mode": "cached Google sign-in",
                }
            ],
        )
        self.assertTrue(corrected["authentication_failed"])
        self.assertEqual("UNSUPPORTED_CLIENT", corrected["authentication_failure_reason"])
        self.assertEqual(
            "cached Google sign-in", corrected["observed_authentication_mode"]
        )

    def test_non_authentication_failure_is_not_misclassified(self) -> None:
        execution = {"exit_code": 41, "authentication_failed": True}
        corrected = reclassify_client_execution(
            execution,
            stdout="Synthetic operational failure",
            stderr="",
            authentication_failure_patterns=[r"(?i)configure\s+cloud\s+identity"],
        )
        self.assertFalse(corrected["authentication_failed"])
        self.assertEqual(41, corrected["exit_code"])
        self.assertFalse(
            detect_authentication_failure(
                "Synthetic operational failure",
                "",
                [r"(?i)configure\s+cloud\s+identity"],
            )
        )


class CoverageAndReportTests(unittest.TestCase):
    def test_reconciled_status_controls_top_level_exit_code(self) -> None:
        self.assertEqual(0, process_exit_code_for_final_status("CAPTURE_VALIDATED"))
        for status in (
            "PARTIAL_CAPTURE",
            "TLS_INTERCEPTION_FAILED",
            "DIRECT_BYPASS_DETECTED",
            "NO_AGENT_TRAFFIC_OBSERVED",
            "CAPTURE_START_FAILED",
            "CLIENT_EXECUTION_FAILED",
            "CAPTURE_FAILED",
        ):
            with self.subTest(status=status):
                self.assertNotEqual(0, process_exit_code_for_final_status(status))

    def test_runner_uses_authoritative_status_for_process_exit(self) -> None:
        runner = (WINDOWS_ROOT / "scripts" / "Invoke-AgentCapture.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("$finalOutcome.final_status", runner)
        self.assertIn("if ($finalStatus -ne 'CAPTURE_VALIDATED')", runner)
        self.assertIn("exit 1", runner)
        self.assertIn("-AdapterPath '$escapedAdapterPath'", runner)
        self.assertIn("$escapedPowerShellPath", runner)
        self.assertIn("$workspacePython", runner)
        self.assertIn("capture_startup_timeout_seconds", runner)
        self.assertIn("$proxyReadyTimeoutSeconds", runner)
        self.assertIn("$workspaceMitmdump", runner)
        self.assertIn("Harness mitmdump executable is missing", runner)
        self.assertIn("'-MitmdumpExecutable', $resolvedMitmdumpPath", runner)
        self.assertIn("mitmdump_executable_path", runner)
        self.assertIn("'verify-secrets'", runner)
        self.assertIn("authentication_secret_available", runner)
        self.assertIn("'verify-auth-selection'", runner)
        self.assertIn("authentication_selection_verified", runner)
        self.assertIn(
            "$clientRuntimeExitCode = [int] $clientExecutionRecord.exit_code",
            runner,
        )

    def test_offline_reanalysis_reconciles_source_control_before_reporting(self) -> None:
        script = (WINDOWS_ROOT / "scripts" / "Invoke-EvidenceAnalysis.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("'launcher-outcome.json'", script)
        self.assertIn("'shutdown-request.json'", script)
        self.assertIn("analysis.reconcile_capture_outcome", script)
        self.assertIn("analysis.agent_runtime", script)
        self.assertIn("reclassify-execution", script)
        self.assertIn("$workspacePython", script)

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
            "runtime_errors": [],
            "client_completion_timestamp": "2024-01-01T00:00:00Z",
            "shutdown_request_timestamp": "2024-01-01T00:00:01Z",
            "proxy_termination_timestamp": "2024-01-01T00:00:02Z",
            "listener_release_timestamp": "2024-01-01T00:00:03Z",
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
            runtime_errors=[{"timestamp_utc": "2024-01-01T00:00:01Z", "timing": "AT_OR_AFTER_SHUTDOWN_REQUEST"}],
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

    def test_runtime_error_timing_controls_shutdown_classification(self) -> None:
        before = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            runtime_errors=[{"timestamp_utc": "2024-01-01T00:00:00.999Z", "timing": "BEFORE_SHUTDOWN_REQUEST"}],
        )
        self.assertEqual("PARTIAL_CAPTURE", before["final_status"])
        self.assertEqual("PRE_SHUTDOWN_RUNTIME_ERROR", before["shutdown_error_classification"])

        exact = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            runtime_errors=[{"timestamp_utc": "2024-01-01T00:00:01Z", "timing": "AT_OR_AFTER_SHUTDOWN_REQUEST"}],
        )
        self.assertEqual("CAPTURE_VALIDATED", exact["final_status"])
        self.assertEqual("BENIGN_CONTROLLED_SHUTDOWN", exact["shutdown_error_classification"])

        after = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            runtime_errors=[{"timestamp_utc": "2024-01-01T00:00:02Z", "timing": "AT_OR_AFTER_SHUTDOWN_REQUEST"}],
        )
        self.assertEqual("CAPTURE_VALIDATED", after["final_status"])

        spanning = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            runtime_errors=[
                {"timing": "BEFORE_SHUTDOWN_REQUEST"},
                {"timing": "AT_OR_AFTER_SHUTDOWN_REQUEST"},
            ],
        )
        self.assertEqual("PARTIAL_CAPTURE", spanning["final_status"])
        self.assertEqual(1, spanning["runtime_error_timing_summary"]["before_shutdown_request"])
        self.assertEqual(1, spanning["runtime_error_timing_summary"]["at_or_after_shutdown_request"])

    def test_runtime_error_with_established_truncation_fails_capture(self) -> None:
        outcome = self._final_outcome(
            launcher_exit_code=1,
            mitmdump_exit_code=1,
            capture_runtime_failure=True,
            runtime_errors=[{"timing": "BEFORE_SHUTDOWN_REQUEST"}],
            no_request_truncation=False,
        )
        self.assertEqual("CAPTURE_FAILED", outcome["final_status"])
        self.assertEqual("EVIDENCE_THREATENING_FAILURE", outcome["shutdown_error_classification"])

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

            failed_execution = {
                **json.loads(
                    (control / "client-execution.json").read_text(encoding="utf-8")
                ),
                "exit_code": 41,
                "authentication_failed": True,
            }
            write_json_atomic(control / "client-execution.json", failed_execution)
            failed_outcome = self._final_outcome(
                client_exit_code=41,
                authentication_failed=True,
            )
            write_json_atomic(control / "capture-outcome.json", failed_outcome)
            json_path, markdown_path = generate_reports(
                run,
                analysis,
                "CLIENT_EXECUTION_FAILED",
                control_directory=control,
                report_directory=layout.report,
            )
            failed_report = json.loads(json_path.read_text(encoding="utf-8"))
            failed_markdown = markdown_path.read_text(encoding="utf-8")
            self.assertEqual(
                "CLIENT_EXECUTION_FAILED", failed_report["capture_status"]
            )
            self.assertEqual(41, failed_report["client_execution"]["exit_code"])
            self.assertTrue(
                failed_report["client_execution"]["authentication_failed"]
            )
            self.assertIn("- Exit code: `41`", failed_markdown)
            self.assertIn("- Authentication failed: `True`", failed_markdown)

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
