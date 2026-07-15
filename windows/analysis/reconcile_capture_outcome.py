"""Reconcile capture lifecycle, integrity, attribution, and shutdown evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .models import write_json_atomic
from .verify_manifest import verify_manifest


FINAL_STATUSES = (
    "CAPTURE_VALIDATED",
    "PARTIAL_CAPTURE",
    "TLS_INTERCEPTION_FAILED",
    "DIRECT_BYPASS_DETECTED",
    "NO_AGENT_TRAFFIC_OBSERVED",
    "CAPTURE_START_FAILED",
    "CLIENT_EXECUTION_FAILED",
    "CAPTURE_FAILED",
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _raw_records_complete(run_directory: Path, records: list[dict[str, Any]], *, websocket: bool) -> bool:
    file_key = "raw_payload_file" if websocket else "raw_body_file"
    size_key = "payload_size" if websocket else "body_size"
    hash_key = "payload_sha256" if websocket else "body_sha256"
    root = run_directory.resolve()
    for record in records:
        relative = record.get(file_key)
        if not isinstance(relative, str):
            return False
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            return False
        if not path.is_file():
            return False
        raw = path.read_bytes()
        if len(raw) != int(record.get(size_key) or 0):
            return False
        if hashlib.sha256(raw).hexdigest() != record.get(hash_key):
            return False
    return True


def calculate_final_outcome(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Return the sole authoritative reportable status for a capture run."""

    proxy_started = bool(facts.get("proxy_started"))
    client_launched = bool(facts.get("client_launched"))
    client_exit_code = facts.get("client_exit_code")
    launcher_exit_code = facts.get("launcher_exit_code")
    mitmdump_exit_code = facts.get("mitmdump_exit_code")
    lifecycle_status = str(facts.get("launcher_final_status") or "UNKNOWN")
    runtime_failure = bool(facts.get("capture_runtime_failure"))
    shutdown_error = runtime_failure or launcher_exit_code not in (None, 0) or mitmdump_exit_code not in (None, 0)

    benign_conditions = {
        "capture_completed_before_shutdown": bool(facts.get("capture_completed_before_shutdown")),
        "metadata_and_raw_files_flushed": bool(facts.get("metadata_and_raw_files_flushed")),
        "manifest_valid": bool(facts.get("manifest_valid")),
        "no_request_truncation": facts.get("no_request_truncation") is True,
        "shutdown_initiated_by_harness": bool(facts.get("shutdown_initiated_by_harness")),
        "listener_released": bool(facts.get("listener_released")),
        "process_terminated_within_cleanup_bound": bool(facts.get("process_terminated_within_cleanup_bound")),
    }
    benign_shutdown = shutdown_error and all(benign_conditions.values())
    integrity_failure = (
        not bool(facts.get("manifest_valid"))
        or facts.get("metadata_and_raw_files_flushed") is False
        or facts.get("no_request_truncation") is False
    )
    if not shutdown_error:
        shutdown_classification = "NONE"
        integrity_affected: bool | None = False
    elif benign_shutdown:
        shutdown_classification = "BENIGN_CONTROLLED_SHUTDOWN"
        integrity_affected = False
    elif integrity_failure:
        shutdown_classification = "EVIDENCE_THREATENING_FAILURE"
        integrity_affected = True
    else:
        shutdown_classification = "BENIGN_NOT_ESTABLISHED"
        integrity_affected = None

    reasons: list[str] = []
    if not proxy_started and not client_launched:
        final_status = "CAPTURE_START_FAILED"
        reasons.append("The proxy did not start and the client was not launched.")
    elif not client_launched:
        final_status = "CAPTURE_FAILED"
        reasons.append("The client was not launched after capture startup activity.")
    elif not proxy_started:
        final_status = "CAPTURE_FAILED"
        reasons.append("The client launched without a successfully started capture proxy.")
    elif bool(facts.get("timed_out")) or bool(facts.get("authentication_failed")) or client_exit_code not in (0,):
        final_status = "CLIENT_EXECUTION_FAILED"
        reasons.append("The launched client did not complete successfully.")
    elif bool(facts.get("tls_error_observed")):
        final_status = "TLS_INTERCEPTION_FAILED"
        reasons.append("The client recorded a TLS interception error.")
    elif facts.get("direct_bypass_status") == "DETECTED":
        final_status = "DIRECT_BYPASS_DETECTED"
        reasons.append("PID-scoped monitoring observed a direct non-proxy connection.")
    elif shutdown_error and not benign_shutdown:
        final_status = "CAPTURE_FAILED" if integrity_failure else "PARTIAL_CAPTURE"
        reasons.append("A capture-runtime/shutdown error remains and the full benign-shutdown proof was not established.")
    elif not bool(facts.get("manifest_valid")) or facts.get("direct_bypass_status") != "NOT_DETECTED":
        final_status = "PARTIAL_CAPTURE"
        reasons.append("Integrity or direct-bypass monitoring did not complete successfully.")
    elif int(facts.get("http_request_count") or 0) + int(facts.get("websocket_message_count") or 0) == 0:
        final_status = "NO_AGENT_TRAFFIC_OBSERVED"
        reasons.append("No attributable HTTP request or WebSocket message was captured.")
    elif not bool(facts.get("attributable_decrypted_traffic")):
        final_status = "PARTIAL_CAPTURE"
        reasons.append("Decrypted attributable client traffic was not established.")
    else:
        final_status = "CAPTURE_VALIDATED"
        reasons.append("Startup, client execution, attributable decrypted capture, manifest integrity, and bypass monitoring all passed with no unresolved runtime failure.")

    if lifecycle_status not in {"UNKNOWN", final_status}:
        reasons.append(f"Lifecycle status {lifecycle_status} is preserved separately from reconciled final status {final_status}.")
    return {
        "schema_version": "egress-capture-outcome/v1",
        "final_status": final_status,
        "launcher_exit_code": launcher_exit_code,
        "mitmdump_exit_code": mitmdump_exit_code,
        "launcher_final_status": lifecycle_status,
        "shutdown_error_observed": shutdown_error,
        "shutdown_error_classification": shutdown_classification,
        "capture_integrity_affected": integrity_affected,
        "benign_shutdown_conditions": benign_conditions,
        "final_status_reason": " ".join(reasons),
        "lifecycle_history": list(facts.get("lifecycle_history") or []),
    }


def reconcile_capture_outcome(
    run_directory: Path,
    control_directory: Path,
    output_directory: Path,
    coverage: Mapping[str, Any],
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    control_directory = control_directory.resolve()
    run = _read_json(run_directory / "run.json", {})
    execution = _read_json(control_directory / "client-execution.json", {})
    launcher = _read_json(control_directory / "launcher-outcome.json", {})
    journal = _read_jsonl(run_directory / "startup-journal.jsonl")
    requests = _read_jsonl(run_directory / "requests.jsonl")
    websockets = _read_jsonl(run_directory / "websockets.jsonl")
    integrity = verify_manifest(run_directory)
    cleanup = run.get("cleanup") or {}
    stop_request = _read_json(control_directory / "shutdown-request.json", {})
    stop_path = control_directory / "stop-capture.signal"
    stop_time = _parse_time(stop_request.get("requested_at_utc"))
    if stop_time is None and stop_path.is_file():
        stop_time = datetime.fromtimestamp(stop_path.stat().st_mtime, tz=datetime.now().astimezone().tzinfo)
    client_end = _parse_time(execution.get("end_time"))
    harness_shutdown = bool(stop_request.get("initiated_by_harness")) or stop_path.is_file()
    lifecycle_history = [
        {"timestamp": item.get("timestamp_utc") or item.get("timestamp"), "stage": item.get("stage"), "event": item.get("event")}
        for item in journal
    ]
    request_records_complete = _raw_records_complete(run_directory, requests, websocket=False)
    websocket_records_complete = _raw_records_complete(run_directory, websockets, websocket=True)
    explicit_truncation = [item.get("body_truncated") for item in requests]
    no_request_truncation: bool | None
    if not requests:
        no_request_truncation = True
    elif any(value is True for value in explicit_truncation):
        no_request_truncation = False
    elif all(value is False for value in explicit_truncation):
        no_request_truncation = True
    else:
        no_request_truncation = None
    manifest = _read_json(run_directory / "evidence-manifest.json", {})
    facts = {
        "proxy_started": bool(coverage.get("proxy_started", run.get("proxy_started"))),
        "client_launched": bool(coverage.get("client_launched", execution.get("started"))),
        "client_exit_code": execution.get("exit_code"),
        "timed_out": bool(execution.get("timed_out")),
        "authentication_failed": bool(execution.get("authentication_failed")),
        "tls_error_observed": bool(coverage.get("tls_error_observed")),
        "direct_bypass_status": coverage.get("direct_bypass_status"),
        "http_request_count": int(coverage.get("http_request_count") or len(requests)),
        "websocket_message_count": int(coverage.get("websocket_message_count") or len(websockets)),
        "attributable_decrypted_traffic": bool(
            coverage.get("mitmproxy_request_attribution_supported")
            and coverage.get("decrypted_readable_request_body")
        ),
        "manifest_valid": bool(integrity.get("valid")),
        "launcher_exit_code": launcher.get("launcher_exit_code"),
        "mitmdump_exit_code": run.get("mitmdump_exit_code"),
        "launcher_final_status": run.get("startup_status"),
        "capture_runtime_failure": run.get("failure_stage") == "capture_runtime",
        "capture_completed_before_shutdown": bool(client_end and stop_time and client_end <= stop_time),
        "metadata_and_raw_files_flushed": bool(
            integrity.get("valid")
            and request_records_complete
            and websocket_records_complete
            and int(manifest.get("capture_error_count") or 0) == 0
            and cleanup.get("stdout_copy_completed") is True
            and cleanup.get("stderr_copy_completed") is True
        ),
        "no_request_truncation": no_request_truncation,
        "shutdown_initiated_by_harness": harness_shutdown,
        "listener_released": cleanup.get("port_released") is True,
        "process_terminated_within_cleanup_bound": bool(
            launcher.get("terminated_within_cleanup_bound", cleanup.get("process_stopped") is True)
        ),
        "lifecycle_history": lifecycle_history,
    }
    outcome = calculate_final_outcome(facts)
    outcome["integrity_facts"] = {
        "manifest_valid": facts["manifest_valid"],
        "request_records_complete": request_records_complete,
        "websocket_records_complete": websocket_records_complete,
        "no_request_truncation": no_request_truncation,
        "capture_completed_before_shutdown": facts["capture_completed_before_shutdown"],
        "shutdown_initiated_by_harness": harness_shutdown,
        "listener_released": facts["listener_released"],
        "process_terminated_within_cleanup_bound": facts["process_terminated_within_cleanup_bound"],
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output_directory / "capture-outcome.json", outcome)
    write_json_atomic(
        output_directory / "reconciled-run.json",
        {"original_run_metadata": run, "lifecycle_history": lifecycle_history, "reconciled_final_state": outcome},
    )
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("control_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("coverage", type=Path)
    args = parser.parse_args()
    outcome = reconcile_capture_outcome(
        args.run_directory,
        args.control_directory,
        args.output_directory,
        _read_json(args.coverage, {}),
    )
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
