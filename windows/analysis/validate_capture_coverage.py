"""Evaluate PID-scoped proxy coverage for one captured client run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .models import write_json_atomic
from .reconcile_capture_outcome import calculate_final_outcome, reconcile_capture_outcome
from .verify_manifest import verify_manifest


CAPTURE_STATUSES = (
    "CAPTURE_VALIDATED",
    "PARTIAL_CAPTURE",
    "TLS_INTERCEPTION_FAILED",
    "DIRECT_BYPASS_DETECTED",
    "NO_AGENT_TRAFFIC_OBSERVED",
    "CAPTURE_START_FAILED",
    "CLIENT_EXECUTION_FAILED",
)
LOOPBACK_ADDRESSES = {"127.0.0.1", "::1", "0.0.0.0", "::", "*"}
TEXTUAL_CONTENT_TYPES = (
    "application/json",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "application/xml",
    "text/",
)
TLS_ERROR_MARKERS = (
    "certificate verify failed",
    "certificate validation",
    "invalid certificate",
    "unknown issuer",
    "self signed certificate",
    "tls handshake",
    "x509",
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Expected object at {path}:{line_number}")
        records.append(value)
    return records


def _body_is_readable(run_directory: Path, request: dict[str, Any]) -> bool:
    if int(request.get("body_size") or 0) <= 0:
        return False
    relative = request.get("raw_body_file")
    if not isinstance(relative, str):
        return False
    path = (run_directory / relative).resolve()
    try:
        path.relative_to(run_directory.resolve())
    except ValueError:
        return False
    if not path.is_file():
        return False
    content_type = str(request.get("content_type") or "").lower()
    if any(marker in content_type for marker in TEXTUAL_CONTENT_TYPES):
        return True
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return printable / len(text) >= 0.85


def _is_direct_connection(connection: dict[str, Any], proxy_port: int) -> bool:
    remote_address = str(connection.get("remote_address") or "")
    remote_port = int(connection.get("remote_port") or 0)
    if not remote_address or remote_port == 0:
        return False
    if remote_address in LOOPBACK_ADDRESSES:
        return False
    return True


def calculate_capture_status(
    *,
    mitmproxy_started: bool,
    client_started: bool,
    client_exit_code: int | None,
    timed_out: bool,
    authentication_failed: bool,
    tls_error_observed: bool,
    direct_bypass_detected: bool,
    request_count: int,
    attributable_request: bool,
    decrypted_readable_request_body: bool,
    manifest_valid: bool,
    process_monitoring_complete: bool,
    launcher_exit_code: int | None = 0,
    mitmdump_exit_code: int | None = 0,
    launcher_final_status: str = "CAPTURE_COMPLETE",
    capture_runtime_failure: bool = False,
    benign_shutdown_proven: bool = False,
) -> str:
    facts = {
        "proxy_started": mitmproxy_started,
        "client_launched": client_started,
        "client_exit_code": client_exit_code,
        "timed_out": timed_out,
        "authentication_failed": authentication_failed,
        "tls_error_observed": tls_error_observed,
        "direct_bypass_status": "DETECTED" if direct_bypass_detected else (
            "NOT_DETECTED" if process_monitoring_complete else "MONITORING_INCOMPLETE"
        ),
        "http_request_count": request_count,
        "websocket_message_count": 0,
        "attributable_decrypted_traffic": attributable_request and decrypted_readable_request_body,
        "manifest_valid": manifest_valid,
        "launcher_exit_code": launcher_exit_code,
        "mitmdump_exit_code": mitmdump_exit_code,
        "launcher_final_status": launcher_final_status,
        "capture_runtime_failure": capture_runtime_failure,
        "capture_completed_before_shutdown": benign_shutdown_proven,
        "metadata_and_raw_files_flushed": benign_shutdown_proven,
        "no_request_truncation": benign_shutdown_proven,
        "shutdown_initiated_by_harness": benign_shutdown_proven,
        "listener_released": benign_shutdown_proven,
        "process_terminated_within_cleanup_bound": benign_shutdown_proven,
    }
    return str(calculate_final_outcome(facts)["final_status"])


def _find_model_identifier(stdout_path: Path) -> str | None:
    if not stdout_path.is_file():
        return None

    def visit(value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"model", "model_id", "model_identifier"} and isinstance(item, str):
                    yield item
                yield from visit(item)
        elif isinstance(value, list):
            for item in value:
                yield from visit(item)

    for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        model = next(iter(visit(event)), None)
        if model:
            return model
    return None


def evaluate_capture_coverage(
    run_directory: Path,
    control_directory: Path,
    output_directory: Path,
    *,
    proxy_port: int,
    expected_vendor_hosts: list[str],
) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    control_directory = control_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    execution = _read_json(control_directory / "client-execution.json", {})
    process_tree = _read_json(control_directory / "process-tree.json", {})
    connection_document = _read_json(control_directory / "connections.json", {})
    proxy_status = _read_json(control_directory / "proxy-status.json", {})
    requests = _read_jsonl(run_directory / "requests.jsonl")
    websockets = _read_jsonl(run_directory / "websockets.jsonl")
    integrity = verify_manifest(run_directory)
    connections = list(connection_document.get("connections") or [])
    direct_connections = [
        connection
        for connection in connections
        if _is_direct_connection(connection, proxy_port)
    ]
    proxy_connections = [
        connection
        for connection in connections
        if str(connection.get("remote_address")) in {"127.0.0.1", "::1"}
        and int(connection.get("remote_port") or 0) == proxy_port
    ]
    hosts = sorted(
        {
            str(record.get("host"))
            for record in [*requests, *websockets]
            if record.get("host")
        }
    )
    readable = any(_body_is_readable(run_directory, request) for request in requests)
    stdout = (control_directory / "client-stdout.txt").read_text(
        encoding="utf-8", errors="replace"
    ) if (control_directory / "client-stdout.txt").is_file() else ""
    stderr = (control_directory / "client-stderr.txt").read_text(
        encoding="utf-8", errors="replace"
    ) if (control_directory / "client-stderr.txt").is_file() else ""
    client_text = f"{stdout}\n{stderr}".lower()
    tls_error = any(marker in client_text for marker in TLS_ERROR_MARKERS)
    monitoring_complete = bool(process_tree.get("monitoring_complete"))
    monitoring_started = bool(process_tree.get("monitoring_started"))
    mitmproxy_started = bool(proxy_status.get("started"))
    client_started = bool(execution.get("started"))
    represented = bool(requests or websockets)
    endpoints_by_pid: dict[int, list[dict[str, Any]]] = {}
    for connection in connections:
        pid = int(connection.get("process_id") or 0)
        endpoint = dict(connection)
        endpoint["represented_in_mitmproxy_capture"] = (
            str(connection.get("remote_address")) in {"127.0.0.1", "::1"}
            and int(connection.get("remote_port") or 0) == proxy_port
            and represented
        )
        endpoints_by_pid.setdefault(pid, []).append(endpoint)
    attributed_processes = []
    for process in process_tree.get("processes") or []:
        item = dict(process)
        item["outbound_endpoints"] = endpoints_by_pid.get(
            int(process.get("process_id") or 0), []
        )
        attributed_processes.append(item)
    result = {
        "schema_version": "egress-capture-coverage/v1",
        "capture_status": "PENDING_RECONCILIATION",
        "attribution_basis": "A dedicated loopback proxy port was applied only to the recorded parent client process and its inherited environment; PID-scoped connection polling covered that parent and observed descendants.",
        "mitmproxy_started": mitmproxy_started,
        "proxy_started": mitmproxy_started,
        "client_launched": client_started,
        "monitoring_started": monitoring_started,
        "mitmproxy_request_attribution_supported": bool(proxy_connections and requests),
        "http_request_count": len(requests),
        "websocket_message_count": len(websockets),
        "http_request_bytes": sum(int(item.get("body_size") or 0) for item in requests),
        "websocket_message_bytes": sum(int(item.get("payload_size") or 0) for item in websockets),
        "total_request_count": len(requests),
        "total_websocket_message_count": len(websockets),
        "total_raw_request_bytes": sum(int(item.get("body_size") or 0) for item in requests),
        "total_raw_websocket_bytes": sum(int(item.get("payload_size") or 0) for item in websockets),
        "decrypted_readable_request_body": readable,
        "client_completed_or_documented_error": bool(
            execution.get("started")
            and (execution.get("exit_code") is not None or execution.get("error"))
        ),
        "tls_error_observed": tls_error,
        "hosts_contacted": hosts,
        "expected_vendor_hosts": expected_vendor_hosts,
        "expected_vendor_hosts_observed": sorted(set(hosts) & set(expected_vendor_hosts)),
        "direct_bypass_status": "DETECTED" if direct_connections else (
            "NOT_DETECTED" if monitoring_complete else "MONITORING_INCOMPLETE"
        ),
        "direct_connections": direct_connections,
        "proxy_connections": proxy_connections,
        "process_monitoring_complete": monitoring_complete,
        "process_monitoring_errors": process_tree.get("monitoring_errors", []),
        "parent_process_id": process_tree.get("root_process_id"),
        "process_attribution": attributed_processes,
        "manifest_valid": bool(integrity.get("valid")),
        "manifest_verification": integrity,
        "model_identifier_observed": _find_model_identifier(
            control_directory / "client-stdout.txt"
        ),
        "limitations": [
            "Get-NetTCPConnection polling can miss connections that open and close between polls.",
            "Connection metadata demonstrates endpoints and routing, not plaintext visibility.",
            "Mitmproxy requests are attributed by the dedicated proxy port and observation window; request metadata does not contain an originating PID.",
            "DNS and non-TCP traffic are outside this Phase 3A monitor.",
            "Missing canaries do not prove that source code or other content was not transmitted.",
        ],
    }
    outcome = reconcile_capture_outcome(
        run_directory, control_directory, output_directory, result
    )
    result["capture_status"] = outcome["final_status"]
    result["capture_outcome"] = outcome
    write_json_atomic(output_directory / "coverage.json", result)
    write_json_atomic(output_directory / "client-execution.json", execution)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("control_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--expected-vendor-host", action="append", default=[])
    args = parser.parse_args()
    result = evaluate_capture_coverage(
        args.run_directory,
        args.control_directory,
        args.output_directory,
        proxy_port=args.proxy_port,
        expected_vendor_hosts=args.expected_vendor_host,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
