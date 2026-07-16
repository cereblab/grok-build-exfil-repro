"""Generate versioned JSON and Markdown reports from derived analysis results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .models import REPORT_SCHEMA, write_json_atomic
from .verify_manifest import verify_manifest


CAPTURE_STATUSES = (
    "CAPTURE_VALIDATED",
    "PARTIAL_CAPTURE",
    "TLS_INTERCEPTION_FAILED",
    "DIRECT_BYPASS_DETECTED",
    "NO_AGENT_TRAFFIC_OBSERVED",
    "CAPTURE_START_FAILED",
    "CLIENT_EXECUTION_FAILED",
    "CAPTURE_FAILED",
    "NOT_EVALUATED",
)
MISSING_CANARY_LANGUAGE = (
    "No tested canary was detected in the captured and successfully decoded evidence layers."
)
PROHIBITED_CONCLUSIONS = (
    "the vendor trained on the data",
    "the vendor retained the data",
    "the vendor sold the data",
    "the vendor intended to steal data",
    "the client is safe",
    "no source code was transmitted",
)


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_no_prohibited_conclusions(report: dict[str, Any]) -> None:
    rendered = json.dumps(report, ensure_ascii=False).lower()
    found = [phrase for phrase in PROHIBITED_CONCLUSIONS if phrase in rendered]
    if found:
        raise ValueError(f"Report contains prohibited conclusion language: {found}")


def _direction_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "client_to_server_occurrences": sum(
            item.get("direction") == "client_to_server" for item in findings
        ),
        "server_to_client_occurrences": sum(
            item.get("direction") == "server_to_client" for item in findings
        ),
        "other_or_unknown_occurrences": sum(
            item.get("direction") not in {"client_to_server", "server_to_client"}
            for item in findings
        ),
    }


def build_report(
    run_directory: Path,
    analysis_directory: Path,
    capture_status: str = "NOT_EVALUATED",
    *,
    control_directory: Path | None = None,
    report_directory: Path | None = None,
) -> dict[str, Any]:
    if capture_status not in CAPTURE_STATUSES:
        raise ValueError(f"Unsupported capture status: {capture_status}")
    run_directory = run_directory.resolve()
    analysis_directory = analysis_directory.resolve()
    control_directory = (control_directory or analysis_directory).resolve()
    report_directory = (report_directory or analysis_directory).resolve()
    output_root = (
        analysis_directory.parent
        if analysis_directory.parent == control_directory.parent == report_directory.parent
        else report_directory
    )
    manifest = _read_json(run_directory / "evidence-manifest.json", {})
    extraction = _read_json(analysis_directory / "extraction-result.json", {})
    classification = _read_json(analysis_directory / "classification.json", {})
    git_validation = _read_json(analysis_directory / "git-validation.json", {})
    coverage = _read_json(control_directory / "coverage.json", {})
    client_execution = _read_json(control_directory / "client-execution.json", {})
    version_correction = _read_json(control_directory / "client-version-correction.json", {})
    if not version_correction:
        version_correction = _read_json(analysis_directory / "client-version-correction.json", {})
    if version_correction:
        client_execution = {**client_execution, **version_correction}
    capture_outcome = _read_json(control_directory / "capture-outcome.json", {})
    if capture_outcome:
        capture_status = str(capture_outcome["final_status"])
    canary_findings = classification.get("canary_findings", [])
    canary_direction_summary = _direction_summary(canary_findings)
    allowed_file_findings = [
        item
        for item in canary_findings
        if item.get("canary_name") == "allowed_file_first_line_canary"
    ]
    allowed_file_direction_summary = _direction_summary(allowed_file_findings)
    http_request_count = int(
        coverage.get("http_request_count", coverage.get("total_request_count", 0)) or 0
    )
    websocket_message_count = int(
        coverage.get(
            "websocket_message_count",
            coverage.get("total_websocket_message_count", 0),
        )
        or 0
    )
    http_request_bytes = int(
        coverage.get("http_request_bytes", coverage.get("total_raw_request_bytes", 0))
        or 0
    )
    websocket_message_bytes = int(
        coverage.get(
            "websocket_message_bytes",
            coverage.get("total_raw_websocket_bytes", 0),
        )
        or 0
    )
    client_launched = bool(
        coverage.get("client_launched", client_execution.get("started", False))
    )
    proxy_started = bool(
        coverage.get("proxy_started", coverage.get("mitmproxy_started", False))
    )
    monitoring_started = bool(coverage.get("monitoring_started", False))
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "capture_status": capture_status,
        "client_version": client_execution.get("normalized_client_version") or client_execution.get("client_version"),
        "authentication_mode": (
            client_execution.get("observed_authentication_mode")
            or client_execution.get("authentication_mode")
        ),
        "capture_outcome": capture_outcome,
        "output_layout": {
            "output_root": str(output_root),
            "control_directory": str(control_directory),
            "raw_directory": str(run_directory / "raw"),
            "analysis_directory": str(analysis_directory),
            "report_directory": str(report_directory),
        },
        "http_request_count": http_request_count,
        "websocket_message_count": websocket_message_count,
        "http_request_bytes": http_request_bytes,
        "websocket_message_bytes": websocket_message_bytes,
        "client_launched": client_launched,
        "proxy_started": proxy_started,
        "monitoring_started": monitoring_started,
        "run_metadata": {
            "run_id": manifest.get("run_id"),
            "capture_start_timestamp": manifest.get("capture_start_timestamp"),
            "capture_stop_timestamp": manifest.get("capture_stop_timestamp"),
            "operating_system": manifest.get("operating_system"),
            "python_version": manifest.get("python_version"),
            "mitmproxy_version": manifest.get("mitmproxy_version"),
            "repository_commit_sha": manifest.get("repository_commit_sha"),
            "capture_ended_cleanly": manifest.get("capture_ended_cleanly"),
        },
        "evidence_integrity": verify_manifest(run_directory),
        "raw_files_processed": extraction.get("raw_files_processed", []),
        "derived_artifacts_created": extraction.get("artifacts", []),
        "decoding_operations": extraction.get("operations", []),
        "decoding_failures": extraction.get("extraction_failures", []),
        "unsupported_encodings": extraction.get("unsupported_encodings", []),
        "processing_limits_reached": extraction.get("processing_limits_reached", []),
        "canary_inventory_sources": classification.get("canary_inventory_sources", []),
        "canary_findings": canary_findings,
        "canary_direction_summary": canary_direction_summary,
        "allowed_file_first_line_summary": allowed_file_direction_summary,
        "canary_summary": (
            f"{len(canary_findings)} exact tested-canary occurrence(s) were detected."
            if canary_findings
            else MISSING_CANARY_LANGUAGE
        ),
        "git_candidate_findings": classification.get("git_candidates", []),
        "git_validation_results": git_validation,
        "client_execution": client_execution,
        "capture_coverage": coverage,
        "limitations": [
            "A canary match proves only that the matched bytes appeared in the inspected evidence layer; it does not establish how those bytes were obtained.",
            "An ignored-file or historical canary match does not establish that the complete file or Git object database was transmitted.",
            "Git byte signatures are candidates until the separate Git validation stage succeeds.",
            "A valid pack or partial object set is not a full repository reconstruction.",
            "WebSocket payloads are reassembled messages exposed by mitmproxy; original protocol-frame boundaries are unavailable.",
            "Fragmentation, application compression, protobuf, and custom binary framing may remain unresolved.",
            "Capture coverage must be evaluated separately for each future client and interface.",
            "ETW and WFP can help assess connection coverage but are not plaintext application-payload capture mechanisms.",
            "GUI and CLI surfaces can route traffic differently and require separate future tests.",
            "Absence of a tested canary is not proof that other content was absent from traffic.",
        ],
        "untested_assumptions": (
            [
                *coverage.get("limitations", []),
                "Unsupported or unsuccessfully decoded layers may contain content that this pipeline cannot classify.",
            ]
            if client_execution
            else [
                "Phase 2 does not execute or evaluate any vendor product.",
                "Direct proxy bypass and TLS interception coverage are not evaluated in Phase 2.",
                "Unsupported or unsuccessfully decoded layers may contain content that this pipeline cannot classify.",
            ]
        ),
    }
    _assert_no_prohibited_conclusions(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Network egress evidence report",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Capture status: `{report['capture_status']}`",
        f"- Final status reason: `{report['capture_outcome'].get('final_status_reason')}`",
        f"- Run ID: `{report['run_metadata'].get('run_id')}`",
        f"- Evidence integrity valid: `{report['evidence_integrity'].get('valid')}`",
        f"- HTTP requests: `{report['http_request_count']}`",
        f"- WebSocket messages: `{report['websocket_message_count']}`",
        f"- HTTP request bytes: `{report['http_request_bytes']}`",
        f"- WebSocket message bytes: `{report['websocket_message_bytes']}`",
        f"- Client launched: `{report['client_launched']}`",
        f"- Proxy started: `{report['proxy_started']}`",
        f"- Monitoring started: `{report['monitoring_started']}`",
        "",
        "## Run metadata",
        "",
        f"- Capture started: `{report['run_metadata'].get('capture_start_timestamp')}`",
        f"- Capture stopped: `{report['run_metadata'].get('capture_stop_timestamp')}`",
        f"- Capture ended cleanly: `{report['run_metadata'].get('capture_ended_cleanly')}`",
        f"- Operating system: `{report['run_metadata'].get('operating_system')}`",
        f"- Python: `{report['run_metadata'].get('python_version')}`",
        f"- mitmproxy: `{report['run_metadata'].get('mitmproxy_version')}`",
        f"- Repository commit: `{report['run_metadata'].get('repository_commit_sha')}`",
        "",
        "## Evidence integrity",
        "",
        f"- Missing files: {len(report['evidence_integrity'].get('missing_files', []))}",
        f"- Modified files: {len(report['evidence_integrity'].get('modified_files', []))}",
        f"- Duplicate manifest paths: {len(report['evidence_integrity'].get('duplicate_manifest_paths', []))}",
        f"- Duplicate-content groups: {len(report['evidence_integrity'].get('duplicate_content_groups', []))}",
        f"- Unexpected raw files: {len(report['evidence_integrity'].get('unexpected_raw_files', []))}",
        "",
        "## Evidence processing",
        "",
        f"- Raw files processed: {len(report['raw_files_processed'])}",
        f"- Derived artifacts created: {len(report['derived_artifacts_created'])}",
        f"- Decoding operations: {len(report['decoding_operations'])}",
        f"- Decoding failures: {len(report['decoding_failures'])}",
        f"- Unsupported encodings: {len(report['unsupported_encodings'])}",
        f"- Processing limits reached: {len(report['processing_limits_reached'])}",
        "",
    ]
    if report["client_execution"] or report["capture_coverage"]:
        client = report["client_execution"]
        coverage = report["capture_coverage"]
        lines.extend(
            [
                "## Client execution and capture coverage",
                "",
                f"- Product: `{client.get('product')}`",
                f"- Client version: `{client.get('client_version')}`",
                f"- Configured authentication mode: `{client.get('authentication_mode')}`",
                f"- Observed authentication mode: `{client.get('observed_authentication_mode')}`",
                f"- Authentication failure reason: `{client.get('authentication_failure_reason')}`",
                f"- Version command: `{client.get('version_command')}`",
                f"- Version exit code: `{client.get('version_exit_code')}`",
                f"- Launcher exit code: `{report['capture_outcome'].get('launcher_exit_code')}`",
                f"- mitmdump exit code: `{report['capture_outcome'].get('mitmdump_exit_code')}`",
                f"- Lifecycle status: `{report['capture_outcome'].get('launcher_final_status')}`",
                f"- Shutdown error classification: `{report['capture_outcome'].get('shutdown_error_classification')}`",
                f"- Client completion timestamp: `{report['capture_outcome'].get('client_completion_timestamp')}`",
                f"- Shutdown request timestamp: `{report['capture_outcome'].get('shutdown_request_timestamp')}`",
                f"- Proxy termination timestamp: `{report['capture_outcome'].get('proxy_termination_timestamp')}`",
                f"- Listener release timestamp: `{report['capture_outcome'].get('listener_release_timestamp')}`",
                f"- Model identifier: `{coverage.get('model_identifier_observed') or client.get('model_identifier')}`",
                f"- Prompt: `{client.get('prompt')}`",
                f"- Exit code: `{client.get('exit_code')}`",
                f"- Timed out: `{client.get('timed_out')}`",
                f"- Authentication failed: `{client.get('authentication_failed')}`",
                f"- Requests captured: `{report['http_request_count']}`",
                f"- WebSocket messages captured: `{report['websocket_message_count']}`",
                f"- Raw request bytes: `{report['http_request_bytes']}`",
                f"- Raw WebSocket bytes: `{report['websocket_message_bytes']}`",
                f"- Decrypted readable request body observed: `{coverage.get('decrypted_readable_request_body')}`",
                f"- Direct bypass status: `{coverage.get('direct_bypass_status')}`",
                f"- Process monitoring complete: `{coverage.get('process_monitoring_complete')}`",
                f"- Parent process ID: `{coverage.get('parent_process_id')}`",
                f"- Hosts contacted: `{', '.join(coverage.get('hosts_contacted', []))}`",
                "",
            ]
        )
        runtime_errors = report["capture_outcome"].get("runtime_error_timeline") or []
        if runtime_errors:
            lines.extend(["### Runtime error chronology", ""])
            for error in runtime_errors:
                lines.append(
                    f"- `{error.get('timestamp_utc')}` ({error.get('timing')}): "
                    f"`{error.get('error_type')}` from `{error.get('source')}`"
                )
            lines.append("")
    if report["decoding_operations"]:
        lines.extend(["### Decoding operations", ""])
        for operation in report["decoding_operations"]:
            lines.append(
                f"- `{operation['extraction_operation']}` from `{operation.get('source_raw_file')}` at depth {operation.get('extraction_depth')}: success=`{operation.get('success')}`"
            )
        lines.append("")
    if report["decoding_failures"]:
        lines.extend(["### Decoding failures", ""])
        for failure in report["decoding_failures"]:
            lines.append(
                f"- `{failure['extraction_operation']}` from `{failure.get('source_raw_file')}`: {failure.get('error_message')}"
            )
        lines.append("")

    lines.extend(["## Canary findings", "", report["canary_summary"], ""])
    direction_summary = report["canary_direction_summary"]
    allowed_summary = report["allowed_file_first_line_summary"]
    lines.extend(
        [
            "- Directional occurrence counts: "
            f"client-to-server={direction_summary['client_to_server_occurrences']}, "
            f"server-to-client={direction_summary['server_to_client_occurrences']}, "
            f"other-or-unknown={direction_summary['other_or_unknown_occurrences']}.",
            "- Allowed-file first-line marker: "
            f"client-to-server={allowed_summary['client_to_server_occurrences']}, "
            f"server-to-client={allowed_summary['server_to_client_occurrences']}, "
            f"other-or-unknown={allowed_summary['other_or_unknown_occurrences']}. "
            "A client-to-server match establishes only that permitted first-line marker was transmitted outbound; "
            "it does not establish that the full file or other repository content was transmitted.",
            "",
        ]
    )
    for finding in report["canary_findings"]:
        direction = finding.get("direction") or "other_or_unknown"
        lines.append(
            f"- `{finding['canary_name']}` direction=`{direction}` in `{finding['source_artifact']}` "
            f"at byte offset {finding['byte_offset']} ({finding['layer']})"
        )
    if report["canary_findings"]:
        lines.append("")

    validation = report["git_validation_results"]
    git_candidates = report["git_candidate_findings"]
    lines.extend(
        [
            "## Git candidates and validation",
            "",
            f"- Candidate signatures: {len(report['git_candidate_findings'])}",
            f"- Bundle validated: `{validation.get('git_bundle_validated', False)}`",
            f"- Pack validated: `{validation.get('git_pack_validated', False)}`",
            f"- Partial expected object set recovered: `{validation.get('partial_git_object_set_recovered', False)}`",
            f"- Complete expected object set recovered: `{validation.get('complete_expected_object_set_recovered', False)}`",
            f"- Expected refs recovered: `{validation.get('expected_refs_recovered', False)}`",
            f"- Full repository reconstructed: `{validation.get('full_repository_reconstructed', False)}`",
            "",
        ]
    )
    for candidate in git_candidates:
        offsets = candidate.get("byte_offset", candidate.get("byte_offsets"))
        lines.append(
            f"- `{candidate['candidate_type']}` in `{candidate['source_artifact']}` at offset(s) `{offsets}`; marker-only validation=`{candidate.get('structurally_validated', False)}`"
        )
    if git_candidates:
        lines.append("")
    for candidate in validation.get("validated_candidates", []):
        lines.append(
            f"- Validated `{candidate['candidate_type']}` `{candidate['candidate_sha256']}`: bundle=`{candidate['git_bundle_validated']}`, pack=`{candidate['git_pack_validated']}`, integrity=`{candidate['repository_integrity_checks_passed']}`, expected objects={candidate['recovered_expected_object_count']}/{candidate['expected_object_count']}, full reconstruction=`{candidate['full_repository_reconstructed']}`"
        )
    if validation.get("validated_candidates"):
        lines.append("")

    lines.extend(["## Explicit limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend(["", "## Untested assumptions", ""])
    lines.extend(f"- {item}" for item in report["untested_assumptions"])
    markdown = "\n".join(lines).rstrip() + "\n"
    lowered = markdown.lower()
    found = [phrase for phrase in PROHIBITED_CONCLUSIONS if phrase in lowered]
    if found:
        raise ValueError(f"Markdown contains prohibited conclusion language: {found}")
    return markdown


def generate_reports(
    run_directory: Path,
    analysis_directory: Path,
    capture_status: str = "NOT_EVALUATED",
    *,
    control_directory: Path | None = None,
    report_directory: Path | None = None,
) -> tuple[Path, Path]:
    report_directory = report_directory or analysis_directory
    report_directory.mkdir(parents=True, exist_ok=True)
    report = build_report(
        run_directory,
        analysis_directory,
        capture_status,
        control_directory=control_directory,
        report_directory=report_directory,
    )
    json_path = report_directory / "report.json"
    markdown_path = report_directory / "report.md"
    write_json_atomic(json_path, report)
    markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    return json_path, markdown_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("analysis_directory", type=Path)
    parser.add_argument("--control-directory", type=Path)
    parser.add_argument("--report-directory", type=Path)
    parser.add_argument("--capture-status", choices=CAPTURE_STATUSES, default="NOT_EVALUATED")
    args = parser.parse_args()
    json_path, markdown_path = generate_reports(
        args.run_directory,
        args.analysis_directory,
        args.capture_status,
        control_directory=args.control_directory,
        report_directory=args.report_directory,
    )
    print(json.dumps({"json_report": str(json_path), "markdown_report": str(markdown_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
