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


def build_report(
    run_directory: Path,
    derived_directory: Path,
    capture_status: str = "NOT_EVALUATED",
) -> dict[str, Any]:
    if capture_status not in CAPTURE_STATUSES:
        raise ValueError(f"Unsupported capture status: {capture_status}")
    manifest = _read_json(run_directory / "evidence-manifest.json", {})
    extraction = _read_json(derived_directory / "extraction-result.json", {})
    classification = _read_json(derived_directory / "classification.json", {})
    git_validation = _read_json(derived_directory / "git-validation.json", {})
    canary_findings = classification.get("canary_findings", [])
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "capture_status": capture_status,
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
        "canary_findings": canary_findings,
        "canary_summary": (
            f"{len(canary_findings)} exact tested-canary occurrence(s) were detected."
            if canary_findings
            else MISSING_CANARY_LANGUAGE
        ),
        "git_candidate_findings": classification.get("git_candidates", []),
        "git_validation_results": git_validation,
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
        "untested_assumptions": [
            "Phase 2 does not execute or evaluate any vendor product.",
            "Direct proxy bypass and TLS interception coverage are not evaluated in Phase 2.",
            "Unsupported or unsuccessfully decoded layers may contain content that this pipeline cannot classify.",
        ],
    }
    _assert_no_prohibited_conclusions(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Network egress evidence report",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Capture status: `{report['capture_status']}`",
        f"- Run ID: `{report['run_metadata'].get('run_id')}`",
        f"- Evidence integrity valid: `{report['evidence_integrity'].get('valid')}`",
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
    for finding in report["canary_findings"]:
        lines.append(
            f"- `{finding['canary_name']}` in `{finding['source_artifact']}` at byte offset {finding['byte_offset']} ({finding['layer']})"
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
    derived_directory: Path,
    capture_status: str = "NOT_EVALUATED",
) -> tuple[Path, Path]:
    report = build_report(run_directory, derived_directory, capture_status)
    json_path = derived_directory / "report.json"
    markdown_path = derived_directory / "report.md"
    write_json_atomic(json_path, report)
    markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    return json_path, markdown_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("derived_directory", type=Path)
    parser.add_argument("--capture-status", choices=CAPTURE_STATUSES, default="NOT_EVALUATED")
    args = parser.parse_args()
    json_path, markdown_path = generate_reports(
        args.run_directory, args.derived_directory, args.capture_status
    )
    print(json.dumps({"json_report": str(json_path), "markdown_report": str(markdown_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
