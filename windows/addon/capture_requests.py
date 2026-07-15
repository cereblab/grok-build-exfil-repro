"""Vendor-neutral mitmproxy addon that preserves untouched request payloads."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http, version
from wsproto.frame_protocol import Opcode


CAPTURE_DIRECTORY_ENV = "EGRESS_CAPTURE_DIR"
MANIFEST_SCHEMA = "egress-evidence-manifest/v1"
METADATA_SCHEMA = "egress-capture-metadata/v1"


def _utc_timestamp(timestamp: float | None = None) -> str:
    instant = (
        datetime.now(timezone.utc)
        if timestamp is None
        else datetime.fromtimestamp(timestamp, timezone.utc)
    )
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
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


def _safe_request_path(path: str) -> tuple[str, bool]:
    """Remove the query and fragment without decoding or normalizing the path."""

    query_present = "?" in path
    path_without_query = path.partition("?")[0]
    return path_without_query.partition("#")[0], query_present


class RequestEvidenceRecorder:
    """Write raw HTTP and supported WebSocket payload bytes plus metadata."""

    def __init__(self) -> None:
        self._capture_directory: Path | None = None
        self._http_directory: Path | None = None
        self._websocket_directory: Path | None = None
        self._request_metadata_path: Path | None = None
        self._websocket_metadata_path: Path | None = None
        self._run_metadata_path: Path | None = None
        self._addon_snapshot_path: Path | None = None
        self._request_sequence = 0
        self._websocket_sequence = 0
        self._connection_sequences: defaultdict[str, int] = defaultdict(int)
        self._capture_error_count = 0
        self._capture_started_at = _utc_timestamp()

    def load(self, _loader: Any) -> None:
        configured_directory = os.environ.get(CAPTURE_DIRECTORY_ENV)
        if not configured_directory:
            raise RuntimeError(
                f"{CAPTURE_DIRECTORY_ENV} is not set; start mitmdump with "
                "scripts/Start-EgressCapture.ps1."
            )

        capture_directory = Path(configured_directory).expanduser().resolve()
        http_directory = capture_directory / "raw" / "http"
        websocket_directory = capture_directory / "raw" / "websocket"
        request_metadata_path = capture_directory / "requests.jsonl"
        websocket_metadata_path = capture_directory / "websockets.jsonl"
        run_metadata_path = capture_directory / "run.json"

        capture_directory.mkdir(parents=True, exist_ok=True)
        http_directory.mkdir(parents=True, exist_ok=True)
        websocket_directory.mkdir(parents=True, exist_ok=True)
        for path in (request_metadata_path, websocket_metadata_path):
            if path.exists() and path.stat().st_size:
                raise RuntimeError(f"Refusing to append to non-empty metadata: {path}")
        if any(http_directory.iterdir()) or any(websocket_directory.iterdir()):
            raise RuntimeError("Refusing to reuse non-empty raw evidence directories.")

        request_metadata_path.touch(exist_ok=True)
        websocket_metadata_path.touch(exist_ok=True)
        if not run_metadata_path.exists():
            minimal_run = {
                "run_id": capture_directory.name,
                "started_at_utc": self._capture_started_at,
                "operating_system": platform.platform(),
                "python_version": platform.python_version(),
                "mitmproxy_version": version.VERSION,
                "repository_commit_sha": None,
            }
            run_metadata_path.write_bytes(_json_bytes(minimal_run))

        provenance_directory = capture_directory / "provenance"
        provenance_directory.mkdir(parents=True, exist_ok=True)
        addon_snapshot_path = provenance_directory / "capture_requests.py"
        source_path = Path(__file__).resolve()
        if source_path != addon_snapshot_path.resolve():
            source_bytes = source_path.read_bytes()
            if addon_snapshot_path.exists():
                if addon_snapshot_path.read_bytes() != source_bytes:
                    raise RuntimeError(
                        f"Refusing to overwrite a different addon snapshot: {addon_snapshot_path}"
                    )
            else:
                with addon_snapshot_path.open("xb") as handle:
                    handle.write(source_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
        elif not addon_snapshot_path.is_file():
            raise RuntimeError("The running addon snapshot is missing.")

        self._capture_directory = capture_directory
        self._http_directory = http_directory
        self._websocket_directory = websocket_directory
        self._request_metadata_path = request_metadata_path
        self._websocket_metadata_path = websocket_metadata_path
        self._run_metadata_path = run_metadata_path
        self._addon_snapshot_path = addon_snapshot_path
        self._write_manifest(capture_ended_cleanly=False)
        ctx.log.info(f"Request evidence directory: {capture_directory}")

    @staticmethod
    def _header(headers: Any, name: str) -> str | None:
        value = headers.get(name) if headers is not None else None
        return str(value) if value is not None else None

    @staticmethod
    def _request_timestamp(flow: http.HTTPFlow) -> str:
        return _utc_timestamp(getattr(flow.request, "timestamp_start", None))

    @staticmethod
    def _connection_identifier(flow: http.HTTPFlow) -> str:
        return "ws-" + hashlib.sha256(str(flow.id).encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _write_raw(directory: Path, sequence: int, raw: bytes) -> tuple[str, str]:
        digest = _sha256_bytes(raw)
        name = f"{sequence:08d}-{digest}.bin"
        destination = directory / name
        temporary = directory / f".{name}.tmp"
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        return digest, name

    @staticmethod
    def _append_metadata(path: Path, record: dict[str, Any]) -> None:
        with path.open("ab", buffering=0) as handle:
            handle.write(_json_bytes(record))
            os.fsync(handle.fileno())

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            self._record_request(flow)
        except Exception as exc:  # Keep the proxied request untouched on recorder failure.
            self._capture_error_count += 1
            ctx.log.error(
                f"REQUEST EVIDENCE CAPTURE FAILED for flow {flow.id}: "
                f"{type(exc).__name__}: {exc}"
            )

    def _record_request(self, flow: http.HTTPFlow) -> None:
        if self._http_directory is None or self._request_metadata_path is None:
            raise RuntimeError("The evidence recorder was not initialized.")

        raw_body = flow.request.raw_content
        if raw_body is None:
            raw_body = b""
        elif not isinstance(raw_body, bytes):
            raw_body = bytes(raw_body)

        self._request_sequence += 1
        body_sha256, body_name = self._write_raw(
            self._http_directory, self._request_sequence, raw_body
        )
        path, query_present = _safe_request_path(str(flow.request.path))
        record = {
            "schema_version": METADATA_SCHEMA,
            "timestamp": self._request_timestamp(flow),
            "request_sequence_number": self._request_sequence,
            "method": str(flow.request.method),
            "scheme": str(getattr(flow.request, "scheme", "")),
            "host": str(flow.request.pretty_host),
            "port": getattr(flow.request, "port", None),
            "path": path,
            "query_present": query_present,
            "http_version": getattr(flow.request, "http_version", None),
            "content_type": self._header(flow.request.headers, "content-type"),
            "content_encoding": self._header(flow.request.headers, "content-encoding"),
            "transfer_encoding": self._header(flow.request.headers, "transfer-encoding"),
            "body_size": len(raw_body),
            "body_sha256": body_sha256,
            "raw_body_file": f"raw/http/{body_name}",
        }
        self._append_metadata(self._request_metadata_path, record)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Capture the exact reassembled message bytes exposed by mitmproxy."""

        try:
            self._record_websocket_message(flow)
        except Exception as exc:  # Keep the proxied message untouched on failure.
            self._capture_error_count += 1
            ctx.log.error(
                f"WEBSOCKET EVIDENCE CAPTURE FAILED for flow {flow.id}: "
                f"{type(exc).__name__}: {exc}"
            )

    def _record_websocket_message(self, flow: http.HTTPFlow) -> None:
        if self._websocket_directory is None or self._websocket_metadata_path is None:
            raise RuntimeError("The evidence recorder was not initialized.")
        if flow.websocket is None or not flow.websocket.messages:
            raise RuntimeError("The WebSocket hook did not expose a message.")

        message = flow.websocket.messages[-1]
        raw_payload = message.content
        if not isinstance(raw_payload, bytes):
            raw_payload = bytes(raw_payload)
        self._websocket_sequence += 1
        connection_id = self._connection_identifier(flow)
        self._connection_sequences[connection_id] += 1
        payload_sha256, payload_name = self._write_raw(
            self._websocket_directory, self._websocket_sequence, raw_payload
        )
        path, query_present = _safe_request_path(str(flow.request.path))
        opcode = Opcode(message.type)
        classification = "text" if opcode is Opcode.TEXT else "binary"
        record = {
            "schema_version": METADATA_SCHEMA,
            "timestamp": _utc_timestamp(message.timestamp),
            "connection_identifier": connection_id,
            "message_sequence_number": self._websocket_sequence,
            "connection_message_sequence_number": self._connection_sequences[connection_id],
            "frame_sequence_number": None,
            "capture_unit": "mitmproxy_reassembled_message",
            "original_frame_boundaries_preserved": False,
            "direction": "client_to_server" if message.from_client else "server_to_client",
            "payload_classification": classification,
            "payload_size": len(raw_payload),
            "payload_sha256": payload_sha256,
            "raw_payload_file": f"raw/websocket/{payload_name}",
            "host": str(flow.request.pretty_host),
            "path": path,
            "query_present": query_present,
            "injected": bool(message.injected),
        }
        self._append_metadata(self._websocket_metadata_path, record)

    def done(self) -> None:
        """Write the final deterministic local integrity manifest."""

        try:
            self._write_manifest(capture_ended_cleanly=True)
        except Exception as exc:
            ctx.log.error(
                f"EVIDENCE MANIFEST FINALIZATION FAILED: {type(exc).__name__}: {exc}"
            )

    def _write_manifest(self, *, capture_ended_cleanly: bool) -> None:
        required = (
            self._capture_directory,
            self._request_metadata_path,
            self._websocket_metadata_path,
            self._run_metadata_path,
            self._addon_snapshot_path,
        )
        if any(value is None for value in required):
            raise RuntimeError("The evidence recorder was not initialized.")
        capture_directory = self._capture_directory
        assert capture_directory is not None
        run_metadata = json.loads(self._run_metadata_path.read_text(encoding="utf-8"))

        def record(path: Path) -> dict[str, Any]:
            return {
                "path": path.relative_to(capture_directory).as_posix(),
                "sha256": _sha256_file(path),
                "size": path.stat().st_size,
            }

        metadata_files = sorted(
            [
                record(self._run_metadata_path),
                record(self._request_metadata_path),
                record(self._websocket_metadata_path),
            ],
            key=lambda item: item["path"],
        )
        raw_evidence_files = sorted(
            [record(path) for path in (capture_directory / "raw").rglob("*") if path.is_file()],
            key=lambda item: item["path"],
        )
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "run_id": run_metadata.get("run_id", capture_directory.name),
            "capture_start_timestamp": run_metadata.get(
                "started_at_utc", self._capture_started_at
            ),
            "capture_stop_timestamp": _utc_timestamp() if capture_ended_cleanly else None,
            "operating_system": run_metadata.get("operating_system", platform.platform()),
            "python_version": run_metadata.get("python_version", platform.python_version()),
            "mitmproxy_version": run_metadata.get("mitmproxy_version", version.VERSION),
            "repository_commit_sha": run_metadata.get("repository_commit_sha"),
            "addon_file": record(self._addon_snapshot_path),
            "metadata_file_sha256": {
                item["path"]: item["sha256"] for item in metadata_files
            },
            "metadata_files": metadata_files,
            "raw_evidence_files": raw_evidence_files,
            "capture_ended_cleanly": capture_ended_cleanly,
            "capture_error_count": self._capture_error_count,
            "integrity_scope": "local_integrity_only_not_cryptographic_nonrepudiation",
        }
        destination = capture_directory / "evidence-manifest.json"
        temporary = capture_directory / ".evidence-manifest.json.tmp"
        with temporary.open("xb") as handle:
            handle.write(_json_bytes(manifest))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)


addons = [RequestEvidenceRecorder()]
