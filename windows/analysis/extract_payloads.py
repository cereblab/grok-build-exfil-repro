"""Bounded extraction of derived payloads from immutable raw evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import re
import tarfile
import urllib.parse
import zipfile
import zlib
from collections import deque
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any

from .models import EXTRACTION_SCHEMA, ExtractionLimits, sha256_bytes, write_json_atomic


BASE64_PATTERN = re.compile(rb"[A-Za-z0-9+/]*={0,2}\Z")
OPAQUE_CONTENT_TYPES = (
    "application/protobuf",
    "application/x-protobuf",
    "application/vnd.google.protobuf",
    "application/msgpack",
    "application/x-msgpack",
    "application/cbor",
)


class ExtractionLimitReached(RuntimeError):
    """Raised before an extraction output would exceed a configured limit."""


class UnsupportedEncoding(RuntimeError):
    """Raised when an optional decoder is unavailable or an encoding is unknown."""


@dataclass
class _Node:
    data: bytes
    source_raw_file: str
    output_file: str | None
    artifact_id: str | None
    depth: int
    content_type: str | None
    extraction_path: list[str]


def _bounded_zlib_decompress(data: bytes, wbits: int, maximum: int) -> bytes:
    decoder = zlib.decompressobj(wbits)
    output = decoder.decompress(data, maximum + 1)
    if len(output) > maximum or decoder.unconsumed_tail:
        raise ExtractionLimitReached("decompressed output exceeds the active byte limit")
    remaining = maximum + 1 - len(output)
    output += decoder.flush(remaining)
    if len(output) > maximum:
        raise ExtractionLimitReached("decompressed output exceeds the active byte limit")
    if not decoder.eof:
        raise zlib.error("compressed stream ended before the end-of-stream marker")
    return output


def _strict_base64(value: bytes, minimum_decoded_length: int) -> bytes | None:
    candidate = value.strip()
    if not candidate or len(candidate) % 4 != 0:
        return None
    if not BASE64_PATTERN.fullmatch(candidate) or b"=" in candidate[:-2]:
        return None
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) < minimum_decoded_length:
        return None
    return decoded


class ExtractionEngine:
    """Create bounded, deduplicated derived artifacts without touching raw input."""

    def __init__(
        self,
        run_directory: Path,
        derived_directory: Path,
        limits: ExtractionLimits | None = None,
    ) -> None:
        self.run_directory = run_directory.resolve()
        self.derived_directory = derived_directory.resolve()
        self.limits = limits or ExtractionLimits()
        self.limits.validate()
        if self.derived_directory == self.run_directory or self.derived_directory.is_relative_to(
            self.run_directory
        ):
            raise ValueError("Derived evidence must be outside the raw run directory.")
        if self.derived_directory.exists() and any(self.derived_directory.iterdir()):
            raise FileExistsError(
                f"Refusing to reuse a non-empty derived directory: {self.derived_directory}"
            )
        self.artifact_directory = self.derived_directory / "artifacts"
        self.artifact_directory.mkdir(parents=True, exist_ok=True)
        self.result: dict[str, Any] = {
            "schema_version": EXTRACTION_SCHEMA,
            "raw_run_directory": str(self.run_directory),
            "derived_directory": str(self.derived_directory),
            "limits": self.limits.to_dict(),
            "raw_files_processed": [],
            "artifacts": [],
            "operations": [],
            "extraction_failures": [],
            "unsupported_encodings": [],
            "opaque_formats": [],
            "processing_limits_reached": [],
            "total_expanded_bytes": 0,
        }
        self._artifacts_by_hash: dict[str, dict[str, Any]] = {}
        self._queue: deque[_Node] = deque()
        self._processed_artifact_ids: set[str] = set()

    def run(self) -> dict[str, Any]:
        metadata = self._load_capture_metadata()
        for raw_relative in sorted(metadata):
            raw_path = self.run_directory / raw_relative
            if not raw_path.is_file():
                self._failure(
                    _Node(b"", raw_relative, None, None, 0, None, []),
                    "read_raw_evidence",
                    FileNotFoundError(raw_relative),
                )
                continue
            data = raw_path.read_bytes()
            item = metadata[raw_relative]
            node = _Node(
                data=data,
                source_raw_file=raw_relative,
                output_file=None,
                artifact_id=None,
                depth=0,
                content_type=item.get("content_type"),
                extraction_path=[raw_relative],
            )
            self.result["raw_files_processed"].append(
                {"path": raw_relative, "size": len(data), "sha256": sha256_bytes(data)}
            )
            content_encoding = item.get("content_encoding")
            if content_encoding:
                self._decode_http_content_encoding(node, str(content_encoding))
            self._queue.append(node)

        while self._queue:
            node = self._queue.popleft()
            if node.artifact_id is not None:
                if node.artifact_id in self._processed_artifact_ids:
                    continue
                self._processed_artifact_ids.add(node.artifact_id)
            self._extract_application_wrappers(node)

        self.result["artifacts"] = sorted(
            self.result["artifacts"], key=lambda item: item["artifact_id"]
        )
        write_json_atomic(self.derived_directory / "extraction-result.json", self.result)
        return self.result

    def _load_capture_metadata(self) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        metadata_specs = (
            ("requests.jsonl", "raw_body_file"),
            ("websockets.jsonl", "raw_payload_file"),
        )
        for metadata_name, file_field in metadata_specs:
            path = self.run_directory / metadata_name
            if not path.is_file():
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    relative = str(record[file_field])
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    self.result["extraction_failures"].append(
                        {
                            "source_raw_file": None,
                            "parent_derived_artifact": None,
                            "extraction_operation": "read_capture_metadata",
                            "extraction_depth": 0,
                            "byte_offset": None,
                            "output_file": None,
                            "output_sha256": None,
                            "output_byte_length": None,
                            "success": False,
                            "error_message": f"{metadata_name}:{line_number}: {exc}",
                        }
                    )
                    continue
                if Path(relative).is_absolute() or ".." in Path(relative).parts:
                    raise ValueError(f"Unsafe raw evidence path in metadata: {relative}")
                records[Path(relative).as_posix()] = record
        return records

    def _maximum_output(self, input_size: int, *, compressed: bool) -> int:
        remaining = (
            self.limits.maximum_total_expanded_bytes
            - int(self.result["total_expanded_bytes"])
        )
        maximum = min(self.limits.maximum_size_per_derived_artifact, remaining)
        if compressed:
            ratio_maximum = max(1, int(input_size * self.limits.decompression_ratio_limit))
            maximum = min(maximum, ratio_maximum)
        if maximum < 0:
            maximum = 0
        return maximum

    def _derive(
        self,
        parent: _Node,
        data: bytes,
        operation: str,
        *,
        byte_offset: int | None = None,
        context: dict[str, Any] | None = None,
        compressed: bool = False,
        content_type: str | None = None,
    ) -> _Node | None:
        depth = parent.depth + 1
        try:
            if depth > self.limits.maximum_extraction_depth:
                raise ExtractionLimitReached("maximum extraction depth reached")
            if len(data) > self.limits.maximum_size_per_derived_artifact:
                raise ExtractionLimitReached("maximum size per derived artifact reached")
            if compressed and len(data) > max(
                1, int(len(parent.data) * self.limits.decompression_ratio_limit)
            ):
                raise ExtractionLimitReached("decompression ratio limit reached")
            if int(self.result["total_expanded_bytes"]) + len(data) > (
                self.limits.maximum_total_expanded_bytes
            ):
                raise ExtractionLimitReached("maximum total expanded bytes reached")

            digest = sha256_bytes(data)
            existing = self._artifacts_by_hash.get(digest)
            if existing is None and len(self._artifacts_by_hash) >= (
                self.limits.maximum_derived_artifacts
            ):
                raise ExtractionLimitReached("maximum derived artifact count reached")

            self.result["total_expanded_bytes"] += len(data)
            parent_reference = parent.output_file
            relationship = {
                "source_raw_file": parent.source_raw_file,
                "parent_derived_artifact": parent_reference,
                "extraction_operation": operation,
                "extraction_depth": depth,
                "byte_offset": byte_offset,
                "context": context or {},
            }
            duplicate = existing is not None
            if existing is None:
                artifact_id = f"artifact-{len(self._artifacts_by_hash) + 1:08d}"
                name = f"{artifact_id}-{digest}.bin"
                output_path = self.artifact_directory / name
                with output_path.open("xb") as handle:
                    handle.write(data)
                existing = {
                    "artifact_id": artifact_id,
                    "output_file": output_path.relative_to(self.derived_directory).as_posix(),
                    "sha256": digest,
                    "byte_length": len(data),
                    "relationships": [relationship],
                }
                self._artifacts_by_hash[digest] = existing
                self.result["artifacts"].append(existing)
            else:
                if relationship not in existing["relationships"]:
                    existing["relationships"].append(relationship)

            operation_record = {
                **relationship,
                "output_file": existing["output_file"],
                "output_sha256": digest,
                "output_byte_length": len(data),
                "success": True,
                "error_message": None,
                "duplicate_content": duplicate,
            }
            self.result["operations"].append(operation_record)
            node = _Node(
                data=data,
                source_raw_file=parent.source_raw_file,
                output_file=existing["output_file"],
                artifact_id=existing["artifact_id"],
                depth=depth,
                content_type=content_type,
                extraction_path=parent.extraction_path + [operation],
            )
            if not duplicate:
                self._queue.append(node)
            return node
        except ExtractionLimitReached as exc:
            self._failure(parent, operation, exc, byte_offset=byte_offset, context=context)
            self.result["processing_limits_reached"].append(
                {
                    "source_raw_file": parent.source_raw_file,
                    "operation": operation,
                    "limit": str(exc),
                }
            )
            return None

    def _failure(
        self,
        parent: _Node,
        operation: str,
        error: Exception,
        *,
        byte_offset: int | None = None,
        context: dict[str, Any] | None = None,
        status: str = "failed",
    ) -> None:
        record = {
            "source_raw_file": parent.source_raw_file,
            "parent_derived_artifact": parent.output_file,
            "extraction_operation": operation,
            "extraction_depth": parent.depth + 1,
            "byte_offset": byte_offset,
            "context": context or {},
            "output_file": None,
            "output_sha256": None,
            "output_byte_length": None,
            "success": False,
            "error_message": f"{type(error).__name__}: {error}",
            "status": status,
        }
        self.result["operations"].append(record)
        self.result["extraction_failures"].append(record)

    def _decode_http_content_encoding(self, root: _Node, header: str) -> None:
        encodings = [item.strip().lower() for item in header.split(",") if item.strip()]
        current = root
        for encoding in reversed(encodings):
            operation = f"http_content_encoding:{encoding}"
            maximum = self._maximum_output(len(current.data), compressed=True)
            try:
                if encoding in ("identity",):
                    continue
                if encoding in ("gzip", "x-gzip"):
                    decoded = _bounded_zlib_decompress(
                        current.data, zlib.MAX_WBITS | 16, maximum
                    )
                elif encoding == "deflate":
                    try:
                        decoded = _bounded_zlib_decompress(
                            current.data, zlib.MAX_WBITS, maximum
                        )
                    except zlib.error:
                        operation = "http_content_encoding:deflate_raw"
                        decoded = _bounded_zlib_decompress(
                            current.data, -zlib.MAX_WBITS, maximum
                        )
                elif encoding == "br":
                    decoded = self._brotli_decompress(current.data, maximum)
                else:
                    raise UnsupportedEncoding(f"unsupported HTTP content encoding: {encoding}")
                next_node = self._derive(
                    current,
                    decoded,
                    operation,
                    compressed=True,
                    content_type=current.content_type,
                )
                if next_node is None:
                    return
                current = next_node
            except UnsupportedEncoding as exc:
                self.result["unsupported_encodings"].append(
                    {"source_raw_file": current.source_raw_file, "encoding": encoding}
                )
                self._failure(current, operation, exc, status="undecoded")
                return
            except (ExtractionLimitReached, zlib.error, OSError, ValueError) as exc:
                self._failure(current, operation, exc, status="undecoded")
                if isinstance(exc, ExtractionLimitReached):
                    self.result["processing_limits_reached"].append(
                        {
                            "source_raw_file": current.source_raw_file,
                            "operation": operation,
                            "limit": str(exc),
                        }
                    )
                return

    @staticmethod
    def _brotli_decompress(data: bytes, maximum: int) -> bytes:
        try:
            import brotli
        except ImportError as exc:
            raise UnsupportedEncoding(
                "Brotli decoder is unavailable; install the documented Brotli dependency"
            ) from exc
        decoder = brotli.Decompressor()
        output = bytearray()
        for offset in range(0, len(data), 64 * 1024):
            output.extend(decoder.process(data[offset : offset + 64 * 1024]))
            if len(output) > maximum:
                raise ExtractionLimitReached("decompressed output exceeds the active byte limit")
        if hasattr(decoder, "is_finished") and not decoder.is_finished():
            raise ValueError("Brotli stream ended before completion")
        return bytes(output)

    def _extract_application_wrappers(self, node: _Node) -> None:
        content_type = (node.content_type or "").lower()
        if any(content_type.startswith(value) for value in OPAQUE_CONTENT_TYPES):
            self.result["opaque_formats"].append(
                {
                    "source_raw_file": node.source_raw_file,
                    "artifact": node.output_file,
                    "content_type": node.content_type,
                    "classification": "opaque_binary",
                }
            )
            return

        if node.data.startswith(b"\x1f\x8b"):
            maximum = self._maximum_output(len(node.data), compressed=True)
            try:
                decoded = _bounded_zlib_decompress(
                    node.data, zlib.MAX_WBITS | 16, maximum
                )
                self._derive(node, decoded, "application_gzip", compressed=True)
            except (ExtractionLimitReached, zlib.error) as exc:
                self._failure(node, "application_gzip", exc, status="undecoded")

        if node.data.startswith(b"PK\x03\x04"):
            self._extract_zip(node)
        if len(node.data) >= 512 and node.data[257:262] == b"ustar":
            self._extract_tar(node)
        if content_type.startswith("multipart/form-data"):
            self._extract_multipart(node)
        if content_type.startswith("application/x-www-form-urlencoded"):
            self._extract_urlencoded(node)
        if content_type.startswith("application/json") or node.data.lstrip().startswith(
            (b"{", b"[", b'"')
        ):
            self._extract_json(node)

        decoded = _strict_base64(
            node.data, self.limits.base64_minimum_decoded_length
        )
        if decoded is not None:
            self._derive(node, decoded, "strict_base64")

    def _extract_json(self, node: _Node) -> None:
        try:
            value = json.loads(node.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._failure(node, "json_parse", exc, status="undecoded")
            return

        def walk(item: Any, pointer: str) -> None:
            if isinstance(item, str):
                encoded = item.encode("utf-8")
                decoded = _strict_base64(
                    encoded, self.limits.base64_minimum_decoded_length
                )
                if decoded is not None:
                    self._derive(
                        node,
                        decoded,
                        "json_base64_string",
                        context={"json_property_path": pointer or "/"},
                    )
                elif pointer == "":
                    self._derive(
                        node,
                        encoded,
                        "json_string",
                        context={"json_property_path": "/"},
                    )
            elif isinstance(item, dict):
                for key in sorted(item):
                    escaped = str(key).replace("~", "~0").replace("/", "~1")
                    walk(item[key], f"{pointer}/{escaped}")
            elif isinstance(item, list):
                for index, child in enumerate(item):
                    walk(child, f"{pointer}/{index}")

        walk(value, "")

    def _extract_multipart(self, node: _Node) -> None:
        try:
            message = BytesParser(policy=email_policy).parsebytes(
                f"Content-Type: {node.content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
                    "ascii"
                )
                + node.data
            )
            if not message.is_multipart():
                raise ValueError("multipart body did not parse into parts")
            for index, part in enumerate(message.iter_parts()):
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = str(part.get_payload()).encode("utf-8")
                self._derive(
                    node,
                    payload,
                    "multipart_part",
                    context={
                        "multipart_field_name": part.get_param(
                            "name", header="content-disposition"
                        ),
                        "multipart_filename": part.get_filename(),
                        "multipart_part_index": index,
                    },
                    content_type=part.get_content_type(),
                )
        except (OSError, UnicodeError, ValueError) as exc:
            self._failure(node, "multipart_parse", exc, status="undecoded")

    def _extract_urlencoded(self, node: _Node) -> None:
        try:
            pairs = urllib.parse.parse_qsl(
                node.data,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=self.limits.maximum_derived_artifacts,
            )
            for index, (name, value) in enumerate(pairs):
                name_bytes = name if isinstance(name, bytes) else name.encode("utf-8")
                value_bytes = value if isinstance(value, bytes) else value.encode("utf-8")
                self._derive(
                    node,
                    value_bytes,
                    "urlencoded_field",
                    context={
                        "field_name": name_bytes.decode("utf-8", errors="replace"),
                        "field_index": index,
                    },
                )
        except (UnicodeError, ValueError) as exc:
            self._failure(node, "urlencoded_parse", exc, status="undecoded")

    def _extract_zip(self, node: _Node) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(node.data)) as archive:
                for member in sorted(archive.infolist(), key=lambda item: item.filename):
                    if member.is_dir():
                        continue
                    if member.file_size > self._maximum_output(
                        member.compress_size, compressed=True
                    ):
                        raise ExtractionLimitReached(
                            f"ZIP member exceeds extraction limits: {member.filename}"
                        )
                    with archive.open(member) as handle:
                        payload = handle.read(
                            self.limits.maximum_size_per_derived_artifact + 1
                        )
                    self._derive(
                        node,
                        payload,
                        "zip_member",
                        context={"archive_member": member.filename},
                        compressed=True,
                    )
        except (ExtractionLimitReached, OSError, RuntimeError, zipfile.BadZipFile) as exc:
            self._failure(node, "zip_extract", exc, status="undecoded")

    def _extract_tar(self, node: _Node) -> None:
        try:
            with tarfile.open(fileobj=io.BytesIO(node.data), mode="r:") as archive:
                for member in sorted(archive.getmembers(), key=lambda item: item.name):
                    if not member.isfile():
                        continue
                    if member.size > self.limits.maximum_size_per_derived_artifact:
                        raise ExtractionLimitReached(
                            f"tar member exceeds extraction limits: {member.name}"
                        )
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise OSError(f"tar member could not be read: {member.name}")
                    payload = handle.read(
                        self.limits.maximum_size_per_derived_artifact + 1
                    )
                    self._derive(
                        node,
                        payload,
                        "tar_member",
                        context={"archive_member": member.name},
                    )
        except (ExtractionLimitReached, OSError, tarfile.TarError) as exc:
            self._failure(node, "tar_extract", exc, status="undecoded")


def extract_run(
    run_directory: Path,
    derived_directory: Path,
    limits: ExtractionLimits | None = None,
) -> dict[str, Any]:
    return ExtractionEngine(run_directory, derived_directory, limits).run()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("derived_directory", type=Path)
    parser.add_argument("--maximum-extraction-depth", type=int, default=6)
    parser.add_argument("--maximum-total-expanded-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--maximum-derived-artifacts", type=int, default=1_000)
    parser.add_argument("--maximum-size-per-derived-artifact", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--decompression-ratio-limit", type=float, default=100.0)
    parser.add_argument("--base64-minimum-decoded-length", type=int, default=12)
    args = parser.parse_args()
    limits = ExtractionLimits(
        maximum_extraction_depth=args.maximum_extraction_depth,
        maximum_total_expanded_bytes=args.maximum_total_expanded_bytes,
        maximum_derived_artifacts=args.maximum_derived_artifacts,
        maximum_size_per_derived_artifact=args.maximum_size_per_derived_artifact,
        decompression_ratio_limit=args.decompression_ratio_limit,
        base64_minimum_decoded_length=args.base64_minimum_decoded_length,
    )
    result = extract_run(args.run_directory, args.derived_directory, limits)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
