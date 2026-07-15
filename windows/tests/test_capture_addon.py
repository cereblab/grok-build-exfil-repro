from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

WINDOWS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WINDOWS_ROOT))

from mitmproxy import ctx
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

from addon.capture_requests import RequestEvidenceRecorder
from analysis.verify_manifest import verify_manifest


class _TestLog:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def info(self, _message: str) -> None:
        return

    def error(self, message: str) -> None:
        self.errors.append(message)


class RequestEvidenceRecorderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="egress-addon-test-")
        self.capture_directory = Path(self.temporary.name)
        self.previous_capture_dir = os.environ.get("EGRESS_CAPTURE_DIR")
        self.previous_log = getattr(ctx, "log", None)
        self.had_log = hasattr(ctx, "log")
        self.test_log = _TestLog()
        os.environ["EGRESS_CAPTURE_DIR"] = self.temporary.name
        ctx.log = self.test_log
        self.recorder = RequestEvidenceRecorder()
        self.recorder.load(None)

    def tearDown(self) -> None:
        if self.previous_capture_dir is None:
            os.environ.pop("EGRESS_CAPTURE_DIR", None)
        else:
            os.environ["EGRESS_CAPTURE_DIR"] = self.previous_capture_dir
        if self.had_log:
            ctx.log = self.previous_log
        else:
            delattr(ctx, "log")
        self.temporary.cleanup()

    @staticmethod
    def _request(**overrides: object) -> SimpleNamespace:
        values: dict[str, object] = {
            "timestamp_start": 1704067200.0,
            "raw_content": b"",
            "method": "POST",
            "scheme": "https",
            "pretty_host": "api.example.test",
            "port": 443,
            "path": "/upload",
            "http_version": "HTTP/2.0",
            "headers": {},
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_records_metadata_and_exact_raw_body_bytes(self) -> None:
        body = b"\x00\xffcompressed-looking\x10\x80"
        flow = SimpleNamespace(
            id="flow-1",
            request=self._request(
                raw_content=body,
                path="/upload?session=TOP-SECRET-QUERY",
                headers={
                    "content-type": "application/octet-stream",
                    "content-encoding": "gzip",
                    "transfer-encoding": "chunked",
                    "authorization": "Bearer MUST-NOT-BE-STORED",
                    "cookie": "session=MUST-NOT-BE-STORED",
                },
            ),
        )
        self.recorder.request(flow)

        self.assertEqual([], self.test_log.errors)
        metadata_bytes = (self.capture_directory / "requests.jsonl").read_bytes()
        record = json.loads(metadata_bytes)
        expected_hash = hashlib.sha256(body).hexdigest()
        self.assertEqual("2024-01-01T00:00:00.000Z", record["timestamp"])
        self.assertEqual(1, record["request_sequence_number"])
        self.assertEqual("POST", record["method"])
        self.assertEqual("https", record["scheme"])
        self.assertEqual("api.example.test", record["host"])
        self.assertEqual(443, record["port"])
        self.assertEqual("/upload", record["path"])
        self.assertTrue(record["query_present"])
        self.assertEqual("application/octet-stream", record["content_type"])
        self.assertEqual("gzip", record["content_encoding"])
        self.assertEqual("chunked", record["transfer_encoding"])
        self.assertIsNone(record["declared_content_length"])
        self.assertTrue(record["raw_content_available"])
        self.assertIsNone(record["body_truncated"])
        self.assertEqual(len(body), record["body_size"])
        self.assertEqual(expected_hash, record["body_sha256"])
        self.assertEqual(body, (self.capture_directory / record["raw_body_file"]).read_bytes())
        self.assertNotIn(b"TOP-SECRET-QUERY", metadata_bytes)
        self.assertNotIn(b"MUST-NOT-BE-STORED", metadata_bytes)
        self.assertNotIn(b"authorization", metadata_bytes.lower())
        self.assertNotIn(b"cookie", metadata_bytes.lower())

    def test_content_length_records_explicit_nontruncation_or_truncation(self) -> None:
        complete = SimpleNamespace(
            id="complete",
            request=self._request(raw_content=b"four", headers={"content-length": "4"}),
        )
        truncated = SimpleNamespace(
            id="truncated",
            request=self._request(raw_content=b"two", headers={"content-length": "4"}),
        )
        self.recorder.request(complete)
        self.recorder.request(truncated)
        records = [json.loads(line) for line in (self.capture_directory / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertFalse(records[0]["body_truncated"])
        self.assertTrue(records[1]["body_truncated"])

    def test_websocket_text_binary_directions_sequences_and_empty_payload(self) -> None:
        messages: list[WebSocketMessage] = []
        flow = SimpleNamespace(
            id="websocket-flow",
            request=self._request(path="/socket?token=DO-NOT-STORE"),
            websocket=SimpleNamespace(messages=messages),
        )
        cases = (
            (Opcode.TEXT, True, b"text payload", "text", "client_to_server"),
            (Opcode.BINARY, False, b"\x00\xff\x10", "binary", "server_to_client"),
            (Opcode.TEXT, True, b"", "text", "client_to_server"),
            (Opcode.TEXT, True, b"", "text", "client_to_server"),
        )
        for index, (opcode, from_client, payload, _classification, _direction) in enumerate(
            cases, start=1
        ):
            messages.append(
                WebSocketMessage(
                    opcode,
                    from_client,
                    payload,
                    timestamp=1704067200.0 + index,
                )
            )
            self.recorder.websocket_message(flow)

        records = [
            json.loads(line)
            for line in (self.capture_directory / "websockets.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(4, len(records))
        self.assertEqual([], self.test_log.errors)
        self.assertEqual([1, 2, 3, 4], [item["message_sequence_number"] for item in records])
        self.assertEqual(
            [1, 2, 3, 4], [item["connection_message_sequence_number"] for item in records]
        )
        self.assertEqual(1, len({item["connection_identifier"] for item in records}))
        self.assertEqual(4, len({item["raw_payload_file"] for item in records}))
        for record, case in zip(records, cases, strict=True):
            payload = case[2]
            self.assertEqual(case[3], record["payload_classification"])
            self.assertEqual(case[4], record["direction"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), record["payload_sha256"])
            self.assertEqual(payload, (self.capture_directory / record["raw_payload_file"]).read_bytes())
            self.assertEqual("/socket", record["path"])
            self.assertIsNone(record["frame_sequence_number"])
            self.assertFalse(record["original_frame_boundaries_preserved"])
        self.assertNotIn(
            "DO-NOT-STORE",
            (self.capture_directory / "websockets.jsonl").read_text(encoding="utf-8"),
        )

    def test_final_manifest_verifies_and_detects_modification(self) -> None:
        body = b"manifest body"
        flow = SimpleNamespace(id="flow-manifest", request=self._request(raw_content=body))
        self.recorder.request(flow)
        self.recorder.done()

        manifest_path = self.capture_directory / "evidence-manifest.json"
        first_bytes = manifest_path.read_bytes()
        manifest = json.loads(first_bytes)
        self.assertTrue(manifest["capture_ended_cleanly"])
        self.assertEqual(1, len(manifest["raw_evidence_files"]))
        self.assertTrue(verify_manifest(self.capture_directory)["valid"])

        self.recorder._write_manifest(capture_ended_cleanly=True)
        self.assertNotEqual(first_bytes, manifest_path.read_bytes())
        raw_path = self.capture_directory / manifest["raw_evidence_files"][0]["path"]
        raw_path.write_bytes(body + b"tampered")
        verification = verify_manifest(self.capture_directory)
        self.assertFalse(verification["valid"])
        self.assertEqual(1, len(verification["modified_files"]))


if __name__ == "__main__":
    unittest.main()
