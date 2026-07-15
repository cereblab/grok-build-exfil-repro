"""Validate adapters and run one client process with PID-scoped Windows monitoring."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import jsonschema

from .models import write_json_atomic


ADAPTER_SCHEMA_VERSION = "egress-adapter/v1"
ALLOWED_PLACEHOLDERS = {
    "working_directory",
    "prompt",
    "proxy_port",
    "ca_certificate",
}
CONTROLLED_ENVIRONMENT_VARIABLES = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "CODEX_CA_CERTIFICATE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
}
CREDENTIAL_ENVIRONMENT_VARIABLES = {
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "GEMINI_API_KEY",
}
BASE_ENVIRONMENT_ALLOWLIST = {
    "APPDATA",
    "CODEX_HOME",
    "CODEX_SQLITE_HOME",
    "COMSPEC",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
}
PROHIBITED_ADAPTER_ENVIRONMENT_VARIABLES = CREDENTIAL_ENVIRONMENT_VARIABLES | {
    "AUTHORIZATION",
    "COOKIE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def load_adapter(adapter_path: Path, schema_path: Path) -> dict[str, Any]:
    adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(adapter)
    validate_adapter_semantics(adapter)
    return adapter


def _placeholders(value: str) -> set[str]:
    return set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", value))


def validate_adapter_semantics(adapter: Mapping[str, Any]) -> None:
    if adapter.get("schema_version") != ADAPTER_SCHEMA_VERSION:
        raise ValueError("Unsupported adapter schema version.")
    template = list(adapter.get("noninteractive_command_template", []))
    template_placeholders = set().union(*(_placeholders(item) for item in template))
    if "working_directory" not in template_placeholders:
        raise ValueError("Command template must contain {working_directory}.")
    if "prompt" not in template_placeholders:
        raise ValueError("Command template must contain {prompt}.")
    all_values = template + list(adapter.get("environment_variables", {}).values())
    unknown = set().union(*(_placeholders(item) for item in all_values)) - ALLOWED_PLACEHOLDERS
    if unknown:
        raise ValueError(f"Unknown adapter placeholders: {sorted(unknown)}")
    prohibited = {
        name.upper()
        for name in adapter.get("environment_variables", {})
        if name.upper() in PROHIBITED_ADAPTER_ENVIRONMENT_VARIABLES
    }
    if prohibited:
        raise ValueError(f"Credential environment variables are prohibited: {sorted(prohibited)}")
    inherited_secrets = {
        name.upper()
        for name in adapter.get("inherited_secret_environment_variables", [])
    }
    unsupported_secrets = inherited_secrets - CREDENTIAL_ENVIRONMENT_VARIABLES
    if unsupported_secrets:
        raise ValueError(
            "Unsupported inherited secret environment variables: "
            f"{sorted(unsupported_secrets)}"
        )
    duplicated_secrets = inherited_secrets & {
        name.upper() for name in adapter.get("environment_variables", {})
    }
    if duplicated_secrets:
        raise ValueError(
            "Inherited secrets must not also be adapter environment variables: "
            f"{sorted(duplicated_secrets)}"
        )
    for pattern in adapter.get("authentication_failure_patterns", []):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"Invalid authentication failure pattern {pattern!r}: {exc}"
            ) from exc
    for classification in adapter.get("authentication_failure_classifications", []):
        try:
            re.compile(classification["pattern"])
        except re.error as exc:
            raise ValueError(
                "Invalid authentication failure classification pattern "
                f"{classification['pattern']!r}: {exc}"
            ) from exc


def substitute(value: str, replacements: Mapping[str, Any]) -> str:
    missing = _placeholders(value) - replacements.keys()
    if missing:
        raise ValueError(f"Missing placeholder values: {sorted(missing)}")
    rendered = value.format_map({key: str(item) for key, item in replacements.items()})
    unresolved = _placeholders(rendered)
    if unresolved:
        raise ValueError(f"Unresolved placeholders: {sorted(unresolved)}")
    return rendered


def resolve_executable(executable: str) -> str | None:
    candidate = Path(executable).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        return str(candidate.absolute()) if candidate.is_file() else None
    return shutil.which(executable)


def redact_text(value: str) -> str:
    redacted = value
    patterns = (
        (r"(?im)^(authorization|proxy-authorization|cookie|set-cookie)\s*[:=].*$", r"\1: [REDACTED]"),
        (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]"),
        (r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED_API_KEY]"),
        (r"(?im)^(GEMINI_API_KEY\s*=\s*).*$", r"\1[REDACTED]"),
        (r"\bAIza[A-Za-z0-9_-]{20,}\b", "[REDACTED_API_KEY]"),
        (r"(?i)(\"?(?:access|refresh|id|session)[_-]?token\"?\s*[:=]\s*\"?)[^\"\s,;]+", r"\1[REDACTED]"),
        (r"(?i)(\"?(?:session[_-]?id|organization[_-]?id|account[_-]?id)\"?\s*[:=]\s*\"?)[^\"\s,;]+", r"\1[REDACTED]"),
        (r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b(?:org|proj)_[A-Za-z0-9_-]{8,}\b", "[REDACTED_IDENTIFIER]"),
    )
    for pattern, replacement in patterns:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def _read_secret_environment_variable(
    name: str, base_environment: Mapping[str, str]
) -> str | None:
    for existing_name, value in base_environment.items():
        if existing_name.upper() == name.upper() and str(value).strip():
            return str(value)
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
        return str(value) if str(value).strip() else None
    except (FileNotFoundError, OSError):
        return None


def verify_inherited_secret_availability(
    adapter: Mapping[str, Any],
    base_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    names = list(adapter.get("inherited_secret_environment_variables", []))
    source = os.environ if base_environment is None else base_environment
    available_count = sum(
        _read_secret_environment_variable(name, source) is not None for name in names
    )
    return {
        "required_count": len(names),
        "available_count": available_count,
        "all_available": available_count == len(names),
    }


def verify_authentication_selection(adapter: Mapping[str, Any]) -> dict[str, Any]:
    selection = adapter.get("authentication_selection")
    if not selection:
        return {
            "configured": False,
            "settings_file": None,
            "selected_value": None,
            "expected_value": None,
            "matches": True,
        }
    settings_path = Path(str(selection["settings_file"])).expanduser().resolve()
    result: dict[str, Any] = {
        "configured": True,
        "settings_file": str(settings_path),
        "selected_value": None,
        "expected_value": str(selection["expected_value"]),
        "matches": False,
    }
    if not settings_path.is_file():
        result["error"] = "Authentication selection settings file is missing."
        return result
    try:
        current: Any = json.loads(settings_path.read_text(encoding="utf-8-sig"))
        for component in selection["json_path"]:
            if not isinstance(current, Mapping) or component not in current:
                result["error"] = "Authentication selection field is missing."
                return result
            current = current[component]
        if not isinstance(current, str):
            result["error"] = "Authentication selection value is not a string."
            return result
        result["selected_value"] = current
        result["matches"] = current == result["expected_value"]
        if not result["matches"]:
            result["error"] = "Selected authentication method does not match the adapter."
        return result
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        result["error"] = f"Authentication selection could not be read: {type(exc).__name__}."
        return result


def build_child_environment(
    base_environment: Mapping[str, str],
    adapter_environment: Mapping[str, str],
    inherited_secret_names: list[str] | tuple[str, ...] = (),
) -> dict[str, str]:
    environment = {
        name: value
        for name, value in base_environment.items()
        if name.upper() in BASE_ENVIRONMENT_ALLOWLIST
    }
    for existing in list(environment):
        if existing.upper() in CONTROLLED_ENVIRONMENT_VARIABLES:
            environment.pop(existing, None)
    environment.update(adapter_environment)
    for name in inherited_secret_names:
        if name.upper() not in CREDENTIAL_ENVIRONMENT_VARIABLES:
            raise ValueError("The adapter requested an unsupported inherited secret.")
        value = _read_secret_environment_variable(name, base_environment)
        if value is None:
            raise ValueError("A required inherited secret is unavailable.")
        environment[name] = value
    return environment


def prepare_invocation(
    adapter: Mapping[str, Any],
    *,
    working_directory: Path,
    prompt: str,
    proxy_port: int,
    ca_certificate: Path,
) -> dict[str, Any]:
    replacements = {
        "working_directory": str(working_directory.resolve()),
        "prompt": prompt,
        "proxy_port": proxy_port,
        "ca_certificate": str(ca_certificate.resolve()),
    }
    resolved = resolve_executable(str(adapter["executable"]))
    arguments = [
        substitute(item, replacements)
        for item in adapter["noninteractive_command_template"]
    ]
    adapter_environment = {
        name: substitute(value, replacements)
        for name, value in adapter["environment_variables"].items()
    }
    executable_for_display = resolved or str(adapter["executable"])
    return {
        "product": adapter["product_name"],
        "vendor": adapter["vendor"],
        "client_surface": adapter["client_surface"],
        "executable": executable_for_display,
        "executable_found": resolved is not None,
        "arguments": arguments,
        "version_command": list(adapter["version_command"]),
        "redacted_command": redact_text(
            subprocess.list2cmdline([executable_for_display, *arguments])
        ),
        "environment_variables": adapter_environment,
        "inherited_secret_environment_variables": list(
            adapter.get("inherited_secret_environment_variables", [])
        ),
        "prompt": prompt,
        "working_directory": str(working_directory.resolve()),
        "timeout_seconds": int(adapter["timeout_seconds"]),
        "expected_vendor_hosts": list(adapter["expected_vendor_hosts"]),
        "authentication_mode": adapter["authentication_mode"],
        "authentication_failure_patterns": list(
            adapter.get("authentication_failure_patterns", [])
        ),
        "authentication_failure_classifications": list(
            adapter.get("authentication_failure_classifications", [])
        ),
        "model_identifier": adapter.get("model_identifier"),
        "approval_mode": adapter["approval_mode"],
        "sandbox_mode": adapter["sandbox_mode"],
    }


def verify_client_version(
    prepared: Mapping[str, Any],
    *,
    timeout_seconds: float = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    """Execute only the adapter's local version command and preserve its result."""

    if runner is None:
        runner = subprocess.run
    executable = str(prepared["executable"])
    resolved = resolve_executable(executable)
    command = list(prepared.get("version_command") or [])
    result: dict[str, Any] = {
        "schema_version": "egress-client-version/v1",
        "executable_path": resolved or executable,
        "version_command": [resolved or executable, *command],
        "version_stdout": "",
        "version_stderr": "",
        "version_exit_code": None,
        "normalized_client_version": None,
        "verified": False,
        "error": None,
    }
    if resolved is None:
        result["error"] = f"Executable not found: {executable}"
        return result
    if not command:
        result["error"] = "Adapter version_command is empty."
        return result
    try:
        completed = runner(
            [resolved, *command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        stdout = redact_text(completed.stdout or "")
        stderr = redact_text(completed.stderr or "")
        result.update(
            version_stdout=stdout,
            version_stderr=stderr,
            version_exit_code=completed.returncode,
        )
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if completed.returncode == 0 and lines:
            result["normalized_client_version"] = lines[0]
            result["verified"] = True
        else:
            result["error"] = "Version command did not exit zero with non-empty stdout."
    except Exception as exc:
        result["error"] = redact_text(f"{type(exc).__name__}: {exc}")
    return result


def gate_identity_changes(
    saved: Mapping[str, Any], current: Mapping[str, Any]
) -> list[str]:
    """Return safety-critical executable/version fields that changed."""

    keys = ("executable_path", "normalized_client_version")
    return [key for key in keys if saved.get(key) != current.get(key)]


def reserve_run_directories(
    *,
    canary_root: Path,
    capture_root: Path,
    derived_root: Path,
    test_id: str,
    run_id: str | None = None,
    reuse: bool = False,
) -> dict[str, str]:
    if run_id is not None and not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        raise ValueError("run_id may contain only letters, digits, dot, underscore, and dash.")
    attempts = 1 if run_id is not None else 10
    for _ in range(attempts):
        candidate_id = run_id or (
            f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-"
            f"{test_id.lower()}-{uuid.uuid4().hex[:8]}"
        )
        canary = canary_root / candidate_id
        capture = capture_root / candidate_id
        output_root = derived_root / candidate_id
        if reuse:
            if not canary.is_dir() or not output_root.is_dir() or capture.exists():
                raise RuntimeError(
                    "Approved run must reuse the existing canary/output root and an unused capture path."
                )
            root = output_root.resolve()
            return {
                "run_id": candidate_id,
                "canary_repository": str(canary.resolve()),
                "capture_directory": str(capture.resolve()),
                "output_root": str(root),
                "control_directory": str(root / "control"),
                "analysis_directory": str(root / "analysis"),
                "report_directory": str(root / "report"),
            }
        if any(path.exists() for path in (canary, capture, output_root)):
            continue
        canary_root.mkdir(parents=True, exist_ok=True)
        capture_root.mkdir(parents=True, exist_ok=True)
        output_root.mkdir(parents=True)
        root = output_root.resolve()
        return {
            "run_id": candidate_id,
            "canary_repository": str(canary.resolve()),
            "capture_directory": str(capture.resolve()),
            "output_root": str(root),
            "control_directory": str(root / "control"),
            "analysis_directory": str(root / "analysis"),
            "report_directory": str(root / "report"),
        }
    raise RuntimeError("Could not reserve unique run directories.")


def collect_windows_snapshot(root_pid: int) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("PID-scoped Get-NetTCPConnection monitoring requires Windows.")
    script = rf"""
$ErrorActionPreference = 'Stop'
$rootPid = {int(root_pid)}
$all = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, ExecutablePath, CreationDate)
$ids = [System.Collections.Generic.HashSet[int]]::new()
$null = $ids.Add($rootPid)
do {{
  $added = $false
  foreach ($process in $all) {{
    if ($ids.Contains([int]$process.ParentProcessId) -and $ids.Add([int]$process.ProcessId)) {{ $added = $true }}
  }}
}} while ($added)
$selected = @($all | Where-Object {{ $ids.Contains([int]$_.ProcessId) }})
$connections = foreach ($process in $selected) {{
  Get-NetTCPConnection -OwningProcess $process.ProcessId -ErrorAction SilentlyContinue |
    Where-Object {{ $_.State -ne 'Listen' }} |
    Select-Object @{{n='ProcessId';e={{[int]$_.OwningProcess}}}}, LocalAddress, LocalPort, RemoteAddress, RemotePort, State
}}
[pscustomobject]@{{ processes = $selected; connections = @($connections) }} | ConvertTo-Json -Compress -Depth 5
"""
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(redact_text(completed.stderr.strip() or "PowerShell monitoring failed."))
    return json.loads(completed.stdout)


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    elif process.poll() is None:
        process.kill()


def _monitor_target(
    root_pid: int,
    stop_event: threading.Event,
    result: dict[str, Any],
    snapshot_provider: Callable[[int], dict[str, Any]],
    interval_seconds: float,
) -> None:
    processes: dict[int, dict[str, Any]] = {}
    connections: dict[tuple[Any, ...], dict[str, Any]] = {}
    errors: list[str] = []
    successful_polls = 0
    while not stop_event.is_set():
        observed_at = utc_now()
        try:
            snapshot = snapshot_provider(root_pid)
            successful_polls += 1
            for item in snapshot.get("processes") or []:
                pid = int(item.get("ProcessId"))
                record = processes.setdefault(
                    pid,
                    {
                        "process_id": pid,
                        "parent_process_id": int(item.get("ParentProcessId") or 0),
                        "executable_path": item.get("ExecutablePath"),
                        "process_start_time": item.get("CreationDate") or observed_at,
                        "first_observed_at": observed_at,
                        "last_observed_at": observed_at,
                    },
                )
                record["last_observed_at"] = observed_at
                if item.get("ExecutablePath"):
                    record["executable_path"] = item["ExecutablePath"]
            for item in snapshot.get("connections") or []:
                record = {
                    "observed_at": observed_at,
                    "process_id": int(item.get("ProcessId") or 0),
                    "local_address": item.get("LocalAddress"),
                    "local_port": int(item.get("LocalPort") or 0),
                    "remote_address": item.get("RemoteAddress"),
                    "remote_port": int(item.get("RemotePort") or 0),
                    "state": str(item.get("State")),
                }
                key = (
                    record["process_id"],
                    record["local_address"],
                    record["local_port"],
                    record["remote_address"],
                    record["remote_port"],
                    record["state"],
                )
                connections.setdefault(key, record)
        except Exception as exc:  # Monitoring failure must not terminate the client.
            message = redact_text(f"{type(exc).__name__}: {exc}")
            if message not in errors:
                errors.append(message)
        stop_event.wait(interval_seconds)
    stopped_at = utc_now()
    for record in processes.values():
        record["process_stop_time"] = stopped_at
    result.update(
        {
            "root_process_id": root_pid,
            "monitoring_complete": successful_polls > 0 and not errors,
            "monitoring_errors": errors,
            "processes": sorted(processes.values(), key=lambda item: item["process_id"]),
            "connections": sorted(
                connections.values(),
                key=lambda item: (
                    item["observed_at"],
                    item["process_id"],
                    item["remote_address"] or "",
                    item["remote_port"],
                ),
            ),
        }
    )


def detect_authentication_failure(
    stdout: str,
    stderr: str,
    adapter_patterns: list[str] | tuple[str, ...] = (),
) -> bool:
    text = f"{stdout}\n{stderr}".lower()
    common_failure = any(
        marker in text
        for marker in (
            "authentication failed",
            "not logged in",
            "login required",
            "unauthorized",
            "invalid api key",
            "status 401",
            "http 401",
        )
    )
    return common_failure or any(
        re.search(pattern, f"{stdout}\n{stderr}") is not None
        for pattern in adapter_patterns
    )


def classify_authentication_failure(
    stdout: str,
    stderr: str,
    classifications: list[Mapping[str, str]] | tuple[Mapping[str, str], ...] = (),
) -> dict[str, str | None]:
    text = f"{stdout}\n{stderr}"
    for classification in classifications:
        if re.search(classification["pattern"], text) is not None:
            return {
                "reason": classification["reason"],
                "observed_authentication_mode": classification[
                    "observed_authentication_mode"
                ],
            }
    return {"reason": None, "observed_authentication_mode": None}


def reclassify_client_execution(
    execution: Mapping[str, Any],
    *,
    stdout: str,
    stderr: str,
    authentication_failure_patterns: list[str] | tuple[str, ...] = (),
    authentication_failure_classifications: (
        list[Mapping[str, str]] | tuple[Mapping[str, str], ...]
    ) = (),
) -> dict[str, Any]:
    corrected = dict(execution)
    corrected["authentication_failed"] = detect_authentication_failure(
        stdout,
        stderr,
        authentication_failure_patterns,
    )
    classification = classify_authentication_failure(
        stdout,
        stderr,
        authentication_failure_classifications,
    )
    corrected["authentication_failure_reason"] = classification["reason"]
    corrected["observed_authentication_mode"] = classification[
        "observed_authentication_mode"
    ]
    return corrected


def run_client(
    prepared: Mapping[str, Any],
    output_directory: Path,
    *,
    base_environment: Mapping[str, str] | None = None,
    snapshot_provider: Callable[[int], dict[str, Any]] = collect_windows_snapshot,
    monitor_interval_seconds: float = 0.35,
    version_verification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    output_directory.mkdir(parents=True, exist_ok=True)
    stdout_path = output_directory / "client-stdout.txt"
    stderr_path = output_directory / "client-stderr.txt"
    process_tree_path = output_directory / "process-tree.json"
    connections_path = output_directory / "connections.json"
    execution_path = output_directory / "client-execution.json"
    started_at = utc_now()
    executable = str(prepared["executable"])
    execution: dict[str, Any] = {
        "schema_version": "egress-client-execution/v1",
        "product": prepared.get("product"),
        "vendor": prepared.get("vendor"),
        "client_surface": prepared.get("client_surface"),
        "authentication_mode": prepared.get("authentication_mode"),
        "client_version": (
            version_verification.get("normalized_client_version")
            if version_verification and version_verification.get("verified")
            else "UNVERIFIED"
        ),
        "version_command": list((version_verification or {}).get("version_command") or []),
        "version_stdout": (version_verification or {}).get("version_stdout", ""),
        "version_stderr": (version_verification or {}).get("version_stderr", ""),
        "version_exit_code": (version_verification or {}).get("version_exit_code"),
        "normalized_client_version": (version_verification or {}).get("normalized_client_version"),
        "model_identifier": prepared.get("model_identifier"),
        "prompt": prepared.get("prompt"),
        "working_directory": prepared.get("working_directory"),
        "executable_path": executable,
        "redacted_command": prepared.get("redacted_command"),
        "start_time": started_at,
        "end_time": None,
        "started": False,
        "exit_code": None,
        "timed_out": False,
        "authentication_failed": False,
        "error": None,
    }
    monitor_result: dict[str, Any] = {
        "root_process_id": None,
        "monitoring_started": False,
        "monitoring_complete": False,
        "monitoring_errors": [],
        "processes": [],
        "connections": [],
    }
    stdout = ""
    stderr = ""
    resolved = resolve_executable(executable)
    if resolved is None:
        execution["error"] = f"Executable not found: {executable}"
    else:
        execution["executable_path"] = resolved
        process: subprocess.Popen[str] | None = None
        stop_event = threading.Event()
        monitor_thread: threading.Thread | None = None
        try:
            child_environment = build_child_environment(
                os.environ if base_environment is None else base_environment,
                prepared.get("environment_variables", {}),
                list(prepared.get("inherited_secret_environment_variables", [])),
            )
            process = subprocess.Popen(
                [resolved, *prepared["arguments"]],
                cwd=prepared["working_directory"],
                env=child_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            execution["started"] = True
            execution["parent_process_id"] = process.pid
            monitor_thread = threading.Thread(
                target=_monitor_target,
                args=(
                    process.pid,
                    stop_event,
                    monitor_result,
                    snapshot_provider,
                    monitor_interval_seconds,
                ),
                daemon=True,
            )
            monitor_result["monitoring_started"] = True
            monitor_thread.start()
            try:
                stdout, stderr = process.communicate(
                    timeout=float(prepared["timeout_seconds"])
                )
            except subprocess.TimeoutExpired:
                execution["timed_out"] = True
                _terminate_process_tree(process)
                stdout, stderr = process.communicate(timeout=10)
            execution["exit_code"] = process.returncode
        except Exception as exc:
            execution["error"] = redact_text(f"{type(exc).__name__}: {exc}")
            if process is not None and process.poll() is None:
                _terminate_process_tree(process)
        finally:
            stop_event.set()
            if monitor_thread is not None:
                monitor_thread.join(timeout=20)
                if monitor_thread.is_alive():
                    monitor_result["monitoring_complete"] = False
                    monitor_result["monitoring_errors"].append(
                        "Process monitor did not stop within 20 seconds."
                    )
    redacted_stdout = redact_text(stdout)
    redacted_stderr = redact_text(stderr)
    execution["authentication_failed"] = detect_authentication_failure(
        redacted_stdout,
        redacted_stderr,
        list(prepared.get("authentication_failure_patterns", [])),
    )
    classification = classify_authentication_failure(
        redacted_stdout,
        redacted_stderr,
        list(prepared.get("authentication_failure_classifications", [])),
    )
    execution["authentication_failure_reason"] = classification["reason"]
    execution["observed_authentication_mode"] = classification[
        "observed_authentication_mode"
    ]
    execution["end_time"] = utc_now()
    stdout_path.write_text(redacted_stdout, encoding="utf-8", newline="\n")
    stderr_path.write_text(redacted_stderr, encoding="utf-8", newline="\n")
    write_json_atomic(process_tree_path, {key: value for key, value in monitor_result.items() if key != "connections"})
    write_json_atomic(connections_path, {"connections": monitor_result["connections"]})
    write_json_atomic(execution_path, execution)
    return execution


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--adapter", type=Path, required=True)
    validate.add_argument("--schema", type=Path, required=True)

    reserve = subparsers.add_parser("reserve-run")
    reserve.add_argument("--canary-root", type=Path, required=True)
    reserve.add_argument("--capture-root", type=Path, required=True)
    reserve.add_argument("--derived-root", type=Path, required=True)
    reserve.add_argument("--test-id", required=True)
    reserve.add_argument("--run-id")
    reserve.add_argument("--reuse", action="store_true")

    reclassify = subparsers.add_parser("reclassify-execution")
    reclassify.add_argument("--adapter", type=Path, required=True)
    reclassify.add_argument("--schema", type=Path, required=True)
    reclassify.add_argument("--source-execution", type=Path, required=True)
    reclassify.add_argument("--stdout", type=Path, required=True)
    reclassify.add_argument("--stderr", type=Path, required=True)
    reclassify.add_argument("--output", type=Path, required=True)

    for command in ("prepare", "run-client"):
        child = subparsers.add_parser(command)
        child.add_argument("--adapter", type=Path, required=True)
        child.add_argument("--schema", type=Path, required=True)
        child.add_argument("--working-directory", type=Path, required=True)
        child.add_argument("--prompt", required=True)
        child.add_argument("--proxy-port", type=int, required=True)
        child.add_argument("--ca-certificate", type=Path, required=True)
        if command == "run-client":
            child.add_argument("--output-directory", type=Path, required=True)
            child.add_argument("--version-verification", type=Path, required=True)

    version = subparsers.add_parser("verify-version")
    version.add_argument("--adapter", type=Path, required=True)
    version.add_argument("--schema", type=Path, required=True)

    secrets = subparsers.add_parser("verify-secrets")
    secrets.add_argument("--adapter", type=Path, required=True)
    secrets.add_argument("--schema", type=Path, required=True)

    auth_selection = subparsers.add_parser("verify-auth-selection")
    auth_selection.add_argument("--adapter", type=Path, required=True)
    auth_selection.add_argument("--schema", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "validate":
        adapter = load_adapter(args.adapter, args.schema)
        print(json.dumps({"valid": True, "schema_version": adapter["schema_version"]}))
        return 0
    if args.command == "reserve-run":
        print(
            json.dumps(
                reserve_run_directories(
                    canary_root=args.canary_root,
                    capture_root=args.capture_root,
                    derived_root=args.derived_root,
                    test_id=args.test_id,
                    run_id=args.run_id,
                    reuse=args.reuse,
                )
            )
        )
        return 0
    if args.command == "reclassify-execution":
        adapter = load_adapter(args.adapter, args.schema)
        execution = json.loads(args.source_execution.read_text(encoding="utf-8"))
        stdout = args.stdout.read_text(encoding="utf-8") if args.stdout.is_file() else ""
        stderr = args.stderr.read_text(encoding="utf-8") if args.stderr.is_file() else ""
        corrected = reclassify_client_execution(
            execution,
            stdout=stdout,
            stderr=stderr,
            authentication_failure_patterns=list(
                adapter.get("authentication_failure_patterns", [])
            ),
            authentication_failure_classifications=list(
                adapter.get("authentication_failure_classifications", [])
            ),
        )
        write_json_atomic(args.output, corrected)
        print(
            json.dumps(
                {
                    "authentication_failed": corrected["authentication_failed"],
                    "exit_code": corrected.get("exit_code"),
                }
            )
        )
        return 0
    if args.command == "verify-version":
        adapter = load_adapter(args.adapter, args.schema)
        prepared = {
            "executable": adapter["executable"],
            "version_command": adapter["version_command"],
        }
        result = verify_client_version(prepared)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["verified"] else 2
    if args.command == "verify-secrets":
        adapter = load_adapter(args.adapter, args.schema)
        result = verify_inherited_secret_availability(adapter)
        print(json.dumps(result))
        return 0 if result["all_available"] else 2
    if args.command == "verify-auth-selection":
        adapter = load_adapter(args.adapter, args.schema)
        result = verify_authentication_selection(adapter)
        print(json.dumps(result))
        return 0 if result["matches"] else 2
    adapter = load_adapter(args.adapter, args.schema)
    prepared = prepare_invocation(
        adapter,
        working_directory=args.working_directory,
        prompt=args.prompt,
        proxy_port=args.proxy_port,
        ca_certificate=args.ca_certificate,
    )
    if args.command == "prepare":
        print(json.dumps(prepared, ensure_ascii=False))
        return 0
    version_verification = json.loads(
        args.version_verification.read_text(encoding="utf-8")
    )
    if not version_verification.get("verified"):
        raise ValueError("Client version was not verified before client execution.")
    if gate_identity_changes(version_verification, {
        "executable_path": prepared["executable"],
        "normalized_client_version": version_verification.get("normalized_client_version"),
    }):
        raise ValueError("Verified executable identity does not match the prepared invocation.")
    result = run_client(
        prepared,
        args.output_directory,
        version_verification=version_verification,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("started") else 2


if __name__ == "__main__":
    raise SystemExit(main())
