"""Create and validate the versioned run-level derived-output layout."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunOutputLayout:
    output_root: Path
    control: Path
    analysis: Path
    report: Path

    def as_dict(self) -> dict[str, str]:
        return {
            "output_root": str(self.output_root),
            "control_directory": str(self.control),
            "analysis_directory": str(self.analysis),
            "report_directory": str(self.report),
        }


def _require_empty(path: Path, label: str) -> None:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(
            f"Refusing to reuse non-empty {label} directory: {path}. "
            "Choose a new versioned output root."
        )


def prepare_output_layout(output_root: Path) -> RunOutputLayout:
    root = output_root.expanduser().resolve()
    layout = RunOutputLayout(
        output_root=root,
        control=root / "control",
        analysis=root / "analysis",
        report=root / "report",
    )
    root.mkdir(parents=True, exist_ok=True)
    layout.control.mkdir(exist_ok=True)
    _require_empty(layout.analysis, "analysis")
    _require_empty(layout.report, "report")
    layout.analysis.mkdir(exist_ok=True)
    layout.report.mkdir(exist_ok=True)
    return layout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    layout = prepare_output_layout(args.output_root)
    print(json.dumps(layout.as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
