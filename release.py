#!/usr/bin/env python3
"""Build mosdns-v4 for every supported target, or for selected targets.

Usage:
    python3 release.py
    python3 release.py linux/amd64
    python3 release.py linux/amd64 windows/amd64
    python3 release.py linux-amd64
    python3 release.py --version v4.0.2
    python3 release.py --list

With no target argument the script builds all supported targets. Target
arguments accept either the Go form ``GOOS/GOARCH`` or the asset form
``GOOS-GOARCH``. Build outputs are written by ``tools/crossbuild`` to
``build/`` as ``mosdns-<target>[.exe]``; the version is injected into the
binary and does not appear in the file name.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# Keep this list in sync with tools/crossbuild/main.go.
SUPPORTED_TARGETS = (
    "darwin/arm64",
    "darwin/amd64",
    "linux/amd64",
    "linux/arm64",
    "linux/armv6",
    "linux/armv7",
    "linux/386",
    "linux/ppc64le",
    "freebsd/amd64",
    "windows/amd64",
)

# Accept the names used by release assets as aliases.
ALIASES = {
    "darwin-arm64": "darwin/arm64",
    "darwin-amd64": "darwin/amd64",
    "linux-amd64": "linux/amd64",
    "linux-arm64": "linux/arm64",
    "linux-armv6": "linux/armv6",
    "linux-armv7": "linux/armv7",
    "linux-386": "linux/386",
    "linux-ppc64le": "linux/ppc64le",
    "freebsd-amd64": "freebsd/amd64",
    "windows-amd64": "windows/amd64",
}


def normalize_targets(values: list[str]) -> list[str]:
    """Return validated, de-duplicated targets in the order given."""
    if not values:
        return []

    selected: list[str] = []
    for value in values:
        for raw in value.split(","):
            name = raw.strip()
            if not name:
                continue
            if name == "all":
                return []
            target = ALIASES.get(name, name)
            if target not in SUPPORTED_TARGETS:
                raise argparse.ArgumentTypeError(
                    f"unsupported target: {name}\n"
                    "supported targets: " + ", ".join(SUPPORTED_TARGETS)
                )
            if target not in selected:
                selected.append(target)
    return selected


def build_command(targets: list[str], version: str | None) -> list[str]:
    command = ["go", "run", "./tools/crossbuild"]
    if version:
        command.extend(["-version", version])
    command.extend(targets)
    return command


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build all supported mosdns-v4 targets, or only selected ones."
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="GOOS/GOARCH or GOOS-GOARCH; omit to build all supported targets",
    )
    parser.add_argument(
        "-version",
        "--version",
        dest="version",
        help="version to inject into main.version (default: git describe)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print supported targets and exit",
    )
    args = parser.parse_args()

    if args.list:
        for target in SUPPORTED_TARGETS:
            print(target)
        return 0

    try:
        targets = normalize_targets(args.targets)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    command = build_command(targets, args.version)
    print("running: " + " ".join(shlex.quote(part) for part in command), flush=True)
    print(f"working directory: {PROJECT_ROOT}", flush=True)
    if not targets:
        print("building all supported targets", flush=True)

    try:
        return subprocess.call(command, cwd=os.fspath(PROJECT_ROOT))
    except FileNotFoundError:
        print("go was not found in PATH", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        print("build interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
