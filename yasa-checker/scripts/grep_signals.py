#!/usr/bin/env python3
"""Language-aware vulnerability pattern grep engine for post-YASA auditing.

Scans project files for patterns indicative of security vulnerabilities,
using ripgrep when available for speed, with Python regex fallback.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

PATTERNS: dict[str, dict[str, list[dict[str, Any]]]] = {
    "python": {
        "command-injection": [
            {
                "id": "fstring-subprocess",
                "pattern": r'''subprocess\.(run|Popen|call|check_output)\(f["']''',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "fstring-os",
                "pattern": r'''os\.(system|popen)\(f["']''',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "concat-subprocess",
                "pattern": r'(os\.(system|popen)|subprocess\.\w+)\s*\([^)]*\+',
                "file_globs": ["*.py"],
                "severity": "MEDIUM",
            },
            {
                "id": "format-subprocess",
                "pattern": r'(os\.(system|popen)|subprocess\.\w+)\s*\([^)]*\.format\(',
                "file_globs": ["*.py"],
                "severity": "MEDIUM",
            },
            {
                "id": "shell-true",
                "pattern": r'shell\s*=\s*True',
                "file_globs": ["*.py"],
                "severity": "MEDIUM",
            },
            {
                "id": "execute-command-wrapper",
                "pattern": r'\.execute_command\(|\.run_command\(|\.shell_command\(|\._exec\s*\(',
                "file_globs": ["*.py"],
                "severity": "LOW",
            },
            {
                "id": "direct-os-system",
                "pattern": r'os\.system\(',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "direct-os-popen",
                "pattern": r'os\.popen\(',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "fstring-eval",
                "pattern": r'''eval\(f["']|exec\(f["']''',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
        ],
        "path-traversal": [
            {
                "id": "fstring-open",
                "pattern": r'''open\(f["']''',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "concat-path",
                "pattern": r'(open|os\.(remove|rename|stat|mkdir|listdir))\s*\([^)]*\+',
                "file_globs": ["*.py"],
                "severity": "MEDIUM",
            },
            {
                "id": "pathlib-concat",
                "pattern": r'Path\([^)]*\+',
                "file_globs": ["*.py"],
                "severity": "MEDIUM",
            },
        ],
        "deserialization": [
            {
                "id": "pickle-loads",
                "pattern": r'pickle\.loads\(',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
            {
                "id": "yaml-load",
                "pattern": r'yaml\.(load|full_load)\(',
                "file_globs": ["*.py"],
                "severity": "HIGH",
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SKIP_DIRS = frozenset(
    {"test", "tests", "venv", ".venv", "node_modules", "__pycache__", ".git", ".tox"}
)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Hit:
    """A single pattern match."""

    file: str
    line: int
    column: int
    snippet: str
    pattern_id: str
    severity: str
    vuln_class: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "pattern_id": self.pattern_id,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
        }


@dataclass
class Stats:
    total_patterns: int = 0
    total_hits: int = 0
    files_scanned: int = 0


# ---------------------------------------------------------------------------
# Glob helpers
# ---------------------------------------------------------------------------


def _skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def _iter_files(root: Path, globs: list[str], max_files: int) -> Iterator[Path]:
    """Yield files matching any of *globs under *root, skipping unwanted dirs."""
    seen = 0
    for pattern in globs:
        for p in root.rglob(pattern):
            # Skip files in unwanted directories
            if any(_skip_dir(part) for part in p.relative_to(root).parts[:-1]):
                continue
            if p.is_file():
                yield p
                seen += 1
                if seen >= max_files:
                    return


# ---------------------------------------------------------------------------
# Ripgrep backend
# ---------------------------------------------------------------------------


def _rg_available() -> bool:
    return shutil.which("rg") is not None


def _run_rg(
    root: Path, pattern: str, file_globs: list[str], max_files: int
) -> list[dict[str, Any]]:
    """Run ripgrep and return raw matches as dicts with keys we need."""
    # Build glob filters (include patterns)
    glob_args: list[str] = []
    for g in file_globs:
        glob_args.extend(["--glob", g])

    # Exclude dirs
    skip_flags: list[str] = []
    for d in SKIP_DIRS:
        skip_flags.extend(["--glob", f"!{d}/**"])

    cmd = [
        "rg",
        "--line-number",
        "--column",
        "--with-filename",
        "--no-heading",
        "--no-messages",
        "--color",
        "never",
        "--max-count",
        str(max_files),
    ]
    cmd.extend(glob_args)
    cmd.extend(skip_flags)
    cmd.extend(["-e", pattern, str(root)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[warn] rg failed for pattern {pattern!r}: {exc}", file=sys.stderr)
        return []

    if result.returncode not in (0, 1):
        # Exit code 2 means rg encountered errors (e.g. permission denied on
        # unreadable files).  With --no-messages these are suppressed but the
        # exit code is still 2.  Check stderr to distinguish real regex errors
        # from benign permission-denied issues.
        stderr_trimmed = result.stderr.strip()
        if stderr_trimmed:
            print(
                f"[warn] rg error for pattern {pattern!r}: {stderr_trimmed}",
                file=sys.stderr,
            )
            return []
        # silent permission errors — process partial results

    matches: list[dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        # rg output format: file:line:col:text
        # Use a conservative split to handle paths with colons
        # If the line looks like: filepath:123:45:content
        # We split on the FIRST two colons after the path.
        # Safer: split maxsplit=3 on colon
        parts = raw_line.split(":", 3)
        if len(parts) < 4:
            continue
        filepath_str, line_str, col_str, text = parts
        matches.append(
            {
                "file": filepath_str,
                "line": int(line_str),
                "column": int(col_str),
                "snippet": text.strip(),
            }
        )
    return matches


# ---------------------------------------------------------------------------
# Python regex (re) backend
# ---------------------------------------------------------------------------


def _run_re(
    root: Path, compiled: re.Pattern, file_globs: list[str], max_files: int
) -> list[dict[str, Any]]:
    """Fallback: glob + re per file."""
    matches: list[dict[str, Any]] = []
    for fp in _iter_files(root, file_globs, max_files):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[warn] cannot read {fp}: {exc}", file=sys.stderr)
            continue
        for m in compiled.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            snippet = text[start:end].strip()
            matches.append(
                {
                    "file": str(fp),
                    "line": lineno,
                    "column": m.start() - text.rfind("\n", 0, m.start()) - 1,
                    "snippet": snippet,
                }
            )
    return matches


# ---------------------------------------------------------------------------
# Deduplication key
# ---------------------------------------------------------------------------


def _dedup_key(m: dict[str, Any], pid: str) -> tuple[str, int, str]:
    return (m["file"], m["line"], pid)


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


def scan_project(
    project_path: str, language: str, max_files: int = 500
) -> tuple[list[Hit], Stats]:
    root = Path(project_path).resolve()
    if not root.is_dir():
        print(f"[error] {project_path} is not a directory or does not exist.", file=sys.stderr)
        sys.exit(2)

    lang_patterns = PATTERNS.get(language, {})
    if not lang_patterns:
        print(
            f"[error] unsupported language: {language!r}. Supported: {list(PATTERNS)}",
            file=sys.stderr,
        )
        sys.exit(2)

    use_rg = _rg_available()
    seen: set[tuple[str, int, str]] = set()
    hits: list[Hit] = []
    all_globs: set[str] = set()
    total_pattern_count = 0

    # Collect globs for files_scanned stat
    for vuln_class, pattern_list in lang_patterns.items():
        for pat in pattern_list:
            for g in pat["file_globs"]:
                all_globs.add(g)
            total_pattern_count += 1

    # Count files scanned (approximate; we scan once, but rg/re do per-pattern)
    files_scanned: int = 0
    scanned_files_set: set[str] = set()
    if not use_rg:
        for g in all_globs:
            for fp in _iter_files(root, [g], max_files):
                scanned_files_set.add(str(fp))
        files_scanned = len(scanned_files_set)

    # For each vulnerable class and pattern
    for vuln_class, pattern_list in lang_patterns.items():
        for pat in pattern_list:
            pid = pat["id"]
            regex = pat["pattern"]
            globs = pat["file_globs"]
            severity = pat["severity"]

            if use_rg:
                raw = _run_rg(root, regex, globs, max_files)
            else:
                try:
                    compiled = re.compile(regex)
                except re.error as exc:
                    print(
                        f"[warn] invalid regex for pattern {pid!r}: {exc}",
                        file=sys.stderr,
                    )
                    continue
                raw = _run_re(root, compiled, globs, max_files)

            for m in raw:
                key = _dedup_key(m, pid)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    Hit(
                        file=m["file"],
                        line=m["line"],
                        column=m.get("column", 0),
                        snippet=m.get("snippet", ""),
                        pattern_id=pid,
                        severity=severity,
                        vuln_class=vuln_class,
                    )
                )

    if use_rg:
        # Count unique files scanned via rg stats — approximate
        files_scanned = len({h.file for h in hits})
        # Better estimate: run a quick file count
        try:
            glob_args = []
            for g in all_globs:
                glob_args.extend(["--glob", g])
            skip_flags = []
            for d in SKIP_DIRS:
                skip_flags.extend(["--glob", f"!{d}/**"])
            count_cmd = ["rg", "--count-matches", "--color", "never"] + glob_args + skip_flags + ["-e", ".", str(root)]
            count_result = subprocess.run(
                count_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            file_count = len(count_result.stdout.splitlines())
            if file_count > 0:
                files_scanned = min(file_count, max_files)
        except (subprocess.TimeoutExpired, OSError):
            pass

    stats = Stats(
        total_patterns=total_pattern_count,
        total_hits=len(hits),
        files_scanned=files_scanned,
    )

    return hits, stats


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def print_table(hits: list[Hit]) -> None:
    """Print a human-readable table."""
    if not hits:
        print("No vulnerability signals found.")
        return
    header = f"{'File':<50} {'Line':<6} {'Pattern':<30} {'Severity':<8} {'Vuln Class'}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for h in hits:
        file_short = h.file if len(h.file) <= 50 else "..." + h.file[-47:]
        print(
            f"{file_short:<50} {h.line:<6} {h.pattern_id:<30} {h.severity:<8} {h.vuln_class}"
        )
    print(sep)
    print(f"Total hits: {len(hits)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Language-aware vulnerability pattern grep for post-YASA auditing.",
    )
    parser.add_argument(
        "--project-path",
        required=True,
        help="Path to the project directory to scan.",
    )
    parser.add_argument(
        "--language",
        required=True,
        choices=sorted(PATTERNS),
        help="Programming language to target patterns for.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Maximum number of files to scan (default: 500).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.max_files < 1:
        parser.error("--max-files must be >= 1")

    hits, stats = scan_project(
        project_path=args.project_path,
        language=args.language,
        max_files=args.max_files,
    )

    if args.json:
        output = {
            "hits": [h.to_dict() for h in hits],
            "stats": asdict(stats),
        }
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print_table(hits)
        print("")  # spacing before stats
        print(f"Patterns checked : {stats.total_patterns}")
        print(f"Files scanned   : {stats.files_scanned}")
        print(f"Total hits      : {stats.total_hits}")


if __name__ == "__main__":
    main()
