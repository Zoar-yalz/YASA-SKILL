#!/usr/bin/env python3
"""Orchestrator for the post-YASA audit pipeline.

Calls grep_signals.py and taint_trace.py as subprocesses, then scores,
ranks, and exports findings.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Script paths (co-located in the same directory)
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).parent.resolve()
GREP_SIGNALS = _SCRIPT_DIR / "grep_signals.py"
TAINT_TRACE = _SCRIPT_DIR / "taint_trace.py"

# ---------------------------------------------------------------------------
# Pattern-id → YASA sink function names (for cross-reference)
# ---------------------------------------------------------------------------
# Maps the grep pattern_id to the YASA sink function name(s) it catches.
# When a YASA rule_config.json lists one of these sink names, any grep hit
# for the matching pattern_id is considered a "missed sink".
_PATTERN_TO_SINKS: dict[str, list[str]] = {
    "fstring-subprocess": [
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
    ],
    "fstring-os": ["os.system", "os.popen"],
    "concat-subprocess": [
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
    ],
    "format-subprocess": [
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
    ],
    "shell-true": ["subprocess.run", "subprocess.Popen", "subprocess.call"],
    "execute-command-wrapper": ["execute_command", "run_command", "shell_command", "_exec"],
    "direct-os-system": ["os.system"],
    "direct-os-popen": ["os.popen"],
    "fstring-eval": ["eval", "exec"],
    "fstring-open": ["open"],
    "concat-path": ["open", "os.remove", "os.rename", "os.stat", "os.mkdir", "os.listdir"],
    "pathlib-concat": ["pathlib.Path"],
    "pickle-loads": ["pickle.loads"],
    "yaml-load": ["yaml.load", "yaml.full_load"],
}

# Sink function names that the overall pipeline considers "dangerous".
_DANGEROUS_SINKS: frozenset[str] = frozenset({
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "eval",
    "exec",
    "pickle.loads",
    "yaml.load",
    "yaml.full_load",
})

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class GrepHit:
    file: str
    line: int
    column: int
    snippet: str
    pattern_id: str
    severity: str
    vuln_class: str


@dataclass
class GrepStats:
    total_hits_raw: int = 0
    total_hits_deduped: int = 0
    files_scanned: int = 0


@dataclass
class YasaContext:
    sinks_configured: int = 0
    sinks_matched: int = 0
    sources_marked: int = 0
    entrypoints_valid: int = 0
    findings: int = 0


@dataclass
class TaintTrace:
    variable: Optional[str] = None
    source_confirmed: bool = False
    taint_source: Optional[str] = None
    interpolation_type: Optional[str] = None
    has_sanitization: bool = False
    trace_hops: int = 0


@dataclass
class Finding:
    id: str
    confidence: str
    score: float
    file: str
    line: int
    snippet: str
    pattern_id: str
    vuln_class: str
    taint_trace: TaintTrace
    yasa_blind: bool


@dataclass
class AuditOutput:
    audit_timestamp: str
    language: str
    project_path: str
    yasa_context: YasaContext
    grep_stats: GrepStats
    missed_sinks: int
    findings: list[Any]  # serialised Finding dicts


# ---------------------------------------------------------------------------
# Score function
# ---------------------------------------------------------------------------


def score_finding(trace_result: dict[str, Any], pattern_severity: str) -> tuple[float, str]:
    """Compute a confidence score (0.0–1.0) and label from taint trace data.

    *trace_result* should have the same shape as the JSON output of
    ``taint_trace.py`` (dict with keys ``source_confirmed``,
    ``has_sanitization``, ``interpolation_type``, etc.).
    """
    score = 0.0

    if trace_result.get("source_confirmed"):
        score += 0.40
    if not trace_result.get("has_sanitization"):
        score += 0.25
    if pattern_severity == "HIGH":
        score += 0.20
    elif pattern_severity == "MEDIUM":
        score += 0.10
    if trace_result.get("interpolation_type") in ("f-string", "concat", "format", "direct"):
        score += 0.15

    score = round(min(score, 1.0), 2)

    if score >= 0.70:
        confidence = "HIGH"
    elif score >= 0.40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return score, confidence


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run_grep_signals(
    project_path: str,
    language: str,
    max_files: int,
) -> dict[str, Any]:
    """Run ``grep_signals.py`` as a subprocess and return the parsed JSON."""
    cmd = [
        sys.executable,
        str(GREP_SIGNALS),
        "--project-path",
        project_path,
        "--language",
        language,
        "--max-files",
        str(max_files),
        "--json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print("[error] grep_signals.py timed out (300s)", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"[error] Failed to run grep_signals.py: {exc}", file=sys.stderr)
        sys.exit(2)

    if result.returncode != 0:
        print(
            f"[error] grep_signals.py exited with code {result.returncode}",
            file=sys.stderr,
        )
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        sys.exit(2)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"[error] Invalid JSON from grep_signals.py: {exc}", file=sys.stderr)
        sys.exit(2)


def _run_taint_trace(
    sink_file: str,
    sink_line: int,
    project_path: str,
    language: str,
) -> dict[str, Any]:
    """Run ``taint_trace.py`` as a subprocess and return parsed JSON."""
    cmd = [
        sys.executable,
        str(TAINT_TRACE),
        "--sink-file",
        sink_file,
        "--sink-line",
        str(sink_line),
        "--project-path",
        project_path,
        "--language",
        language,
        "--json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {
            "variable": None,
            "source_confirmed": False,
            "taint_source": None,
            "interpolation_type": None,
            "has_sanitization": False,
            "trace_hops": 0,
            "errors": ["taint_trace.py timed out"],
        }
    except OSError as exc:
        return {
            "variable": None,
            "source_confirmed": False,
            "taint_source": None,
            "interpolation_type": None,
            "has_sanitization": False,
            "trace_hops": 0,
            "errors": [str(exc)],
        }

    if result.returncode != 0:
        # Non-zero exit is not necessarily fatal (trace may simply fail)
        # Return empty-ish result
        return {
            "variable": None,
            "source_confirmed": False,
            "taint_source": None,
            "interpolation_type": None,
            "has_sanitization": False,
            "trace_hops": 0,
            "errors": [f"taint_trace.py exited with code {result.returncode}"],
        }

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "variable": None,
            "source_confirmed": False,
            "taint_source": None,
            "interpolation_type": None,
            "has_sanitization": False,
            "trace_hops": 0,
            "errors": ["Invalid JSON from taint_trace.py"],
        }


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_str(val: Any, default: str = "") -> str:
    if isinstance(val, str):
        return val
    return default


# ---------------------------------------------------------------------------
# YASA config loading
# ---------------------------------------------------------------------------


def _load_yasa_sinks(rule_config_path: str) -> set[str]:
    """Return the set of YASA-configured sink function names."""
    path = Path(rule_config_path)
    if not path.is_file():
        print(f"[warn] YASA rule config not found: {rule_config_path}", file=sys.stderr)
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] Cannot parse YASA rule config: {exc}", file=sys.stderr)
        return set()

    sinks: set[str] = set()

    # Normalise to list
    if isinstance(data, dict):
        data = [data]

    for rule in data:
        if not isinstance(rule, dict):
            continue
        sinks_section = rule.get("sinks", {})
        if isinstance(sinks_section, dict):
            for _kind, sink_list in sinks_section.items():
                if isinstance(sink_list, list):
                    for sink in sink_list:
                        if isinstance(sink, dict):
                            name = sink.get("fsig", sink.get("name", sink.get("fregex", "")))
                            if name:
                                sinks.add(name)
    return sinks


def _load_source_summary(source_summary_path: str) -> dict[str, Any]:
    """Load the YASA scan_summary.json for context."""
    path = Path(source_summary_path)
    if not path.is_file():
        print(f"[warn] Source summary not found: {source_summary_path}", file=sys.stderr)
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] Cannot parse source summary: {exc}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate grep hits by (file, line), keeping highest severity.

    Severity ranking: HIGH > MEDIUM > LOW.
    """
    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best: dict[tuple[str, int], dict[str, Any]] = {}
    for h in hits:
        key = (h["file"], h["line"])
        existing = best.get(key)
        if existing is None:
            best[key] = h
        else:
            existing_rank = severity_rank.get(existing.get("severity", "LOW"), 0)
            current_rank = severity_rank.get(h.get("severity", "LOW"), 0)
            if current_rank > existing_rank:
                best[key] = h
    return list(best.values())


# ---------------------------------------------------------------------------
# YASA cross-reference
# ---------------------------------------------------------------------------


def _is_yasa_blind(
    hit: dict[str, Any],
    yasa_sinks: set[str],
) -> bool:
    """Determine whether a grep hit corresponds to a YASA-configured sink.

    We check by:
    1. Looking up the pattern_id in ``_PATTERN_TO_SINKS``.
    2. Checking if any of the corresponding function names are in the
       YASA configured sink set.
    """
    pattern_id = hit.get("pattern_id", "")
    known_sinks = _PATTERN_TO_SINKS.get(pattern_id, [])
    for fn in known_sinks:
        if fn in yasa_sinks:
            return True
    return False


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _build_finding_id(index: int) -> str:
    return f"AUDIT-{index:03d}"


def _print_summary_table(findings: list[Finding], stats: GrepStats, yasa_ctx: YasaContext) -> None:
    """Print a human-readable summary to stdout."""
    print()
    print("=" * 78)
    print("  POST-YASA AUDIT SUMMARY")
    print("=" * 78)
    print(f"  Raw grep hits       : {stats.total_hits_raw}")
    print(f"  Deduplicated hits   : {stats.total_hits_deduped}")
    print(f"  Files scanned       : {stats.files_scanned}")
    if yasa_ctx.sinks_configured > 0:
        print(f"  YASA sinks configured: {yasa_ctx.sinks_configured}")
        print(f"  YASA sinks matched   : {yasa_ctx.sinks_matched}")
    print(f"  Total findings      : {len(findings)}")
    print("-" * 78)

    if not findings:
        print("  No findings to report.")
        print("=" * 78)
        return

    # Sort findings by score descending for the table
    sorted_findings = sorted(findings, key=lambda f: f.score, reverse=True)

    header = (
        f"{'ID':<12} {'Confidence':<10} {'Score':<7} "
        f"{'File':<48} {'Line':<6} {'Pattern':<28} {'Vuln Class'}"
    )
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for f in sorted_findings:
        file_short = f.file if len(f.file) <= 48 else "..." + f.file[-45:]
        print(
            f"{f.id:<12} {f.confidence:<10} {f.score:<7.2f} "
            f"{file_short:<48} {f.line:<6} {f.pattern_id:<28} {f.vuln_class}"
        )
    print(sep)
    print(f"  Total findings: {len(findings)}")
    print("=" * 78)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    project_path: str,
    language: str,
    max_files: int,
    yasa_sinks_path: Optional[str],
    source_summary_path: Optional[str],
) -> AuditOutput:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---- Step 1: Run grep_signals.py ----
    print("[*] Running grep_signals.py …", file=sys.stderr)
    grep_output = _run_grep_signals(project_path, language, max_files)

    raw_hits: list[dict[str, Any]] = grep_output.get("hits", [])
    grep_stats_raw = grep_output.get("stats", {})
    raw_count = len(raw_hits)
    files_scanned = _safe_int(grep_stats_raw.get("files_scanned", 0))

    print(f"    → {raw_count} raw hits across {files_scanned} files", file=sys.stderr)

    # ---- Step 2: Load YASA configuration (optional) ----
    yasa_sinks: set[str] = set()
    yasa_ctx = YasaContext()

    if yasa_sinks_path:
        print(f"[*] Loading YASA sink config: {yasa_sinks_path}", file=sys.stderr)
        yasa_sinks = _load_yasa_sinks(yasa_sinks_path)
        yasa_ctx.sinks_configured = len(yasa_sinks)
        print(f"    → {len(yasa_sinks)} sinks configured", file=sys.stderr)

    if source_summary_path:
        print(f"[*] Loading source summary: {source_summary_path}", file=sys.stderr)
        summary = _load_source_summary(source_summary_path)
        yasa_ctx.sources_marked = _safe_int(summary.get("sources_marked", 0))
        yasa_ctx.entrypoints_valid = _safe_int(summary.get("entrypoints_valid", 0))
        yasa_ctx.findings = _safe_int(summary.get("findings", 0))

    # ---- Step 3: Deduplicate ----
    print("[*] Deduplicating hits …", file=sys.stderr)
    deduped = _deduplicate_hits(raw_hits)
    deduped_count = len(deduped)
    print(f"    → {deduped_count} unique hits after dedup", file=sys.stderr)

    # ---- Step 4: Determine which hits to trace ----
    # Trace ALL deduplicated hits. Mark yasa_blind for hits whose sink
    # matches a YASA-configured sink (YASA should have found these but didn't).
    hits_to_trace: list[dict[str, Any]] = list(deduped)
    has_yasa = bool(yasa_sinks)
    for h in hits_to_trace:
        h["yasa_blind"] = bool(yasa_sinks) and _is_yasa_blind(h, yasa_sinks)

    missed_sinks = sum(1 for h in hits_to_trace if h["yasa_blind"])
    if has_yasa:
        yasa_ctx.sinks_matched = missed_sinks

    yasa_blind_count = sum(1 for h in hits_to_trace if h["yasa_blind"])
    unconfigured_count = len(hits_to_trace) - yasa_blind_count
    print(
        f"    → {len(hits_to_trace)} hits to trace "
        f"(yasa_blind={yasa_blind_count}, unconfigured={unconfigured_count})",
        file=sys.stderr,
    )

    # ---- Step 5: Taint-trace each hit and score ----
    findings: list[Finding] = []
    finding_index = 0

    for idx, hit in enumerate(hits_to_trace, start=1):
        sink_file = hit["file"]
        sink_line = hit["line"]
        pattern_severity = hit.get("severity", "LOW")
        pattern_id = hit.get("pattern_id", "")
        vuln_class = hit.get("vuln_class", "")
        snippet = hit.get("snippet", "")

        print(
            f"    [{idx}/{len(hits_to_trace)}] tracing {sink_file}:{sink_line} "
            f"({pattern_id}) …",
            file=sys.stderr,
        )

        trace_json = _run_taint_trace(
            sink_file=sink_file,
            sink_line=sink_line,
            project_path=project_path,
            language=language,
        )

        score, confidence_label = score_finding(trace_json, pattern_severity)

        taint_trace = TaintTrace(
            variable=trace_json.get("variable"),
            source_confirmed=bool(trace_json.get("source_confirmed")),
            taint_source=trace_json.get("taint_source"),
            interpolation_type=trace_json.get("interpolation_type"),
            has_sanitization=bool(trace_json.get("has_sanitization")),
            trace_hops=_safe_int(trace_json.get("trace_hops", 0)),
        )

        finding_index += 1
        findings.append(
            Finding(
                id=_build_finding_id(finding_index),
                confidence=confidence_label,
                score=score,
                file=sink_file,
                line=sink_line,
                snippet=snippet,
                pattern_id=pattern_id,
                vuln_class=vuln_class,
                taint_trace=taint_trace,
                yasa_blind=hit.get("yasa_blind", False),
            )
        )

    # ---- Step 6: Sort by score descending ----
    findings.sort(key=lambda f: f.score, reverse=True)

    # Re-number after sort
    for i, f in enumerate(findings, start=1):
        f.id = _build_finding_id(i)

    # ---- Step 7: Assemble output ----
    stats = GrepStats(
        total_hits_raw=raw_count,
        total_hits_deduped=deduped_count,
        files_scanned=files_scanned,
    )

    output = AuditOutput(
        audit_timestamp=timestamp,
        language=language,
        project_path=project_path,
        yasa_context=yasa_ctx,
        grep_stats=stats,
        missed_sinks=missed_sinks,
        findings=[_serialise_finding(f) for f in findings],
    )

    return output


def _serialise_finding(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "confidence": f.confidence,
        "score": f.score,
        "file": f.file,
        "line": f.line,
        "snippet": f.snippet,
        "pattern_id": f.pattern_id,
        "vuln_class": f.vuln_class,
        "taint_trace": {
            "variable": f.taint_trace.variable,
            "source_confirmed": f.taint_trace.source_confirmed,
            "taint_source": f.taint_trace.taint_source,
            "interpolation_type": f.taint_trace.interpolation_type,
            "has_sanitization": f.taint_trace.has_sanitization,
            "trace_hops": f.taint_trace.trace_hops,
        },
        "yasa_blind": f.yasa_blind,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Post-YASA audit pipeline: grep signals, taint-trace, "
        "score, and rank findings.",
    )
    parser.add_argument(
        "--project-path",
        required=True,
        help="Path to the project directory to audit.",
    )
    parser.add_argument(
        "--language",
        required=True,
        help="Programming language (passed through to sub-tools).",
    )
    parser.add_argument(
        "--yasa-sinks",
        default=None,
        help="Optional path to YASA rule_config.json for sink cross-reference.",
    )
    parser.add_argument(
        "--source-summary",
        default=None,
        help="Optional path to YASA scan_summary.json for context.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the audit findings JSON.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Maximum number of files to scan (default: 500).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.max_files < 1:
        parser.error("--max-files must be >= 1")

    output = run_pipeline(
        project_path=args.project_path,
        language=args.language,
        max_files=args.max_files,
        yasa_sinks_path=args.yasa_sinks,
        source_summary_path=args.source_summary,
    )

    # Write output JSON
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    serialised = {
        "audit_timestamp": output.audit_timestamp,
        "language": output.language,
        "project_path": output.project_path,
        "yasa_context": asdict(output.yasa_context),
        "grep_stats": asdict(output.grep_stats),
        "missed_sinks": output.missed_sinks,
        "findings": output.findings,
    }
    out_path.write_text(
        json.dumps(serialised, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[*] Audit report written to: {out_path}", file=sys.stderr)

    # Build Finding objects from serialised data for the summary table
    deserialised_findings: list[Finding] = []
    for fd in output.findings:
        tt = fd.get("taint_trace", {})
        deserialised_findings.append(
            Finding(
                id=fd.get("id", ""),
                confidence=fd.get("confidence", "LOW"),
                score=fd.get("score", 0.0),
                file=fd.get("file", ""),
                line=fd.get("line", 0),
                snippet=fd.get("snippet", ""),
                pattern_id=fd.get("pattern_id", ""),
                vuln_class=fd.get("vuln_class", ""),
                taint_trace=TaintTrace(
                    variable=tt.get("variable"),
                    source_confirmed=tt.get("source_confirmed", False),
                    taint_source=tt.get("taint_source"),
                    interpolation_type=tt.get("interpolation_type"),
                    has_sanitization=tt.get("has_sanitization", False),
                    trace_hops=tt.get("trace_hops", 0),
                ),
                yasa_blind=fd.get("yasa_blind", True),
            )
        )

    _print_summary_table(deserialised_findings, output.grep_stats, output.yasa_context)


if __name__ == "__main__":
    main()
