#!/usr/bin/env python3
"""Lightweight, grep-based taint tracing tool.

Checks whether user-controlled input can reach a specific sink by
tracing variable assignments, function calls, and returns across a
single file up to a configurable number of hops.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PYTHON_KEYWORDS: frozenset[str] = frozenset({
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
    "try", "while", "with", "yield",
})

# Patterns to extract (variable, interpolation_type) from a sink line.
# The order matters – we try more specific patterns first.
# Match common sink function calls and capture their first variable argument.
VAR_IN_CALL = re.compile(
    r"(?:popen|run|exec|eval|system|call|Popen|check_output|check_call|"
    r"getoutput|getstatusoutput)\s*\(\s*(\w+)\s*\)"
)
VAR_FSTRING = re.compile(r"\{(\w+)}")
VAR_FORMAT = re.compile(r"""\.format\s*\(\s*(\w+)\s*\)""")
VAR_CONCAT_LEFT = re.compile(r"""['\"][^'\"]*['\"]\s*\+\s*(\w+)""")
VAR_CONCAT_RIGHT = re.compile(r"""(\w+)\s*\+\s*['\"][^'\"]*['\"]""")
VAR_CONCAT_BOTH = re.compile(r"""(\w+)\s*\+\s*(\w+)""")

# Source patterns – case-insensitive match against assignment right-hand sides.
# Use \b word boundaries to avoid false positives (e.g. "form" inside ".format").
SOURCE_PATTERNS = re.compile(
    r"(?:\brequest\b|\bargs\b|\bform\b|\bbody\b|\bjson\b|"
    r"\bquery_params\b|\bpath_params\b|\bheaders\b|"
    r"\bcookies\b|\bGET\b|\bPOST\b|\bFILES\b|\bdata\b|"
    r"\.get_json\(\)|\bsys\.argv\b|\benviron\b|\bparams\b)",
    re.IGNORECASE,
)

# Sanitization patterns – checked on every line in the trace path.
SANITIZE_PATTERNS = re.compile(
    r"(?:shlex\.quote|\.escape\(\)|re\.match|re\.fullmatch|"
    r"ensure_valid|validate|sanitize|os\.path\.abspath)",
)

# Assignment: optional leading whitespace, variable, =, rest.
ASSIGN_RE = re.compile(r"^\s*(\w+)\s*=\s*(.+?)\s*(?:#.*)?$")

# Function definition line.
FUNC_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")

# Return statement.
RETURN_RE = re.compile(r"^\s*return\s+(.+?)\s*(?:#.*)?$")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class TaintResult:
    variable: Optional[str] = None
    sink_file: str = ""
    sink_line: int = 0
    source_confirmed: bool = False
    taint_source: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    interpolation_type: Optional[str] = None
    has_sanitization: bool = False
    sanitization_detail: Optional[str] = None
    trace_hops: int = 0
    confidence: str = "none"
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Variable extraction helpers
# ---------------------------------------------------------------------------


def _extract_variables_from_line(line: str) -> list[tuple[str, str]]:
    """Return list of (variable_name, interpolation_type) found on *line*."""
    found: list[tuple[str, str]] = []

    # direct call argument
    m = VAR_IN_CALL.search(line)
    if m:
        found.append((m.group(1), "direct"))

    # f-string interpolation  {var}
    for m in VAR_FSTRING.finditer(line):
        found.append((m.group(1), "f-string"))

    # .format(...)
    m = VAR_FORMAT.search(line)
    if m:
        found.append((m.group(1), "format"))

    # concat: "literal" + var   or   var + "literal"   or   var + var
    for m in VAR_CONCAT_LEFT.finditer(line):
        found.append((m.group(1), "concat"))
    for m in VAR_CONCAT_RIGHT.finditer(line):
        found.append((m.group(1), "concat"))
    for m in VAR_CONCAT_BOTH.finditer(line):
        for g in (m.group(1), m.group(2)):
            if g not in PYTHON_KEYWORDS:
                found.append((g, "concat"))

    # fallback: treat any simple identifier in a function-call argument
    # position as a potential taint variable.
    if not found:
        call_args_match = re.search(r"\(\s*(\w+)\s*\)", line)
        if call_args_match:
            found.append((call_args_match.group(1), "method_wrapper"))

    return found


def _identifiers_in_expr(expr: str) -> list[str]:
    """Return variable-like identifiers from *expr* (shallow, no keywords)."""
    no_strings = re.sub(r"""["\'][^"\']*["\']""", "", expr)
    return [
        m.group(1)
        for m in re.finditer(r"\b([a-zA-Z_]\w*)\b", no_strings)
        if m.group(1) not in PYTHON_KEYWORDS
    ]


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


def _read_lines(path: Path) -> list[str]:
    """Return file lines (empty list on error)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _find_function_def(
    lines: list[str], func_name: str, start: int = 0
) -> Optional[int]:
    """Return 1-indexed line of ``def func_name(``, searching from *start*."""
    for i in range(start, len(lines)):
        m = FUNC_DEF_RE.match(lines[i])
        if m and m.group(1) == func_name:
            return i + 1  # 1-indexed
    return None


def _get_function_params(lines: list[str], def_line_1idx: int) -> list[str]:
    """Extract parameter names from a function definition line."""
    if def_line_1idx < 1 or def_line_1idx > len(lines):
        return []
    line = lines[def_line_1idx - 1]
    # Match def funcname(params):
    m = re.match(r"^\s*(?:async\s+)?def\s+\w+\s*\((.*)\)\s*:", line)
    if not m:
        return []
    params_str = m.group(1).strip()
    if not params_str:
        return []
    # Simple split by comma (handles simple params, not complex defaults)
    params: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in params_str:
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth -= 1
        elif ch == "," and depth == 0:
            params.append("".join(buf).strip().split("=")[0].strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        params.append("".join(buf).strip().split("=")[0].strip())
    return [p for p in params if re.match(r"^\w+$", p)]


def _split_call_args(args_str: str) -> list[str]:
    """Split a function call argument string into individual argument strings."""
    args: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in args_str:
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        args.append("".join(buf).strip())
    return args


def _function_body_extents(
    lines: list[str], def_line_1idx: int
) -> tuple[int, int]:
    """Return (start_line_1idx, end_line_1idx_exclusive) of a function body.

    The start is the line *after* the ``def`` line.  We stop at the next
    top-level ``def`` (same or lesser indent) or EOF.
    """
    if def_line_1idx < 1 or def_line_1idx > len(lines):
        return def_line_1idx, def_line_1idx

    idx = def_line_1idx - 1  # 0-indexed
    def_indent = len(lines[idx]) - len(lines[idx].lstrip())
    body_start = idx + 2  # line after def + possible docstring? Be conservative.

    # If the next line is a docstring or blank, keep scanning for real body.
    # Simple approach: body begins at first indented line after def.
    for j in range(idx + 1, len(lines)):
        if lines[j].strip() and not lines[j].strip().startswith("#"):
            curr_indent = len(lines[j]) - len(lines[j].lstrip())
            if curr_indent > def_indent:
                body_start = j + 1
                break

    for j in range(body_start, len(lines)):
        stripped = lines[j].strip()
        if stripped and not stripped.startswith("#"):
            curr_indent = len(lines[j]) - len(lines[j].lstrip())
            if curr_indent <= def_indent and stripped.startswith("def "):
                return body_start, j + 1  # j is 0-indexed

    return body_start, len(lines) + 1


# ---------------------------------------------------------------------------
# Assignment search
# ---------------------------------------------------------------------------


def _find_assignments(
    lines: list[str], variable: str, up_to_line: int
) -> list[tuple[int, str]]:
    """Return list of (line_number_1idx, rhs_expr) for *variable*."""
    assigns: list[tuple[int, str]] = []
    for i in range(min(up_to_line, len(lines))):
        m = ASSIGN_RE.match(lines[i])
        if m and m.group(1) == variable:
            assigns.append((i + 1, m.group(2).strip()))
    return assigns


# ---------------------------------------------------------------------------
# Source / sanitisation checks
# ---------------------------------------------------------------------------


def _has_source(expr: str) -> Optional[str]:
    """Return the matched source pattern substring, or *None*."""
    m = SOURCE_PATTERNS.search(expr)
    return m.group(0) if m else None


def _has_sanitization(line: str) -> Optional[str]:
    """Return the matched sanitization pattern substring, or *None*."""
    m = SANITIZE_PATTERNS.search(line)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Recursive tracer
# ---------------------------------------------------------------------------


def _trace_variable(
    variable: str,
    lines: list[str],
    sink_line_1idx: int,
    max_hops: int,
    *,
    _depth: int = 0,
    _visited: Optional[set[str]] = None,
) -> dict[str, Any]:
    """Trace *variable* backwards to find a user-input source.

    Returns a dictionary with keys:
        source_found, source_expr, source_line, hops,
        has_sanitization, sanitization_detail, errors
    """
    if _visited is None:
        _visited = set()
    if _depth > max_hops:
        return {
            "source_found": False,
            "source_expr": None,
            "source_line": None,
            "hops": _depth,
            "has_sanitization": False,
            "sanitization_detail": None,
            "errors": [f"Max hops ({max_hops}) reached."],
        }

    var_key = f"{variable}:{sink_line_1idx}"
    if var_key in _visited:
        return {
            "source_found": False,
            "source_expr": None,
            "source_line": None,
            "hops": _depth,
            "has_sanitization": False,
            "sanitization_detail": None,
            "errors": [f"Cycle detected tracing '{variable}'."],
        }
    _visited.add(var_key)

    errors: list[str] = []

    # 1. Find most recent assignment
    assigns = _find_assignments(lines, variable, sink_line_1idx)
    if not assigns:
        errors.append(f"No assignment to '{variable}' before line {sink_line_1idx}.")
        return {
            "source_found": False,
            "source_expr": None,
            "source_line": None,
            "hops": _depth + 1,
            "has_sanitization": False,
            "sanitization_detail": None,
            "errors": errors,
        }

    line_num, rhs = assigns[-1]
    hops = _depth + 1

    # 2. Check the whole line for sanitisation
    raw_line = lines[line_num - 1] if line_num <= len(lines) else ""
    san_detail = _has_sanitization(raw_line)

    # 3. Check if RHS is a direct source
    src = _has_source(rhs)
    if src:
        return {
            "source_found": True,
            "source_expr": rhs,
            "source_line": line_num,
            "hops": hops,
            "has_sanitization": san_detail is not None,
            "sanitization_detail": san_detail,
            "errors": errors,
        }

    # 4. Check if RHS is a function call – trace into its body
    #    Match dotted names too:  mod.func(...)
    func_call_match = re.match(r"^([\w.]+)\s*\((.*)\)\s*$", rhs)
    if func_call_match:
        func_full = func_call_match.group(1)  # e.g. "shlex.quote" or "get_input"
        args_str = func_call_match.group(2)

        # Separate module from function name for definition lookup
        func_name = func_full.split(".")[-1]
        def_line = _find_function_def(lines, func_name)

        if def_line is not None:
            if hops >= max_hops:
                errors.append(
                    f"Max hops ({max_hops}) reached tracing into '{func_name}()'."
                )
            else:
                # Extract parameter names and map to call-site arguments
                func_params = _get_function_params(lines, def_line)
                call_site_args = _split_call_args(args_str)
                # Build map: parameter_name -> argument_expression
                param_map: dict[str, str] = {}
                for p_name, p_val in zip(func_params, call_site_args):
                    param_map[p_name] = p_val

                body_start, body_end = _function_body_extents(lines, def_line)
                # Look for return statements in the body that contain a source
                for bi in range(body_start - 1, min(body_end - 1, len(lines))):
                    rm = RETURN_RE.match(lines[bi])
                    if not rm:
                        continue
                    ret_expr = rm.group(1).strip()

                    # --- Helper: trace an expression from a return statement ---
                    def _trace_return_expr(
                        _expr: str, _line_1idx: int
                    ) -> Optional[dict[str, Any]]:
                        """Trace identifiers in a return expression, respecting
                        parameter-to-argument mapping."""
                        # If the return is a simple variable, trace it directly
                        _var_m = re.match(r"^(\w+)$", _expr)
                        if _var_m:
                            _var = _var_m.group(1)
                            if _var in param_map:
                                # Map parameter to call-site argument and trace
                                _cs_expr = param_map[_var]
                                _cs_var_m = re.match(r"^(\w+)$", _cs_expr)
                                if _cs_var_m:
                                    return _trace_variable(
                                        _cs_var_m.group(1),
                                        lines,
                                        line_num,  # caller's assignment line
                                        max_hops,
                                        _depth=hops,
                                        _visited=_visited,
                                    )
                                # Complex call-site expression: extract identifiers
                                for _cs_var in _identifiers_in_expr(_cs_expr):
                                    _inner = _trace_variable(
                                        _cs_var,
                                        lines,
                                        line_num,
                                        max_hops,
                                        _depth=hops,
                                        _visited=_visited,
                                    )
                                    if _inner.get("source_found"):
                                        return _inner
                                return None
                            # Not a param – trace normally within this function
                            return _trace_variable(
                                _var,
                                lines,
                                _line_1idx,
                                max_hops,
                                _depth=hops,
                                _visited=_visited,
                            )

                        # Complex return expression – check for direct source
                        _src = _has_source(_expr)
                        if _src:
                            # Ensure the matched source isn't a parameter name
                            _src_word = _src.strip().lstrip(".").rstrip("()")
                            if _src_word in param_map:
                                # Map to call-site arg and continue
                                _cs_expr = param_map[_src_word]
                                return _trace_return_expr(_cs_expr, _line_1idx)
                            return {
                                "source_found": True,
                                "source_expr": _expr,
                                "source_line": _line_1idx,
                                "hops": hops + 1,
                                "has_sanitization": san_detail is not None,
                                "sanitization_detail": san_detail,
                                "errors": errors,
                            }

                        # Extract identifiers and try tracing each
                        for _id_var in _identifiers_in_expr(_expr):
                            if _id_var in param_map:
                                _cs_expr = param_map[_id_var]
                                _cs_var_m = re.match(r"^(\w+)$", _cs_expr)
                                if _cs_var_m:
                                    _inner = _trace_variable(
                                        _cs_var_m.group(1),
                                        lines,
                                        line_num,
                                        max_hops,
                                        _depth=hops,
                                        _visited=_visited,
                                    )
                                    if _inner.get("source_found"):
                                        return _inner
                                continue
                            _inner = _trace_variable(
                                _id_var,
                                lines,
                                _line_1idx,
                                max_hops,
                                _depth=hops,
                                _visited=_visited,
                            )
                            if _inner.get("source_found"):
                                return _inner
                        return None

                    result_inner = _trace_return_expr(ret_expr, bi + 1)
                    if result_inner is not None:
                        if result_inner.get("source_found"):
                            result_inner["has_sanitization"] = (
                                result_inner["has_sanitization"]
                                or san_detail is not None
                            )
                            if san_detail and not result_inner["sanitization_detail"]:
                                result_inner["sanitization_detail"] = san_detail
                            result_inner["hops"] = result_inner.get("hops", hops + 1)
                            result_inner["errors"].extend(errors)
                            return result_inner

        # If we couldn't trace the function, try extracting argument
        # variables and tracing those.
        arg_vars = _identifiers_in_expr(args_str)
        for arg_var in arg_vars:
            inner = _trace_variable(
                arg_var,
                lines,
                line_num,
                max_hops,
                _depth=hops,
                _visited=_visited,
            )
            if inner.get("source_found"):
                inner["has_sanitization"] = (
                    inner["has_sanitization"] or san_detail is not None
                )
                if san_detail and not inner["sanitization_detail"]:
                    inner["sanitization_detail"] = san_detail
                inner["hops"] = inner.get("hops", hops + 1)
                inner["errors"].extend(errors)
                return inner

        if def_line is None:
            errors.append(
                f"Function '{func_name}()' not defined in the same file."
            )

    # 5. Fallback: if RHS itself is a variable name, trace it
    var_only_match = re.match(r"^(\w+)$", rhs)
    if var_only_match and var_only_match.group(1) not in PYTHON_KEYWORDS:
        inner = _trace_variable(
            var_only_match.group(1),
            lines,
            line_num,
            max_hops,
            _depth=hops,
            _visited=_visited,
        )
        if inner.get("source_found"):
            inner["has_sanitization"] = (
                inner["has_sanitization"] or san_detail is not None
            )
            if san_detail and not inner["sanitization_detail"]:
                inner["sanitization_detail"] = san_detail
            inner["hops"] = inner.get("hops", hops + 1)
            inner["errors"].extend(errors)
            return inner

    # 6. Generic fallback: extract all identifiers from the RHS and try
    #    tracing each one.  This catches patterns such as:
    #        x = "echo {0}".format(arg)
    #        x = prefix + user_input
    id_vars = _identifiers_in_expr(rhs)
    for id_var in id_vars:
        if id_var == variable:
            continue  # skip self-reference
        inner = _trace_variable(
            id_var,
            lines,
            line_num,
            max_hops,
            _depth=hops,
            _visited=_visited,
        )
        if inner.get("source_found"):
            inner["has_sanitization"] = (
                inner["has_sanitization"] or san_detail is not None
            )
            if san_detail and not inner["sanitization_detail"]:
                inner["sanitization_detail"] = san_detail
            inner["hops"] = inner.get("hops", hops + 1)
            inner["errors"].extend(errors)
            return inner

    return {
        "source_found": False,
        "source_expr": None,
        "source_line": None,
        "hops": hops,
        "has_sanitization": san_detail is not None,
        "sanitization_detail": san_detail,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def _confidence(source_confirmed: bool, has_san: bool, hops: int) -> str:
    if not source_confirmed:
        return "none"
    if has_san:
        return "low"
    if hops <= 2:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Main analysis entry-point
# ---------------------------------------------------------------------------


def run_taint_trace(
    sink_file: Path,
    sink_line: int,
    project_path: Path,
    language: str = "python",
    max_hops: int = 3,
) -> TaintResult:
    """Run the taint trace and return a ``TaintResult``."""
    result = TaintResult(
        sink_file=str(sink_file.resolve()),
        sink_line=sink_line,
        source_file=str(sink_file.resolve()),
    )

    lines = _read_lines(sink_file)
    if not lines:
        result.errors.append(f"Cannot read file: {sink_file}")
        return result

    if sink_line < 1 or sink_line > len(lines):
        result.errors.append(
            f"Sink line {sink_line} out of range (file has {len(lines)} lines)."
        )
        return result

    sink_content = lines[sink_line - 1]

    # 1. Extract possible tainted variables from the sink line
    variables = _extract_variables_from_line(sink_content)
    if not variables:
        result.errors.append(
            f"Could not extract a variable from sink line {sink_line}: "
            f"{sink_content.strip()!r}"
        )
        return result

    result.variable = variables[0][0]
    result.interpolation_type = variables[0][1]

    # 2. Check sink line itself for sanitisation
    san = _has_sanitization(sink_content)
    if san:
        result.has_sanitization = True
        result.sanitization_detail = san

    # 3. Trace each extracted variable; use the first one that confirms a source.
    best_trace: Optional[dict[str, Any]] = None
    for var_name, _interp in variables:
        if best_trace is not None and best_trace.get("source_found"):
            break
        trace = _trace_variable(var_name, lines, sink_line, max_hops)
        if trace.get("source_found"):
            best_trace = trace
            result.variable = var_name
            result.interpolation_type = _interp
            break
        elif best_trace is None:
            best_trace = trace

    if best_trace is None:
        # Should not happen, but guard anyway.
        result.errors.append("Internal error: no trace result produced.")
        return result

    result.trace_hops = best_trace.get("hops", 1)
    if best_trace.get("source_found"):
        result.source_confirmed = True
        result.taint_source = best_trace.get("source_expr")
        result.source_line = best_trace.get("source_line")

        # Merge sanitisation discovered during tracing
        if best_trace.get("has_sanitization"):
            result.has_sanitization = True
            result.sanitization_detail = (
                best_trace.get("sanitization_detail") or result.sanitization_detail
            )

    result.errors.extend(best_trace.get("errors", []))
    result.confidence = _confidence(
        result.source_confirmed, result.has_sanitization, result.trace_hops
    )
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lightweight grep-based taint tracing.  Checks whether "
        "user-controlled input can reach a specific sink.",
    )
    parser.add_argument(
        "--sink-file",
        required=True,
        type=Path,
        help="Path to the file containing the sink (e.g. /path/file.py).",
    )
    parser.add_argument(
        "--sink-line",
        required=True,
        type=int,
        help="1-indexed line number of the sink in the sink-file.",
    )
    parser.add_argument(
        "--project-path",
        required=True,
        type=Path,
        help="Root path of the project being analysed (used for context).",
    )
    parser.add_argument(
        "--language",
        default="python",
        help="Language of the source code (default: python).",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=3,
        help="Maximum number of trace hops (default: 3).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON.",
    )
    return parser


def _format_human(result: TaintResult) -> str:
    lines: list[str] = [
        f"Variable:            {result.variable}",
        f"Sink File:           {result.sink_file}",
        f"Sink Line:           {result.sink_line}",
        f"Source Confirmed:    {result.source_confirmed}",
    ]
    if result.taint_source:
        lines.append(f"Taint Source:        {result.taint_source}")
    if result.source_file:
        lines.append(f"Source File:         {result.source_file}")
    if result.source_line:
        lines.append(f"Source Line:         {result.source_line}")
    lines.append(f"Interpolation Type:  {result.interpolation_type}")
    lines.append(f"Has Sanitization:    {result.has_sanitization}")
    if result.sanitization_detail:
        lines.append(f"Sanitization Detail: {result.sanitization_detail}")
    lines.append(f"Trace Hops:          {result.trace_hops}")
    lines.append(f"Confidence:          {result.confidence}")
    if result.errors:
        lines.append(f"Errors:              {'; '.join(result.errors)}")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    sink_file: Path = args.sink_file
    project_path: Path = args.project_path

    if not sink_file.is_file():
        print(f"Error: sink file not found: {sink_file}", file=sys.stderr)
        return 1

    if not project_path.is_dir():
        print(f"Error: project path is not a directory: {project_path}", file=sys.stderr)
        return 1

    result = run_taint_trace(
        sink_file=sink_file,
        sink_line=args.sink_line,
        project_path=project_path,
        language=args.language,
        max_hops=args.max_hops,
    )

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print(_format_human(result))

    return 0  # analysis completed (even if taint not found)


if __name__ == "__main__":
    sys.exit(main())
