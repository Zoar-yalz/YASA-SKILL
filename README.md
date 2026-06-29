# YASA-SKILL

OpenCode agent skill for automated security code review — static taint analysis + pattern-based audit + AI-powered triage.

## What it does

A three-phase pipeline that finds vulnerabilities your linter misses:

| Phase | Name | How | Output |
|-------|------|-----|--------|
| 1 | **YASA Taint Scan** | AST-level source→sink tracking via YASA-Engine | SARIF with full `codeFlow` evidence |
| 2 | **Post-Scan Audit** | Grep-based pattern matching for YASA-blind patterns (f-string injection, method wrappers, concat commands) | `audit_findings.json` with confidence scores |
| 3 | **AI Review** | Agent reads source code context, classifies CONFIRMED / LIKELY / FALSE_POSITIVE, generates fix recommendations | Reviewed findings with `ai_verdict` + `ai_fix` |

Phase 1 is the surgeon. Phase 2 is the bloodhound. Phase 3 is the triage surgeon that eliminates false positives and confirms true vulnerabilities.

## Quick start

```bash
# Install into any project
unzip yasa-checker-opencode-*.zip -d /path/to/project

# Install YASA-Engine (first time only)
python yasa-checker/scripts/install_yasa_release.py

# Verify
python yasa-checker/scripts/preflight_yasa.py
# → {"ok": true, "mode": "full"}

# Run a scan
/yasa-check project=myapp language=python vuln=PythonCommandInjection
```

Or via agent invocation:
```
@yasa-checker audit ./src for command injection
```

## Architecture

```
User request
    ↓
Phase 1: YASA-Engine (AST taint tracking)
    → scan_summary.json
    ↓
Phase 2: grep_signals → cross-ref YASA sinks → taint_trace → score
    → audit_findings.json
    ↓
Phase 3: Read source context → classify verdict → generate fix → write back
    → Reviewed report with CONFIRMED / LIKELY / FP / recommendations
```

## Confidence scoring

Each Phase 2 finding gets a 0-100 score from four weighted factors:

| Factor | Weight | What it checks |
|--------|--------|---------------|
| Source reach | 40% | User input reaches the sink argument |
| No sanitization | 25% | No `shlex.quote`, validation, or escaping found |
| Dangerous sink | 20% | Pattern severity (HIGH = 20, MEDIUM = 10) |
| Direct interpolation | 15% | f-string, concatenation, or `.format()` pattern |

Phase 3's AI review then overrides these scores based on actual code context — upgrading LOW findings that are genuinely exploitable and downgrading false positives.

## Files

```
.opencode/skills/yasa-checker/SKILL.md    ← Skill definition
yasa-checker/scripts/           (10)      ← Python scripts
yasa-checker/references/        (10)      ← Reference docs
yasa-checker/DESIGN.md                    ← Architecture design doc
```

## Requirements

- Python 3.9+
- YASA-Engine v0.3.1 (auto-downloadable)
- ripgrep (optional, for faster Phase 2 grep)
- OpenCode or compatible agent runtime
