---
name: yasa-checker
description: Static taint analysis with YASA-Engine plus post-scan grep audit and AI-powered contextual code review. Finds command injection, path traversal, SSRF, deserialization, and other vulnerability classes that pure static analysis misses. Use for security auditing of Python/Node.js codebases — install YASA, run scans, and produce reviewed finding reports.
license: MIT
compatibility: opencode
metadata:
  audience: security-engineers
  workflow: security-audit
  tags: yasa,taint-analysis,command-injection,path-traversal,code-review,static-analysis
---

# YASA Checker

Three-phase security analysis pipeline: YASA static taint tracking → grep-based pattern audit → AI contextual review.

## Phase 1: YASA Taint Scan

Run AST-level source-to-sink taint tracking via YASA-Engine.

**Before scanning:**
```bash
# Install YASA (first time only)
python yasa-checker/scripts/install_yasa_release.py --version v0.3.1 --install-dir .yasa-tools

# Verify environment
python yasa-checker/scripts/preflight_yasa.py
# → {"ok": true, "mode": "full"} means ready
# → {"ok": false, "mode": "config-only"} means generate rules only
```

**Build rule_config.json:**

Identify the project path, language, and vulnerability class (e.g., PythonCommandInjection, PythonPathTraversal, PythonSSRF). Create entrypoints using verified function names from route handlers:

```python
# Verify entrypoint names exist before writing config:
grep -rn "async def function_name\|def function_name" <project>/
```

Write `rule_config.json` with:
- `checkerIds`: `["taint_flow_python_input"]`
- `sources`: `TaintSource` (request attributes), `FuncCallReturnValueTaintSource`, `FuncCallArgTaintSource`
- `sinks`: `FuncCallTaintSink` with `fsig` for each sink function
- `entrypoints`: list of `{"functionName": "...", "filePath": "/..."}` (filePath relative to sourcePath with leading slash, bare functionName for Python)

Validate:
```bash
python yasa-checker/scripts/validate_rule_config.py rule_config.json --language python
```

**Run YASA:**
```bash
.yasa-tools/yasa-v0.3.1/yasa-engine-linux-x64 \
  --sourcePath <PROJECT> \
  --language python \
  --report .yasa-workspace/report \
  --checkerIds "taint_flow_python_input" \
  --ruleConfigFile .yasa-workspace/rule_config.json \
  --entrypointMode ONLY_CUSTOM
```

If YASA produces `parsePackage error` or `EntryPoints are not found`, check:
1. `deps/uast4py/uast4py` exists and is executable at the project root
2. Entrypoint function names are bare (no class prefix) for Python
3. File paths have leading `/` and are relative to sourcePath
4. The right checker ID is specified via `--checkerIds`

**Extract metrics:**
```bash
python yasa-checker/scripts/extract_scan_metrics.py .yasa-workspace/report/scan_summary.json
```

If YASA has findings, convert SARIF to evidence:
```bash
python yasa-checker/scripts/sarif_to_evidence.py .yasa-workspace/report/report.sarif -o evidence.json
```

## Phase 2: Post-Scan Audit

Run **after every scan** (even 0 findings). Catches patterns YASA cannot trace through f-strings, method wrappers, or framework abstractions.

```bash
python yasa-checker/scripts/post_scan_audit.py \
  --project-path <PROJECT_SOURCE> \
  --language python \
  --yasa-sinks <RULE_CONFIG.json> \
  --source-summary <REPORT_DIR>/scan_summary.json \
  --output <REPORT_DIR>/audit_findings.json
```

This runs: grep_patterns → cross-reference YASA sinks → deduplicate → taint_trace each hit → score confidence (HIGH/MEDIUM/LOW).

## Phase 3: AI Contextual Review

After `audit_findings.json` is produced, review each finding by reading actual source code context. **This is the critical step that eliminates false positives and confirms true vulnerabilities.**

For full review protocol, read `yasa-checker/references/ai-review-guide.md`. Execute:

### 1. Load findings
```python
audit = json.load(open('audit_findings.json'))
findings = sorted(audit['findings'], key=lambda f: f['score'], reverse=True)
```

### 2. Read source context — batch by file
Group findings by `file`. For each unique file, use `Read` to read from `(min_line - 15)` to `(max_line + 15)`. All findings in a file reviewed in one batch.

### 3. For each finding, classify:
- **CONFIRMED**: Source is clearly user-controllable, no sanitization, direct exploit path. Cite the exact `variable → sink` chain.
- **LIKELY**: Source seems user-controllable but indirect. Needs one human confirmation hop.
- **FALSE_POSITIVE**: Source is NOT user-controllable. Explain exactly why (e.g., "local integer", "hardcoded constant").
- **NEEDS_MANUAL_REVIEW**: Ambiguous — state what additional info would resolve it.

### 4. Override severity
LOW findings with confirmed user input → **HIGH**. MEDIUM with confirmed FP → **INFO**.

### 5. Generate fix
For CONFIRMED/LIKELY: produce a concrete fix snippet using patterns already in the codebase. If the same file uses `shlex.quote()` elsewhere, recommend that.

### 6. Write back
Append `ai_verdict`, `ai_rationale`, `ai_severity`, `ai_fix` to each reviewed finding.

## Output Format

Produce a combined report:

```markdown
## YASA environment
<full/config-only/evidence-only>

## Scan summary
| Metric | Value |
|---|---:|
| Valid entrypoints | N |
| Sources marked | N |
| Sinks matched | N |
| Findings | N |

## Post-Scan Audit (AI Reviewed)
| # | File:Line | Pattern | AI Verdict | AI Sev | Rationale | Fix |
|---:|---|---|---|---|---|---|

## AI Reviewed — Key Findings
- **CONFIRMED** (N): list with fix snippets
- **FALSE_POSITIVE** (N): list with dismissal reasons
- **LIKELY** (N): list with the question to resolve
```

## Modes

| Mode | YASA | Pipeline | When |
|------|------|----------|------|
| Full | available | Phase 1 + 2 + 3 | YASA installed |
| Config-only | absent | Phase 2 + 3 | Generate rules, audit |
| Evidence-only | absent | Phase 1 triage | SARIF/logs provided |

In config-only mode, skip YASA scan but still run post-scan audit and AI review. Source code must be available.

## Key Rules

- **Audit ALWAYS runs** — even when YASA finds vulns (different pattern classes)
- **Never claim a vuln without source confirmation** — use LIKELY if you can't verify
- **Read actual code for AI review** — don't review from JSON alone
- **Prefer codebase patterns for fixes** — use `shlex.quote` if the file already does elsewhere
- **Batch reads by file** — one Read per file, not per finding
