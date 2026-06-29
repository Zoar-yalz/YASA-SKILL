# YASA Checker Skill

OpenCode agent skill for static taint analysis + post-scan vulnerability auditing.

Combines **[YASA-Engine](https://github.com/YASA-Engine/yasa)** AST-level taint tracking with a dedicated post-scan grep-based audit phase and an AI-powered contextual review that reads source code, removes false positives, and generates fix recommendations.

---

## What It Does

YASA Checker runs a three-phase security analysis pipeline. **Phase 1** uses YASA-Engine to perform source-to-sink taint tracking across the AST, producing SARIF output with codeFlow evidence. **Phase 2** supplements that with grep-based pattern matching that targets vulnerability classes YASA cannot model — f-string injection into subprocess calls, method-wrapped command executors, framework-level command abstractions, and string-concatenated shell commands. Each Phase 2 hit is cross-referenced against YASA's sink configuration, traced for variable taint provenance, and assigned a confidence score. **Phase 3** is the AI review stage: the orchestrating agent reads source code context around each finding, determines whether the source is truly user-controllable, classifies each as CONFIRMED / LIKELY / FALSE_POSITIVE, and generates specific fix recommendations. The result is a combined finding set that catches YASA-detectable patterns, YASA-blind patterns, and eliminates false positives through contextual analysis.

---

## Quick Start

```shell
unzip yasa-checker-opencode-final.zip -d .
python yasa-checker/scripts/install_yasa_release.py
python yasa-checker/scripts/preflight_yasa.py     # ok=true means ready
```

---

## Three Analysis Phases

### Phase 1 — YASA Taint Scan

- **AST-level source→sink taint tracking** across the call graph
- Outputs **SARIF** with full `codeFlow` arrays showing each propagation step
- Requires a `rule_config.json` that defines sources, sinks, sanitizers, and entrypoints
- Run via `/yasa-check project=<path> language=<lang> vuln=<class>`

### Phase 2 — Post-Scan Audit

- **Grep-based pattern matching** for YASA-blind vulnerability patterns:

  | Pattern class | Examples |
  |---|---|
  | f-string commands | `subprocess.run(f"...")`, `os.system(f"...")` |
  | Method wrappers | `.execute_command()`, `.run_command()`, `.shell_command()` |
  | String concatenation | `subprocess.run(cmd + arg)` |
  | `.format()` injection | `os.system(cmd.format(user_input))` |
  | `shell=True` | `subprocess.run(..., shell=True)` |

- Cross-references each hit against the YASA sink configuration to identify **missed sinks** (patterns YASA should have caught but didn't)
- Runs **variable taint tracing** on each hit to confirm whether the interpolated value originates from an attacker-controlled source
- Assigns a **confidence score** per finding (HIGH / MEDIUM / LOW)

### Phase 3 — AI Review (Automated Triage)

- **Reads source code context** (±15 lines around each finding) using the agent's Read tool
- **Classifies every finding** into one of four verdicts:

  | Verdict | Meaning |
  |---|---|
  | `CONFIRMED` | User-controllable source + no sanitization + exploitable path |
  | `LIKELY` | Source seems controllable but chain is indirect; one human hop needed |
  | `FALSE_POSITIVE` | Source is NOT user-controllable (local int, hardcoded constant) |
  | `NEEDS_MANUAL_REVIEW` | Ambiguous; states what additional info would resolve it |

- **Overrides automated confidence** based on actual code context (LOW findings can be upgraded to HIGH when source is confirmed)
- **Generates fix recommendations** using patterns already present in the codebase (e.g., if the same file uses `shlex.quote()` elsewhere, recommends that)
- **Groups findings by file** to minimize reads — all findings in the same file are reviewed in a single batch

---

## Modes of Operation

| Mode | YASA binary | rule_config.json | SARIF evidence | Pipeline steps |
|---|---|---|---|---|---|
| **Full** | Required | Required | Generated | Phase 1 + Phase 2 + Phase 3 (AI Review) + triage |
| **Config-only** | Not required | Required | Not required | Phase 2 + Phase 3 (AI Review) + config generation |
| **Evidence-only** | Not required | Not required | Provided | SARIF triage and verdict only |

---

## Commands

| Command | Description |
|---|---|
| `/yasa-preflight` | Check environment — detects YASA binary, config, and available modes |
| `/yasa-install` | Download and install YASA-Engine into `.yasa-tools/` (asks for approval first) |
| `/yasa-check project=<path> language=<lang> vuln=<class>` | Full workflow: runs preflight, generates or loads config, executes Phase 1 + Phase 2 |

---

## Agent Invocation

```
@yasa-checker install YASA v0.3.1 into .yasa-tools
@yasa-checker generate a PythonCommandInjection rule_config.json for samples/myapp
@yasa-checker audit OpenHands for command injection
```

---

## Directory Structure

```
yasa-checker/
├── scripts/                 # 10 Python scripts
│   ├── install_yasa_release.py   # Download & install YASA-Engine
│   ├── preflight_yasa.py         # Environment readiness check
│   ├── grep_signals.py           # Language-aware grep pattern engine
│   ├── taint_trace.py            # Variable taint provenance tracer
│   ├── post_scan_audit.py        # Audit pipeline orchestrator
│   ├── sarif_to_evidence.py      # SARIF → triage evidence converter
│   ├── validate_rule_config.py   # Rule config schema validation
│   ├── normalize_rule_config.py  # Rule config normalization
│   ├── write_local_config.py     # Local agent config writer
│   └── extract_scan_metrics.py   # YASA scan metric extraction
├── references/              # 10 reference documents
│   ├── ai-review-guide.md          # AI contextual review protocol
│   ├── debugging-playbook.md
│   ├── environment-contract.md
│   ├── examples.md
│   ├── install-yasa.md
│   ├── nodejs-yasa-rules.md
│   ├── python-yasa-rules.md
│   ├── post-scan-audit.md         # Full audit pipeline documentation
│   ├── rulegen-workflow.md
│   ├── sink-catalog.md
│   └── triage-verdicts.md
└── evals/                   # Evaluation prompts
    └── eval-prompts.md
```

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.9+ | All scripts target CPython 3.9+ |
| YASA-Engine | 0.3.1 | Downloadable via `install_yasa_release.py` |
| ripgrep | — | Optional; auto-detected for faster grep in Phase 2 |
| OpenCode | — | Agent runtime for slash commands and agent invocation |

---

## Confidence Scoring

Each post-scan finding is scored on a 0.0–1.0 scale using four factors:

| Factor | Weight | Condition |
|---|---|---|
| Source reach | 0.40 | Taint trace confirmed the variable originates from user/attacker input |
| No sanitization | 0.25 | No input validation or escaping detected on the taint path |
| Dangerous sink | 0.20 (HIGH) / 0.10 (MEDIUM) | Sink function is classified as `HIGH` or `MEDIUM` severity |
| Direct interpolation | 0.15 | Interpolation type is f-string, concat, `.format()`, or direct |

**Confidence tiers:**

| Score range | Label |
|---|---|
| 0.70 – 1.00 | **HIGH** |
| 0.40 – 0.69 | **MEDIUM** |
| 0.00 – 0.39 | **LOW** |

---

## Example Output

```
================================================================================
  POST-YASA AUDIT SUMMARY
================================================================================
  Raw grep hits       : 48
  Deduplicated hits   : 37
  Files scanned       : 214
  YASA sinks configured: 12
  YASA sinks matched   : 3
  Total findings      : 9
--------------------------------------------------------------------------------
ID           Confidence  Score   File                                              Line   Pattern                       Vuln Class
--------------------------------------------------------------------------------
AUDIT-001    HIGH        0.85    .../openhands/runtime/utils.py                    142    fstring-subprocess            CommandInjection
AUDIT-002    HIGH        0.75    .../openhands/agents/code_exec.py                 89     execute-command-wrapper       CommandInjection
AUDIT-003    MEDIUM      0.55    .../openhands/sandbox/exec.py                     204    shell-true                    CommandInjection
AUDIT-004    MEDIUM      0.50    .../openhands/runtime/builder.py                  67     concat-subprocess             CommandInjection
...
--------------------------------------------------------------------------------
  Total findings: 9
================================================================================
```
