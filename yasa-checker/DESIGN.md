# YASA Checker: Architecture Design Document

## 1. Problem Statement

Static taint analysis engines like YASA are powerful tools for detecting
source-to-sink data flows — they model the call graph, trace variable
propagation through assignment chains, and produce SARIF output with
structured codeFlow evidence. For textbook patterns like
`os.popen(user_input)`, YASA is precise and definitive.

In practice, real-world codebases are riddled with patterns that static
taint analysis cannot model:

- **F-string interpolation**: `subprocess.run(f"echo {user_input}")` — the
  f-string is evaluated at runtime; YASA sees a string literal, not a taint
  flow.
- **Method-wrapper abstractions**:
  `obj.execute_command(user_input)` — unless the method is in YASA's sink
  catalog, the flow terminates at the wrapper boundary.
- **Framework-level command builders**: ORM query builders, HTTP client
  abstractions, shell utilities that compose strings internally.
- **Multi-layer call chains**: `A → B → C` where each layer does partial
  string construction; the taint is diluted across function boundaries.

A real-world validation against **OpenHands** (218 files, ~33K LOC of Python)
illustrates the gap. YASA-Engine v0.3.1 with a comprehensive
PythonCommandInjection rule set returned **zero findings**. A subsequent
manual grep audit — using the same sink catalog — found **3 unpatched command
injection vulnerabilities**, each involving f-string or concatenation
patterns that YASA could not trace.

This is not a YASA deficiency. It is a fundamental blind spot of
AST-level taint analysis: engines trace variables, not string contents.
The checker compensates by adding a second, complementary grep-based
audit phase (Phase 2) that catches patterns YASA cannot model, and a
third, AI-powered review phase (Phase 3) that reads source code context
to eliminate false positives, confirm true positives, and generate fix
recommendations — tasks that neither static analysis nor grep can perform.

---

## 2. Design Philosophy: Three-Phase Pipeline

The pipeline combines three analysis strategies that mirror distinct
cognitive roles:

### Phase 1 — YASA Taint Scan: The Surgeon

- **Role**: Precise, AST-level source→sink tracing with full call-graph
  awareness.
- **Output**: SARIF with `codeFlow` arrays showing each propagation step.
- **Strength**: High precision, structured evidence, low false-positive rate.
- **Weakness**: Blind to runtime string interpolation, method-wrapper
  abstraction, multi-file framework flows.

### Phase 2 — Post-Scan Audit: The Bloodhound

- **Role**: Broad, pattern-based grep with variable taint tracing and
  confidence scoring.
- **Output**: Structured `audit_findings.json` with ranked findings.
- **Strength**: High recall, catches YASA-blind patterns, cross-language.
- **Weakness**: Lower precision, regex-based tracing can produce false
  positives.

### Phase 3 — AI Review: The Triage Surgeon

- **Role**: Contextual source-code review of each finding by the orchestrating
  agent model — reads actual code, determines true controllability, classifies
  CONFIRMED / LIKELY / FALSE_POSITIVE, and generates fix recommendations.
- **Output**: Augmented `audit_findings.json` with `ai_verdict`, `ai_rationale`,
  `ai_severity`, and `ai_fix` fields on each reviewed finding.
- **Strength**: Eliminates Phase 2 false positives, upgrades LOW findings that
  are actually exploitable, produces actionable fix code — all without human
  intervention.
- **Weakness**: Relies on model reasoning quality; cannot resolve
  cross-file or dynamic dispatch chains that require execution knowledge.

**No single phase is sufficient.** Phase 1 finds the textbook cases with
precision. Phase 2 finds the messy patterns Phase 1 misses. Phase 3 filters
Phase 2's noise and provides actionable remediation — transforming a raw
finding list into a reviewed, prioritized, and fix-ready report.

---

## 3. Architecture Diagram

```
User Input (project path, language, vuln class)
    │
    ▼
┌──────────────────────────────────────────────────────────────────────┐
│              YASA Checker Agent (orchestrator)                        │
│              Agent definition: .opencode/agents/yasa-checker.md       │
│              Entry points: /yasa-check, /yasa-preflight, /yasa-install│
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Preflight ────────────────────────────────────────────────────────── │
│  ┌──────────────────────┐   ┌───────────────────────┐                │
│  │  preflight_yasa.py   │   │  install_yasa_release.py               │
│  │  Detects mode:       │   │  Downloads YASA from  │                │
│  │  full / config-only  │   │  GitHub release       │                │
│  └──────────────────────┘   └───────────────────────┘                │
│                                                                       │
│  Phase 1: YASA Taint Scan                                             │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────────┐ │
│  │ normalize_   │→ │ validate_rule_   │→ │  YASA    │→ │ sarif_to_ │ │
│  │ rule_config  │  │ config.py        │  │  Engine  │  │ evidence  │ │
│  │ .py          │  │ Config linting   │  │ (binary) │  │ .py       │ │
│  │ RuleGen→JSON │  │                  │  │          │  │ SARIF→JSON│ │
│  └──────────────┘  └──────────────────┘  └──────────┘  └──────────┘ │
│                                                    │                 │
│  Phase 2: Post-Scan Audit (ALWAYS runs)             │                 │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────────┐ │
│  │ grep_signals │→ │ Cross-reference  │→ │ taint_   │→ │ post_scan│ │
│  │ .py          │  │ with YASA sinks  │  │ trace.py │  │ _audit   │ │
│  │14 patterns   │  │ yasa_blind flag  │  │ Variable │  │ .py      │ │
│  │by vuln class │  │ Deduplicate      │  │ tracing  │  │ Score+   │ │
│  └──────────────┘  └──────────────────┘  └──────────┘  │ rank     │ │
│                                                         └──────────┘ │
│                                                                       │
│  Phase 3: AI Review (Agent-model reasoning, no scripts)                │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │ Read source  │→ │ Classify verdict │→ │ Generate fix + override  │ │
│  │ context (±15 │  │ CONFIRMED/LIKELY │  │ severity, write back     │ │
│  │ lines, batch │  │ FP/NEEDS_REVIEW  │  │ ai_* fields to JSON      │ │
│  │ by file)     │  │                  │  │                          │ │
│  └──────────────┘  └──────────────────┘  └──────────────────────────┘ │
│                                                                       │
│  Output: Combined Report                                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  scan_summary.json  +  audit_findings.json  +  Evidence JSON     │  │
│  │  (Phase 1 metrics)    (Phase 2+3 findings)    (SARIF codeFlow)   │  │
│  │                       with ai_verdict, ai_severity, ai_fix       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Script Pipeline Design

Each script is a standalone Python executable. They communicate via
filesystem (JSON on disk) and are composed by the orchestrator agent
via `subprocess.run`. This design choice — scripts as subprocesses rather
than imports — ensures each script is independently testable, debuggable,
and replaceable.

| Script | Role | Input | Output |
|---|---|---|---|
| `preflight_yasa.py` | Environment check | `.yasa-agent.json`, PATH, filesystem | JSON: `ok` / `mode` / `selected_command` / sources / problems |
| `install_yasa_release.py` | YASA binary installation | GitHub release URL | `.yasa-tools/yasa-v0.3.1/` + `.yasa-agent.json` |
| `write_local_config.py` | Config file writer | CLI args | `.yasa-agent.json` |
| `normalize_rule_config.py` | RuleGen → YASA config | RuleGen selection JSON + language | `rule_config.json` (YASA-native format) |
| `validate_rule_config.py` | Config schema linting | `rule_config.json` + language | Issues list: errors / warnings |
| `extract_scan_metrics.py` | Metrics extraction | `scan_summary.json` or log text | Metrics dict: entrypoints, sources, sinks, findings |
| `sarif_to_evidence.py` | SARIF evidence packaging | `report.sarif` | Evidence JSON with codeFlow steps |
| `grep_signals.py` | Pattern-based grep scan | Source tree + language | Structured hits list + scan stats |
| `taint_trace.py` | Variable taint provenance | Sink file:line + project root | TaintResult: source, sanitization, hops |
| `post_scan_audit.py` | Phase 2 orchestrator | grep hits + YASA sink config | `audit_findings.json` + human-readable table |

### Composition rules:

- **Phase 1 scripts** form a linear pipeline: `normalize_rule_config` →
  `validate_rule_config` → YASA binary → `sarif_to_evidence` → `extract_scan_metrics`.
- **Phase 2 scripts** form a fan-in pipeline: `grep_signals` → (dedup +
  cross-ref) → `taint_trace` (per hit) → `post_scan_audit` aggregates.
- **Cross-phase**: `post_scan_audit` reads the YASA `rule_config.json` to
  determine which grep hits correspond to configured sinks (yasa_blind flag).
- **`preflight_yasa.py` runs first** to determine mode (full vs. config-only
  vs. evidence-only) and gates which pipeline stages execute.

---

## 5. Post-Scan Audit Pipeline (Deep Dive)

The audit pipeline in `post_scan_audit.py` follows six sequential steps:

### Step 1: Signal Grep

`grep_signals.py` runs 14 language-specific regex patterns organized by
vulnerability class (command-injection, path-traversal, deserialization).
Each pattern has an ID, severity, and file-glob filter.

**Backend selection**: ripgrep (fast) is auto-detected and preferred.
Python `re` module (slow) is the fallback. ripgrep reduces scan time on a
33K LOC project from ~8s to ~0.8s.

**Pattern organization by class** ensures the output groups related findings.
Example patterns:

| ID | Regex Target | Severity |
|---|---|---|
| `fstring-subprocess` | `subprocess.run(f"...")` | HIGH |
| `concat-subprocess` | `os.system(cmd + arg)` | MEDIUM |
| `execute-command-wrapper` | `.execute_command(` | LOW |
| `shell-true` | `shell=True` | MEDIUM |
| `pickle-loads` | `pickle.loads(` | HIGH |

### Step 2: Cross-Reference with YASA Sink Config

Each grep hit is checked against the YASA-configured
`sinks.FuncCallTaintSink` list using a static map
(`_PATTERN_TO_SINKS`). Two outcomes:

- **yasa_blind = true**: The sink function IS in YASA's config. YASA should
  have found this but couldn't (likely due to f-string/concat/wrapper
  abstraction). This is a Phase 1 miss — most actionable.
- **yasa_blind = false**: The sink function is NOT in YASA's config. This
  indicates a configuration gap (the user didn't add this sink to their
  rules). Educational signal to update the rule set.

### Step 3: Deduplication

By `(file, line)` tuple, keeping the hit with the highest severity ranking
(HIGH > MEDIUM > LOW). This prevents double-counting when multiple patterns
match the same line (e.g., both `fstring-subprocess` and `shell-true`).

### Step 4: Variable Taint Trace

For each unique hit, `taint_trace.py`:

1. **Extracts the tainted variable** from the sink line using regex patterns
   for f-string `{var}`, `.format(var)`, concatenation (`"literal" + var`),
   and direct call arguments.
2. **Searches backward** through the file for prior assignments to that
   variable, following the chain up to a configurable number of hops (default: 3).
3. **Checks for user-input sources**: `request`, `args`, `body`, `form`,
   `json`, `sys.argv`, `environ`, etc.
4. **Checks for sanitization**: `shlex.quote`, `.escape()`, validation
   functions, `os.path.abspath`.
5. **Follows function boundaries**: If the assignment is a function call, the
   tracer searches for the function definition, extracts parameters, maps
   call-site arguments to parameter names, and traces return statements.

Tracing is single-file only (no cross-file call resolution). The tracer
uses regex, not AST — this is an explicit trade-off (see §8).

### Step 5: Confidence Scoring

Each finding receives a 0.0–1.0 score computed from four weighted factors
(see §6 for details). The score maps to a three-tier confidence label:
HIGH (≥0.70), MEDIUM (0.40–0.69), LOW (<0.40).

### Step 6: Report Generation

Output is a structured `audit_findings.json` containing:

- Audit metadata (timestamp, language, project path)
- YASA context (sinks configured, sources marked, YASA findings count)
- Grep stats (raw/deduped hits, files scanned)
- Missed sink count
- Per-finding entries: ID, confidence, score, file, line, snippet,
  pattern_id, vuln_class, taint trace, and `yasa_blind` flag

A human-readable summary table is printed to stdout for immediate feedback
in the agent log.

---

## 6. AI Review: Automated Triage Protocol

The AI review phase (Phase 3) runs inside the orchestrating agent's model
reasoning — it is **not a Python script**. It reads source code, applies
security heuristics, and augments each finding with verdict, rationale, and
fix recommendations. The full protocol is documented in
`references/ai-review-guide.md`.

### Why not a script?

Three tasks that the AI review performs cannot be reliably implemented in
static code:

1. **Source controllability judgment**: "Is `process.pid` user-controllable?"
   requires understanding that `pid` is a local OS construct — knowledge that
   grep cannot encode.
2. **Pattern recognition in context**: "This `execute_command` call uses
   `shlex.quote` but the one 10 lines above does not" — requires comparing
   two code regions and recognizing inconsistency.
3. **Fix generation**: "Use `shlex.quote` because the same file does it at line
   362" — requires reading the file and adapting existing safe patterns.

### Review protocol

For each Phase 2 finding (MEDIUM+ by default), the agent:

1. **Reads source context**: Uses the `Read` tool to read ±15 lines around the
   sink. Grouped by file — all findings in the same file reviewed in one batch.
2. **Analyzes source**: Determines if the tainted variable originates from
   user-controllable input (request, settings API, etc.) or trusted sources
   (local integers, hardcoded constants, system paths).
3. **Checks sanitization**: Looks for `shlex.quote`, validation functions,
   parameterized APIs, type guards — patterns that the regex-based
   `taint_trace.py` may have missed.
4. **Classifies verdict**: `CONFIRMED` / `LIKELY` / `FALSE_POSITIVE` /
   `NEEDS_MANUAL_REVIEW` with rationale text citing the exact code evidence.
5. **Overrides severity**: LOW findings with confirmed user input → **HIGH**.
   MEDIUM findings that are false positives → **INFO**.
6. **Generates fix**: For CONFIRMED/LIKELY findings, produces a concrete code
   snippet using the same patterns already present in the codebase.
7. **Writes back**: Appends `ai_verdict`, `ai_rationale`, `ai_severity`,
   `ai_fix` fields to each reviewed finding.

### Expected impact

In the OpenHands validation (12 Phase 2 findings, 2 MEDIUM, 10 LOW):

| Before AI Review | After AI Review | Rationale |
|---|---|---|
| system_stats.py:59 — MEDIUM | → **FALSE_POSITIVE**, INFO | `process.pid` is local int, not user input |
| base.py:301 — LOW (git_user_name) | → **CONFIRMED**, **HIGH** | User settings → shell cmd, no shlex.quote |
| base.py:311 — LOW (git_user_email) | → **CONFIRMED**, **HIGH** | Same pattern, same file, fix applies to both |
| base.py:584 — MEDIUM (PRE_COMMIT_HOOK) | → **LIKELY**, MEDIUM | Config variable, needs ownership check |

The AI review eliminates 1 FP, upgrades 2 real vulns from LOW→HIGH, and
provides fix snippets for all 3 actionable findings — all without a human
opening a single file.

### Performance

- **Reads**: 1 read per affected file (not per finding). OpenHands: 2 files
  with findings → 2 reads, ~2s total.
- **Token cost**: ~500 tokens per reviewed finding (context + rationale +
  fix). 12 findings → ~6K tokens total.
- **No latency penalty**: The agent is already reading output JSONs; the
  source reads are incremental.

---

## 7. Confidence Scoring Model

The scoring model is a weighted sum of four binary factors, each
representing a dimension of exploitability evidence:

| Factor | Weight | How Determined | Rationale |
|---|---|---|---|
| Source reachability | 0.40 | `taint_trace.py` confirms user input reaches the sink argument | Strongest signal — without user input, the finding is a coding-practice issue, not a vulnerability |
| No sanitization | 0.25 | Absence of `shlex.quote`, `.escape()`, `validate`, `re.match` on the trace path | Sanitized inputs are defense-in-depth; unsanitized inputs are one step from exploitation |
| Dangerous sink type | 0.20 (HIGH) / 0.10 (MEDIUM) | Pattern severity classification | `os.system` and `eval` are inherently more dangerous than `open()` |
| Direct interpolation | 0.15 | f-string, concatenation, `.format()`, or direct variable pass | Direct interpolation means user data reaches the sink without transformation; less risk for method-wrapper patterns |

### Formula:

```
score = (source_reachable × 0.40)
      + (no_sanitization × 0.25)
      + (sink_danger × weight)
      + (direct_interpolation × 0.15)
```

### Tier boundaries:

| Score Range | Label | Implication |
|---|---|---|
| 0.70 – 1.00 | **HIGH** | Source confirmed + no sanitization + dangerous sink. Likely exploitable. Prioritize for patching. |
| 0.40 – 0.69 | **MEDIUM** | Source trace incomplete but pattern is suspicious. Needs manual review. |
| 0.00 – 0.39 | **LOW** | Suspicious pattern but source unconfirmed. Informational — likely a false positive. |

The 0.40 weight on source reachability ensures that no finding reaches HIGH
without confirmed user-input provenance. This is intentional: the audit
phase is high-recall, and the scoring model provides the precision gate.

---

## 8. Modes of Operation

The checker adapts to available resources using three modes, determined by
`preflight_yasa.py`:

| Mode | YASA Binary | rule_config.json | SARIF Evidence | Pipeline Steps | When Used |
|---|---|---|---|---|---|
| **Full** | Required | Required | Generated | Phase 1 + Phase 2 + triage | YASA installed, rule config available |
| **Config-only** | Not required | Required | Not required | Phase 2 only | YASA binary absent; user wants audit + config for later |
| **Evidence-only** | Not required | Not required | Provided (existing SARIF) | Phase 1 evidence triage only | Only SARIF/logs available; no source code access |

The mode is detected at startup and communicated to the orchestrator agent,
which then limits which commands are available.

---

## 9. Key Design Decisions

### AI review is model reasoning, not code

Phase 3 runs inside the orchestrating agent's model, not as a Python script.
The decision to keep it in the agent definition rather than implementing it
as a script is deliberate: source controllability judgment, pattern
inconsistency detection, and fix generation require semantic reasoning that
no static tool can perform. The agent reads code, applies heuristics, and
produces structured output — the same way a human security reviewer would,
but automated.

### Audit always runs

Even when YASA finds vulnerabilities, the post-scan audit runs. The two
phases target different pattern classes; YASA's success does not imply the
audit has nothing to find. In the OpenHands test, YASA found 0 findings but
the audit found 3 — running both is the only safe default.

### Scripts are subprocesses, not imports

Each script is independently invocable from the command line with its own
argument parser. This means:

- Each script has a clean, documented interface
- Scripts can be tested in isolation
- A failure in one script does not crash the parent process
- Scripts can be replaced independently (e.g., swap `grep_signals` for a
  Rust-based pattern matcher)

The cost is serialization overhead (JSON parse/write per step) and the
inability to share in-memory state. For a pipeline that runs once per
project scan, this cost is negligible.

### Grep first, trace second

Pattern grep is cheap (~1s for 33K LOC). Taint trace is expensive (~0.5s
per hit). By deduplicating before tracing, the pipeline avoids redundant
work. With 48 raw hits deduplicated to 37, and 37 traces at 0.5s each, the
full audit completes in ~20s instead of ~45s.

### No AST for audit phase

`taint_trace.py` uses regex for variable extraction and backward assignment
search. This is a deliberate trade-off:

- **Pro**: Works across languages without language-specific parsers. Simple
  to maintain and debug. No dependency on parser libraries.
- **Con**: Cannot trace through object attributes (`obj.attr` → no assignment
  match), list comprehensions, decorators, or complex expressions. Misses
  cross-file function calls.

The trade-off is acceptable because the audit phase is the high-recall
complement to YASA's high-precision AST tracing. If the regex tracer cannot
confirm a source, the finding defaults to LOW confidence — the pattern is
still surfaced for human review, just scored conservatively.

### YASA is the source of truth

The audit pipeline loads the YASA `rule_config.json` to determine sink
configuration. Findings are cross-referenced against this config to produce
the `yasa_blind` flag. This means:

- The audit does not duplicate YASA's sink catalog — it inherits it.
- A `yasa_blind=true` finding means "this pattern corresponds to a sink
  YASA was configured to detect but could not trace." This is the most
  actionable finding class — it indicates a concrete gap in AST-level
  analysis for that specific sink.
- A `yasa_blind=false` finding means "this pattern is outside YASA's
  configured scope." It may still be a vulnerability, but it requires
  the user to update their rule configuration.

---

## 10. Limitations & Future Work

### Current limitations

| Limitation | Impact | Root Cause |
|---|---|---|
| Regex taint tracing | Cannot trace object attributes, decorators, list comprehensions | No AST parser in audit phase |
| Single-file tracing | Cross-file call chains are invisible | No project-wide call graph in audit phase |
| Python-centric patterns | Go and Node.js patterns exist but cover fewer scenarios | Development priority; Python is the primary target |
| No incremental scanning | Full project re-scan on every invocation | No persistent index or file-change tracking |
| No ML confidence calibration | Static weights may not reflect actual TP/FP rates | No historical finding database |

### Future directions

1. **AST-based taint tracing for the audit phase**: Integrate a lightweight
   AST walker (uast4py) to replace regex-based variable tracing. This would
   enable attribute tracking, comprehension variable resolution, and
   decorator unwrapping. The grep-first architecture remains — only the
   trace backend changes.

2. **Cross-file function tracing**: Build a simple call-graph index
   (function name → file:line map) that allows `taint_trace.py` to follow
   calls into other files. Limited to direct imports (no dynamic dispatch).

3. **Machine learning confidence scoring**: Train a classifier on
   historically confirmed vs. dismissed findings, using features beyond the
   current 4-factor model (e.g., trace path length, number of sanitizers
   on path, sink argument position, file age, author commit history).

4. **Incremental/delta scanning**: Maintain a file-hash index so only
   changed files are re-scanned on subsequent runs. Critical for CI/CD
   integration.

5. **IDE integration**: Output findings in SARIF format (already partially
   supported via `sarif_to_evidence.py`) for IDE inline annotation. Add
   VS Code and JetBrains plugin wrappers.

6. **Expanded language support**: Add comprehensive patterns for Go
  (`os/exec`, `sql.DB.Query`), TypeScript/Node.js (`child_process.exec`,
   `eval`), and Java (`Runtime.exec`, `ProcessBuilder`).

---

## 11. File Manifest

| File | Role |
|---|---|
| `scripts/preflight_yasa.py` | Environment readiness check — detects YASA binary, determines mode, validates workspace directories |
| `scripts/install_yasa_release.py` | Downloads YASA-Engine from GitHub release, extracts, verifies SHA256, writes `.yasa-agent.json` |
| `scripts/write_local_config.py` | Writes a repository-local `.yasa-agent.json` with user-specified paths |
| `scripts/normalize_rule_config.py` | Converts RuleGen selection JSON to YASA-native `rule_config.json` format with path/name normalization |
| `scripts/validate_rule_config.py` | Lints `rule_config.json` for structural errors — missing sink buckets, malformed entrypoints, Python-specific path rules |
| `scripts/extract_scan_metrics.py` | Parses `scan_summary.json` or YASA log output to extract entrypoint/source/sink/finding counts |
| `scripts/sarif_to_evidence.py` | Unpacks SARIF results into structured evidence packages with codeFlow step arrays |
| `scripts/grep_signals.py` | Runs 14 vulnerability patterns across source tree using ripgrep (fast) or Python re (fallback) |
| `scripts/taint_trace.py` | Regex-based variable taint provenance tracer — backward assignment search, source detection, sanitization check, function boundary crossing |
| `scripts/post_scan_audit.py` | Orchestrates the full Phase 2 pipeline: grep → cross-ref → dedup → trace → score → report |
| `references/sink-catalog.md` | Reference catalog of source/sink signatures for Python and Node.js vulnerability classes |
| `references/python-yasa-rules.md` | Python-specific rule generation guidance for YASA RuleGen |
| `references/nodejs-yasa-rules.md` | Node.js-specific rule generation guidance for YASA RuleGen |
| `references/rulegen-workflow.md` | Step-by-step RuleGen invocation patterns |
| `references/install-yasa.md` | Instructions for manual YASA installation and configuration |
| `references/examples.md` | Example workflows and expected output patterns |
| `references/environment-contract.md` | Contract for environment variables, file paths, and directory structure |
| `references/debugging-playbook.md` | Debugging guidance for common YASA and audit failures |
| `references/triage-verdicts.md` | Triage decision framework for evaluating findings |
| `references/post-scan-audit.md` | Full audit pipeline documentation — pattern catalog, taint trace methodology, scoring algorithm |
| `references/ai-review-guide.md` | AI contextual review protocol — verdict classification, severity override rules, fix generation patterns |
| `evals/eval-prompts.md` | Evaluation prompts for testing and validating the checker pipeline |
| `README.md` | Quick-start guide, command reference, confidence scoring summary |
| `DESIGN.md` | Architecture design document (this file) |
