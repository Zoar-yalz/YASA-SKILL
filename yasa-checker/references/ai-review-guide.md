# AI Review Guide

After `post_scan_audit.py` produces `audit_findings.json`, the orchestrator agent performs automated context-aware triage on each finding. This guide defines the review protocol.

## When to run

The AI review runs in **every workflow** where source code is available (full and config-only modes). Skip only in evidence-only mode (SARIF triage without source).

## Review scope

By default, review only findings with confidence **MEDIUM or HIGH**. LOW findings are skipped unless the user explicitly requests full review. This balances thoroughness against token cost.

## Review protocol (per finding)

### Step 1: Read source context

Use the `Read` tool to read the source file around the sink line:
- Range: `sink_line - 15` to `sink_line + 15` (30 lines of context)
- **Group by file**: If multiple findings are in the same file, read once and review all together

### Step 2: Source analysis

Determine whether the tainted variable originates from user-controllable input. Look for:

**User-controllable sources** (→ likely vuln):
- `request.args`, `request.form`, `request.json`, `request.body`, `request.query_params`
- `request.headers`, `request.cookies`, `request.GET`, `request.POST`
- Function parameters that trace back to FastAPI route params (`Query`, `Body`, `Path`, `Header`)
- User settings / database fields that users can modify via the API
- `sys.argv`, environment variables exposed to users

**NOT user-controllable** (→ false positive):
- Local integers (`process.pid`, `os.getpid()`, loop counters)
- Hardcoded constants or module-level string literals
- Trusted internal config files (not editable by end users)
- System paths constructed from trusted components

### Step 3: Sanitization analysis

Check whether the variable is sanitized before reaching the sink. Look for:

**Sanitization patterns** (→ mitigated):
- `shlex.quote(variable)` or `shlex.quote(f"{var}")`
- `re.match(r'^[a-zA-Z0-9_-]+$', variable)` — strict whitelist
- `variable.escape()` or framework-provided escaping
- `os.path.abspath()` with prefix verification for path traversal
- Parameterized APIs (SQL placeholders, subprocess list form without `shell=True`)
- Input validation from well-known libraries (Pydantic validators, marshmallow)

**Missing sanitization** (→ confirmed vuln):
- Double-quote wrapping alone (`f'cmd "{variable}"'`) — trivially breakable
- No shlex.quote or equivalent
- `shell=True` with string command from user input

### Step 4: Classify verdict

| Verdict | Criteria | Example |
|---------|----------|---------|
| `CONFIRMED` | User-controllable source confirmed, no sanitization, direct exploit path | `os.popen(request.args['cmd'])` |
| `LIKELY` | Source seems controllable but chain is indirect; needs 1 human hop | `workspace.execute_command(cmd)` where `cmd` comes from an object attribute built from user data |
| `FALSE_POSITIVE` | Source is NOT user-controllable; explain exactly why | `/proc/{process.pid}/io` — pid is local int |
| `NEEDS_MANUAL_REVIEW` | Ambiguous context; explain what would resolve it | Dynamic import of a class that may or may not have dangerous methods |

### Step 5: Assign AI severity

Override the automated score-based severity with context-aware judgment:

| Original | After review | When |
|----------|-------------|------|
| LOW | **HIGH** | Source confirmed user-controllable + no sanitization + dangerous sink |
| MEDIUM | **HIGH** | Same as above |
| HIGH | **HIGH** | Keep |
| MEDIUM | **INFO** | Confirmed false positive (downgrade, not remove) |
| LOW | **INFO** | Same |

### Step 6: Generate fix

For `CONFIRMED` and `LIKELY` findings, produce a fix recommendation:

- **Prefer codebase patterns**: If the same file uses `shlex.quote()` elsewhere, recommend it
- **Provide exact snippet**: Not "add input validation" — the actual code
- **Show before/after**: So a reviewer can verify at a glance

### Step 7: Write back

For each reviewed finding, add these fields to the JSON:

```json
{
  "ai_verdict": "CONFIRMED",
  "ai_rationale": "git_user_name comes from user settings API (UserInfo model), flows directly into shell command via f-string interpolation. No shlex.quote() or input validation. Double-quote wrapping is trivially breakable with `\"; malicious_cmd; #`.",
  "ai_severity": "HIGH",
  "ai_fix": "cmd = f'git config --global user.name {shlex.quote(user_info.git_user_name)}'",
  "ai_reviewed": true
}
```

For FALSE_POSITIVE:
```json
{
  "ai_verdict": "FALSE_POSITIVE",
  "ai_rationale": "process.pid is a local integer attribute, not user-controllable. /proc/{pid}/io path is constructed from a trusted system value.",
  "ai_severity": "INFO",
  "ai_fix": null,
  "ai_reviewed": true
}
```

## Review batch size

Review findings in batches by file. Example for a scan with 12 findings in 2 files:

```
1. Read system_stats.py:44-74 (1 finding)
   → Review AUDIT-001 → write verdict
2. Read app_conversation_service_base.py:286-330 (first batch, 4 findings)
   → Review AUDIT-003,004,005,006 → write verdicts
3. Read app_conversation_service_base.py:332-386 (second batch, 3 findings)  
   → Review AUDIT-007,008,009 → write verdicts
4. Read app_conversation_service_base.py:496-550, 553-599 (final batch, 4 findings)
   → Review AUDIT-002,010,011,012 → write verdicts
```

This avoids reading the same large file multiple times.

## Do not

- Claim a vulnerability without citing the exact source→sink path
- Recommend generic mitigations — give specific code
- Skip the source read step — always verify with actual code context
- Mark something CONFIRMED if you can't see the full taint chain — use LIKELY instead
