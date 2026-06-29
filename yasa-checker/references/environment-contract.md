# YASA Environment Contract

Before running YASA, determine which execution mode is available.

## Full mode

Full mode is available when at least one YASA execution entry is configured:

- `yasa_engine` in `.yasa-agent.json`
- `yasa_command` in `.yasa-agent.json`
- `YASA_ENGINE` environment variable
- `YASA_WRAPPER` environment variable
- `yasa-engine`, `YASA-Engine`, or `yasa` in `PATH`
- a discoverable executable under `.yasa-tools/`

Also required:

- project path exists
- language is known or inferable
- workspace directory is writable
- report directory is writable

Allowed in full mode:

- build callgraph
- generate `rule_config.json`
- run YASA scan
- parse SARIF/codeFlow
- triage findings

## Config-only mode

Use this mode when YASA is unavailable but the source repository is available.

Allowed:

- generate `rule_config.json`
- normalize `rule_config.json`
- validate config shape
- explain scan commands
- report missing environment requirements

Forbidden:

- claim that scan was executed
- claim finding count
- claim TP/FP based on a scan that did not run

## Evidence-only mode

Use this mode when YASA is unavailable but SARIF/logs/codeFlow artifacts are provided.

Allowed:

- extract metrics from logs
- parse SARIF into evidence packages
- triage findings from provided evidence
- debug likely checker mistakes

Forbidden:

- claim fresh scan execution

## Mandatory preflight rule

Before running YASA commands, run:

```bash
python yasa-checker/scripts/preflight_yasa.py
```

If the preflight result has `ok=false`, stop scan execution and report missing components.
