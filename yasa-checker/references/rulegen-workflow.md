# RuleGen Workflow

The central rule is: do not ask the model to freely find vulnerabilities. Use YASA and project facts to narrow the problem, then use model reasoning only for structured selection, configuration repair, and evidence-based triage.

## Pipeline

1. Intake
   - Identify project path, language, vulnerability class, scan scope, and available YASA wrapper.
   - Identify known source, sink, and entrypoint information.
   - Decide whether the task is known-vulnerability reproduction or exploratory checker generation.

2. Environment preflight
   - Run `scripts/preflight_yasa.py`.
   - If YASA is unavailable, switch to config-only mode unless the user asks to install YASA.

3. FactBuild
   - If source or entrypoint is unknown, build or reuse YASA callgraph facts.
   - Prefer CHA callgraph when available.

   Typical command:

   ```bash
   yasa-engine --sourcePath <PROJECT> --language <LANGUAGE> --dumpAllCG --cgAlgo CHA
   ```

4. Candidate extraction
   - Match known dangerous sink signatures.
   - Build reverse callgraph edges: callee -> callers.
   - BFS backward from each sink to possible entrypoints.
   - Limit default depth to 6.
   - Filter stdlib and tests.
   - Preserve compact source-to-sink trace paths.

5. RuleGen selection
   - Feed structured candidate JSON, not whole-source dumps.
   - Ask for only JSON output containing selected entrypoints, sources, and sinks.
   - Treat model output as an intermediate representation, not final YASA config.

6. Config conversion
   - Convert intermediate selection to YASA `rule_config.json`.
   - Normalize Python entrypoints.
   - Bucket source entries by kind.
   - Put function-call sinks under `sinks.FuncCallTaintSink`.

7. Scan
   - Use `ONLY_CUSTOM` when using generated custom entrypoints.
   - Capture valid entrypoints, sources marked, sinks matched, and findings.

8. Evidence expansion
   - Convert SARIF/codeFlow into compact evidence packages.
   - Include source, sink, codeFlow, affected variables when available, snippets, and missing evidence.

9. Triage
   - Triage only from evidence.
   - Do not mark a finding TP merely because YASA reports a taint flow.

10. Report
   - Return generated config, commands, scan summary, findings, debug notes, and limitations.

## Candidate JSON format

Trace path:

```json
{
  "source_name": "StaticFiles :: __call__",
  "sink_name": "os.stat",
  "path_length": 4,
  "path": [
    "StaticFiles :: __call__",
    "StaticFiles :: get_response",
    "StaticFiles :: lookup_path",
    "os.stat"
  ],
  "file": "/starlette/staticfiles.py"
}
```

Entrypoint candidate:

```json
{
  "file": "/starlette/staticfiles.py",
  "function": "__call__",
  "class": "StaticFiles",
  "reason": "HTTP request entrypoint reaching file operation"
}
```

Sink candidate:

```json
{
  "fsig": "os.stat",
  "file": "/starlette/staticfiles.py",
  "line": 177,
  "callers": ["lookup_path"],
  "vulnerability_class": "PathTraversal"
}
```

## RuleGen selection schema

The model selection output must be valid JSON only:

```json
{
  "selected_entrypoints": [
    {
      "file": "/starlette/staticfiles.py",
      "function": "__call__"
    }
  ],
  "selected_sources": [
    {
      "kind": "TaintSource",
      "path": "scope",
      "scopeFile": "all",
      "scopeFunc": "all"
    },
    {
      "kind": "FuncCallArgTaintSource",
      "fsig": "lookup_path",
      "args": ["0"],
      "scopeFile": "all",
      "scopeFunc": "all"
    }
  ],
  "selected_sinks": [
    {
      "fsig": "os.stat",
      "args": ["*"],
      "attribute": "PythonPathTraversal"
    }
  ]
}
```
