# YASA Debugging Playbook

Use this when YASA output is empty, unexpectedly small, or inconsistent.

## Debug order

Always debug in this order:

1. Environment/preflight.
2. Valid entrypoints.
3. Sources marked.
4. Sinks matched.
5. Findings.
6. Triage evidence quality.

## 0. Environment/preflight

Run:

```bash
python yasa-checker/scripts/preflight_yasa.py
```

If `ok=false`, stop scan execution and report missing components.

## 1. Valid entrypoints

If `Valid entrypoints` is zero:

- Check `functionName`.
- Check `filePath`.
- Check leading slash.
- Remove class prefix for Python.
- Remove invalid entrypoint fields.
- Use `ONLY_CUSTOM`.
- Confirm project root.

Python examples:

- Correct: `{"functionName": "__call__", "filePath": "/starlette/staticfiles.py"}`
- Incorrect: `{"functionName": "StaticFiles.__call__", "filePath": "starlette/staticfiles.py"}`

## 2. Sources marked

If `Sources marked` is zero:

- Source path may be wrong.
- Source scope may be too narrow.
- Direct variable name may not match UAST representation.
- Add `FuncCallArgTaintSource` when propagation crosses function calls.
- Consider return-value sources if the untrusted value is produced by a helper function.

## 3. Sinks matched

If `Sinks matched` is zero:

- Sink `fsig` may not match YASA's function signature.
- Inspect callgraph node names.
- Inspect SARIF or report output.
- Try simpler names only when supported by evidence.
- Check scan scope.

## 4. Findings

If entrypoints, sources, and sinks are nonzero but findings are zero:

- Source may not reach sink.
- Sanitization may exist.
- Propagation may break through object fields, callbacks, async calls, or framework abstractions.
- Additional source kinds may be needed.
- Scan scope may exclude relevant files.

## 5. Triage quality

If findings exist but confidence is low:

- Check whether codeFlow contains affected variable names.
- Expand snippets around source, sink, and intermediate assignments.
- Include relevant sanitization code.
- Mark `NR` if evidence is insufficient.
