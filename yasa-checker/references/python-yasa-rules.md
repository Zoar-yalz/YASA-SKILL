# Python YASA Rules

## Entrypoints

For Python entrypoints:

- `functionName` must be a bare function name.
- Correct: `"__call__"`.
- Incorrect: `"StaticFiles.__call__"`.
- Correct: `"lookup_path"`.
- Incorrect: `"StaticFiles.lookup_path"`.
- `filePath` must be relative to project root with a leading `/`.
- Correct: `"/starlette/staticfiles.py"`.
- Incorrect: `"starlette/staticfiles.py"`.
- Do not include an `attribute` field in Python entrypoints.
- Use `entrypointMode = "ONLY_CUSTOM"` for generated custom entrypoints.

If YASA reports `match entryPoint fail`, debug in this order:

1. Remove class prefix from `functionName`.
2. Add leading `/` to `filePath`.
3. Remove invalid entrypoint fields such as `attribute`.
4. Use `ONLY_CUSTOM`.
5. Check whether `filePath` is relative to the actual YASA project root.

## Normalization

Use logic equivalent to:

```python
bare_name = ep_func.split(".")[-1].split("\\n")[0].strip()

if not ep_file.startswith("/"):
    ep_file = "/" + ep_file.lstrip("./")
```

## Source modeling

Prefer combining direct taint sources and function-argument taint sources when propagation crosses function boundaries.

For Python path traversal, a typical source configuration is:

```json
{
  "TaintSource": [
    {
      "path": "scope",
      "scopeFile": "all",
      "scopeFunc": "all"
    },
    {
      "path": "path",
      "scopeFile": "all",
      "scopeFunc": "all"
    }
  ],
  "FuncCallArgTaintSource": [
    {
      "fsig": "lookup_path",
      "args": ["0"],
      "scopeFile": "all",
      "scopeFunc": "all"
    }
  ],
  "FuncCallReturnValueTaintSource": []
}
```

Do not rely only on `TaintSource` when the relevant value crosses function boundaries.

## Checker ID

Default Python taint checker:

```json
["taint_flow_python_input"]
```

## Common Python path traversal sinks

```json
[
  {
    "fsig": "os.stat",
    "args": ["*"],
    "attribute": "PythonPathTraversal"
  },
  {
    "fsig": "open",
    "args": ["*"],
    "attribute": "PythonPathTraversal"
  },
  {
    "fsig": "FileResponse",
    "args": ["*"],
    "attribute": "PythonPathTraversal"
  },
  {
    "fsig": "anyio.open_file",
    "args": ["*"],
    "attribute": "PythonPathTraversal"
  },
  {
    "fsig": "Path.open",
    "args": ["*"],
    "attribute": "PythonPathTraversal"
  }
]
```
