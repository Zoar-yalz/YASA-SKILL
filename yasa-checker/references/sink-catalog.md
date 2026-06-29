# Source and Sink Catalog

This catalog gives starting points. Do not treat it as complete or authoritative. Always confirm signatures against YASA callgraph or SARIF output.

## PythonPathTraversal

Sources:

```json
[
  {
    "kind": "TaintSource",
    "path": "scope",
    "scopeFile": "all",
    "scopeFunc": "all"
  },
  {
    "kind": "TaintSource",
    "path": "request",
    "scopeFile": "all",
    "scopeFunc": "all"
  },
  {
    "kind": "TaintSource",
    "path": "path",
    "scopeFile": "all",
    "scopeFunc": "all"
  }
]
```

Sinks:

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

## NodejsCommandInjection

Sources:

Project-specific request/context/config values.

Sinks:

```json
[
  {
    "fsig": "spawn",
    "args": ["*"],
    "attribute": "NodejsCommandInjection"
  },
  {
    "fsig": "exec",
    "args": ["*"],
    "attribute": "NodejsCommandInjection"
  },
  {
    "fsig": "execFile",
    "args": ["*"],
    "attribute": "NodejsCommandInjection"
  }
]
```

## SSRF

Candidate sources:

- URL parameters
- request body fields
- headers
- route parameters

Candidate sinks:

- HTTP client request functions
- fetch-like APIs
- URL openers

Use only after confirming YASA `fsig` names from project facts.

## SQL Injection

Candidate sources:

- request/query/body fields
- route parameters
- externally supplied filters or sort keys

Candidate sinks:

- raw query execution
- SQL string execution
- ORM raw-query APIs

Use only after confirming actual call signatures.
