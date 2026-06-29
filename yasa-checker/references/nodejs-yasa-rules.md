# Node.js YASA Rules

## Checker ID

Default Node.js taint checker:

```json
["taint_flow_js_input"]
```

## Common command injection sinks

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

## Common source candidates

Node.js source candidates depend heavily on project structure. Prefer:

- request parameters
- query parameters
- route parameters
- parsed JSON body
- context fields derived from external input
- externally supplied configuration fields
- environment-derived user-controlled values when project evidence supports that model

## Evidence quality warning

Node.js SARIF/codeFlow output may contain lower information density than Python output. If triage confidence is low, expand evidence around:

- source line
- sink line
- local function body
- intermediate variable assignments
- argument construction immediately before sink
- path or command construction helpers

Do not mark TP only because a Node.js taint flow exists. Require attacker-controlled input, reachability, and absence of effective sanitization.
