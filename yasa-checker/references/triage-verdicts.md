# Triage Verdicts

Use only these verdicts.

## Verdict scale

- `TP`: true positive, exploitable with strong evidence.
- `L_TP`: likely true positive, plausible exploitability but one important detail remains incomplete.
- `NR`: needs review, insufficient evidence.
- `L_FP`: likely false positive, probably sanitized or unreachable.
- `FP`: false positive, clearly not exploitable.

## Requirements for TP

Do not mark `TP` merely because YASA reports a taint flow.

Require evidence that:

1. The source is attacker-controlled.
2. The sink is security-sensitive.
3. The path is reachable.
4. Sanitization is absent, incomplete, or bypassable.

## Triage output

```json
{
  "verdict": "TP",
  "confidence": 0.82,
  "reasoning": "Attacker-controlled scope['path'] reaches os.stat and FileResponse through get_path, get_response, and lookup_path without segment-safe containment validation.",
  "source": "starlette/staticfiles.py:111",
  "sink": "starlette/staticfiles.py:177",
  "missing_evidence": []
}
```

## Evidence package schema

```json
{
  "finding_id": "string",
  "vulnerability_class": "string",
  "source": {
    "file": "string",
    "line": 0,
    "symbol": "string",
    "snippet": "string"
  },
  "sink": {
    "file": "string",
    "line": 0,
    "symbol": "string",
    "snippet": "string"
  },
  "code_flow": [
    {
      "step": 0,
      "file": "string",
      "line": 0,
      "affected_node": "string",
      "snippet": "string"
    }
  ],
  "sanitization_evidence": [],
  "reachability_evidence": []
}
```
