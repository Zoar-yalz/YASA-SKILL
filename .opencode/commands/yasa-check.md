---
description: Run the YASA checker workflow with the yasa-checker agent.
agent: yasa-checker
---

Use the YASA checker workflow on the following target:

$ARGUMENTS

Follow the full workflow:
1. Run environment preflight.
2. Identify language, vulnerability class, source/sink/entrypoint, project path, and scan scope.
3. Build or inspect callgraph facts if needed and available.
4. Generate or debug YASA `rule_config.json`.
5. Normalize and validate the config.
6. Explain or run scan only when authorized and preflight is ok.
7. Report environment, valid entrypoints, sources marked, sinks matched, findings, debug notes, and limitations.
8. Run post-scan audit for YASA-blind vulnerability patterns.
9. Run AI review on audit findings — read source context, classify CONFIRMED/LIKELY/FP, assign severity, generate fixes.
10. Merge all findings into final report with AI-reviewed annotations.
