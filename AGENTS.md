# YASA Checker Skill

This repo contains the yasa-checker OpenCode skill — a three-phase security analysis pipeline for static taint analysis + post-scan audit + AI review.

## Editing the skill

- `yasa-checker/SKILL.md` — skill definition (what agents see when they load this skill)
- `yasa-checker/scripts/` — Python scripts (subprocess-invoked, independently testable)
- `yasa-checker/references/` — reference docs (progressively loaded by the orchestrator)

## Validation

```bash
# Syntax check all scripts
python3 -m py_compile yasa-checker/scripts/*.py

# Check skill frontmatter
# name must match directory name: yasa-checker
# description must be 1-1024 chars
```

## Packaging

```bash
# Create release zip (from repo root)
zip -r yasa-checker-opencode-$(date +%Y%m%d).zip \
  .opencode/ \
  yasa-checker/ \
  -x "*.pyc" -x "__pycache__/*" -x ".git/*"
```
