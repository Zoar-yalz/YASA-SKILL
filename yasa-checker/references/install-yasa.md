# Installing YASA Engine

This skill can guide installation of the public YASA-Engine release, but it does not bundle the YASA binary.

The public YASA-Engine `v0.3.1` release provides platform bundles such as:

- `yasa-linux-x64.zip`
- `yasa-macos-x64.zip`
- `yasa-macos-arm64.zip`

The helper script downloads from this release URL pattern:

```text
https://github.com/antgroup/YASA-Engine/releases/download/v0.3.1/<ASSET_NAME>
```

## Recommended install location

Install under a repository-local tool directory:

```text
.yasa-tools/
  yasa-v0.3.1/
```

This avoids polluting the system environment.

## Automatic release installation

Run only after explicit user approval:

```bash
python yasa-checker/scripts/install_yasa_release.py --version v0.3.1 --install-dir .yasa-tools
```

The script will:

1. detect platform unless `--platform` is provided;
2. download the matching release zip from GitHub;
3. extract it under `.yasa-tools/yasa-v0.3.1`;
4. verify files listed in `sha256sum.txt` when possible;
5. locate the likely YASA executable;
6. write `.yasa-agent.json`.

Platform override examples:

```bash
python yasa-checker/scripts/install_yasa_release.py --platform linux-x64
python yasa-checker/scripts/install_yasa_release.py --platform macos-x64
python yasa-checker/scripts/install_yasa_release.py --platform macos-arm64
```

## Manual installation

Download the correct asset manually:

```text
https://github.com/antgroup/YASA-Engine/releases/download/v0.3.1/yasa-linux-x64.zip
https://github.com/antgroup/YASA-Engine/releases/download/v0.3.1/yasa-macos-x64.zip
https://github.com/antgroup/YASA-Engine/releases/download/v0.3.1/yasa-macos-arm64.zip
```

Extract it:

```bash
mkdir -p .yasa-tools/yasa-v0.3.1
unzip yasa-linux-x64.zip -d .yasa-tools/yasa-v0.3.1
```

Locate the executable:

```bash
find .yasa-tools/yasa-v0.3.1 -type f -perm -111 | grep -i yasa
```

Write local config:

```bash
python yasa-checker/scripts/write_local_config.py \
  --yasa-engine <PATH_TO_YASA_EXECUTABLE> \
  --workspace .yasa-workspace \
  --report-dir .yasa-workspace/report
```

## Local configuration

The skill reads `.yasa-agent.json` when available:

```json
{
  "yasa_engine": ".yasa-tools/yasa-v0.3.1/<YASA_EXECUTABLE>",
  "yasa_command": null,
  "uastSDKPath": null,
  "workspace_dir": ".yasa-workspace",
  "report_dir": ".yasa-workspace/report",
  "default_entrypoint_mode": "ONLY_CUSTOM",
  "supports_callgraph": true,
  "supports_sarif": true
}
```

Priority order:

1. explicit user-provided command
2. `.yasa-agent.json`
3. environment variables
4. `PATH`
5. local `.yasa-tools/`
6. unavailable: config-only mode
