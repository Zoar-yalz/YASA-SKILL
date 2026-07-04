# YASA Checker：架构设计与上手指南

## 1. 这是什么？

YASA Checker 是一个运行在 OpenCode 智能体（Agent）上的安全代码审查 Skills。它把静态污点分析（YASA-Engine）、模式扫描（grep-based audit）和 AI 上下文审查组合成一个三阶段自动化管线，找出其他工具遗漏的安全漏洞。

**一句话概括：** 告诉它你要审哪个项目、审什么漏洞类型，它会自动跑完三个分析阶段，产出一份带有确认/误报分类和修复建议的漏洞报告。

---

## 2. 为什么需要它？

一个现实的对比：以 OpenHands 项目（199 个 Python 文件，约 3.3 万行代码）为例：

| 分析方式 | 发现 | 说明 |
|---|---|---|
| 纯 YASA 静态污点追踪 | **0 个漏洞** | 无法追踪 f-string、方法包装器、字符串拼接等运行时模式 |
| 加 Phase 2（pattern grep） | 12 个可疑点 | 捕获了 YASA 盲区，但混入了 10 个误报 |
| 再加 Phase 3（AI 审查） | **2 个确认漏洞 + 10 个排除** | 准确分类，自动给出修复方案 |

**结论：** 单一分析手段都不够——YASA 精确但覆盖窄，grep 覆盖广但噪音大，AI 能按源代码上下文去伪存真。三阶段组合后才能真正可用。

YASA 的盲区主要包括：
- **f-string 注入**：`subprocess.run(f"rm {user_input}")`——YASA 看到的是字符串字面量，不是污点流
- **方法包装器抽象**：`workspace.execute_command(user_input)`——除非把包装方法加入 sink 配置，否则追踪在包装边界断裂
- **跨层调用链**：`A → B → C` 每一步做部分字符串拼接，污点在函数边界稀释

---

## 3. 架构概览

```
用户输入（项目路径、语言、漏洞类型）
    │
    ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 1：YASA 污点扫描（精准手术刀）                           │
│  AST 级 source→sink 追踪，输出 SARIF + codeFlow                │
│  强项：高精度、证据结构化；弱项：看不到运行时字符串拼接            │
├───────────────────────────────────────────────────────────────┤
│  Phase 2：Post-Scan Audit（猎犬嗅探）                           │
│  14 种模式正则 grep → YASA sink 交叉比对 → 污点变量反向追踪 → 评分 │
│  强项：高召回、捕获 YASA 盲区；弱项：正则追踪会产生误报           │
├───────────────────────────────────────────────────────────────┤
│  Phase 3：AI 上下文审查（分诊医生）                              │
│  读取源代码 ±15 行 → 判源可控性 → 判定 CONFIRMED/LIKELY/FP      │
│  → 覆盖严重度 → 生成修复代码 → 写回 ai_verdict 等字段            │
└───────────────────────────────────────────────────────────────┘
    │
    ▼
  综合报告（YASA 指标 + 审查后的漏洞列表 + 修复建议）
```

---

## 4. 目录结构

```
yasa-skills/
├── .opencode/                       ← OpenCode 插件：智能体 + 命令 + Skills 定义
├── yasa-checker/
│   ├── scripts/   (10 个 Python)    ← 管线脚本（预检、安装、规则生成、扫描、审计）
│   ├── references/ (10 个文档)       ← 参考文档（规则手册、调试指南、审查协议）
│   └── evals/                       ← 评估用例
├── README.md                        ← 项目主页
├── AGENTS.md                        ← 开发者指南
└── DESIGN.zh-CN.md                  ← 本文件
```

核心脚本按功能分组：

| 分组 | 脚本 | 作用 |
|------|------|------|
| 环境 & 安装 | `preflight_yasa.py`、`install_yasa_release.py`、`write_local_config.py` | 检测 YASA、安装引擎、写配置 |
| 规则工程 | `normalize_rule_config.py`、`validate_rule_config.py` | RuleGen → 生成 → 校验 |
| Phase 1 | `extract_scan_metrics.py`、`sarif_to_evidence.py` | 提取扫描指标、SARIF 转证据 |
| Phase 2 | `grep_signals.py`、`taint_trace.py`、`post_scan_audit.py` | 模式匹配 → 变量追踪 → 评分 |
| Phase 3 | 无需脚本（智能体推理） | AI 读源码 → 判源 → 分类 → 生成修复 |

---

## 5. 快速上手

### 5.1 环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| Python | 3.9+ | 所有脚本基于 CPython 3.9+ |
| YASA-Engine | 0.3.1 | 自动下载（`install_yasa_release.py`） |
| ripgrep（`rg`） | — | 可选，Phase 2 加速（检测到自动使用） |
| OpenCode | — | 智能体运行时 |

### 5.2 安装

```bash
# 1. 安装 YASA-Engine 到 .yasa-tools/ 目录（仅首次）
python yasa-checker/scripts/install_yasa_release.py

# 2. 验证环境
python yasa-checker/scripts/preflight_yasa.py
# 输出：{"ok": true, "mode": "full"}   ← 表示一切就绪
```

### 5.3 跑一次完整扫描

```bash
# 方式一：通过 OpenCode 命令触发
/yasa-check project=/path/to/target language=python vuln=PythonCommandInjection

# 方式二：通过智能体调用
@yasa-checker audit /path/to/project for command injection
```

智能体会自动完成：
1. 预检环境 → 确定模式（full / config-only / evidence-only）
2. 生成 `rule_config.json`（定义 sources、sinks、entrypoints）
3. 运行 YASA 引擎（Phase 1）
4. 运行 post-scan audit（Phase 2）
5. 对每个发现做 AI 上下文审查（Phase 3）
6. 产出综合报告

---

## 6. 三阶段详解

### 6.1 Phase 1 — YASA 污点扫描

**角色**：精准手术刀，做 AST 级别的 source→sink 污点追踪。

**关键概念**：

- **Source**：用户可控的输入来源（请求体 `body`、查询参数 `query_params`、路径参数 `path_params`、HTTP 头 `headers` 等）
- **Sink**：危险函数调用（`subprocess.run`、`open`、`os.remove`、`httpx.AsyncClient.get` 等）
- **Entrypoint**：分析的入口函数（通常是路由处理函数）
- **Taint Flow**：从 source 到 sink 的变量传递链

**工作流**：

```
用户指定（项目路径 + 漏洞类型）
    → 生成 rule_config.json（定义 sources / sinks / entrypoints）
    → validate_rule_config.py 校验配置
    → 运行 yasa-engine-linux-x64
    → 输出 scan_summary.json + report.sarif + entrypoints.json
    → sarif_to_evidence.py 将 SARIF 转为证据 JSON
```

**YASA 的局限性**：无法追踪运行时字符串拼接（f-string、`+` 拼接、`.format()`），也无法穿透方法包装器抽象。

### 6.2 Phase 2 — Post-Scan Audit

**角色**：猎犬嗅探，用正则模式匹配捕获 YASA 盲区的漏洞。

**六步管线**：

```
grep_signals.py（14 种模式）
    → 交叉比对 YASA sink 配置（标记 yasa_blind）
    → 按 (file, line) 去重
    → taint_trace.py（每条命中做变量反向追踪）
    → 置信度评分（0.0～1.0）
    → 输出 audit_findings.json + 终端可读表格
```

**14 种扫描模式（按漏洞类型分组）**：

| 模式 ID | 匹配目标 | 严重度 | 说明 |
|---|---|---|---|
| `fstring-subprocess` | `subprocess.run(f"...")` | HIGH | f-string 中的用户输入直接拼入命令 |
| `concat-subprocess` | `os.system(cmd + arg)` | MEDIUM | 字符串拼接后传入 shell |
| `execute-command-wrapper` | `.execute_command(` | LOW | 方法包装器，可能是安全封装也可能是裸传 |
| `shell-true` | `shell=True` | MEDIUM | subprocess 启用 shell 模式 |
| `fstring-open` | `open(f"...")` | MEDIUM | f-string 作为文件路径 |
| `pickle-loads` | `pickle.loads(` | HIGH | 不安全的反序列化 |
| ... | ... | ... | 共计 14 种 |

**变量污点追踪（taint_trace.py）**：

从 sink 行提取被污染的变量 → 在文件内向上搜索该变量的赋值链 → 检测赋值源是否为用户输入（`request`、`args`、`body`、`form`、`json`、`sys.argv` 等）→ 检测是否有消毒处理（`shlex.quote`、`.escape()`、验证函数等）→ 尝试跨函数边界追踪。

> **重要设计选择**：追踪使用正则而非 AST。优点是跨语言、无外部依赖；缺点是无法追踪对象属性、列表推导、装饰器。这是刻意的取舍——这个阶段是高召回率的补充，精确度由 Phase 3 的 AI 审查来补偿。

### 6.3 Phase 3 — AI 上下文审查

**角色**：分诊医生，用模型推理能力对每个发现做源代码级上下文审查。

**为什么不用脚本实现？** 三个任务是 grep/正则无法可靠完成的：

1. **源可控性判断**："`process.pid` 是用户可控的吗？"——需要理解这是操作系统本地构造
2. **上下文模式识别**："隔壁 10 行用了 `shlex.quote`，这里怎么没用？"——需要对比两个代码区域
3. **修复代码生成**："这里应该用 `shlex.quote`，因为第 362 行就这么做的"——需要读取文件并适配已有的安全模式

**审查协议**（详见 `references/ai-review-guide.md`）：

1. **读取源代码**：按文件分组，一次 `Read` 覆盖 ±15 行上下文
2. **分析源**：判断变量来源是用户可控制（请求、设置 API）还是可信源（本地整数、硬编码常量、系统路径）
3. **检查消毒**：查找 `shlex.quote`、验证函数、参数化 API、类型守卫
4. **分类判定**：
   - `CONFIRMED`：源明显可控 + 无消毒 + 直接利用路径，给出精确的 `变量 → sink` 链路
   - `LIKELY`：源似乎可控但链路间接，需要人工确认一步
   - `FALSE_POSITIVE`：源不可控，引用确切代码证据解释为什么
   - `NEEDS_MANUAL_REVIEW`：模糊，说明需要什么额外信息才能判定
5. **覆盖严重度**：LOW 发现 + 确认可控源 → 升级为 **HIGH**；MEDIUM + 确认误报 → 降为 **INFO**
6. **生成修复**：使用项目中已有的编码模式（如该文件其他地方已用 `shlex.quote`，就推荐同样做法）
7. **写回结果**：将 `ai_verdict`、`ai_rationale`、`ai_severity`、`ai_fix` 写回每个发现

---

## 7. 脚本职责一览

| 脚本 | 输入 | 输出 |
|---|---|---|
| `preflight_yasa.py` | `.yasa-agent.json` | 模式判定 JSON |
| `install_yasa_release.py` | GitHub Release URL | `.yasa-tools/` 目录 |
| `normalize_rule_config.py` | RuleGen 选择 JSON | `rule_config.json` |
| `validate_rule_config.py` | `rule_config.json` | 问题列表 |
| `extract_scan_metrics.py` | `scan_summary.json` | 指标 JSON |
| `sarif_to_evidence.py` | `report.sarif` | 证据 JSON（含 codeFlow） |
| `grep_signals.py` | 源码树 + 语言 | 命中列表 + 扫描统计 |
| `taint_trace.py` | sink 文件:行号 | TaintResult（源、消毒、跳数） |
| `post_scan_audit.py` | grep 命中 + YASA sink 配置 | `audit_findings.json` |
| `write_local_config.py` | CLI 参数 | `.yasa-agent.json` |

---

## 8. 置信度评分模型

Phase 2 的每条发现会被打一个 0.0～1.0 的分数，由四个加权因素计算：

| 因素 | 权重 | 判断方式 | 设计理由 |
|---|---|---|---|
| 源可达性 | 0.40 | `taint_trace.py` 确认用户输入到达 sink 参数 | 最强信号——没有用户输入，就不是漏洞而是代码规范问题 |
| 无消毒 | 0.25 | 追踪路径上缺少 `shlex.quote`、`.escape()`、`validate` 等 | 消毒过的输入是纵深防御；未消毒离利用只一步之遥 |
| 危险 sink | 0.20（HIGH）/ 0.10（MEDIUM） | 模式严重度分类 | `os.system` 和 `eval` 本质上比 `open()` 更危险 |
| 直接插值 | 0.15 | f-string、拼接、`.format()` 或直接变量传递 | 直接插值意味着用户数据未经转换直达 sink |

**计算公式**：

```
得分 = (源可达 × 0.40) + (无消毒 × 0.25) + (sink危险度 × 权重) + (直接插值 × 0.15)
```

**置信度分级**：

| 得分范围 | 标签 | 含义 |
|---|---|---|
| 0.70 – 1.00 | **HIGH** | 源已确认 + 无消毒 + 危险 sink。很可能可利用，优先修复。 |
| 0.40 – 0.69 | **MEDIUM** | 源追踪不完整但模式可疑。需人工审查。 |
| 0.00 – 0.39 | **LOW** | 可疑模式但源未确认。信息级——大概率是误报。 |

**设计关键**：源可达性 0.40 的权重确保了没有确认用户输入来源的发现永远不可能达到 HIGH——审计阶段是高召回的，评分模型提供了精度控制闸门。

---

## 9. 关键设计决策

这里解释几个贯穿整个项目的重要设计选择，以及为什么这么做。

### 9.1 为什么要 AI 审查而不是写脚本？

Phase 3 的审查逻辑没有实现为 Python 脚本，而是由智能体模型直接推理执行。因为有三个任务代码写不了：

- **"`process.pid` 是用户可控的吗？"** — 脚本只知道这是 `process.pid` 字符串，智能体知道这是操作系统给的本机进程号，不可控
- **"第 300 行没用 `shlex.quote`，但第 362 行用了，这是遗漏吗？"** — 脚本只能逐行匹配，智能体能跨行对比，发现同一文件里的不一致模式
- **"这里该怎么修？"** — 脚本只能输出模板化的建议，智能体能读文件找到已有的安全写法，给出适配项目风格的精确修复代码

### 9.2 为什么审计每次都跑，即使 YASA 没发现问题？

两个阶段针对不同的漏洞类型。YASA 找的是精确的 source→sink 链路（`os.popen(user_input)`），审计找的是 YASA 看不到的模式（`f"rm {file}"`、`execute_command(cmd)`）。两者互不包含——YASA 发现 0 个漏洞，审计可能发现 2 个，反过来也可能。**两条线都跑才是最安全的选择。**

OpenHands 实测证明了这一点：YASA 0 发现，审计 12 发现（其中 2 个确认真实漏洞）。

### 9.3 为什么 Grep 在先，追踪在后？

Grep 扫描整个项目只要 1 秒。变量污点追踪每条命中要花约 0.5 秒。如果每条 raw hit 都追踪，48 条命中需要 ~24 秒。但去重后只剩 12 条 → ~6 秒。**先去重再追踪，能省 75% 的时间。**

### 9.4 为什么审计的 taint_trace 用正则而不是 AST？

正则追踪跨语言通用、零外部依赖、简单可维护。代价是追踪不了深层结构（对象属性、装饰器、跨文件调用）。但这个取舍是合理的：**Phase 2 追求高召回率，漏不掉；Phase 3 的 AI 审查负责过滤误报。** 正则确认不了源 → 保守打 LOW → 不影响最终判断。

### 9.5 什么是 yasa_blind？为什么重要？

每条审计发现都会和 YASA 的 sink 配置交叉比对：

- **yasa_blind=true**：这个 sink 函数 YASA 配置了，但因为 f-string/方法包装/字符串拼接等问题追踪不到——这是 YASA 覆盖盲区，通常是最有价值的发现
- **yasa_blind=false**：这个 sink 函数不在 YASA 配置里——可能也是漏洞，但你得先把规则加上才能让 YASA 看到它

---

## 10. 扩展指南

### 10.1 添加新的漏洞模式

编辑 `scripts/grep_signals.py`，在对应漏洞类别下添加新模式：

```python
# 在 PATTERNS_BY_CLASS["python"]["command-injection"] 中添加
{
    "id": "my-new-pattern",
    "regex": r"dangerous_func\s*\(\s*f\"",
    "severity": "HIGH",
    "glob": "*.py",
    "description": "Detects dangerous_func with f-string injection"
}
```

### 10.2 添加新语言支持

1. 在 `grep_signals.py` 中添加 `PATTERNS_BY_CLASS["your-lang"]` 字典
2. 在 `sink-catalog.md` 中添加对应语言的 sink 签名
3. 在 `references/` 中创建 `your-lang-yasa-rules.md`
4. 更新 `post_scan_audit.py` 中的 `_PATTERN_TO_SINKS` 映射

### 10.3 添加新的 sink 类型

1. 在 `sink-catalog.md` 中添加 sink 函数签名
2. 在 `grep_signals.py` 中添加匹配该 sink 的正则模式
3. 在 RuleGen 选择中注册该 sink 类型

### 10.4 发布新版本

```bash
# 语法检查所有脚本
python3 -m py_compile yasa-checker/scripts/*.py

# 打包
zip -r yasa-checker-opencode-$(date +%Y%m%d).zip \
  .opencode/ \
  yasa-checker/ \
  -x "*.pyc" -x "__pycache__/*" -x ".git/*"
```

---

## 11. 限制与未来方向

### 当前限制

| 限制 | 影响 | 根因 |
|---|---|---|
| 正则污点追踪 | 无法追踪对象属性、装饰器、列表推导 | 审计阶段无 AST 解析器 |
| 单文件追踪 | 跨文件调用链不可见 | 审计阶段无项目级调用图 |
| Python 偏向 | Go / Node.js 模式覆盖较少 | 开发优先级：Python 是第一目标 |
| 无增量扫描 | 每次调用都全量重扫 | 无持久化索引或文件变更追踪 |
| 无 ML 置信度校准 | 静态权重可能不反映真实 TP/FP 率 | 无历史发现数据库 |

### 未来方向

1. **AST 版污点追踪**：集成轻量 AST 遍历器（uast4py）替换正则追踪
2. **跨文件函数追踪**：构建简单调用图索引实现跨文件追踪
3. **机器学习置信度校准**：用历史确认/排除数据训练分类器
4. **增量/差异扫描**：维护文件哈希索引，仅重扫变更文件
5. **IDE 集成**：以 SARIF 格式输出，支持 VS Code / JetBrains 内联标注
6. **扩展语言支持**：完善 Go、Node.js、Java 的漏洞模式

---

## 12. 参考资料

| 文档 | 用途 |
|---|---|
| `references/ai-review-guide.md` | Phase 3 AI 审查协议完整定义 |
| `references/python-yasa-rules.md` | Python 规则生成指南（入口名、路径格式等） |
| `references/rulegen-workflow.md` | RuleGen 完整工作流（吸纳→预检→事实构建→选择→规范化→校验→扫描→分诊） |
| `references/sink-catalog.md` | Python / Node.js 常见 source / sink 签名目录 |
| `references/debugging-playbook.md` | 零发现输出时的调试顺序 |
| `references/triage-verdicts.md` | 分类决策框架（TP / L_TP / NR / L_FP / FP） |
| `references/environment-contract.md` | 环境变量、文件路径、目录结构约定 |
