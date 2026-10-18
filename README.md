# LogHawk

> 轻量级、离线优先的 SSH 认证日志威胁分析器。零第三方运行时依赖，一条命令即可从
> `auth.log` 中定位暴力破解、异常成功登录与用户名枚举。

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-28%20passed-brightgreen)](tests)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

LogHawk 面向安全运维、应急响应与安全学习者：它把分散在数千行 OpenSSH 日志中的
失败认证、来源 IP 和成功登录串成一条**可解释、可追溯**的证据链，并给出可直接执行的
处置建议。工具本身不扫描、不封禁、不修改任何系统配置。

> [!IMPORTANT]
> 本项目仅用于**已获授权的安全测试、日志审计与学习研究**。使用前请确认你对目标
> 主机与日志拥有合法访问权限。演示日志中的 IP 均来自 RFC 5737 文档保留网段。

## 目录

- [为什么选择 LogHawk](#为什么选择-loghawk)
- [快速开始](#快速开始)
- [检测规则](#检测规则)
- [命令行参考](#命令行参考)
- [JSON 输出](#json-输出)
- [退出码与 CI 集成](#退出码与-ci-集成)
- [设计说明](#设计说明)
- [项目结构](#项目结构)
- [开发与测试](#开发与测试)
- [仓库地址](#仓库地址)
- [局限性](#局限性)
- [安全与合规](#安全与合规)
- [License](#license)

## 为什么选择 LogHawk

- **零依赖**：仅使用 Python 3.9+ 标准库，无需 `pip install` 即可运行。
- **离线只读**：不发起网络请求、不上传日志、不修改原始文件。
- **证据可追溯**：每条告警包含来源 IP、账号、时间范围、原始日志行号与处置建议。
- **面向真实日志**：支持普通文本、`.gz` 轮转日志、标准输入与 IPv6 来源地址。
- **适合自动化**：结构化 JSON 与明确的退出码，可直接接入 CI、SOAR 或巡检脚本。
- **默认克制**：三条高信噪比规则，宁可少报，不堆砌无法解释的“告警”。

## 快速开始

### 环境要求

- Python 3.9 或更高版本
- 任意 Linux、macOS 或 Windows 终端

不需要安装任何第三方依赖。在仓库根目录直接运行：

```bash
python -m loghawk demo/auth.log
```

macOS/Linux 若 `python` 指向 Python 2，请改用 `python3`。

输出参考（节选）：

```text
LogHawk 0.1.0 | SSH 认证日志威胁分析
输入: demo/auth.log
解析: 共 25 行 / 认证事件 17 条 / 忽略 8 行
配置: 失败阈值 5 次，窗口 5 分钟，成功回溯 10 分钟，枚举阈值 3 个用户名
------------------------------------------------------------------------
[CRITICAL] LH-002 暴力破解后登录成功
  来源 IP  : 198.51.100.23
  关联账号 : root
  时间范围 : 2026-10-18 09:12:05 ~ 2026-10-18 09:12:51
  摘要     : 来源 IP 在成功登录前 10 分钟内有 7 次失败认证，随后账号 root 通过 password 登录成功。
  证据:
    - 成功登录: 第 14 行 / 2026-10-18 09:12:51 / root
    - 此前失败: 7 次，涉及账号 root(5), admin(1), oracle(1)
    - 失败时间范围: 2026-10-18 09:12:05 ~ 2026-10-18 09:12:31
    - 失败日志行号: 7, 8, 9, 10, 11, 12, 13
  建议     : 按账号失陷预案处理：立即隔离主机、终止可疑会话、封禁来源 IP、轮换该账号凭据并检查持久化与横向移动痕迹。

[HIGH] LH-001 SSH 暴力破解尝试
  ...
```

演示数据命中 3 条规则，因此命令默认以退出码 `1` 结束。若只想查看报告而不让 CI
判定失败：

```bash
python -m loghawk demo/auth.log --fail-on never
```

### 分析真实日志

```bash
# 需要当前用户对日志有读取权限
python -m loghawk /var/log/auth.log

# 读取轮转压缩日志
python -m loghawk /var/log/auth.log.2.gz

# 从标准输入读取，适合 zcat / journalctl 管道
zcat /var/log/auth.log.2.gz | python -m loghawk -
journalctl -u ssh --no-pager -o short | python -m loghawk -
```

> `journalctl` 的默认 JSON 或 verbose 格式不在支持范围内，请使用 `-o short` 输出
> 与 syslog 兼容的短格式。

### 可选安装

如果希望使用 `loghawk` 命令而不是 `python -m loghawk`：

```bash
python -m pip install .
loghawk demo/auth.log
```

安装过程只读取打包元数据；项目没有运行时第三方依赖。

### Windows 控制台中文乱码

若终端使用旧代码页导致中文显示异常，可在当前 PowerShell 会话中执行：

```powershell
chcp 65001 > $null
$env:PYTHONUTF8 = "1"
python -m loghawk demo/auth.log
```

这只影响显示，不影响检测结果或 JSON 文件内容。LogHawk 在非 UTF-8 输出流上会自动
降级为替换字符，不会因编码异常中断；JSON 输出会自动使用 ASCII 转义保留数据。

## 检测规则

| 规则 | 级别 | 触发条件 | 默认值 |
| --- | --- | --- | --- |
| `LH-001` SSH 暴力破解尝试 | HIGH | 同一来源 IP 在时间窗内的失败认证次数达到阈值 | 5 次 / 5 分钟 |
| `LH-002` 暴力破解后登录成功 | CRITICAL | 成功登录前回溯窗口内，同一来源 IP 的失败认证达到阈值 | 5 次 / 10 分钟 |
| `LH-003` 疑似 SSH 用户名枚举 | MEDIUM | 同一来源 IP 在时间窗内使用不同无效用户名的数量达到阈值 | 3 个 / 5 分钟 |

规则细节：

- **按来源 IP 聚合**：不同 IP 的失败记录不会合并计算，避免跨来源误报。
- **窗口边界包含在内**：恰好位于窗口右边界的事件会计入。
- **不重叠告警窗口**：一次已命中的连续攻击窗口不会重复生成同类告警；若攻击在之后
  再次达到阈值，会生成新的告警。
- **规则可叠加**：一次针对 `root` 的爆破成功后，通常会同时看到 `LH-001` 与
  `LH-002`。这是预期行为：前者描述攻击过程，后者描述可能的失陷结果。
- **只统计可解析事件**：`Failed password`、`Failed publickey` 与 `Accepted` 等
  OpenSSH 认证行会被解析；`Invalid user` 单独出现的行会被忽略，以避免同一尝试重复计数。

### 支持的日志形态

LogHawk 期望 OpenSSH 写入 syslog 的标准行，例如：

```text
Oct 18 09:12:05 web01 sshd[1201]: Failed password for invalid user admin from 198.51.100.23 port 55221 ssh2
Oct 18 09:12:51 web01 sshd[1208]: Accepted password for root from 198.51.100.23 port 55228 ssh2
Oct 18 08:12:01 web01 sshd[1101]: Accepted publickey for deploy from 203.0.113.24 port 50222 ssh2: RSA SHA256:AAAA
```

- syslog 时间戳不带年份，默认按**当前年份**解析；分析历史日志时请使用 `--year 2025`。
- 时区不在日志中，LogHawk 按日志显示的本地时间直接比较。
- 暂不支持 RFC 5424 结构、Windows 事件日志与云审计日志。

## 命令行参考

```text
python -m loghawk [path] [options]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `path` | `-` | 日志路径，支持 `.gz`；`-` 表示标准输入 |
| `--format {text,json}` | `text` | 输出格式 |
| `--failed-threshold N` | `5` | 触发暴力破解的最少失败次数 |
| `--window MIN` | `5` | 暴力破解与用户名枚举的时间窗口（分钟） |
| `--success-lookback MIN` | `10` | 成功登录向前回溯失败记录的时间（分钟） |
| `--enum-threshold N` | `3` | 触发用户名枚举的最少不同无效用户名数量 |
| `--min-severity LEVEL` | `LOW` | 仅显示不低于该级别的告警 |
| `--fail-on LEVEL` | `HIGH` | 达到该级别时返回退出码 `1`；`never` 表示从不失败 |
| `--year YEAR` | 当前年份 | 为无年份 syslog 时间戳指定年份 |
| `--version` | - | 显示版本并退出 |
| `-h, --help` | - | 显示帮助并退出 |

常用用法：

```bash
# 更敏感：3 次失败即告警，窗口 10 分钟
python -m loghawk demo/auth.log --failed-threshold 3 --window 10

# 只输出高危与严重告警
python -m loghawk demo/auth.log --min-severity HIGH

# 历史日志 + JSON 报告
python -m loghawk demo/auth.log --year 2025 --format json

# 仅当出现 CRITICAL 时让流水线失败
python -m loghawk demo/auth.log --fail-on CRITICAL
```

## JSON 输出

```bash
python -m loghawk demo/auth.log --format json
```

结构参考（省略部分字段）：

```json
{
  "tool": { "name": "LogHawk", "version": "0.1.0" },
  "input": {
    "source": "demo/auth.log",
    "total_lines": 25,
    "auth_events": 17,
    "ignored_lines": 8
  },
  "config": {
    "failed_threshold": 5,
    "window_minutes": 5,
    "success_lookback_minutes": 10,
    "enumeration_threshold": 3
  },
  "summary": {
    "total": 3,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 1,
      "LOW": 0,
      "INFO": 0
    }
  },
  "alerts": [
    {
      "rule_id": "LH-002",
      "title": "暴力破解后登录成功",
      "severity": "CRITICAL",
      "source_ip": "198.51.100.23",
      "username": "root",
      "first_seen": "2026-10-18T09:12:05",
      "last_seen": "2026-10-18T09:12:51",
      "summary": "来源 IP 在成功登录前 10 分钟内有 7 次失败认证，随后账号 root 通过 password 登录成功。",
      "evidence": ["成功登录: 第 14 行 / 2026-10-18 09:12:51 / root"],
      "line_numbers": [7, 8, 9, 10, 11, 12, 13, 14],
      "recommendation": "按账号失陷预案处理：..."
    }
  ]
}
```

字段约定：

- 告警按严重级别降序排列，同级别按首次发现时间升序排列。
- `line_numbers` 能直接定位到原始日志行，便于复核与取证。
- `summary.total` 与 `alerts` 受 `--min-severity` 过滤影响。
- **退出码判定始终基于完整检测结果**，不会被 `--min-severity` 隐藏的告警绕过。

## 退出码与 CI 集成

| 退出码 | 含义 |
| --- | --- |
| `0` | 未发现达到 `--fail-on` 级别的告警，或使用了 `--fail-on never` |
| `1` | 发现达到 `--fail-on` 级别的告警 |
| `2` | 参数错误、文件不可读或输入处理失败 |

GitHub Actions 用法：

```yaml
- name: Analyze SSH auth log
  run: |
    python -m loghawk /var/log/auth.log --format json --fail-on HIGH > loghawk-report.json
```

在 Windows PowerShell 中，重定向默认可能生成 UTF-16 文件。若下游要求 UTF-8，请显式
转换编码，或在 WSL/Git Bash 中执行重定向。

## 设计说明

### 为什么只做离线日志分析

离线分析避免了三类常见问题：在生产主机上引入额外网络服务、把敏感日志发送到外部
系统，以及工具自身成为新的攻击面。LogHawk 的输入只有日志文本，输出只有标准输出，
因此可以安全地放进隔离环境、应急响应包或 CI 流水线。

### 为什么使用标准库

项目目标是小而可审计。解析、时间窗口、数据类和 JSON 序列化都可以用标准库完成；
不引入第三方依赖，也使代码更容易在受限主机和离线环境中运行。

### 为什么告警必须带证据

只给“发现爆破”结论无法支撑响应。LogHawk 将时间范围、账号分布、行号与成功登录事件
放进告警，让分析人员可以在原始日志中逐条复核，避免把扫描噪声误当成入侵结论。

## 项目结构

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   └── feature_request.yml
│   ├── workflows/
│   │   └── ci.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   └── publish-to-github.md
├── loghawk/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── detector.py
│   ├── models.py
│   ├── parser.py
│   └── report.py
├── demo/
│   └── auth.log
├── tests/
│   ├── __init__.py
│   ├── test_cli.py
│   ├── test_detector.py
│   └── test_parser.py
├── .editorconfig
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── pyproject.toml
```

## 开发与测试

无需安装依赖：

```bash
python -m unittest discover -s tests -v
```

测试覆盖：

- syslog 前缀、IPv4/IPv6、无效用户、公钥认证与压缩日志解析；
- 阈值边界、失败后成功登录、用户名枚举与跨 IP 隔离；
- 文本/JSON 输出、标准输入、文件错误、过滤与退出码。

提交前建议再执行：

```bash
python -m compileall -q loghawk tests
python -m loghawk demo/auth.log --format json --fail-on never
```

代码风格要求与贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 仓库地址

- GitHub 仓库：[guoguoguo-dev/loghawk](https://github.com/guoguoguo-dev/loghawk)
- 克隆地址：`https://github.com/guoguoguo-dev/loghawk.git`

```bash
git clone https://github.com/guoguoguo-dev/loghawk.git
cd loghawk
python -m loghawk demo/auth.log
```

更新与发布流程见 [docs/publish-to-github.md](docs/publish-to-github.md)。

## 局限性

- 规则基于固定阈值，不了解组织的正常登录基线；高流量跳板机可能产生误报。
- 无法判断账号是否真的失陷，只能提示“失败后成功登录”这一高风险组合。
- 不支持多行日志、跨年自动推断、时区转换与 Windows 事件日志。
- 未接入威胁情报、地理定位或 IP 信誉数据，避免引入网络依赖与隐私问题。
- 不是 SIEM 替代品。生产环境建议将 JSON 输出接入集中日志平台，并保留原始日志。

## 安全与合规

- 仅用于**授权范围内**的日志审计、应急响应与教学研究。
- 不得将本工具用于未授权访问、凭据窃取、拒绝服务或规避安全机制。
- 演示日志与文档中的 IP 均来自 RFC 5737 文档保留地址，不对应真实主机。
- 处理真实日志时请遵守数据最小化原则，避免把包含用户名、IP、命令的日志公开上传。
- 发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要直接开公开 Issue。

## License

[MIT](LICENSE) © 2026 guoguoguo-dev
