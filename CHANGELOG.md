# Changelog

本项目的所有重要变更都会记录在此文件中，格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-10-18

### Added

- 解析 OpenSSH syslog 格式的 `Failed` 与 `Accepted` 认证事件，支持 IPv4/IPv6
  以及 `sshd`、`sshd-session` 进程名。
- 检测同一来源 IP 的 SSH 暴力破解尝试（LH-001）。
- 检测暴力破解后成功登录的高风险场景（LH-002）。
- 检测不同无效用户名的短时间枚举行为（LH-003）。
- 文本报告与稳定结构的 JSON 报告，包含行号、证据与处置建议。
- CLI 阈值、时间窗口、最低告警级别、失败退出码等参数。
- 支持普通日志、`.gz` 压缩日志与标准输入。
- 28 项基于标准库 `unittest` 的单元与 CLI 测试。
- GitHub Actions CI、Issue 模板、PR 模板与安全报告流程。

### Fixed

- 修复 Windows 非 UTF-8 控制台下 CLI 输出中文时因 `UnicodeEncodeError`
  退出的问题；文本输出降级为替换字符，JSON 输出改用 ASCII 转义。
- CI 强制 UTF-8，并增加 Windows cp1252 控制台回退测试。

### Security

- 全程离线运行，不发起网络请求，不上传日志内容。
- 仅读取输入文件，不修改、不删除原始日志。
