# 贡献指南

感谢你愿意改进 LogHawk。本项目优先接受**小而清晰、可测试、无新增运行时依赖**的改动。

## 开始之前

- 使用 Python 3.9+。
- 阅读 [README.md](README.md) 与 [SECURITY.md](SECURITY.md)。
- 不要在 Issue、PR 或测试数据中粘贴真实生产日志、用户名、IP、Token 或私钥。
- 安全问题请走私密渠道，不要先开公开 Issue。

## 本地开发

```bash
git clone https://github.com/guoguoguo-dev/loghawk.git
cd loghawk
python -m unittest discover -s tests -v
python -m loghawk demo/auth.log --fail-on never
```

项目没有运行时第三方依赖，也不需要虚拟环境即可运行测试。仍然建议使用虚拟环境隔离
开发工具：

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate
```

## 代码约定

- 仅使用 Python 标准库；新增运行时依赖需要先在 Issue 中讨论。
- 保持 Python 3.9 兼容，不使用 3.10+ 独有语法。
- 公共函数与类添加简洁 docstring；检测规则必须给出可解释证据。
- 不引入网络请求、遥测、文件写入或系统命令执行。
- 解析器遇到无法识别的行应跳过，而不是抛出异常中断整份日志。
- 新增检测规则时：
  - 分配稳定的规则 ID（`LH-00x`）；
  - 定义明确的严重级别与默认阈值；
  - 添加命中、未命中、边界条件和跨 IP 隔离测试；
  - 同步更新 README 的规则表与 CHANGELOG。

## 测试要求

提交 PR 前运行：

```bash
python -m unittest discover -s tests -v
python -m compileall -q loghawk tests
```

新增行为必须附带测试。涉及输出的测试应断言结构或关键字段，避免依赖整段终端文本。

## 分支与提交

建议使用短生命周期功能分支：

```bash
git switch -c feat/sarif-output
git switch -c fix/ipv6-parsing
```

提交信息建议遵循 Conventional Commits：

```text
feat: add SARIF output
fix: handle IPv6 source addresses
docs: clarify syslog year handling
test: cover window boundary
chore: update CI matrix
```

一个提交只做一件事。不要在同一 PR 中混入无关格式化或重构。

## Pull Request 清单

- [ ] 描述了要解决的问题与实现方式
- [ ] 测试在本地通过
- [ ] 新增或修改行为有对应测试
- [ ] 没有新增运行时依赖
- [ ] 没有提交真实日志、凭据或个人信息
- [ ] 同步更新了 README/CHANGELOG（如适用）
- [ ] PR 标题清晰，必要时关联 Issue

维护者可能会要求缩小范围、补充测试或调整规则阈值。请保持讨论聚焦于可验证的行为。

## 报告问题

- 功能缺陷：使用 Bug Report Issue 表单。
- 功能建议：使用 Feature Request 表单。
- 安全漏洞：按 [SECURITY.md](SECURITY.md) 私下报告。

提交日志片段前请先脱敏，并说明操作系统、Python 版本、命令与预期行为。
