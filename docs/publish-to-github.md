# 将 LogHawk 发布到 GitHub

本文以 **Windows PowerShell + HTTPS** 为主路径，同时给出 SSH 与 GitHub CLI 方案。
所有命令都可以逐条复制执行；尖括号 `<...>` 中的内容需要替换为你自己的信息。

## 0. 前置检查

在项目根目录打开 PowerShell：

```powershell
cd D:\Project
git --version
python --version
python -m unittest discover -s tests -v
```

确认：

- Python 输出为 3.9 或更高版本；
- 26 项测试全部 `OK`；
- 当前目录包含 `README.md`、`loghawk/`、`samples/` 等文件；
- 没有把真实生产日志、Token、私钥或 `.env` 文件放入目录。

检查 Git 身份（只需配置一次）：

```powershell
git config --get user.name
git config --get user.email
```

若为空，配置**你自己的**姓名与邮箱：

```powershell
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

> 这里应使用你希望公开出现在提交历史中的邮箱。若担心隐私，可使用 GitHub 提供的
> `noreply` 邮箱。

## 1. 本地初始化与首次提交

若当前目录还没有 `.git`，执行：

```powershell
git init -b main
git add .
git status --short
git commit -m "feat: initial LogHawk release"
git log --oneline -1
```

逐条说明：

| 命令 | 作用 |
| --- | --- |
| `git init -b main` | 初始化仓库，并把默认分支命名为 `main` |
| `git add .` | 将工作区文件加入暂存区，`.gitignore` 中的文件会被排除 |
| `git status --short` | 提交前复核将要提交的文件，确认没有敏感信息 |
| `git commit -m "..."` | 生成首个本地提交 |
| `git log --oneline -1` | 确认提交已生成 |

若本地仓库和首次提交已经存在（本目录的交付状态），可以直接跳到第 2 步，用下面的
命令确认：

```powershell
git status
git log --oneline -3
```

理想状态下 `git status` 显示：

```text
On branch main
nothing to commit, working tree clean
```

## 2. 在 GitHub 创建空仓库

1. 登录 GitHub，打开 <https://github.com/new>。
2. **Repository name** 填写 `loghawk`（也可用其他名称，后续 URL 同步替换）。
3. **Description** 可填写：
   `Lightweight, offline SSH authentication log threat analyzer`
4. 选择 **Public**；如果暂时不想公开，选择 **Private** 也可以。
5. **不要**勾选 `Add a README file`、`Add .gitignore`、`Choose a license`。
   本项目已经包含这些文件，初始化远程会制造额外提交与推送冲突。
6. 点击 **Create repository**。
7. 在仓库页面复制 HTTPS 地址，形如：

   ```text
   https://github.com/<your-name>/loghawk.git
   ```

> 仓库名、用户名和地址必须完全对应。GitHub 用户名不区分大小写，但 URL 中的路径
> 拼写错误会导致 `Repository not found`。

## 3. 关联远程仓库并推送

```powershell
git remote add origin https://github.com/<your-name>/loghawk.git
git remote -v
git branch -M main
git push -u origin main
```

逐条说明：

| 命令 | 作用 |
| --- | --- |
| `git remote add origin <URL>` | 为本地仓库添加名为 `origin` 的远程地址 |
| `git remote -v` | 验证 fetch/push 地址正确 |
| `git branch -M main` | 确保当前分支名为 `main` |
| `git push -u origin main` | 首次推送，并把本地 `main` 设为跟踪 `origin/main` |

首次推送可能弹出浏览器要求登录 GitHub，这是 Git Credential Manager 的正常流程。
成功后应看到类似输出：

```text
branch 'main' set up to track 'origin/main'.
```

若 `origin` 已存在但地址错误：

```powershell
git remote set-url origin https://github.com/<your-name>/loghawk.git
git remote -v
```

不要用下面的方式把 Token 写进远程地址，否则 Token 可能进入 shell 历史或截图：

```text
# 不要这样做
https://ghp_xxx@github.com/<your-name>/loghawk.git
```

## 4. 认证方式

### 方案 A：Git Credential Manager（推荐）

Windows 版 Git 通常自带 Git Credential Manager。第一次 `git push` 时：

1. 弹出浏览器窗口；
2. 登录 GitHub；
3. 授权 Git Credential Manager；
4. 回到 PowerShell，推送自动继续。

若没有弹窗，可手动触发：

```powershell
git credential-manager configure
git push -u origin main
```

### 方案 B：Personal Access Token（HTTPS）

GitHub 已不接受账户密码作为 Git 密码。若使用 Token：

1. 打开 GitHub **Settings → Developer settings → Personal access tokens**。
2. 创建 **Fine-grained token**，限制到目标仓库。
3. 仓库权限至少授予 **Contents: Read and write**；元数据权限保持默认只读。
4. 设置合理的过期时间。
5. 在 `git push` 提示 `Password` 时粘贴 Token（不是 GitHub 登录密码）。

Token 只应保存在系统凭据管理器中，不要写入脚本、README 或仓库文件。

### 方案 C：SSH

```powershell
ssh-keygen -t ed25519 -C "you@example.com"
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" | Set-Clipboard
```

把剪贴板内容添加到 GitHub **Settings → SSH and GPG keys → New SSH key**，然后：

```powershell
ssh -T git@github.com
git remote set-url origin git@github.com:<your-name>/loghawk.git
git push -u origin main
```

`ssh -T` 首次连接会询问是否信任主机指纹；请对照 GitHub 官方公布的指纹确认后再输入
`yes`。看到 `successfully authenticated` 即表示 SSH 可用。

### 方案 D：GitHub CLI（可选）

已安装 [GitHub CLI](https://cli.github.com/) 时，可以一条命令完成建仓与推送：

```powershell
gh auth login
gh repo create loghawk --public --source=. --remote=origin --push
```

若 `gh` 未安装，可通过 winget 安装：

```powershell
winget install --id GitHub.cli
```

安装后需要重新打开终端，再执行 `gh auth login`。

## 5. 验证发布结果

```powershell
git status
git branch -vv
git log --oneline --decorate -3
git ls-remote --heads origin
```

然后在浏览器打开：

```text
https://github.com/<your-name>/loghawk
```

检查：

- README 正常渲染，中文无乱码；
- `loghawk/`、`samples/`、`tests/` 等目录完整；
- **Actions** 页面中的 CI 工作流通过；
- 仓库首页的 License 显示为 MIT；
- `git status` 没有未提交文件。

CI 首次运行可能需要几十秒；若失败，点进具体 job 查看日志，本地先复现：

```powershell
python -m unittest discover -s tests -v
```

## 6. 打标签与发布 Release

确认 `main` 已推送且 CI 绿色后：

```powershell
git tag -a v0.1.0 -m "LogHawk v0.1.0"
git push origin v0.1.0
```

然后：

1. 打开 `https://github.com/<your-name>/loghawk/releases/new`；
2. **Choose a tag** 选择 `v0.1.0`；
3. **Release title** 填写 `LogHawk v0.1.0`；
4. 从 [CHANGELOG.md](../CHANGELOG.md) 复制 `0.1.0` 段落作为发布说明；
5. 勾选 **Set as the latest release**；
6. 点击 **Publish release**。

若需要附带源码压缩包，GitHub 会自动生成 `Source code (zip)` 与
`Source code (tar.gz)`，无需手工上传。

## 7. 可选：保护主分支

仓库公开后，建议开启基本分支保护：

1. 进入 **Settings → Rules → New branch ruleset**（旧界面为
   **Settings → Branches → Add branch protection rule**）。
2. 目标分支填写 `main`。
3. 启用：
   - Require a pull request before merging；
   - Require status checks to pass（选择 CI job）；
   - Do not allow force pushes。
4. 保存后，日常开发使用功能分支与 Pull Request。

## 8. 常见问题排查

### `fatal: not a git repository`

说明当前目录不是仓库根目录：

```powershell
cd D:\Project
git status
```

### `error: remote origin already exists`

说明已经添加过远程地址，改用：

```powershell
git remote set-url origin https://github.com/<your-name>/loghawk.git
git remote -v
```

### `error: src refspec main does not match any`

本地还没有提交，或分支名不是 `main`：

```powershell
git add .
git commit -m "feat: initial LogHawk release"
git branch -M main
git push -u origin main
```

### `Support for password authentication was removed`

不要输入 GitHub 账户密码。改用 Git Credential Manager、Personal Access Token 或 SSH。

### `Permission denied (publickey)`

SSH Key 未添加到 GitHub，或当前仓库仍使用 HTTPS：

```powershell
ssh -T git@github.com
git remote -v
git remote set-url origin git@github.com:<your-name>/loghawk.git
```

### `Updates were rejected because the remote contains work...`

通常是因为创建远程仓库时勾选了 README/License。二选一：

**推荐：删除远程空仓库，重新创建一个完全空白的仓库**，再重新推送。

**或者**把远程初始提交合并进来：

```powershell
git pull --rebase origin main
git push -u origin main
```

若提示 `refusing to merge unrelated histories`，说明两边历史完全独立；更安全的做法仍是
重建空仓库。不要在首次推送时使用 `git push --force` 覆盖远程内容。

### `remote: Repository not found`

依次检查：

1. URL 中的用户名与仓库名是否正确；
2. 仓库是否为 Private，以及当前账号是否有权限；
3. 认证是否使用了有权限的账号；
4. 仓库是否已经被重命名或删除。

### `LF will be replaced by CRLF`

项目已通过 [.gitattributes](../.gitattributes) 固定文本换行。若仍出现提示，通常不影响
提交；不要为了消除提示而全局修改 `core.autocrlf`。

### 中文显示乱码

确认文件以 UTF-8 保存，Git 不负责终端字体与代码页。Windows 终端可执行：

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
```

### CI 在 Windows 上失败

先在本地 PowerShell 复现：

```powershell
python -m unittest discover -s tests -v
python -m loghawk samples/auth.log --fail-on never
```

再检查 GitHub Actions 日志中的 Python 版本与失败测试名。CI 矩阵覆盖 Python 3.9 与
3.13，避免使用仅新版本支持的语法。

## 9. 发布前检查清单

- [ ] `python -m unittest discover -s tests -v` 全部通过
- [ ] `git status` 干净，无 `.env`、Token、私钥或真实日志
- [ ] README 中的 `<your-name>` 等占位符已按需替换
- [ ] 远程仓库为空仓库，未额外初始化 README/License
- [ ] `git remote -v` 指向正确仓库
- [ ] 首次 `git push -u origin main` 成功
- [ ] GitHub Actions CI 绿色
- [ ] Release 标签 `v0.1.0` 已创建
- [ ] 仓库描述、Topics、License 已完善

## 10. 后续维护建议

```powershell
# 从远程同步
git pull --ff-only

# 新建功能分支
git switch -c feat/json-sarif

# 提交与推送功能分支
git add .
git commit -m "feat: add SARIF output"
git push -u origin feat/json-sarif
```

在 GitHub 上发起 Pull Request，等待 CI 与代码审查后合并。发现安全问题时不要开公开
Issue，请按 [SECURITY.md](../SECURITY.md) 的流程私下报告。
