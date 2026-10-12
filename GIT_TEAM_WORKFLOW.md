# 团队 Git 协作说明

## 1. 基本原则

- GitHub 仓库是项目代码的唯一正式来源，不再通过压缩包合并代码。
- `main` 只保存能够启动、测试通过的稳定版本。
- 每个人在自己的功能分支开发，不直接在 `main` 上修改。
- 一项任务对应一个分支和一个 Pull Request。
- 提交源代码和必要文档，不提交依赖、缓存、构建结果、日志和本地密钥。

## 2. 第一次获取项目

```bash
git clone https://github.com/amagas11/uav-network-security-simulator.git
cd uav-network-security-simulator
```

首次使用 Git 的成员还需要设置自己的提交身份：

```bash
git config --global user.name "你的姓名或GitHub用户名"
git config --global user.email "你的GitHub邮箱"
```

## 3. 开始一个新任务

先更新本地 `main`，再创建自己的分支：

```bash
git switch main
git pull --ff-only origin main
git switch -c feature/姓名-任务简称
```

示例：

```bash
git switch -c feature/zhang-dos-frontend
git switch -c feature/li-crypto-integration
git switch -c fix/wang-fdi-display
```

分支名前缀建议：

- `feature/`：新增功能；
- `fix/`：修复问题；
- `docs/`：只修改文档；
- `test/`：补充测试。

## 4. 开发中保存修改

每完成一个可说明的小步骤就提交一次：

```bash
git status
git add 涉及的文件
git commit -m "feat: 增加DoS防御状态展示"
git push -u origin feature/姓名-任务简称
```

建议使用以下提交前缀：

- `feat:` 新功能；
- `fix:` 问题修复；
- `docs:` 文档修改；
- `test:` 测试修改；
- `refactor:` 不改变功能的代码整理；
- `chore:` 构建或配置调整。

不要长期堆积大量未提交修改，也不要使用 `git add .` 后不检查提交内容。

## 5. 开发期间同步其他人的更新

当别人的功能已经合入 `main`，而自己的工作还没有完成时：

```bash
git status
git fetch origin
git rebase origin/main
```

同步前应先提交当前修改。如果暂时不能提交，可以使用：

```bash
git stash push -u -m "临时保存当前工作"
git fetch origin
git rebase origin/main
git stash pop
```

如果双方修改不同文件或同一文件的不同位置，Git 通常会自动合并。只有修改同一位置时才需要人工解决冲突。

解决冲突后：

```bash
git add 已解决的文件
git rebase --continue
```

不确定如何处理冲突时不要删除文件或强制覆盖，先把冲突文件和双方意图发到群里确认。

## 6. 合并到 main

功能完成并通过本地测试后：

1. 将功能分支推送到 GitHub；
2. 在 GitHub 创建 Pull Request，目标分支选择 `main`；
3. 在说明中写清楚改了什么、如何验证、是否影响接口；
4. 由至少一位未参与本次修改的成员检查；
5. 检查通过后合并；
6. 合并后其他成员同步最新 `main`。

```bash
git switch main
git pull --ff-only origin main
```

## 7. 减少冲突的约定

- 开工前在群里说明正在修改的模块和预计涉及的文件。
- 后端接口字段变化时，同时更新接口类型、字段说明和测试。
- 尽量避免两个人同时大范围修改同一个核心文件。
- Word、图片、视频等二进制文件不能逐行合并，尽量指定单一负责人修改。
- 技术说明优先使用 Markdown，便于 Git 展示差异和处理冲突。
- 不提交真实密码、访问令牌、私钥和个人环境配置。

## 8. 常用检查命令

```bash
git status
git branch --show-current
git log --oneline --graph --decorate -10
git diff
git diff --staged
git remote -v
```

提交或推送前至少执行 `git status`，确认没有把依赖目录、运行结果或无关文件加入提交。
