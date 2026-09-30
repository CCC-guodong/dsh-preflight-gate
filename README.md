# dsh-preflight-gate

> 给 [DSH（DeepSeek Harness）](https://github.com/deepseek-ai) 用的**沙箱预检 + 一次性授权**插件。
> 把「先执行 → 撞沙箱 → 报错 → 再申请」变成「**执行前就问**」，并且**一批操作只点一次**。

DSH 原生 cordis 插件，挂在 `tools/pre-execute` 上，不启子进程、不改宿主代码。

---

## 它解决什么

DSH 默认的文件沙箱策略是 `workspace-write`：只有会话工作区 + 平台临时区可写。越界的操作会**先执行、再失败**，
于是常见这些让人困惑的报错：

| 现象 | 真正原因 |
|---|---|
| `[sandbox: file access denied under workspace-write mode]` | 写到了工作区外（其它盘符、`~/.cargo`、pnpm/npm store 等） |
| `SEC_E_NO_CREDENTIALS` / `AcquireCredentialsHandle failed` | 受限模式下取不到 Windows 凭据库（schannel）——**不是网络或服务器故障**（TCP 层 `Test-NetConnection` 反而是通的，很多人据此去查 nginx） |
| `esbuild spawn EPERM` / `StandardOutputEncoding is only supported when standard output is redirected` | 受限模式下子进程不能使用管道 stdio（命名管道不可用），测试/构建器起不来 |
| `程序'xxx.cmd'运行失败：拒绝访问` | 执行了工作区外的程序（例如微信开发者工具 CLI） |

而 DSH 的审批词汇只有 **`allowed-once`**——没有 allow-always、没有授权存储，所以"每条都要点一次"是机制使然。
这个插件做两件事来消除这些摩擦。

## 两个能力

### A. 预检：该拦的提前拦，不该拦的不插手

规则分两类，并按**会话策略**决定是否生效——`danger-full-access` 下沙箱类规则一律放行（没有沙箱可撞，
拦它没有意义）：

| 规则类别 | 受限会话 `read-only` / `workspace-write` | 无沙箱会话 `danger-full-access` |
|---|---|---|
| **沙箱类**：越界写 / 越界执行 / 网络凭据 / 管道 stdio / 包管理器写宿主目录 | `deny` + 明确的重发指引 | **放行** |
| **沙箱类 + 需确认**：`git push`、`ssh/scp`、发布 | `deny` + 重发指引 | `ask` 确认 |
| **确认类**：杀宿主进程/服务、容器改动 | `ask` 确认 | `ask` 确认 |

审批被禁用（`approval policy: never`）时，插件**不自己 fail-closed**：受限+沙箱类仍 `deny`（理由换成
"审批被禁用、升权不可能"），其余放行。

### B. 一次性授权：一份清单、一次点击、整轮放行

模型在开一轮活儿之前，把本轮所有越界操作列成清单提交：

```
request_sandbox_access({
  operations: "写 ~/.cargo/config.toml\n运行 npx vitest\ngit push origin main",
  why: "本轮要装依赖、跑测试并推送",
  scope: "turn"
})
```

流程：

1. DSH 弹出**一次**审批，**弹窗正文就是这份清单**；
2. 批准 → 插件把会话文件策略临时切到 `danger-full-access`，并在本轮内停手；
3. 该轮所有操作（写工作区外文件、跑测试、推送、驱动模拟器）**不再逐条弹审批**；
4. 本轮结束（`agent/turn-stopping`）**自动恢复**原策略，授权同时作废；
5. 拒绝 → 工具返回明确文案，模型必须停手，不重试、不换写法。

`scope: "session"` 则保持到你手动切回（`/permission workspace-write`）。

### 效果对比

| | 默认 DSH | 装了这个插件 |
|---|---|---|
| 一条越界命令 | 白跑一次 → 报错 → 重发 → 点一次 | 执行前拦下给指引 → 重发 → 点一次（或清单一次搞定） |
| 一轮 6 项越界操作 | 约 6 次点击 | **1 次点击** |
| `danger-full-access` 会话 | 沙箱类操作本来会成功 | 插件不插手（只对 push/杀进程这类确认类问一次） |
| `never` + 受限会话 | fail-closed，报成 `the user rejected tool ...`（像用户拒绝） | 说清"审批被禁用"，不做假拒绝 |

## 安装

要求：DSH `0.1.5-rc.2` 起（本插件在该版本上开发与实测）。宿主需已挂载 `dsh-tools`、`dsh-sandbox-policy`、
`dsh-user-approval`（`dsh-base` 默认都有）。

1. 把本仓库放进你的 profile（`<profile>` 通常是 `web`）：

```bash
git clone https://github.com/chun07645-dev/dsh-preflight-gate.git
mkdir -p ~/.dsh/profiles/web/node_modules/dsh-preflight-gate
cp dsh-preflight-gate/index.js dsh-preflight-gate/package.json \
   ~/.dsh/profiles/web/node_modules/dsh-preflight-gate/
```

2. 在 `~/.dsh/profiles/web/cordis.patch.yml` 里加一段：

```yaml
- insert:
    - id: preflight-gate
      name: 'dsh-preflight-gate'
      config:
        enabled: true
        trace: false                  # true → <会话工作区>/.dsh-preflight-trace.log
        batchApproval: true           # 注册 request_sandbox_access
        batchScope: 'turn'            # turn（本轮）| session
        autoRestoreMode: true         # 轮末自动恢复原策略
        strictWhenApprovalsDisabled: false
        disabledRules: []             # 例：['child-pipe']
        extraRules: []                # 例：[{ id: my-rule, why: 原因, pattern: '正则', alsoConsequential: false }]
```

3. 重启 DSH（或换个包名让它重新 import，见下"热加载"）。

验证：把会话切到 `workspace-write`（`/permission workspace-write`），让它执行一条写工作区外的命令——
应该被拦下并给出升权指引，而不是白跑一次再报沙箱错。

## 会话策略与预设（重要）

内置预设把"最宽沙箱"和"关审批"绑在了一起：

| 预设 | 沙箱 | 审批 |
|---|---|---|
| `read-only` | read-only | `ask` |
| `workspace-write` | workspace-write | `ask` |
| `danger-full-access` | danger-full-access | `never` |

所以"切到全权"= 顺手关掉审批，之后所有 `ask` 类操作都会 fail-closed（`the user rejected tool ...` 那种假拒绝）。
想"干活不撞墙、但 push/deploy 仍能问一次"，自定义一个预设即可：

```yaml
- id: permission
  config:
    presets:
      read-only: { sandbox: read-only, approval: ask }
      workspace-write: { sandbox: workspace-write, approval: ask }
      danger-full-access: { sandbox: danger-full-access, approval: never }
      gate: { sandbox: danger-full-access, approval: ask }
```

然后 `/permission gate`。

## 规则表

| id | 类别 | 命中 |
|---|---|---|
| `outside-write` | 沙箱类 | 越界路径 + 写入动作（含重定向、`write`/`edit` 的越界目标） |
| `outside-exec` | 沙箱类 | 执行工作区外的程序（段首 / `&` / `Start-Process` / `cmd /c` 位置的可执行文件） |
| `global-install` | 沙箱类 | `winget/choco/scoop/pip/cargo/dotnet/gem/mvn/gradle …`、`npm|pnpm|yarn -g` |
| `pkg-store` | 沙箱类 | 项目内安装（`pnpm add`、`npm i`…）要写工作区外的 store/cache |
| `network-client` | 沙箱类 | `curl`、`Invoke-WebRequest/iwr/irm`、`wget`、`git fetch/pull/clone/lfs` |
| `remote-mutation` | 沙箱类 + 确认 | `git push`/`git remote`、`ssh/scp/sftp/rsync`、`npm|pnpm publish`、`gh pr/release` |
| `child-pipe` | 沙箱类 | `vitest/jest/esbuild/npx/npm run/pnpm run …` 需要管道 stdio 的测试/构建器 |
| `host-services` | 确认类 | `Stop-Process`/`taskkill`/`sc stop`/`schtasks`/`reg add`… |
| `containers` | 确认类 | `docker/kubectl/helm` 的改动类子命令 |

解析细节（都是踩出来的）：

- 按命令段判定：`Set-Content .\a.txt; Select-String 'C:\outside\f'` 只有带越界路径的那段算命中；
- 判定意图前先剥掉引号内容，`-Pattern 'rd '` 不会被当成写动作；
- 长 cmdlet 用词边界、短别名（`rd`/`md`/`rm`/`mv`/`cp`…）只在命令段开头才算动作；
- 裸路径遇到空格会被截断（`D:\work\my project` → `D:\work\my`），因此"候选是工作区/临时区的
  被截断前缀"判为区内；相对路径按**会话工作区**解析而不是宿主进程 cwd。

## 工作原理

- 挂 `tools/pre-execute` 瀑布，返回 `{ kind: 'deny' | 'ask', reason }` 或 `next()`；进程内判定，无子进程。
- 会话策略通过 `ctx.get('sandboxPolicy').resolve({ session })` 读取；审批策略通过
  `ctx.get('approval').effectivePolicy(session)` 读取。
- 一次性授权：`ctx.get('approval').request(...)` 弹一次审批 → `setSandboxMode(session, 'danger-full-access')`
  → 本轮 grep 停手 → `agent/turn-stopping` 里恢复原策略。
- 工具通过 `ctx.tools.register(defineTool({...}))` 注册。

**设计边界（重要）**：

- 工具入参被宿主 `deepFreeze`（`dsh-tools` 的 `createExecution`），插件**无法改写**模型给的参数——所以
  "帮你把多余参数摘掉"这种事做不到，只能解释或不插手。
- 审批只有一次性结果（`allowed-once`），没有"记住授权"，所以"整轮放行"必须由插件临时放宽会话策略实现。
- 授权期间沙箱是**整轮放宽**的，不是只放开清单里那几条；清单是给人审的**范围说明**，不是执行期白名单。

## 测试

```bash
node test-preflight.mjs ./index.js   # 53 项：误判回归 + 真越界拦截 + 策略矩阵 + 接线
node test-batch.mjs      ./index.js   # 22 项：一次性授权（获批/拒绝/never/全权/跨轮/清单渲染）
```

两套都是纯 Node、无依赖。

## 已知边界

- 规则是**文本匹配**：`node some-script.js` 这种"脚本内部自己越界写"拦不住；命令里未加引号的字面量也可能命中。
- 只决定"要不要先问/先拦/何时放行"，真正的授权仍由 DSH 的沙箱与审批通道负责。
- Windows 特有的受限行为（凭据库、命名管道）是在 Windows 上踩出来的结论；Linux/macOS 下同类规则仍然适用
  （越界写、包管理器、`npx` 等），但错误文本会不同。

## 版本记录

- **1.3.1** 删除"冗余升权参数"拦截：它依赖插件读到的会话策略，而该读值出现过误判（把 `workspace-write`
  读成 `danger-full-access`），后果是把一次**合法升权**挡掉了。现在升权参数完全交给 DSH 判定；提示文案
  不再把插件的模式读值当事实；一次性授权只按真实 session id 登记（避免跨会话串号）。
- **1.3.0** 新增 `request_sandbox_access`（一次性授权）+ 轮末自动恢复。
- **1.2.0** 规则分沙箱类/确认类；`danger-full-access` 下沙箱类放行；`never` 不再自我 fail-closed。
- **1.1.x** 命令段判定；剥引号判意图；短别名只在段首；空格/相对路径修复；新增
  `outside-exec` / `network-client` / `child-pipe`；`danger-full-access` 带升权参数提前纠正。

### 为什么不用 Claude Code hooks 来实现

先试过 `@deepseek-ai/dsh-hooks-claude-code`（`PreToolUse` → `tools/pre-execute`，输出
`permissionDecision: "ask"`）。能挂上、也触发，但：

1. 钩子载荷只经 **stdin** 传给子进程，而受限执行器 `@deepseek-ai/dsh-pwsh-sandbox` **不转发 stdin**
   （未受限的 `@deepseek-ai/dsh-pwsh-local` 会转发）→ 钩子在 `workspace-write` 会话里永远读到空载荷；
2. 受限路径下钩子包装进程会挂到 hook 超时才退出 → **每次工具调用 +10 秒**。

原生监听器没有子进程、没有 stdin、没有超时，所以选了插件而不是钩子。

## 热加载（DSH 现状）

宿主按**包名**缓存插件模块，实测：换包名（`dsh-preflight-gate` → `dsh-preflight-gate-v131`…）会立即重新 import，
**免重启生效**；只改同名包里的文件或入口文件名**不会**热加载，必须重启 DSH。

## License

MIT，见 [LICENSE](./LICENSE)。


