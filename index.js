/**
 * dsh-preflight-gate —— 沙箱预检 + 一次性授权（原生 cordis 插件，进程内拦截）
 * ============================================================================
 * 两件事：
 *   A. 预检（tools/pre-execute）：把「先执行 → 撞沙箱 → 报错 → 再申请」变成「执行前就问」。
 *   B. 一次性授权（新工具 request_sandbox_access）：模型在开一轮活儿之前把本轮所有越界操作
 *      列成清单提交，用户**看一次、点一次**，整轮就放行到底，不再逐条弹审批。
 *      —— DSH 的审批词汇只有 allowed-once（没有 allow-always / 没有授权存储），所以"逐条问"
 *      是机制使然；要一次点完，只能由本插件在获批后临时把会话模式放到最宽并在本轮内停手。
 *
 * B 的语义
 *   request_sandbox_access({ operations, why, scope })
 *     · operations：本轮要做的越界操作，一行一条（写哪、跑什么、推哪里）
 *     · scope：turn（默认）本轮结束后自动恢复原权限；session 保持到你手动切回
 *     · 执行时走 DSH 审批通道弹**一次**确认，reason 就是这份清单
 *     · 获批 → setSandboxMode(session, 'danger-full-access') + 本插件本轮停手
 *     · 本轮结束（agent/turn-stopping）→ 若当前模式仍是插件改的那个，自动恢复原模式并收回授权
 *   审批被禁用（approval policy: never）时工具不会弹窗，直接说明"无法一次授权"。
 *
 * A 的规则分类（v1.2.0 起）
 *   sandboxOnly      只因为沙箱会挡住才存在（越界写/执行、网络凭据、管道 stdio、包管理器）：
 *                    受限会话 → 提前 deny；danger-full-access → 放行。
 *   alsoConsequential 顺带改动外部真实世界（push/ssh/发布）：受限时 deny，无沙箱时 ask。
 *   确认类（杀宿主进程、容器改动）：任何模式都只 ask。
 *   never 时本插件不自己 fail-closed（受限+沙箱类仍 deny，但换成"审批被禁用"的说明；其余放行）。
 *
 * 版本
 *   v1.3.1 删掉"冗余升权参数"拦截：它依赖插件读到的会话策略，而该读值出现过误判
 *          （把 workspace-write 读成 danger-full-access），代价是挡掉一次合法升权。
 *          现在升权参数一律交给 DSH 自己判定；文案也不再把自己的模式读值当事实断言。
 *          另外授权只按真实 session id 登记，取不到 id 就不登记（避免跨会话串号）。
 *   v1.3.0 新增 request_sandbox_access（一次性授权）+ agent/turn-stopping 自动恢复。
 *   v1.2.0 规则分沙箱类/确认类；danger-full-access 下沙箱类放行；never 不再自我 fail-closed。
 *   v1.1.x 命令段判定、剥引号判意图、短别名只在段首、空格/相对路径修复、新增
 *          outside-exec / network-client / child-pipe、full-access 带升权参数提前纠正。
 *
 * 配置（cordis.patch.yml 的 preflight-gate*.config）
 *   enabled: true              总开关
 *   trace: false               写 <会话工作区>/.dsh-preflight-trace.log
 *   batchApproval: true        是否注册 request_sandbox_access 工具
 *   batchScope: 'turn'         工具未传 scope 时的默认值（'turn' | 'session'）
 *   autoRestoreMode: true      本轮结束是否自动恢复原文件策略
 *   strictWhenApprovalsDisabled: false
 *   disabledRules: [] / extraRules: []
 */

import { appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';

export const name = 'preflight-gate';
export const inject = ['tools'];

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------
function normalizeFsPath(p) {
  let s = resolve(String(p));
  if (process.platform === 'win32') s = s.toLowerCase();
  s = s.replace(/[\\/]+$/, '');
  return s === '' ? sep : s;
}

function canonAgainst(p, base) {
  const raw = String(p);
  return normalizeFsPath(isAbsolute(raw) ? raw : join(base, raw));
}

function isInside(child, parent) {
  const tail = parent.endsWith(sep) ? parent : parent + sep;
  return child === parent || child.startsWith(tail);
}

function isTruncatedPrefix(candidate, root) {
  return root.startsWith(candidate + ' ') || root.startsWith(candidate + sep);
}

function tempRoots() {
  return [tmpdir(), process.env.TEMP, process.env.TMP, process.platform === 'win32' ? 'C:\\Windows\\Temp' : '/tmp']
    .filter((p) => typeof p === 'string' && p.length > 0)
    .map(normalizeFsPath);
}

function pathVerdict(rawPath, workspace, temps) {
  const canon = canonAgainst(rawPath, workspace);
  if (isInside(canon, workspace) || temps.some((root) => isInside(canon, root))) return { outside: false, canon };
  if (isTruncatedPrefix(canon, workspace) || temps.some((root) => isTruncatedPrefix(canon, root))) {
    return { outside: false, canon, truncated: true };
  }
  return { outside: true, canon };
}

function extractPaths(command) {
  const found = new Set();
  const push = (raw) => {
    const cleaned = String(raw).trim().replace(/["',;)]+$/, '');
    if (cleaned.length > 2) found.add(cleaned);
  };
  for (const m of command.matchAll(/"([A-Za-z]:[\\/][^"]*)"/g)) push(m[1]);
  for (const m of command.matchAll(/'([A-Za-z]:[\\/][^']*)'/g)) push(m[1]);
  for (const m of command.matchAll(/[A-Za-z]:[\\/][^"'\s|;,)<>]*/g)) push(m[0]);
  for (const m of command.matchAll(/\\\\[A-Za-z0-9._$-]+[\\/][^"'\s|;,)<>]*/g)) push(m[0]);
  if (process.platform !== 'win32') {
    for (const m of command.matchAll(/(?:^|[\s"'=(])(\/(?:[^"'\s|;,)<>])+)/g)) push(m[1]);
  }
  return [...found];
}

// ---------------------------------------------------------------------------
// 意图识别
// ---------------------------------------------------------------------------
const WRITE_TOKENS =
  /(\bSet-Content\b|\bAdd-Content\b|\bClear-Content\b|\bOut-File\b|\bNew-Item\b|\bNew-ItemProperty\b|\bSet-ItemProperty\b|\bRemove-Item\b|\bRemove-ItemProperty\b|\bCopy-Item\b|\bMove-Item\b|\bRename-Item\b|\bExport-Csv\b|\bExport-Clixml\b|\bExpand-Archive\b|\brobocopy\b|\bxcopy\b|\bicacls\b|\btakeown\b|\battrib\b|\bmkdir\b|writeFileSync|\bwriteFile\b|appendFile|createWriteStream|WriteAllText|WriteAllBytes|CreateDirectory|sed\s+-i|git\s+clone|tar\s+-x)/i;

const SHORT_ALIAS_WRITE = /^\s*(md|rd|rm|del|erase|rmdir|mv|cp|move|copy|mkdir|touch)\s/i;

const REDIRECT_OP = /(^|[^>0-9])>>?/;

const EXEC_EXT = /\.(exe|cmd|bat|com|ps1|vbs|js|mjs|cjs|py|sh)$/i;

function stripQuoted(command) {
  return command.replace(/"[^"]*"/g, '""').replace(/'[^']*'/g, "''");
}

function hasWriteIntent(segment) {
  const bare = stripQuoted(segment);
  return WRITE_TOKENS.test(bare) || SHORT_ALIAS_WRITE.test(bare) || REDIRECT_OP.test(bare);
}

function outsideProgram(segment, outsidePaths) {
  for (const p of outsidePaths) {
    if (!EXEC_EXT.test(p)) continue;
    const idx = segment.indexOf(p);
    if (idx < 0) continue;
    const before = segment.slice(0, idx).replace(/["']/g, '').trim();
    if (before === '') return p;
    if (/[&|;]$/.test(before)) return p;
    if (/(?:start-process|\/c|\/k|-file|-command)\s*$/i.test(before)) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------
// 规则表
// ---------------------------------------------------------------------------
const RULES = [
  { id: 'outside-write', sandboxOnly: true, why: '目标路径在会话工作区之外，workspace-write 只允许写工作区与平台临时区' },
  { id: 'outside-exec', sandboxOnly: true, why: '要执行的程序位于工作区之外，受限模式会以「拒绝访问」失败' },
  {
    id: 'global-install',
    sandboxOnly: true,
    pattern:
      /(\b(winget|choco|scoop|pip|pipx|poetry|uv|cargo|dotnet|nuget|gem|composer|mvn|gradle)\b[^\n|;&]*\b(install|add|restore|tool\s+install|update|upgrade|global)\b|\b(npm|pnpm|yarn|bun|corepack)\b[^\n|;&]*[\s"'=(](?:-g|--global|global)\b)/i,
    why: '全局安装 / 宿主级包管理器变更要写工作区之外的宿主目录（全局 bin、site-packages、~/.cargo、~/.m2、~/.dotnet 等）',
  },
  {
    id: 'pkg-store',
    sandboxOnly: true,
    pattern: /\b((npm|pnpm|yarn|bun)\b[^\n|;&]*\b(i|install|ci|add)\b|pnpm\s+store\b)/i,
    why: '项目内安装也要写工作区之外的 store/cache 目录（pnpm store、npm cache）',
  },
  {
    id: 'network-client',
    sandboxOnly: true,
    pattern: /(\bcurl\b|\bInvoke-WebRequest\b|\biwr\b|\bInvoke-RestMethod\b|\birm\b|\bwget\b|\bStart-BitsTransfer\b|\bgit\b[^\n|;&]*\b(fetch|pull|clone|lfs)\b)/i,
    why: '受限模式下取不到 Windows 凭据库（schannel），HTTPS 会以 SEC_E_NO_CREDENTIALS / AcquireCredentialsHandle failed 失败——那是沙箱造成的，不是网络或服务器故障',
  },
  {
    id: 'remote-mutation',
    sandboxOnly: true,
    alsoConsequential: true,
    pattern:
      /(\bgit\b[^\n|;&]*\b(push|remote)\b|\bgit\s+tag\b[^\n|;&]*\b(push|-d)\b|\b(ssh|scp|sftp|rsync|plink|pscp)\b|\bnpm\s+publish\b|\bpnpm\s+publish\b|\bgh\s+(pr|release|repo)\b)/i,
    why: '受限模式下 SSH/HTTPS 取不到凭据库（SEC_E_NO_CREDENTIALS）会失败；即便能跑，这类操作也会改动远端真实环境',
  },
  {
    id: 'child-pipe',
    sandboxOnly: true,
    pattern:
      /(\bvitest\b|\bjest\b|\bmocha\b|\bplaywright\b|\bcypress\b|\besbuild\b|node\s+--test\b|\bnpx\b|\bnpm\s+(test|exec|run)\b|\bpnpm\s+(test|exec|dlx|run)\b|\byarn\s+(test|exec|run)\b)/i,
    why: '受限模式下子进程不能有管道 stdio（命名管道不可用），测试/构建器会以 esbuild spawn EPERM 或 StandardOutputEncoding 报错失败',
  },
  {
    id: 'host-services',
    pattern:
      /\b(Stop-Process|taskkill|Stop-Service|Start-Service|Restart-Service|sc\s+(config|create|delete|stop|start)|schtasks|reg\s+(add|delete|import)|netsh|bcdedit|powercfg|New-Service|Set-Service)\b/i,
    why: '会改动宿主进程 / 服务 / 注册表 / 计划任务',
  },
  {
    id: 'containers',
    pattern: /\b(docker|podman|kubectl|helm)\b[^\n|;&]*\b(rm|rmi|prune|delete|apply|create|run|stop|kill|scale|rollout)\b/i,
    why: '会改动真实容器 / 集群环境',
  },
];

// ---------------------------------------------------------------------------
// 理由文本
// ---------------------------------------------------------------------------
function escalateReason(ruleId, why, mode, detail) {
  return [
    `沙箱预检（preflight-gate）：命中规则「${ruleId}」。`,
    `原因：${why}`,
    detail ? `命中内容：${detail}` : '',
    `（插件读到的会话策略是 ${mode}，仅供参考——请以运行时上下文里的 "Current DSH file policy" 为准。）`,
    ``,
    `直接执行会失败并白跑一次。两种做法二选一：`,
    `  · 只这一条要放行 → 重发这**同一次调用**，带上成对参数：`,
    `      sandbox_permissions: "workspace-write"（仅当策略是 read-only）或 "danger-full-access"；justification: "<一句话理由>"`,
    `  · 本轮还有一批越界操作 → 用 request_sandbox_access 一次性提交清单，用户点一次即可放行整轮。`,
    `请勿换写法绕过。`,
  ]
    .filter((line) => line !== '')
    .join('\n');
}

function confirmReason(ruleId, why, mode, detail) {
  return [
    `沙箱预检（preflight-gate）：命中规则「${ruleId}」。`,
    `原因：${why}`,
    detail ? `命中内容：${detail}` : '',
    `这一步本身能执行，但会改动工作区之外的真实环境，所以先请你确认。`,
    `拒绝请说明原因，模型会改用更小的动作，不会绕道重试。`,
  ]
    .filter((line) => line !== '')
    .join('\n');
}

function approvalsDisabledReason(ruleId, why, mode, detail) {
  return [
    `沙箱预检（preflight-gate）：命中规则「${ruleId}」，当前会话文件策略 ${mode}，这一步会被沙箱挡住；`,
    `但本会话审批被禁用（approval policy: never），无法升权，也没有人能应答确认 —— 请不要把它理解成用户拒绝。`,
    `原因：${why}`,
    detail ? `命中内容：${detail}` : '',
    ``,
    `可选做法：`,
    `  · 请用户把权限预设切到带审批的那一档（/permission workspace-write，或自定义 danger-full-access + approval ask）后重发同一次调用；`,
    `  · 请用户把预设切到 danger-full-access（没有沙箱就没有这层拦截）；`,
    `  · 或者由用户手动执行这条命令。`,
  ]
    .filter((line) => line !== '')
    .join('\n');
}

/** 把清单渲染成审批提示里那段文字。 */
export function formatPlan(operations, why, scope) {
  const list = String(operations)
    .split(/\r?\n/)
    .map((s) => s.replace(/^\s*(?:\d+[.)、]|[-*])\s*/, '').trim())
    .filter((s) => s.length > 0);
  const numbered = list.map((op, i) => `  ${i + 1}) ${op}`).join('\n');
  return [
    `一次性权限申请（scope=${scope}）`,
    `理由：${why}`,
    `本轮要执行的越界操作共 ${list.length} 项：`,
    numbered,
    ``,
    `批准后：这些操作不再逐条弹审批，也不会被文件沙箱拦住；` +
      (scope === 'session' ? `权限保持到你手动切回（/permission workspace-write）。` : `本轮结束后自动恢复原权限。`),
    `注意：清单之外的同类操作也会按同一授权执行，所以请确认清单覆盖了本轮真实范围。`,
  ].join('\n');
}

// ---------------------------------------------------------------------------
// 判定核心（纯函数，便于测试）
// ---------------------------------------------------------------------------
function evaluate({ toolName, args, mode, approvalPolicy, workspace, temps, rules }) {
  const active = rules.filter((r) => r.enabled !== false);
  const confined = mode !== 'danger-full-access';

  const decide = (rule, detail) => {
    const sandboxMatters = rule.sandboxOnly === true && confined;
    const consequential = rule.alsoConsequential === true || rule.sandboxOnly !== true;

    if (sandboxMatters) {
      return approvalPolicy === 'never'
        ? { kind: 'deny', ruleId: rule.id, reason: approvalsDisabledReason(rule.id, rule.why, mode, detail) }
        : { kind: 'deny', ruleId: rule.id, reason: escalateReason(rule.id, rule.why, mode, detail) };
    }
    if (!consequential) return null;
    if (approvalPolicy === 'never') {
      return rule.strict === true ? { kind: 'deny', ruleId: rule.id, reason: approvalsDisabledReason(rule.id, rule.why, mode, detail) } : null;
    }
    return { kind: 'ask', ruleId: rule.id, reason: confirmReason(rule.id, rule.why, mode, detail) };
  };

  if (toolName === 'pwsh' || toolName === 'bash') {
    const command = typeof args.command === 'string' ? args.command : '';
    if (command.length === 0) return null;

    const segments = command
      .split(/[;\n]|\|\||&&|\|/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    for (const segment of segments.length > 0 ? segments : [command]) {
      const outside = extractPaths(segment)
        .map((p) => ({ raw: p, ...pathVerdict(p, workspace, temps) }))
        .filter((v) => v.outside);
      if (outside.length === 0) continue;

      const program = outsideProgram(segment, outside.map((v) => v.raw));
      const execRule = active.find((r) => r.id === 'outside-exec');
      if (program !== null && execRule !== undefined) {
        const d = decide(execRule, program);
        if (d !== null) return d;
      }
      if (hasWriteIntent(segment)) {
        const writeRule = active.find((r) => r.id === 'outside-write');
        if (writeRule !== undefined) {
          const d = decide(writeRule, outside.map((v) => v.raw).slice(0, 3).join(' / '));
          if (d !== null) return d;
        }
      }
    }

    for (const rule of active) {
      if (rule.id === 'outside-write' || rule.id === 'outside-exec') continue;
      if (rule.pattern === undefined) continue;
      if (!rule.pattern.test(command)) continue;
      const d = decide(rule, undefined);
      if (d !== null) return d;
    }
    return null;
  }

  if (toolName === 'write' || toolName === 'edit') {
    const target = args.file_path ?? args.path;
    if (typeof target !== 'string' || target.length === 0) return null;
    const verdict = pathVerdict(target, workspace, temps);
    if (!verdict.outside) return null;
    const rule = active.find((r) => r.id === 'outside-write');
    if (rule === undefined) return null;
    return decide(rule, `${target}（工作区 ${workspace}）`);
  }

  return null;
}

// ---------------------------------------------------------------------------
// 会话模式切换 + 授权状态
// ---------------------------------------------------------------------------
function sessionKeyOf(session) {
  return session?.id ?? session?.header?.id ?? undefined;
}

/** 走官方写路径切换会话文件策略；官方模块不可用时退回等价的事件写入。 */
async function switchSandboxMode(session, mode) {
  try {
    const mod = await import('@deepseek-ai/dsh-sandbox-policy');
    if (typeof mod.setSandboxMode === 'function') {
      mod.setSandboxMode(session, mode);
      return true;
    }
  } catch {
    /* 退回下面的等价写入 */
  }
  try {
    session.append('sandbox/mode', { mode });
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------
export function apply(ctx, config = {}) {
  if (config.enabled === false) {
    ctx.logger?.info?.('preflight-gate: disabled by config');
    return;
  }
  const traceOn = config.trace === true;
  const strict = config.strictWhenApprovalsDisabled === true;
  const batchEnabled = config.batchApproval !== false;
  const defaultScope = config.batchScope === 'session' ? 'session' : 'turn';
  const autoRestore = config.autoRestoreMode !== false;
  const disabled = new Set(Array.isArray(config.disabledRules) ? config.disabledRules : []);
  const extraRules = (Array.isArray(config.extraRules) ? config.extraRules : [])
    .filter((r) => r && typeof r.id === 'string' && typeof r.pattern === 'string' && typeof r.why === 'string')
    .map((r) => ({
      id: r.id,
      why: r.why,
      sandboxOnly: r.sandboxOnly !== false,
      alsoConsequential: r.alsoConsequential === true,
      strict: r.strict === true,
      pattern: new RegExp(r.pattern, 'i'),
    }));
  const rules = [...RULES, ...extraRules].map((r) => ({ strict, ...r, enabled: !disabled.has(r.id) }));

  /** sessionId → { scope, previousMode, switched }；只活在进程内。 */
  const grants = new Map();

  function trace(workspace, line) {
    if (!traceOn) return;
    try {
      appendFileSync(join(workspace, '.dsh-preflight-trace.log'), `${new Date().toISOString()} ${line}\n`, 'utf8');
    } catch {
      /* 排障日志写不了就算了 */
    }
  }

  function policyOf(session) {
    const service = ctx.get('sandboxPolicy');
    if (service !== undefined && session !== undefined) {
      const resolved = service.resolve({ session });
      return { mode: resolved.mode ?? 'workspace-write', workspace: resolved.workspaceRoot ?? session?.header?.cwd ?? process.cwd() };
    }
    return { mode: 'workspace-write', workspace: session?.header?.cwd ?? process.cwd() };
  }

  // ---------------------------------------------------------------- 一次性授权工具
  if (batchEnabled) {
    void (async () => {
      let defineTool = (tool) => tool;
      try {
        const mod = await import('@deepseek-ai/dsh-tools');
        if (typeof mod.defineTool === 'function') defineTool = mod.defineTool;
      } catch {
        /* 用裸定义兜底 */
      }
      try {
        ctx.tools.register(
          defineTool({
            name: 'request_sandbox_access',
            description:
              '一次性申请本轮所需的越界权限：把本轮所有会动到会话工作区之外的命令/文件操作列成清单提交，用户审一次即可放行整轮，之后不再逐条弹审批。'
              + '只在你确实要执行这些操作时调用，调用前先把清单写在回复里给用户看。'
              + '获批后本轮可正常执行（含 git push、跑测试、写工作区外文件等）；本轮结束自动恢复原权限。'
              + '用户拒绝时不要重试，改为说明并缩小范围。',
            parameters: {
              operations: {
                type: 'string',
                required: true,
                description: '本轮要执行的越界操作，一行一条，写清楚对象（例如「写 C:\\Users\\me\\.dsh\\config.json」「运行 npx vitest」「git push origin main」）。',
              },
              why: {
                type: 'string',
                required: true,
                description: '一句话说明为什么这一轮需要这些权限（会显示在审批弹窗里）。',
              },
              scope: {
                type: 'string',
                description: `授权范围："turn" 本轮有效（默认，结束后自动恢复）；"session" 保持到你手动切回。缺省为 ${defaultScope}。`,
              },
            },
            output: {
              schema: { type: 'string' },
              render: (_args, value) => [{ type: 'text', text: String(value) }],
            },
            async execute(args, exec) {
              const session = exec?.agent?.session;
              const operations = typeof args.operations === 'string' ? args.operations.trim() : '';
              const why = typeof args.why === 'string' ? args.why.trim() : '';
              const scope = args.scope === 'session' ? 'session' : args.scope === 'turn' ? 'turn' : defaultScope;
              if (session === undefined) return 'request_sandbox_access：本次调用没有会话上下文，无法授权。请告知用户手动执行。';
              if (operations.length === 0) return 'request_sandbox_access：operations 不能为空，请把本轮越界操作一行一条列出来。';
              if (why.length === 0) return 'request_sandbox_access：why 不能为空。';

              const { mode } = policyOf(session);
              const approval = ctx.get('approval');
              if (approval === undefined || typeof approval.request !== 'function') {
                return 'request_sandbox_access：本组合没有审批服务，无法一次授权。受限会话下请用户切预设或手动执行。';
              }
              const effective = approval.effectivePolicy?.(session) ?? 'ask';
              if (effective === 'never') {
                return [
                  'request_sandbox_access：本会话审批被禁用（approval policy: never），不会弹窗，因此无法一次授权——不要重试本工具。',
                  `当前文件策略：${mode}。`,
                  mode === 'danger-full-access'
                    ? '既然已是 danger-full-access，直接执行即可（本插件在无沙箱模式下不拦沙箱类操作）。'
                    : '请用户把预设切到带审批的那一档（/permission workspace-write），或切到 danger-full-access，或由用户手动执行。',
                ].join('\n');
              }

              const plan = formatPlan(operations, why, scope);
              const outcome = await approval.request({
                agent: exec.agent,
                toolName: 'request_sandbox_access',
                ...(exec.callId !== undefined ? { callId: exec.callId } : {}),
                reason: plan.length > 1800 ? `${plan.slice(0, 1800)}\n…（清单过长已截断，完整清单见对话）` : plan,
                ...(exec.signal !== undefined ? { signal: exec.signal } : {}),
              });

              if (outcome === 'allowed-once') {
                const key = sessionKeyOf(session);
                const switched = mode === 'danger-full-access' ? false : await switchSandboxMode(session, 'danger-full-access');
                // 会话 id 拿不到就不登记授权：宁可这次只当"已批准"，也不要让授权落到别的会话头上
                if (key !== undefined) grants.set(key, { scope, previousMode: mode, switched, at: Date.now() });
                trace(policyOf(session).workspace, `batch-granted scope=${scope} previousMode=${mode} switched=${switched}`);
                return [
                  `已获一次性授权（scope=${scope}），本轮可以直接执行清单里的操作，不会再逐条弹审批。`,
                  switched
                    ? `文件策略已临时切到 danger-full-access${autoRestore ? `，${scope === 'session' ? '会话结束或用户手动切回前' : '本轮结束后'}自动恢复到 ${mode}` : ''}。`
                    : `文件策略本来就是 ${mode}，本插件本轮不再拦截。`,
                  `清单（${plan.split('\n').filter((l) => /^\s+\d+\)/.test(l)).length} 项）已记录在审批理由里。`,
                  `现在开始执行即可，不要再用 sandbox_permissions。`,
                ].join('\n');
              }
              if (outcome === 'rejected') {
                return [
                  '用户**拒绝**了这次一次性授权。',
                  '不要执行清单里的越界操作，也不要重试本工具或改写法绕过；请说明你打算怎么做、或请用户指出哪几项可以去掉，然后再请示。',
                ].join('\n');
              }
              if (outcome === 'cancelled') return '一次性授权被取消（用户撤回或中断）。停手，等用户指示。';
              return '一次性授权无法完成：没有可用的审批通道（unavailable）。请告知用户手动切预设或手动执行。';
            },
          }),
        );
        ctx.logger?.info?.('preflight-gate: request_sandbox_access registered');
      } catch (error) {
        ctx.logger?.warn?.(`preflight-gate: 注册 request_sandbox_access 失败：${String(error)}`);
      }
    })();
  }

  // ---------------------------------------------------------------- 预检
  ctx.on('tools/pre-execute', (exec, next) => {
    const args = exec?.arguments ?? {};
    const session = exec?.agent?.session;
    const { mode, workspace } = policyOf(session);
    const workspaceKey = normalizeFsPath(workspace);

    // 升权参数交给 DSH 自己判定：
    //   · 只带一个 → 工具自己明确拒绝（invalid escalation: sandbox_permissions requires a justification）；
    //   · 成对但会话已是最宽 → 工具自己报 not strictly wider；
    //   · 成对且会话受限 → 正常升权，工具自己弹审批。
    // 插件不再插手这三种情况：v1.3.1 曾在这里拦"冗余参数"，但它依赖插件读到的会话策略，
    // 而那个读值出现过误判（把 workspace-write 读成 danger-full-access），
    // 结果是把一次**合法升权**挡掉了。宁可少说一句，不可挡正事。

    // 已获一次性授权：本轮不再拦（沙箱也已临时放宽）
    const key = sessionKeyOf(session);
    const grant = key === undefined ? undefined : grants.get(key);
    if (grant !== undefined) {
      trace(workspace, `tool=${exec?.name} mode=${mode} granted scope=${grant.scope} → pass`);
      return next();
    }

    if (args.sandbox_permissions !== undefined) return next();

    const approvalPolicy = ctx.get('approval')?.effectivePolicy?.(session) ?? 'ask';
    const decision = evaluate({
      toolName: String(exec?.name ?? ''),
      args,
      mode,
      approvalPolicy,
      workspace: workspaceKey,
      temps: tempRoots(),
      rules,
    });

    if (decision === null) return next();
    trace(workspace, `tool=${exec?.name} mode=${mode} approval=${approvalPolicy} rule=${decision.ruleId} kind=${decision.kind}`);
    return { kind: decision.kind, reason: decision.reason };
  });

  // ---------------------------------------------------------------- 本轮结束：收回授权 + 恢复模式
  ctx.on('agent/turn-stopping', async ({ agent }) => {
    const session = agent?.session;
    const key = sessionKeyOf(session);
    const grant = key === undefined ? undefined : grants.get(key);
    if (grant === undefined || grant.scope !== 'turn') return;
    grants.delete(key);
    const current = policyOf(session);
    if (autoRestore && grant.switched && current.mode === 'danger-full-access') {
      const restored = await switchSandboxMode(session, grant.previousMode ?? 'workspace-write');
      trace(current.workspace, `batch-revoked scope=turn restored=${restored} -> ${grant.previousMode}`);
    } else {
      trace(current.workspace, 'batch-revoked scope=turn (no mode restore needed)');
    }
  });

  ctx.logger?.info?.(`preflight-gate: active (tools/pre-execute, ${rules.filter((r) => r.enabled).length} rules${batchEnabled ? ', batch approval on' : ''})`);
}

/** 供本地测试使用；DSH 只使用 name/inject/apply。 */
export const __internals = {
  RULES,
  evaluate,
  extractPaths,
  pathVerdict,
  hasWriteIntent,
  normalizeFsPath,
  canonAgainst,
  tempRoots,
  formatPlan,
};

export default { name, inject, apply };
