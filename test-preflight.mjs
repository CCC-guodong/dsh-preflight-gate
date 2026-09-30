/**
 * preflight-gate v1.2.0 回归测试
 * 覆盖：实机误判回归、真越界拦截、以及「规则该不该在当前模式生效」的完整矩阵。
 * 用法：node test-preflight.mjs <插件文件> [输出文件]
 */
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const mod = await import(pathToFileURL(process.argv[2]).href);
const { RULES, evaluate, tempRoots, normalizeFsPath } = mod.__internals;

const WORKSPACE = normalizeFsPath('D:\\work\\my project');
const TEMPS = tempRoots();

let pass = 0;
const failures = [];

function run({ tool, args, mode = 'workspace-write', approval = 'ask', disabled = [], strict = false }) {
  return evaluate({
    toolName: tool,
    args,
    mode,
    approvalPolicy: approval,
    workspace: WORKSPACE,
    temps: TEMPS,
    rules: RULES.map((r) => ({ ...r, strict, enabled: !disabled.includes(r.id) })),
  });
}

function check(name, expected, opts) {
  const d = run(opts);
  const got = d === null ? 'pass' : `${d.kind}:${d.ruleId}`;
  if (got === expected) pass++;
  else failures.push(`${name}\n    expected ${expected}\n    got      ${got}${d ? `\n    reason   ${d.reason.split('\n')[0]}` : ''}`);
  return d;
}

const OUT_WRITE = 'C:\\Users\\user\\.dsh\\x.txt';
const ctxOpts = (mode, approval) => ({ mode, approval });

// ============================================================ A. 实机误判回归（受限会话必须放行）
for (const [name, opts] of [
  ['引号内工作区路径 + Select-String（只读）', { tool: 'pwsh', args: { command: `Select-String -Path 'D:\\work\\my project\\backend\\src\\app.ts' -Pattern 'foo'` } }],
  ['裸路径含空格（被截断）+ 只读', { tool: 'pwsh', args: { command: `Select-String -Path D:\\work\\my project\\backend\\src\\app.ts -Pattern 'rd '` } }],
  ['裸路径含空格 + Get-ChildItem', { tool: 'pwsh', args: { command: `Get-ChildItem D:\\work\\my project\\miniprogram -Recurse` } }],
  ['工作区内写（引号）', { tool: 'pwsh', args: { command: `Set-Content 'D:\\work\\my project\\a.txt' hi` } }],
  ['工作区内写（相对路径）', { tool: 'pwsh', args: { command: `Set-Content .\\a.txt hi` } }],
  ['write 相对路径', { tool: 'write', args: { file_path: 'miniprogram/pages/index.js' } }],
  ['edit 相对路径', { tool: 'edit', args: { file_path: 'backend/src/app.ts' } }],
  ['write 工作区内绝对路径（含空格）', { tool: 'write', args: { file_path: 'D:\\work\\my project\\backend\\app.ts' } }],
  ['git status（只读）', { tool: 'pwsh', args: { command: 'git status --short' } }],
  ['pnpm build（不预先拦）', { tool: 'pwsh', args: { command: 'pnpm build' } }],
  ['read 越界（读允许）', { tool: 'read', args: { file_path: 'C:\\Users\\user\\.dsh\\settings.yaml' } }],
  ['复合命令：一段写区内 + 一段读区外', { tool: 'pwsh', args: { command: `Set-Content .\\a.txt ok; Select-String -Path 'C:\\Users\\user\\.dsh\\settings.yaml' -Pattern 'model'` } }],
  ['管道：读区外 + 写区内', { tool: 'pwsh', args: { command: `Get-Content 'C:\\Users\\user\\.dsh\\settings.yaml' | Set-Content .\\a.txt` } }],
  ['只读区外 .js（不是执行）', { tool: 'pwsh', args: { command: `Select-String -Path 'D:\\Program Files (x86)\\x\\app.js' -Pattern 'foo'` } }],
  ['引号里的动作词（数据）', { tool: 'pwsh', args: { command: `Select-String -Path 'D:\\work\\my project\\a.ts' -Pattern 'rm -rf'` } }],
]) check(name, 'pass', opts);

// ============================================================ B. 受限会话 + ask：沙箱类拦下、确认类询问
check('越界写（pwsh）', 'deny:outside-write', { tool: 'pwsh', args: { command: `Set-Content ${OUT_WRITE} hi` } });
check('越界写（write 工具）', 'deny:outside-write', { tool: 'write', args: { file_path: 'C:\\Users\\user\\.dsh\\AGENTS.md' } });
check('工作区同名前缀的另一目录', 'deny:outside-write', { tool: 'write', args: { file_path: 'D:\\work\\my\\x.ts' } });
check('.. 跳出工作区', 'deny:outside-write', { tool: 'pwsh', args: { command: `Set-Content 'D:\\work\\my project\\..\\other\\x.txt' hi` } });
check('管道写区外（Out-File）', 'deny:outside-write', { tool: 'pwsh', args: { command: `Get-Content 'C:\\a.txt' | Out-File 'C:\\Users\\user\\.dsh\\y.txt'` } });
check('段首短别名 rd', 'deny:outside-write', { tool: 'pwsh', args: { command: `rd 'D:\\outside\\somedir'` } });
check('Remove-Item 区外', 'deny:outside-write', { tool: 'pwsh', args: { command: `Remove-Item 'C:\\Users\\user\\.dsh\\x' -Recurse -Force` } });
check('启动区外 CLI', 'deny:outside-exec', { tool: 'pwsh', args: { command: `& 'D:\\Tools\\some-cli\\cli.cmd' open` } });
check('Start-Process 区外程序', 'deny:outside-exec', { tool: 'pwsh', args: { command: `Start-Process 'D:\\outside\\tool.exe'` } });
check('git push', 'deny:remote-mutation', { tool: 'pwsh', args: { command: 'git push origin main' } });
check('scp', 'deny:remote-mutation', { tool: 'pwsh', args: { command: 'scp a.txt user@host:/tmp/' } });
check('curl', 'deny:network-client', { tool: 'pwsh', args: { command: 'curl https://api.example.com/health' } });
check('git fetch', 'deny:network-client', { tool: 'pwsh', args: { command: 'git fetch origin' } });
check('npx vitest', 'deny:child-pipe', { tool: 'pwsh', args: { command: 'npx vitest run' } });
check('npm i -g', 'deny:global-install', { tool: 'pwsh', args: { command: 'npm i -g typescript' } });
check('pnpm add', 'deny:pkg-store', { tool: 'pwsh', args: { command: 'pnpm add lodash' } });
check('杀宿主进程 → ask', 'ask:host-services', { tool: 'pwsh', args: { command: 'Stop-Process -Name node -Force' } });
check('docker rm → ask', 'ask:containers', { tool: 'pwsh', args: { command: 'docker rm -f web' } });

// ============================================================ C. 受限会话 + never（审批禁用）
check('never + curl（沙箱类仍拦，理由换成审批禁用）', 'deny:network-client', { tool: 'pwsh', args: { command: 'curl https://x/y' }, ...ctxOpts('workspace-write', 'never') });
check('never + 杀进程（默认放行，尊重用户选择）', 'pass', { tool: 'pwsh', args: { command: 'Stop-Process -Name node -Force' }, ...ctxOpts('workspace-write', 'never') });
check('never + 杀进程（strict 时拦下并说明）', 'deny:host-services', { tool: 'pwsh', args: { command: 'Stop-Process -Name node -Force' }, ...ctxOpts('workspace-write', 'never'), strict: true });

// ============================================================ D. danger-full-access（本次修复重点：沙箱类一律放行）
check('full + curl → 放行（原 bug：被拦）', 'pass', { tool: 'pwsh', args: { command: 'curl https://x/y' }, ...ctxOpts('danger-full-access', 'never') });
check('full + git fetch → 放行', 'pass', { tool: 'pwsh', args: { command: 'git fetch origin' }, ...ctxOpts('danger-full-access', 'never') });
check('full + npx vitest → 放行', 'pass', { tool: 'pwsh', args: { command: 'npx vitest run' }, ...ctxOpts('danger-full-access', 'never') });
check('full + npm i -g → 放行', 'pass', { tool: 'pwsh', args: { command: 'npm i -g typescript' }, ...ctxOpts('danger-full-access', 'never') });
check('full + write 区外 → 放行', 'pass', { tool: 'write', args: { file_path: 'C:\\Users\\user\\.dsh\\AGENTS.md' }, ...ctxOpts('danger-full-access', 'never') });
check('full + 区外 CLI → 放行', 'pass', { tool: 'pwsh', args: { command: `& 'D:\\outside\\cli.cmd' open` }, ...ctxOpts('danger-full-access', 'never') });
check('full + git push + never → 放行（没人能应答就不拦）', 'pass', { tool: 'pwsh', args: { command: 'git push origin main' }, ...ctxOpts('danger-full-access', 'never') });
check('full + git push + ask → 确认', 'ask:remote-mutation', { tool: 'pwsh', args: { command: 'git push origin main' }, ...ctxOpts('danger-full-access', 'ask') });
check('full + 杀进程 + ask → 确认', 'ask:host-services', { tool: 'pwsh', args: { command: 'Stop-Process -Name node' }, ...ctxOpts('danger-full-access', 'ask') });
check('full + 杀进程 + never → 放行', 'pass', { tool: 'pwsh', args: { command: 'Stop-Process -Name node' }, ...ctxOpts('danger-full-access', 'never') });

// ============================================================ E. disabledRules / extraRules
check('disabledRules 关掉 network-client', 'pass', { tool: 'pwsh', args: { command: 'curl https://x/y' }, disabled: ['network-client'] });

// ============================================================ F. apply() 接线
function makeCtx(mode, approval) {
  const listeners = new Map();
  return {
    ctx: {
      logger: { info() {}, warn() {} },
      get(key) {
        if (key === 'sandboxPolicy') return { resolve: () => ({ mode, workspaceRoot: WORKSPACE }) };
        if (key === 'approval') return { effectivePolicy: () => approval };
        return undefined;
      },
      on(event, fn) { listeners.set(event, fn); },
    },
    listener: () => listeners.get('tools/pre-execute'),
  };
}
const execOf = (args) => ({ name: 'pwsh', arguments: args, agent: { session: { header: { cwd: WORKSPACE } } } });

{
  const { ctx, listener } = makeCtx('danger-full-access', 'never');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: 'curl https://x/y' }), () => 'NEXT');
  if (d === 'NEXT') pass++;
  else failures.push(`apply: full-access 下 curl 应放行，得到 ${JSON.stringify(d)}`);
}
{
  const { ctx, listener } = makeCtx('workspace-write', 'ask');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: `Set-Content ${OUT_WRITE} hi` }), () => 'NEXT');
  if (d !== 'NEXT' && d.kind === 'deny') pass++;
  else failures.push('apply: 受限会话越界写应 deny');
}
{
  // 全权会话 + 成对参数 → 交回给 DSH 自己判（插件不再基于自己的模式读值拦截）
  const { ctx, listener } = makeCtx('danger-full-access', 'ask');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: 'git status', sandbox_permissions: 'danger-full-access', justification: 'x' }), () => 'NEXT');
  if (d === 'NEXT') pass++;
  else failures.push(`apply: 全权会话 + 成对升权参数 应交回 DSH，得到 ${JSON.stringify(d)}`);
}
{
  // 只带 sandbox_permissions（缺 justification）→ 由 DSH 自己拒绝（invalid escalation），插件不插手
  const { ctx, listener } = makeCtx('danger-full-access', 'ask');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: 'git status', sandbox_permissions: 'danger-full-access' }), () => 'NEXT');
  if (d === 'NEXT') pass++;
  else failures.push(`apply: 全权会话 + 半个参数 应放行给 DSH 自己报错，得到 ${JSON.stringify(d)}`);
}
{
  // 受限会话 + 半个参数 → 同样交给 DSH 自己拒绝
  const { ctx, listener } = makeCtx('workspace-write', 'ask');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: 'git status', sandbox_permissions: 'danger-full-access' }), () => 'NEXT');
  if (d === 'NEXT') pass++;
  else failures.push(`apply: 受限会话 + 半个参数 应放行给 DSH 自己报错，得到 ${JSON.stringify(d)}`);
}
{
  // 受限会话 + 成对参数 → 正常升权，交给工具自己弹审批
  const { ctx, listener } = makeCtx('workspace-write', 'ask');
  mod.apply(ctx, { enabled: true });
  const d = listener()(execOf({ command: 'git status', sandbox_permissions: 'danger-full-access', justification: 'x' }), () => 'NEXT');
  if (d === 'NEXT') pass++;
  else failures.push(`apply: 受限会话 + 成对升权参数 应放行给工具审批，得到 ${JSON.stringify(d)}`);
}

// ============================================================ 结果
const lines = [
  `passed ${pass} / ${pass + failures.length}`,
  ...(failures.length === 0 ? ['ALL OK'] : ['FAILURES:', ...failures.map((f, i) => `${i + 1}. ${f}`)]),
];
process.stdout.write(lines.join('\n') + '\n');
try {
  writeFileSync(process.argv[3] ?? join(tmpdir(), 'dsh-preflight-gate-test-out.txt'), lines.join('\n'), 'utf8');
} catch {
  /* 输出文件写不了无所谓 */
}



