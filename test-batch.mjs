/**
 * preflight-gate v1.3.0 一次性授权（request_sandbox_access）测试
 * 用法：node test-batch.mjs <插件文件>
 */
import { pathToFileURL } from 'node:url';

const mod = await import(pathToFileURL(process.argv[2]).href);
const WORKSPACE = 'C:\\work\\demo';

let pass = 0;
const failures = [];
const ok = (name, cond, extra = '') => {
  if (cond) pass++;
  else failures.push(`${name}${extra ? `\n    ${extra}` : ''}`);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeHarness({ mode = 'workspace-write', approval = 'ask', outcome = 'allowed-once' } = {}) {
  const state = { mode, appended: [], requests: 0, lastReason: undefined };
  const listeners = new Map();
  let tool;
  const session = {
    id: 'session-demo',
    header: { cwd: WORKSPACE },
    append(type, data) {
      state.appended.push([type, data]);
      if (type === 'sandbox/mode') state.mode = data.mode;
    },
  };
  const ctx = {
    logger: { info() {}, warn() {} },
    tools: { register(t) { tool = t; } },
    on(event, fn) { listeners.set(event, fn); },
    get(key) {
      if (key === 'sandboxPolicy') return { resolve: () => ({ mode: state.mode, workspaceRoot: WORKSPACE }) };
      if (key === 'approval') {
        return {
          effectivePolicy: () => approval,
          request: async (req) => { state.requests++; state.lastReason = req.reason; return outcome; },
        };
      }
      return undefined;
    },
  };
  mod.apply(ctx, { enabled: true, batchApproval: true });
  return {
    state,
    session,
    agent: { session },
    pre: (args) => listeners.get('tools/pre-execute')?.({ name: 'pwsh', arguments: args, agent: { session } }, () => 'NEXT'),
    turnStopping: () => listeners.get('agent/turn-stopping')?.({ agent: { session } }),
    tool: () => tool,
  };
}

// ---------------------------------------------------------------- 1) 获批：解锁整轮 + 临时放宽 + 本轮自动恢复
{
  const h = makeHarness();
  await sleep(80);
  const tool = h.tool();
  ok('注册了 request_sandbox_access', tool?.name === 'request_sandbox_access', `得到 ${tool?.name}`);

  const before = await h.pre({ command: 'curl https://x/y' });
  ok('授权前 curl 被拦', before && before.kind === 'deny', JSON.stringify(before));

  const result = await tool.execute(
    { operations: '写 C:\\Users\\me\\.dsh\\config.json\n运行 npx vitest\ngit push origin main', why: '本轮要装插件并跑测试', scope: 'turn' },
    { agent: h.agent, callId: 'call-1' },
  );
  ok('获批文案说明已授权', /已获一次性授权/.test(result), result);
  ok('审批被请求一次', h.state.requests === 1, `requests=${h.state.requests}`);
  ok('审批理由里有清单条目', /1\) 写 C:\\Users\\me\\\.dsh\\config\.json/.test(h.state.lastReason ?? ''), h.state.lastReason);
  ok('模式切到 danger-full-access', h.state.mode === 'danger-full-access' && h.state.appended.some(([t, d]) => t === 'sandbox/mode' && d.mode === 'danger-full-access'));

  const after = await h.pre({ command: 'curl https://x/y' });
  ok('授权后 curl 放行', after === 'NEXT', JSON.stringify(after));
  const push = await h.pre({ command: 'git push origin main' });
  ok('授权后 git push 也放行', push === 'NEXT', JSON.stringify(push));

  await h.turnStopping();
  ok('本轮结束恢复 workspace-write', h.state.mode === 'workspace-write', h.state.mode);
  const rearmed = await h.pre({ command: 'curl https://x/y' });
  ok('恢复后 curl 重新被拦', rearmed && rearmed.kind === 'deny', JSON.stringify(rearmed));
}

// ---------------------------------------------------------------- 2) 被拒：不切模式、不放行、不重试
{
  const h = makeHarness({ outcome: 'rejected' });
  await sleep(80);
  const result = await h.tool().execute({ operations: 'git push', why: 'x' }, { agent: h.agent, callId: 'c' });
  ok('拒绝文案明确', /拒绝/.test(result) && /不要重试|不要执行/.test(result), result);
  ok('拒绝后不切模式', h.state.mode === 'workspace-write' && !h.state.appended.some(([t]) => t === 'sandbox/mode'));
  const d = await h.pre({ command: 'curl https://x/y' });
  ok('拒绝后仍然拦', d && d.kind === 'deny');
}

// ---------------------------------------------------------------- 3) 审批被禁用：不弹窗、说明清楚
{
  const h = makeHarness({ approval: 'never' });
  await sleep(80);
  const result = await h.tool().execute({ operations: 'git push', why: 'x' }, { agent: h.agent, callId: 'c' });
  ok('never 时不请求审批', h.state.requests === 0, `requests=${h.state.requests}`);
  ok('never 时说明无法授权', /审批被禁用/.test(result) && /无法一次授权/.test(result), result);
}

// ---------------------------------------------------------------- 4) 已是 danger-full-access：不重复切模式、无需恢复
{
  const h = makeHarness({ mode: 'danger-full-access' });
  await sleep(80);
  const result = await h.tool().execute({ operations: 'git push', why: 'x', scope: 'turn' }, { agent: h.agent, callId: 'c' });
  ok('全权会话直接说明无需切换', /本来就是/.test(result), result);
  const appends = h.state.appended.filter(([t]) => t === 'sandbox/mode').length;
  ok('全权会话不再写 sandbox/mode 事件', appends === 0, `appends=${appends}`);
  await h.turnStopping();
  ok('全权会话本轮结束不回退', h.state.mode === 'danger-full-access');
}

// ---------------------------------------------------------------- 5) session 范围：本轮结束不收回
{
  const h = makeHarness();
  await sleep(80);
  await h.tool().execute({ operations: 'git push', why: 'x', scope: 'session' }, { agent: h.agent, callId: 'c' });
  await h.turnStopping();
  ok('session 范围跨轮保持', h.state.mode === 'danger-full-access', h.state.mode);
  const d = await h.pre({ command: 'curl https://x/y' });
  ok('session 范围下一轮仍放行', d === 'NEXT', JSON.stringify(d));
}

// ---------------------------------------------------------------- 6) 清单渲染
{
  const text = mod.__internals.formatPlan('1. 写 A\n- 跑 B\n\nC', '因为有活', 'turn');
  ok('清单去掉了序号与项目符号', /1\) 写 A/.test(text) && /2\) 跑 B/.test(text) && /3\) C/.test(text), text);
  ok('清单说明本轮自动恢复', /本轮结束后自动恢复/.test(text), text);
}

const lines = [
  `passed ${pass} / ${pass + failures.length}`,
  ...(failures.length === 0 ? ['ALL OK'] : ['FAILURES:', ...failures.map((f, i) => `${i + 1}. ${f}`)]),
];
process.stdout.write(lines.join('\n') + '\n');

