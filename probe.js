// 分层探测：每层独立超时、独立结果，供 main.js 调用，也可用 node 单独测试。
// 不依赖 electron，便于 node tools/probe-test.js 直接验证。
const net = require('net');
const http = require('http');
const https = require('https');
const { execFile } = require('child_process');

const DEFAULTS = {
  icmpTimeout: 1500,
  tcpTimeout: 2000,
  httpTimeout: 5000,
  ztTimeout: 2000,
  ztExe: 'C:\\ProgramData\\ZeroTier\\One\\zerotier-one_x64.exe',
  ztPeer: '7a4a08c762',
  routePrefix: '192.168.100.0',
};

function sh(exe, args, timeout) {
  return new Promise((resolve) => {
    execFile(exe, args, { timeout, windowsHide: true, encoding: 'buffer' }, (err, out) => {
      resolve({ err, out: out ? out.toString('utf8') : '' });
    });
  });
}

// ---------- L2a：ICMP ----------
async function probeIcmp(host, timeout) {
  const t0 = Date.now();
  const { err, out } = await sh('ping', ['-n', '1', '-w', String(timeout), host], timeout + 2000);
  const ok = !err && /TTL=\d+/i.test(out);
  const m = out.match(/[=<]\s*(\d+)\s*ms/i) || out.match(/time[=<](\d+)ms/i);
  return {
    ok,
    ms: Date.now() - t0,
    rtt: m ? Number(m[1]) : null,
    err: ok ? '' : (/无法访问目标主机|Destination host unreachable/i.test(out) ? '主机不可达'
      : /请求超时|Request timed out/i.test(out) ? 'ICMP 超时'
        : (err && err.killed) ? 'ICMP 超时' : 'ICMP 失败'),
  };
}

// ---------- L2b：TCP 端口 ----------
function probeTcp(host, port, timeout) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let sock;
    const fin = (ok, code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { if (sock) sock.destroy(); } catch (_) {}
      resolve({ ok, ms: Date.now() - t0, err: ok ? '' : (code || '连接失败') });
    };
    const timer = setTimeout(() => fin(false, 'TIMEOUT'), timeout);
    try { sock = net.connect({ host, port }); } catch (e) { fin(false, e.code || e.message); return; }
    sock.once('connect', () => fin(true));
    sock.once('error', (e) => fin(false, e.code || e.message));
  });
}

// ---------- L2c：路由快照 ----------
async function probeRoute(prefix) {
  const { err, out } = await sh('route', ['print', '-4'], 4000);
  if (err) return { ok: false, err: 'route 查询失败' };
  const rows = out.split(/\r?\n/).filter((l) => l.includes(prefix));
  const row = rows.find((l) => /^\s*\d+\.\d+\.\d+\.\d+\s/.test(l));
  if (!row) return { ok: false, err: '无 ' + prefix + ' 路由' };
  const f = row.trim().split(/\s+/);
  return { ok: true, iface: f[3], nexthop: f[2], metric: f[4] || '', err: '' };
}

// ---------- L3：HTTP ----------
function probeHttp(url, timeout, headers) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    let done = false;
    const fin = (o) => { if (!done) { done = true; resolve(Object.assign({ ms: Date.now() - t0 }, o)); } };
    const req = mod.request(u, { method: 'GET', headers: headers || {}, timeout }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        let models = [];
        try { models = (JSON.parse(body).data || []).map((m) => m.id); } catch (_) {}
        fin({ ok: res.statusCode >= 200 && res.statusCode < 300, http: res.statusCode, err: res.statusCode >= 200 && res.statusCode < 300 ? '' : 'HTTP ' + res.statusCode, models });
      });
    });
    req.on('timeout', () => { req.destroy(); fin({ ok: false, http: 0, err: 'HTTP_TIMEOUT' }); });
    req.on('error', (e) => fin({ ok: false, http: 0, err: e.code || e.message }));
    req.end();
  });
}

// ---------- L1：ZeroTier ----------
async function probeZt(o) {
  const svc = await sh('sc', ['query', 'ZeroTierOneService'], 3000);
  if (!/RUNNING/i.test(svc.out)) return { ok: false, state: 'service-down', latency: null, detail: 'ZeroTier 服务未运行' };
  const { err, out } = await sh(o.ztExe, ['-q', '-j', 'listpeers'], o.ztTimeout);
  if (err) {
    const msg = (err.message || '') + (out || '');
    if (/authtoken\.secret not found or readable/i.test(msg)) return { ok: false, state: 'no-token', latency: null, detail: 'authtoken.secret 不可读（需 SYSTEM/提权）' };
    if (/timed? ?out/i.test(msg)) return { ok: false, state: 'query-timeout', latency: null, detail: 'listpeers 超时' };
    return { ok: false, state: 'query-error', latency: null, detail: msg.split('\n')[0].slice(0, 120) };
  }
  try {
    const peers = JSON.parse(out);
    const p = peers.find((x) => x.address === o.ztPeer);
    if (!p) return { ok: false, state: 'peer-missing', latency: null, detail: '网关 peer ' + o.ztPeer + ' 不在 peers 列表' };
    const act = (p.paths || []).filter((x) => x.active);
    const latency = p.latency > 0 ? p.latency : null;
    if (!p.tunneled && act.length) return { ok: true, state: 'direct', latency, path: act[0].address, detail: 'P2P 直连' };
    return { ok: true, state: 'relay', latency, path: 'relay', detail: p.tunneled ? 'TCP 隧道中继' : 'UDP 中继' };
  } catch (e) {
    return { ok: false, state: 'parse-error', latency: null, detail: '解析失败' };
  }
}

// ---------- 判定 ----------
function verdictOf(r) {
  if (r.l3.skipped) return r.l2.tcp.ok ? 'ok' : verdictOfL2(r);
  if (r.l3.ok) return 'ok';
  if (r.l3.http === 401 || r.l3.http === 403) return 'auth';
  if (r.l2.tcp.ok) return 'api-hang';
  return verdictOfL2(r);
}

function verdictOfL2(r) {
  // 只填 IP（无端口）时，TCP 层没有意义，用 ICMP + 路由判主机是否可达
  if (r.l2.tcp.skipped) {
    if (r.l2.icmp.ok) return 'ok';
    if (!r.l2.route.ok) return 'local-network';
    return r.l1.state === 'peer-missing' ? 'zt-peer-down' : 'path-down';
  }
  if (r.l2.tcp.err === 'ECONNREFUSED') return 'port-closed';
  const tcpTimeout = r.l2.tcp.err === 'TIMEOUT' || r.l2.tcp.err === 'ETIMEDOUT';
  if (r.l2.tcp.ok) return 'ok';
  if (tcpTimeout && r.l2.icmp.ok) return 'tcp-filtered';
  if (tcpTimeout && !r.l2.icmp.ok && !r.l2.route.ok) return 'local-network';
  if (tcpTimeout && !r.l2.icmp.ok) return r.l1.state === 'peer-missing' ? 'zt-peer-down' : 'path-down';
  return 'unknown';
}

async function probeAll(opts) {
  const o = Object.assign({}, DEFAULTS, opts || {});
  const t0 = Date.now();
  const hostPort = o.hostPort;
  const [l1, icmp0, route] = await Promise.all([
    probeZt(o),
    probeIcmp(hostPort.host, o.icmpTimeout),
    probeRoute(o.routePrefix),
  ]);
  // ICMP 常被目标限速（实测约 1/10 丢），失败时补测一次，避免把限速报成断线
  let icmp = icmp0;
  if (!icmp0.ok) {
    const retry = await probeIcmp(hostPort.host, o.icmpTimeout);
    if (retry.ok) { retry.retried = true; icmp = retry; }
  }
  const tcp = hostPort.port
    ? await probeTcp(hostPort.host, hostPort.port, o.tcpTimeout)
    : { skipped: true, ok: false, ms: 0, err: 'SKIPPED(未指定端口)' };
  const httpRes = !o.apiUrl
    ? { skipped: true, ok: true, http: 0, ms: 0, err: '', models: [] }
    : tcp.ok
      ? await probeHttp(o.apiUrl.replace(/\/+$/, '') + '/models', o.httpTimeout, o.headers)
      : { skipped: true, ok: false, http: 0, ms: 0, err: 'SKIPPED(L2 不通)', models: [] };
  const r = {
    ts: Date.now(),
    total_ms: Date.now() - t0,
    l1,
    l2: { icmp, tcp, route },
    l3: httpRes,
    target: hostPort,
  };
  r.verdict = verdictOf(r);
  return r;
}

module.exports = { probeAll, probeIcmp, probeTcp, probeHttp, probeRoute, probeZt, verdictOf, DEFAULTS };
