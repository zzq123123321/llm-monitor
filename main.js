const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, net, screen, shell, globalShortcut } = require('electron');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const { execFile } = require('child_process');
const nodeNet = require('net');
const probe = require('./probe');

function dataRoot() {
  return app.isPackaged ? app.getPath('userData') : __dirname;
}
function getConfigFile() { return path.join(dataRoot(), 'config.json'); }
function getLogDir()     { return path.join(dataRoot(), 'data'); }
function getDbgFile()    { return path.join(dataRoot(), 'debug.log'); }

function loadConfig() {
  try {
    const c = JSON.parse(fs.readFileSync(getConfigFile(), 'utf8').replace(/^\uFEFF/, ''));
    if (c && typeof c.apiBase === 'string' && c.apiBase) return c;
  } catch (_) {}
  return {};
}
function saveConfig(patch) {
  try {
    fs.writeFileSync(getConfigFile(), JSON.stringify(Object.assign(loadConfig(), patch), null, 2));
  } catch (e) { dbg('saveConfig: ' + e.message); }
}
// 优先级：config.json（界面里保存的） > 环境变量 LLM_API_BASE > 默认
let API = process.env.LLM_API_BASE || 'http://192.168.100.190:8080/v1';
let API_KEY = process.env.LLM_API_KEY || '';
{
  const c = loadConfig();
  if (c.apiBase) API = c.apiBase;
  if (c.apiKey) API_KEY = c.apiKey;
}
const POLL_MS = 5000;
// 分层探测：每层独立超时，互不掩盖
const ICMP_TIMEOUT = 1500;  // L2a ICMP
const L2_TIMEOUT = 2000;    // L2b TCP 端口
const L3_TIMEOUT = 5000;    // L3 HTTP
const L1_TIMEOUT = 2000;    // L1 ZeroTier 查询
const HISTORY_MAX = 240;

// ZeroTier 打洞监测：4090 网段 192.168.100.0/24 经 ZT 成员 192.168.191.236 路由，
// 该网关节点 ID 为 7a4a08c762（2026-09-10 流量关联法确认）。
const ZT_EXE = 'C:\\ProgramData\\ZeroTier\\One\\zerotier-one_x64.exe';
const ZT_PEER = '7a4a08c762';
const ZT_POLL_MS = 15000;
const LOG_KEEP_DAYS = 14;

function dbg(msg) {
  try { fs.appendFileSync(getDbgFile(), new Date().toISOString() + ' ' + msg + '\n'); } catch (_) {}
}

let win = null;
let tray = null;
let isQuiting = false;
let pinned = true;
let collapsed = false;
const FULL_H = 560;
// 收缩高度 196：实测收缩态内容自然高度 194px（2026-09-11），+2px 余量；
// 196 在 100/125/150/175% 缩放下均为整数物理像素，避免底边框被 DPI 舍入挤掉
const COMPACT_H = 196;
const history = [];
let lastModels = [];

// ---------- 持久化日志：只记录断连/异常，中文可读 ----------
// data/monitor-YYYYMMDD.log：每行 [YYYY-MM-DD HH:mm:ss] 事件描述
const ST_CN = { online: '在线', degraded: '异常', offline: '离线', checking: '检测中', auth: '在线·未授权' };
const ZT_CN = {
  direct: '直连', relay: '经中继', offline: '对端离线', checking: '检测中', unknown: '查询失败',
  'no-token': 'token 不可读', 'service-down': '服务未运行', 'query-timeout': '查询超时', 'query-error': '查询异常',
};

function pad2(n) { return String(n).padStart(2, '0'); }
function ymdOf(ts) {
  const d = new Date(ts || Date.now());
  return '' + d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate());
}
function stampOf(ts) {
  const d = new Date(ts || Date.now());
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function appendLog(msg, ts) {
  try {
    if (!fs.existsSync(getLogDir())) fs.mkdirSync(getLogDir());
    fs.appendFileSync(path.join(getLogDir(), 'monitor-' + ymdOf(ts) + '.log'), '[' + stampOf(ts) + '] ' + msg + '\n');
  } catch (e) { dbg('appendLog: ' + e.message); }
}

function ztDesc() {
  return (ZT_CN[ztState.status] || ztState.status) + (ztState.latency ? '（' + ztState.latency + 'ms）' : '');
}

function pruneLogs() {
  try {
    if (!fs.existsSync(getLogDir())) fs.mkdirSync(getLogDir());
    const cutoff = Date.now() - LOG_KEEP_DAYS * 86400000;
    for (const f of fs.readdirSync(getLogDir())) {
      if (!f.endsWith('.log')) continue;
      const p = path.join(getLogDir(), f);
      if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
    }
  } catch (e) { dbg('pruneLogs: ' + e.message); }
}

// ---------- 托盘图标：纯代码生成 32x32 PNG 圆点（随状态变色） ----------
function crc32(buf) {
  if (!crc32.table) {
    crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crc32.table[n] = c;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crc32.table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
}

function makeDotPng(rgb) {
  const W = 32, H = 32, cx = 15.5, cy = 15.5, R = 10;
  const raw = Buffer.alloc(H * (1 + W * 4));
  for (let y = 0; y < H; y++) {
    const off = y * (1 + W * 4);
    raw[off] = 0;
    for (let x = 0; x < W; x++) {
      const d = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
      let a = 0;
      if (d <= R) a = 255;
      else if (d <= R + 1.5) a = Math.round(255 * (1 - (d - R) / 1.5));
      const o = off + 1 + x * 4;
      raw[o] = rgb[0]; raw[o + 1] = rgb[1]; raw[o + 2] = rgb[2]; raw[o + 3] = a;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([sig, pngChunk('IHDR', ihdr), pngChunk('IDAT', zlib.deflateSync(raw)), pngChunk('IEND', Buffer.alloc(0))]);
}

const DOT_COLORS = {
  online: [52, 211, 153],
  degraded: [251, 191, 36],
  offline: [248, 113, 113],
  checking: [96, 165, 250],
  auth: [251, 191, 36],
};

function dotImage(status) {
  return nativeImage.createFromBuffer(makeDotPng(DOT_COLORS[status] || DOT_COLORS.checking));
}

function classify(checks) {
  if (!checks.length) return 'checking';
  const last0 = checks[checks.length - 1];
  if (last0 && last0.auth) return 'auth';
  if (checks.slice(-3).every((c) => !c.ok)) return 'offline';
  const fails = checks.slice(-10).filter((c) => !c.ok).length;
  const last = checks[checks.length - 1];
  if (!last.ok || fails > 2) return 'degraded';
  return 'online';
}

// ---------- 单次连通性检测：分层探测（L1 ZeroTier / L2 路由+ICMP+TCP / L3 HTTP） ----------

const TCP_ERR_CN = {
  TIMEOUT: 'TCP 超时', ETIMEDOUT: 'TCP 超时', ECONNREFUSED: '端口未监听',
  EHOSTUNREACH: '主机不可达', ENETUNREACH: '网络不可达', ECONNRESET: '连接被重置',
};
const VERDICT_CN = {
  ok: '正常',
  auth: '服务在·鉴权失败',
  'port-closed': '端口未监听',
  'tcp-filtered': 'ICMP 通·TCP 被拦',
  'local-network': '本机网络/路由异常',
  'zt-peer-down': 'ZeroTier 对端离线',
  'path-down': '路径不通',
  'api-hang': '端口通·HTTP 无响应',
  unknown: '原因不明',
};

function targetOf(api) {
  if (/^https?:\/\//i.test(api)) {
    try {
      const u = new URL(api);
      const host = u.hostname.replace(/^\[/, '').replace(/\]$/, '');
      const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
      return { host, port, apiUrl: api, mode: 'api' };
    } catch (_) { return null; }
  }
  const m = api.match(/^\[([^\]]+)\]:(\d+)$/) || api.match(/^([^\s\]:]+):(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]), apiUrl: '', mode: 'tcp' };
  // 只填主机/IP（无端口）：只做 L1 + 路由 + ICMP，不测端口
  const h = api.match(/^\[([^\]]+)\]$/) || api.match(/^([A-Za-z0-9._-]+)$/);
  if (h) return { host: h[1], port: 0, apiUrl: '', mode: 'icmp' };
  return null;
}

async function checkOnce() {
  const t = targetOf(API);
  if (!t) return { ts: Date.now(), ms: 0, ok: false, http: 0, err: '无法识别的地址', models: [], mode: 'api', layers: null };
  const r = await probe.probeAll({
    apiUrl: t.apiUrl,
    hostPort: { host: t.host, port: t.port },
    icmpTimeout: ICMP_TIMEOUT,
    tcpTimeout: L2_TIMEOUT,
    httpTimeout: L3_TIMEOUT,
    ztTimeout: L1_TIMEOUT,
    routePrefix: '192.168.100.0',
    headers: API_KEY ? { Authorization: 'Bearer ' + API_KEY } : {},
  });
  const tcpOk = r.l2.tcp.ok;
  const icmpOnly = t.mode === 'icmp';
  const ok = t.mode === 'api' ? r.l3.ok : icmpOnly ? r.l2.icmp.ok : tcpOk;
  const auth = r.verdict === 'auth';
  const ms = t.mode === 'api' ? (r.l3.ms || r.l2.tcp.ms) : icmpOnly ? (r.l2.icmp.rtt || 0) : r.l2.tcp.ms;
  let err = '';
  if (!ok) {
    if (icmpOnly) err = 'ICMP 不通（仅测 IP 可达性）';
    else if (t.mode === 'api' && tcpOk) err = r.l3.err === 'HTTP_TIMEOUT' ? 'HTTP 无响应' : r.l3.err;
    else err = TCP_ERR_CN[r.l2.tcp.err] || r.l2.tcp.err || '连接失败';
  }
  return {
    ts: r.ts, ms: ms || 0, ok, auth, http: r.l3.http || (tcpOk ? 200 : 0), err,
    models: r.l3.models || [], mode: t.mode,
    layers: { zt: r.l1, icmp: r.l2.icmp, route: r.l2.route, tcp: r.l2.tcp, http: r.l3, verdict: r.verdict },
  };
}

function trimHistory() {
  while (history.length > HISTORY_MAX) history.shift();
}

function pushState() {
  if (!win || win.isDestroyed()) return;
  const last = history.length ? history[history.length - 1] : null;
  win.webContents.send('state', {
    checks: history.slice(), models: lastModels, zt: ztState, apiBase: API, collapsed,
    hasKey: !!API_KEY,
    layers: last ? last.layers : null,
    verdict: last && last.layers ? last.layers.verdict : '',
  });
}

function updateTrayStatus() {
  if (!tray) return;
  const st = classify(history);
  const ztTip = {
    direct: '打洞成功',
    relay: '经中继',
    offline: '对端离线',
    checking: '打洞检测中',
    unknown: '打洞查询失败',
  }[ztState.status] || '打洞未知';
  const tip = ({
    online: 'LLM Monitor · 在线',
    degraded: 'LLM Monitor · 异常（近期存在失败）',
    offline: 'LLM Monitor · 离线',
    checking: 'LLM Monitor · 检测中',
    auth: 'LLM Monitor · 在线但未授权',
  }[st]) + ' | ' + ztTip;
  tray.setImage(dotImage(st));
  tray.setToolTip(tip);
}

async function pollLoop() {
  let first = true;
  let prevSt = null;
  while (!isQuiting) {
    const t0 = Date.now();
    const r = await checkOnce();
    if (first) { dbg('first check: ' + JSON.stringify(r)); first = false; }
    history.push(r);
    trimHistory();
    if (r.ok && r.models.length) lastModels = r.models;
    pushState();
    updateTrayStatus();
    const L = r.layers;
    syncZt(L);
    if (!r.ok) {
      const now = Date.now();
      const v = L ? L.verdict : 'unknown';
      if (v !== lastFailVerdict || now - lastFailLogAt > 60000) {
        appendLog('失败：' + (r.err || 'HTTP ' + r.http) + '（' + r.ms + 'ms）｜' + layerText(L), r.ts);
        lastFailVerdict = v;
        lastFailLogAt = now;
      }
    } else {
      lastFailVerdict = '';
    }
    const st = classify(history);
    if (prevSt && st !== prevSt) {
      appendLog('目标状态变化：' + ST_CN[prevSt] + ' → ' + ST_CN[st] + (st === 'online' ? '（已恢复）' : ''));
      dbg('api state change ' + prevSt + ' -> ' + st);
    }
    prevSt = st;
    await new Promise((res) => setTimeout(res, Math.max(500, POLL_MS - (Date.now() - t0))));
  }
}

function layerText(L) {
  if (!L) return '（无分层数据）';
  const short = (s) => String(s || '').replace(/^(ICMP|TCP|HTTP)\s+/, '');
  const tcp = L.tcp.skipped ? '跳过' : L.tcp.ok ? L.tcp.ms + 'ms' : short(TCP_ERR_CN[L.tcp.err] || L.tcp.err || '失败');
  const icmp = L.icmp.ok ? (L.icmp.rtt != null ? L.icmp.rtt + 'ms' : '通') : short(L.icmp.err || '失败');
  const http = L.http.skipped ? '跳过' : (L.http.ok ? L.http.http + ' ' + L.http.ms + 'ms'
    : (L.http.http ? String(L.http.http) : (L.http.err === 'HTTP_TIMEOUT' ? '无响应' : short(L.http.err || '失败'))));
  return '判定=' + (VERDICT_CN[L.verdict] || L.verdict)
    + '｜L1 ' + (L.zt.state || '?') + (L.zt.latency ? ' ' + L.zt.latency + 'ms' : '')
    + '｜路由 ' + (L.route.ok ? L.route.nexthop : '无')
    + '｜ICMP ' + icmp
    + '｜TCP ' + tcp
    + '｜HTTP ' + http;
}

let lastFailLogAt = 0;
let lastFailVerdict = '';
let ztState = { status: 'checking', latency: null, path: '', detail: '' };

const ZT_MAP = {
  direct: 'direct', relay: 'relay', 'peer-missing': 'offline',
  'no-token': 'no-token', 'service-down': 'service-down',
  'query-timeout': 'query-timeout', 'query-error': 'query-error',
};

function syncZt(L) {
  if (!L || !L.zt) return;
  const z = L.zt;
  const prev = ztState.status;
  ztState = {
    status: ZT_MAP[z.state] || 'unknown',
    latency: z.latency || null,
    path: z.path || '',
    detail: z.detail || '',
  };
  if (ztState.status !== prev) {
    appendLog('打洞状态变化：' + (ZT_CN[prev] || prev) + ' → ' + (ZT_CN[ztState.status] || ztState.status)
      + (ztState.detail ? '（' + ztState.detail + '）' : ''));
    dbg('zt state change ' + prev + ' -> ' + ztState.status + ' ' + ztState.detail);
  }
}

// ---------- 窗口 ----------
function createWindow() {
  const wa = screen.getPrimaryDisplay().workArea;
  win = new BrowserWindow({
    width: 360,
    height: FULL_H,
    x: wa.x + wa.width - 380,
    y: wa.y + 16,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    resizable: false,
    skipTaskbar: true,
    show: false,
    hasShadow: false,
    backgroundColor: '#00000000',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.setAlwaysOnTop(pinned, 'screen-saver');
  win.loadFile('index.html');
  win.once('ready-to-show', () => {
    win.show();
    setShownOnAllDesktops();
    dbg('ready-to-show isVisible=' + win.isVisible() + ' bounds=' + JSON.stringify(win.getBounds())
      + ' displays=' + JSON.stringify(screen.getAllDisplays().map((d) => d.bounds)));
    setTimeout(() => {
      dbg('t+3s isVisible=' + win.isVisible() + ' bounds=' + JSON.stringify(win.getBounds()));
      win.show();
      win.focus();
      win.setAlwaysOnTop(true, 'screen-saver');
      setShownOnAllDesktops();
    }, 3000);
  });
  win.webContents.on('console-message', (e, level, message) => dbg('renderer[' + level + '] ' + message));
  win.webContents.on('did-fail-load', (e, code, desc) => dbg('did-fail-load code=' + code + ' ' + desc));
  win.on('closed', () => {
    win = null;
    if (!isQuiting) app.quit();
  });
}

// ---------- 跨虚拟桌面显示（Win11 22H2+；Win10 上静默无效） ----------
function setShownOnAllDesktops() {
  if (process.platform !== 'win32' || !win || win.isDestroyed()) return;
  try {
    const h = '0x' + win.getNativeWindowHandle().readBigUInt64LE().toString(16).padStart(16, '0');
    const ps = 'Add-Type -Namespace W -Name N -MemberDefinition \'[DllImport("user32.dll")] public static extern int SetWindowDisplayAffinity(IntPtr hWnd, int dwAffinity);\'; [W.N]::SetWindowDisplayAffinity([IntPtr]' + h + ', 4)';
    execFile('powershell.exe', ['-NoProfile', '-Command', ps], { timeout: 5000 }, (e, out, err) => {
      dbg('SetWindowDisplayAffinity: ' + (e ? (err || e.message) : 'ok'));
    });
  } catch (e) { dbg('SetWindowDisplayAffinity err ' + e.message); }
}

function toggleWindowVisible() {
  if (!win || win.isDestroyed()) return;
  if (win.isVisible()) win.hide();
  else {
    win.show();
    win.setAlwaysOnTop(true, 'screen-saver');
    setShownOnAllDesktops();
  }
}

function quitApp() {
  isQuiting = true;
  if (tray) { tray.destroy(); tray = null; }
  if (win) win.destroy();
  app.quit();
}

// ---------- 托盘 ----------
function createTray() {
  tray = new Tray(dotImage('checking'));
  const menu = Menu.buildFromTemplate([
    { label: '显示 / 隐藏窗口', click: toggleWindowVisible },
    {
      label: '窗口置顶',
      type: 'checkbox',
      checked: pinned,
      click: (item) => {
        pinned = item.checked;
        if (win) win.setAlwaysOnTop(pinned, 'screen-saver');
      },
    },
    { type: 'separator' },
    { label: '退出', click: quitApp },
  ]);
  tray.setContextMenu(menu);
  tray.setToolTip('LLM Monitor · 检测中');
  tray.on('double-click', toggleWindowVisible);
}

// ---------- IPC ----------
ipcMain.handle('toggle-pin', () => {
  pinned = !pinned;
  if (win) win.setAlwaysOnTop(pinned, 'screen-saver');
  return pinned;
});

function toggleCollapse() {
  if (!win || win.isDestroyed()) return collapsed;
  collapsed = !collapsed;
  // 注意：resizable:false 的透明窗口上 setSize 无效，必须用 setContentSize
  win.setContentSize(360, collapsed ? COMPACT_H : FULL_H);
  dbg('collapse -> ' + collapsed + ' bounds=' + JSON.stringify(win.getBounds()));
  pushState();
  return collapsed;
}

ipcMain.handle('toggle-collapse', () => toggleCollapse());

ipcMain.on('hide', () => { if (win) win.hide(); });
ipcMain.on('close', quitApp);

ipcMain.handle('get-config', () => ({ apiBase: API }));

ipcMain.handle('set-config', async (_e, url) => {
  const u = String(url || '').trim().replace(/\/+$/, '');
  const isUrl = /^https?:\/\/.+/i.test(u);
  const isTcp = /^\[[^\]]+\]:\d+$/.test(u) || /^[^\s\]:]+:\d+$/.test(u);
  const isHost = /^\[[^\]]+\]$/.test(u) || /^[A-Za-z0-9._-]+$/.test(u);
  if (!isUrl && !isTcp && !isHost) return { ok: false, err: '格式：http(s)://主机:端口/v1、主机:端口，或只填主机/IP（仅测可达性）' };
  if (isTcp) {
    const port = Number(u.match(/:(\d+)$/)[1]);
    if (port < 1 || port > 65535) return { ok: false, err: '端口需在 1–65535 之间' };
  }
  const prev = API;
  API = u;
  saveConfig({ apiBase: u });
  appendLog('监测目标：' + prev + ' → ' + u);
  dbg('api base changed: ' + prev + ' -> ' + u);
  // 新地址立即复测一次，界面马上反馈
  const r = await checkOnce();
  history.push(r);
  trimHistory();
  if (r.ok && r.models.length) lastModels = r.models;
  pushState();
  updateTrayStatus();
  if (!r.ok) appendLog('新目标首测失败：' + (r.err || 'HTTP ' + r.http) + '（' + u + '）', r.ts);
  return { ok: true, apiBase: API };
});

// 保存 API Key（写进 config.json，界面不显示明文）
ipcMain.handle('set-key', async (_e, key) => {
  const k = String(key || '').trim();
  API_KEY = k;
  saveConfig({ apiKey: k });
  appendLog('API Key ' + (k ? '已更新（' + k.length + ' 字符）' : '已清除'));
  dbg('api key updated, len=' + k.length);
  const r = await checkOnce();
  history.push(r);
  trimHistory();
  if (r.ok && r.models.length) lastModels = r.models;
  pushState();
  updateTrayStatus();
  appendLog('更新 Key 后首测：' + (r.ok ? '通过 HTTP ' + r.http : (r.err || 'HTTP ' + r.http)), r.ts);
  return { ok: true, hasKey: !!API_KEY, testOk: r.ok, http: r.http };
});

// 打开日志：优先打开今天的记录文件；没有则打开日志目录
ipcMain.on('open-logs', () => {
  try {
    if (!fs.existsSync(getLogDir())) fs.mkdirSync(getLogDir());
    const today = path.join(getLogDir(), 'monitor-' + ymdOf() + '.log');
    if (fs.existsSync(today)) shell.openPath(today);
    else shell.openPath(getLogDir());
  } catch (e) { dbg('open-logs: ' + e.message); }
});

// ---------- 启动 ----------
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', toggleWindowVisible);
  app.whenReady().then(() => {
    pruneLogs();
    createWindow();
    createTray();
    pollLoop();
    globalShortcut.register('CommandOrControl+Shift+M', () => {
      if (!win || win.isDestroyed()) return;
      win.show();
      win.setAlwaysOnTop(true, 'screen-saver');
      setShownOnAllDesktops();
      dbg('forced show isVisible=' + win.isVisible() + ' bounds=' + JSON.stringify(win.getBounds()));
    });
    // 全局快捷键：Ctrl+Shift+C 收缩 / 展开
    globalShortcut.register('CommandOrControl+Shift+C', () => { if (win) toggleCollapse(); });
  });
}
app.on('will-quit', () => { isQuiting = true; });
app.on('window-all-closed', () => {
  if (!tray) app.quit();
});