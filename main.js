const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, net, screen, shell, globalShortcut } = require('electron');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const { execFile } = require('child_process');
const nodeNet = require('net');

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
function saveConfig(apiBase) {
  try {
    fs.writeFileSync(getConfigFile(), JSON.stringify(Object.assign(loadConfig(), { apiBase }), null, 2));
  } catch (e) { dbg('saveConfig: ' + e.message); }
}
// 优先级：config.json（界面里保存的） > 环境变量 LLM_API_BASE > 默认
let API = process.env.LLM_API_BASE || 'http://192.168.100.190:8080/v1';
{
  const c = loadConfig();
  if (c.apiBase) API = c.apiBase;
}
const POLL_MS = 5000;
const CHECK_TIMEOUT = 5000;
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
const ST_CN = { online: '在线', degraded: '异常', offline: '离线', checking: '检测中' };
const ZT_CN = { direct: '直连', relay: '经中继', offline: '对端离线', checking: '检测中', unknown: '查询失败' };

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
};

function dotImage(status) {
  return nativeImage.createFromBuffer(makeDotPng(DOT_COLORS[status] || DOT_COLORS.checking));
}

function classify(checks) {
  if (!checks.length) return 'checking';
  if (checks.slice(-3).every((c) => !c.ok)) return 'offline';
  const fails = checks.slice(-10).filter((c) => !c.ok).length;
  const last = checks[checks.length - 1];
  if (!last.ok || fails > 2) return 'degraded';
  return 'online';
}

// ---------- 单次连通性检测：GET /v1/models ----------
function errMsg(e) {
  if (e && e.name === 'AbortError') return '超时';
  const code = (e && e.cause && e.cause.code) || '';
  if (code === 'ECONNREFUSED') return '连接被拒绝 (ECONNREFUSED)';
  if (code === 'ETIMEDOUT') return '连接超时 (ETIMEDOUT)';
  if (code === 'ECONNRESET') return '连接被重置 (ECONNRESET)';
  const m = (e && e.message) || '';
  return m.replace('net::', '') || '连接失败';
}

// ---------- 目标识别：http(s) URL → API 模式；host:port → TCP 模式 ----------
function parseTarget() {
  if (/^https?:\/\//i.test(API)) return { type: 'api' };
  const m6 = API.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m6) return { type: 'tcp', host: m6[1], port: Number(m6[2]) };
  const m = API.match(/^([^\s\]:]+):(\d+)$/);
  if (m) return { type: 'tcp', host: m[1], port: Number(m[2]) };
  return { type: 'invalid', err: '无法识别的地址：http(s)://… 或 主机:端口（IPv6 用 [地址]:端口）' };
}

// ---------- 单次 TCP 连接探测（IPv4/主机名/IPv6 均可） ----------
function tcpCheck(host, port) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let sock;
    const timer = setTimeout(() => fin(false, '连接超时（' + CHECK_TIMEOUT + 'ms）'), CHECK_TIMEOUT);
    function fin(ok, err) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { if (sock) sock.destroy(); } catch (_) {}
      resolve(ok
        ? { ts: Date.now(), ms: Date.now() - t0, ok: true, http: 200, err: '', models: [], mode: 'tcp' }
        : { ts: Date.now(), ms: Date.now() - t0, ok: false, http: 0, err: err || '连接失败', models: [], mode: 'tcp' });
    }
    try { sock = nodeNet.connect({ host, port }); } catch (e) { fin(false, e.message); return; }
    sock.once('connect', () => fin(true));
    sock.once('error', (e) => fin(false,
      e.code === 'ECONNREFUSED' ? '连接被拒绝 (ECONNREFUSED)'
        : e.code === 'ENETUNREACH' ? '网络不可达 (ENETUNREACH)'
        : e.code === 'EHOSTUNREACH' ? '主机不可达 (EHOSTUNREACH)'
        : (e.code || e.message || '连接失败')));
  });
}

async function checkOnce() {
  const t = parseTarget();
  if (t.type === 'tcp') return tcpCheck(t.host, t.port);
  if (t.type === 'invalid') return { ts: Date.now(), ms: 0, ok: false, http: 0, err: t.err, models: [], mode: 'api' };
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CHECK_TIMEOUT);
  try {
    const res = await net.fetch(API + '/models', { signal: ctrl.signal });
    clearTimeout(timer);
    const ms = Date.now() - t0;
    if (!res.ok) return { ts: Date.now(), ms, ok: false, http: res.status, err: 'HTTP ' + res.status, models: [], mode: 'api' };
    let models = [];
    try {
      const j = await res.json();
      models = (j.data || []).map((m) => m.id);
    } catch (_) { /* 模型列表解析失败不影响连通判定 */ }
    return { ts: Date.now(), ms, ok: true, http: res.status, models, mode: 'api' };
  } catch (e) {
    clearTimeout(timer);
    return { ts: Date.now(), ms: Date.now() - t0, ok: false, http: 0, err: errMsg(e), models: [], mode: 'api' };
  }
}

function trimHistory() {
  while (history.length > HISTORY_MAX) history.shift();
}

function pushState() {
  if (!win || win.isDestroyed()) return;
  win.webContents.send('state', { checks: history.slice(), models: lastModels, zt: ztState, apiBase: API, collapsed });
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
    if (!r.ok) {
      appendLog((r.mode === 'tcp' ? 'TCP 断连' : 'API 断连') + '：' + (r.err || 'HTTP ' + r.http) + '（耗时 ' + r.ms + 'ms）｜打洞：' + ztDesc(), r.ts);
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

// ---------- ZeroTier 打洞状态 ----------
let ztState = { status: 'checking', latency: null, path: '', detail: '' };

function checkZt() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') { resolve({ status: 'unknown', detail: '仅支持 Windows' }); return; }
    execFile(ZT_EXE, ['-q', '-j', 'listpeers'], { timeout: 8000, windowsHide: true }, (err, out) => {
      if (err) {
        const code = (err.code && String(err.code)) || '';
        const detail = /ENOENT/.test(code) ? 'ZeroTier 未安装' : /timeout/i.test(err.message || '') ? '查询超时' : (err.message || '查询失败');
        resolve({ status: 'unknown', detail, latency: null, path: '' });
        return;
      }
      try {
        const peers = JSON.parse(out);
        const p = peers.find((x) => x.address === ZT_PEER);
        if (!p) { resolve({ status: 'offline', detail: '网关对端不在线', latency: null, path: '' }); return; }
        const act = (p.paths || []).filter((pt) => pt.active);
        const lat = p.latency > 0 ? p.latency : null;
        if (!p.tunneled && act.length) {
          resolve({ status: 'direct', latency: lat, path: act[0].address, detail: 'P2P 直连 ' + act[0].address });
        } else {
          resolve({ status: 'relay', latency: lat, path: 'relay', detail: p.tunneled ? 'TCP 隧道中继' : 'UDP 中继（打洞未建立）' });
        }
      } catch (e) {
        resolve({ status: 'unknown', detail: '解析失败 ' + e.message, latency: null, path: '' });
      }
    });
  });
}

async function ztLoop() {
  let first = true;
  while (!isQuiting) {
    const t0 = Date.now();
    const prev = ztState.status;
    ztState = await checkZt();
    if (first) { dbg('first zt check: ' + JSON.stringify(ztState)); first = false; }
    if (ztState.status !== prev) {
      appendLog('打洞状态变化：' + (ZT_CN[prev] || prev) + ' → ' + (ZT_CN[ztState.status] || ztState.status) + (ztState.detail ? '（' + ztState.detail + '）' : ''));
      dbg('zt state change ' + prev + ' -> ' + ztState.status + ' ' + ztState.detail);
    }
    pushState();
    updateTrayStatus();
    await new Promise((res) => setTimeout(res, Math.max(500, ZT_POLL_MS - (Date.now() - t0))));
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
  if (!isUrl && !isTcp) return { ok: false, err: '格式：http(s)://主机:端口/v1 或 主机:端口（IPv6 用 [地址]:端口）' };
  if (!isUrl) {
    const port = Number(u.match(/:(\d+)$/)[1]);
    if (port < 1 || port > 65535) return { ok: false, err: '端口需在 1–65535 之间' };
  }
  const prev = API;
  API = u;
  saveConfig(u);
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
    ztLoop();
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