// 生成 256x256 PNG 图标 → build/icon.png（electron-builder 会自动转 .ico 用于 Windows）
// 风格与 UI 一致：深色玻璃圆角底 + 发光绿色状态点 + 蓝色延迟曲线
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const S = 256;
const px = Buffer.alloc(S * S * 4);

function setPixel(x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= S || y >= S) return;
  const i = (y * S + x) * 4;
  // alpha over（sa 钳制到 [0,1]，防止 alpha 超 1 时字节回绕产生杂色）
  const sa = Math.max(0, Math.min(1, a / 255));
  const da = px[i + 3] / 255;
  const oa = sa + da * (1 - sa);
  if (oa <= 0) return;
  px[i] = Math.round((r * sa + px[i] * da * (1 - sa)) / oa);
  px[i + 1] = Math.round((g * sa + px[i + 1] * da * (1 - sa)) / oa);
  px[i + 2] = Math.round((b * sa + px[i + 2] * da * (1 - sa)) / oa);
  px[i + 3] = Math.round(oa * 255);
}

function smooth(t) { t = Math.max(0, Math.min(1, t)); return t * t * (3 - 2 * t); }
function coverage(dist, width) { return smooth(0.5 + width / 2 - dist) > 0 ? (0.5 - (dist - width / 2) / Math.max(width, 0.001)) : 0; }

// 圆角矩形 SDF
function sdfRRect(x, y, cx, cy, hw, hh, r) {
  const qx = Math.abs(x - cx) - (hw - r);
  const qy = Math.abs(y - cy) - (hh - r);
  const ax = qx > 0 ? qx : 0, ay = qy > 0 ? qy : 0;
  return Math.hypot(ax, ay) + Math.min(Math.max(qx, qy), 0) - r;
}

// 到折线段的最小距离
function distPolyline(x, y, pts) {
  let d = Infinity;
  for (let i = 0; i < pts.length - 1; i++) {
    const [x1, y1] = pts[i], [x2, y2] = pts[i + 1];
    const dx = x2 - x1, dy = y2 - y1;
    const l2 = dx * dx + dy * dy;
    let t = l2 ? ((x - x1) * dx + (y - y1) * dy) / l2 : 0;
    t = Math.max(0, Math.min(1, t));
    d = Math.min(d, Math.hypot(x - (x1 + t * dx), y - (y1 + t * dy)));
  }
  return d;
}

const bgTop = [24, 34, 56], bgBot = [12, 18, 33];
const dotC = [52, 211, 153], dotCore = [167, 243, 208];
const waveC = [96, 165, 250];
const wavePts = [[44, 202], [76, 182], [104, 192], [134, 162], [162, 180], [190, 152], [212, 168]];

for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    // 1. 背景
    const dRect = sdfRRect(x + 0.5, y + 0.5, 128, 128, 120, 120, 56);
    const bgA = Math.max(0, Math.min(1, 0.5 - dRect));
    if (bgA > 0) {
      const t = y / S;
      setPixel(x, y,
        bgTop[0] + (bgBot[0] - bgTop[0]) * t,
        bgTop[1] + (bgBot[1] - bgTop[1]) * t,
        bgTop[2] + (bgBot[2] - bgTop[2]) * t, bgA * 255);
    }
    const dDot = Math.hypot(x - 128, y - 106);
    const dWave = distPolyline(x, y, wavePts);
    // 2. 曲线（先画，位于点下方区域）
    const wGlow = smooth(1 - (dWave - 4) / 14) * 0.30;
    if (wGlow > 0.01) setPixel(x, y, waveC[0], waveC[1], waveC[2], wGlow * 255);
    if (dWave < 4.5) setPixel(x, y, waveC[0], waveC[1], waveC[2], Math.max(0, 1 - (dWave - 1.5) / 3) * 255);
    if (dWave < 2.5) setPixel(x, y, 200, 225, 255, (1 - dWave / 2.5) * 255 * 0.55);
    const dEnd = Math.hypot(x - 212, y - 168);
    if (dEnd < 8) setPixel(x, y, 225, 242, 255, smooth(1 - (dEnd - 3.5) / 4.5) * 255 * 0.95);
    // 3. 状态点（后画，压在最上层；光晕只在点外）
    if (dDot > 38) {
      const glow = smooth(1 - (dDot - 38) / 36) * 0.5;
      if (glow > 0.01) setPixel(x, y, dotC[0], dotC[1], dotC[2], glow * 255);
    } else {
      setPixel(x, y, dotC[0], dotC[1], dotC[2], Math.max(0, 1 - (dDot - 35) / 3) * 255);
      if (dDot <= 22) setPixel(x, y, dotCore[0], dotCore[1], dotCore[2], smooth(1 - (dDot - 13) / 9) * 255 * 0.85);
    }
  }
}

// ---- PNG 编码（纯 JS：IHDR/IDAT/IEND + zlib） ----
function crc32(buf) {
  if (!crc32.table) {
    const t = new Int32Array(256);
    for (let n = 0; n < 256; n++) { let v = n; for (let k = 0; k < 8; k++) v = v & 1 ? 0xedb88320 ^ (v >>> 1) : v >>> 1; t[n] = v; }
    crc32.table = t;
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crc32.table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4);
ihdr[8] = 8; ihdr[9] = 6; // 8bit RGBA
const raw = Buffer.alloc(S * (S * 4 + 1));
for (let y = 0; y < S; y++) {
  raw[y * (S * 4 + 1)] = 0;
  px.copy(raw, y * (S * 4 + 1) + 1, y * S * 4, (y + 1) * S * 4);
}
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);
const outDir = path.join(__dirname, '..', 'build');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'icon.png'), png);
console.log('icon written: build/icon.png', png.length, 'bytes');