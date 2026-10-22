// 无依赖的 asar 打包器：把目录打成 Electron 可读的 app.asar。
// 用法：node tools/pack-asar.js <源目录> <输出文件>
// 头部布局与 electron-builder 产物一致（含每文件 integrity 哈希），避免完整性校验失败。
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BLOCK = 4194304;

function walk(dir, base, out) {
  for (const name of fs.readdirSync(dir).sort()) {
    const p = path.join(dir, name);
    const rel = base ? base + '/' + name : name;
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p, rel, out);
    else out.push({ rel, p, size: st.size });
  }
}

function main() {
  const src = process.argv[2];
  const dst = process.argv[3];
  if (!src || !dst) { console.error('用法：node tools/pack-asar.js <源目录> <输出文件>'); process.exit(1); }

  const list = [];
  walk(src, '', list);

  const files = {};
  let offset = 0;
  const blobs = [];
  for (const f of list) {
    const buf = fs.readFileSync(f.p);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const blocks = [];
    for (let i = 0; i < buf.length; i += BLOCK) {
      blocks.push(crypto.createHash('sha256').update(buf.slice(i, i + BLOCK)).digest('hex'));
    }
    files[f.rel] = {
      size: buf.length,
      integrity: { algorithm: 'SHA256', hash, blockSize: BLOCK, blocks: blocks.length ? blocks : [hash] },
      offset: String(offset),
    };
    offset += buf.length;
    blobs.push(buf);
  }

  const json = Buffer.from(JSON.stringify({ files }), 'utf8');
  const pad = (4 - (json.length % 4)) % 4;
  const aligned = json.length + pad;

  const head = Buffer.alloc(16);
  head.writeUInt32LE(4, 0);
  head.writeUInt32LE(aligned + 8, 4);  // 8 + 该值 = 内容起点
  head.writeUInt32LE(aligned + 4, 8);
  head.writeUInt32LE(json.length, 12);

  const padding = Buffer.alloc(pad, 0x20);
  fs.writeFileSync(dst, Buffer.concat([head, json, padding, ...blobs]));

  console.log('已写入 ' + dst);
  console.log('  文件 ' + list.length + ' 个，内容 ' + offset + ' 字节，合计 ' + fs.statSync(dst).size + ' 字节');
  for (const f of list) console.log('    ' + f.rel + '  ' + f.size + ' B  @' + files[f.rel].offset);
}

main();
