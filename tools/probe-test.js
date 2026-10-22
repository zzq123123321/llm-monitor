// 分层探测自检：用四种可复现的失败，验证每层能独立分辨。
// 运行：node tools/probe-test.js
const http = require('http');
const { probeAll } = require('../probe');

const API_PORT = 28999; // 本地桩服务
let stubMode = '401';

function stub() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      if (stubMode === '401') { res.writeHead(401); res.end('{"error":"invalid token"}'); return; }
      if (stubMode === 'hang') { return; } // 不回应，测 L3 超时
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"data":[{"id":"qwen3.8-27b"}]}');
    });
    srv.listen(API_PORT, '127.0.0.1', () => resolve(srv));
  });
}

function show(name, r, expect) {
  const v = r.verdict;
  const mark = v === expect ? 'PASS' : 'FAIL';
  console.log(`\n[${mark}] ${name}  预期=${expect} 实际=${v}  总耗时=${r.total_ms}ms`);
  console.log(`   L1 zt   : ${r.l1.state}${r.l1.latency ? ' ' + r.l1.latency + 'ms' : ''}  ${r.l1.detail || ''}`);
  console.log(`   L2 icmp : ok=${r.l2.icmp.ok} rtt=${r.l2.icmp.rtt} ${r.l2.icmp.err}`);
  console.log(`   L2 route: ok=${r.l2.route.ok} ${r.l2.route.ok ? r.l2.route.nexthop + ' via ' + r.l2.route.iface : r.l2.route.err}`);
  console.log(`   L2 tcp  : ok=${r.l2.tcp.ok} ${r.l2.tcp.ms}ms ${r.l2.tcp.err}`);
  console.log(`   L3 http : ran=${r.l3.err !== 'SKIPPED(L2 不通)'} ok=${r.l3.ok} http=${r.l3.http} ${r.l3.ms}ms ${r.l3.err}`);
  return v === expect;
}

(async () => {
  const srv = await stub();
  let pass = 0, total = 0;
  const base = { apiUrl: `http://127.0.0.1:${API_PORT}/v1`, hostPort: { host: '127.0.0.1', port: API_PORT }, routePrefix: '192.168.100.0' };

  // 1) 端口封闭：L2 REFUSED，L3 跳过
  total++; if (show('端口未监听', await probeAll(Object.assign({}, base, { hostPort: { host: '127.0.0.1', port: 28998 } })), 'port-closed')) pass++;

  // 2) 服务在但鉴权失败：L2 通 + L3 401
  stubMode = '401';
  total++; if (show('HTTP 401 鉴权失败', await probeAll(base), 'auth')) pass++;

  // 3) 端口通但 HTTP 不回应：L3 超时
  stubMode = 'hang';
  total++; if (show('HTTP 无响应', await probeAll(Object.assign({}, base, { httpTimeout: 1200 })), 'api-hang')) pass++;

  // 4) 正常
  stubMode = 'ok';
  total++; if (show('全部正常', await probeAll(base), 'ok')) pass++;

  // 5) 黑洞地址（TEST-NET-1，保证丢包）：ICMP 与 TCP 双超时
  total++; if (show('路径不通（黑洞 IP）', await probeAll({
    apiUrl: 'http://192.0.2.1:20128/v1',
    hostPort: { host: '192.0.2.1', port: 20128 },
    icmpTimeout: 1200, tcpTimeout: 1500, httpTimeout: 1000,
    routePrefix: '192.0.2.0',
  }), 'local-network')) pass++;

  srv.close();
  console.log(`\n结果：${pass}/${total} 通过`);
  process.exit(pass === total ? 0 : 1);
})();
