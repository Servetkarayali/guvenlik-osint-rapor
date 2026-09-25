// Aktif tarama modulu.
// ONEMLI: Bu modul YALNIZCA sahipligi dogrulanmis alan adlari icin cagrilir
// (bkz. verify.js) ve kullanici acik onay verdikten sonra calisir.
// Kapsam bilincli olarak dar tutulmustur: sömürü, kaba kuvvet, yuk testi,
// zafiyet istismari YOKTUR. Yalnizca hizli TCP baglanti kontrolu ve
// az sayida standart uc noktaya tekil, zararsiz HTTP istegi yapilir.
import net from 'node:net';
import https from 'node:https';
import http from 'node:http';
import { withTimeout } from './util.js';

// Yaygin, iyi bilinen hizmet portlari (yalnizca "acik/kapali" bilgisi).
const COMMON_PORTS = [
  { port: 21, servis: 'FTP' },
  { port: 22, servis: 'SSH' },
  { port: 25, servis: 'SMTP' },
  { port: 80, servis: 'HTTP' },
  { port: 110, servis: 'POP3' },
  { port: 143, servis: 'IMAP' },
  { port: 443, servis: 'HTTPS' },
  { port: 3306, servis: 'MySQL' },
  { port: 3389, servis: 'RDP' },
  { port: 5432, servis: 'PostgreSQL' },
  { port: 6379, servis: 'Redis' },
  { port: 8080, servis: 'HTTP-alt' },
  { port: 8443, servis: 'HTTPS-alt' },
];

function probePort(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (state) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(state);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done('acik'));
    socket.once('timeout', () => done('filtreli'));
    socket.once('error', (e) => done(e.code === 'ECONNREFUSED' ? 'kapali' : 'filtreli'));
    socket.connect(port, host);
  });
}

export async function scanPorts(host) {
  const results = [];
  // Dusuk eszamanlilik: hedefe yuk bindirmemek icin kucuk gruplar halinde.
  const batchSize = 4;
  for (let i = 0; i < COMMON_PORTS.length; i += batchSize) {
    const batch = COMMON_PORTS.slice(i, i + batchSize);
    const states = await Promise.all(batch.map((p) => probePort(host, p.port)));
    batch.forEach((p, idx) => results.push({ ...p, durum: states[idx] }));
  }
  return results;
}

// Standart, herkesce bilinen hassas uc noktalarin VARLIGINI kontrol eder
// (icerigini indirmez, sömurmez). Yalnizca durum kodu bakilir.
const CHECK_PATHS = [
  '/.git/config',
  '/.env',
  '/admin/',
  '/server-status',
  '/.well-known/security.txt',
  '/phpinfo.php',
];

function headStatus(target, pathName) {
  const { host, protocol, port } = target;
  const lib = protocol === 'https' ? https : http;
  return withTimeout(new Promise((resolve) => {
    const req = lib.request(
      { method: 'GET', host, port: Number(port), path: pathName,
        headers: { 'User-Agent': 'GuvenlikOSINT-Aktif/0.1 (izinli-tarama)' },
        rejectUnauthorized: false, timeout: 6000 },
      (res) => {
        // Govdeyi tuketip at; icerigi saklamayiz.
        res.on('data', () => {});
        res.on('end', () => resolve({ path: pathName, statusCode: res.statusCode }));
      }
    );
    req.on('error', () => resolve({ path: pathName, statusCode: null, error: true }));
    req.on('timeout', () => { req.destroy(); resolve({ path: pathName, statusCode: null, error: true }); });
    req.end();
  }), 7000, 'uc nokta').catch(() => ({ path: pathName, statusCode: null, error: true }));
}

export async function checkEndpoints(target) {
  const out = [];
  for (const p of CHECK_PATHS) {
    const r = await headStatus(target, p);
    // 200/403 = mevcut olabilir; 404 = yok. Yorum raporda yapilir.
    out.push({
      ...r,
      erisilebilir: r.statusCode === 200,
      korumali: r.statusCode === 401 || r.statusCode === 403,
    });
  }
  return out;
}

export async function runActive(target) {
  const [ports, endpoints] = await Promise.all([
    scanPorts(target.host),
    checkEndpoints(target),
  ]);
  return { ports, endpoints };
}
