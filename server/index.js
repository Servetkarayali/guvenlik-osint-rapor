// Guvenlik & OSINT Rapor sunucusu (sifir bagimlilik, saf Node).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTarget, isBlockedHost, nowIso } from './lib/util.js';
import * as passive from './lib/passive.js';
import * as verify from './lib/verify.js';
import { runActive } from './lib/active.js';
import { buildPassiveFindings, buildActiveFindings, scoreAndSort } from './lib/report.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, '..', 'public');
const PORT = process.env.PORT || 3000;

// --- Basit oran sinirlama (IP basina, bellek ici) ---
const rate = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const win = 60000; // 1 dk
  const max = 20;
  const arr = (rate.get(ip) || []).filter((t) => now - t < win);
  arr.push(now);
  rate.set(ip, arr);
  return arr.length > max;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function readBody(req, limit = 100000) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > limit) { reject(new Error('Istek govdesi cok buyuk.')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

async function serveStatic(req, res) {
  let rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (rel === '/') rel = '/index.html';
  const filePath = path.normalize(path.join(PUBLIC, rel));
  if (!filePath.startsWith(PUBLIC)) { res.writeHead(403); res.end('Yasak'); return; }
  fs.readFile(filePath, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Bulunamadi'); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(buf);
  });
}

async function handleApi(req, res, ip) {
  const url = new URL(req.url, 'http://x');

  if (rateLimited(ip)) return sendJson(res, 429, { hata: 'Cok fazla istek. Lutfen biraz bekleyin.' });

  // Girdi ayristirma yardimcisi
  const getTarget = (raw) => {
    const t = parseTarget(raw);
    if (isBlockedHost(t.host)) throw new Error('Yerel/ozel adresler taranamaz.');
    return t;
  };

  // 1) Pasif tarama + OSINT (her URL icin izinli)
  if (url.pathname === '/api/scan/passive' && req.method === 'POST') {
    const body = JSON.parse(await readBody(req) || '{}');
    let target;
    try { target = getTarget(body.url); }
    catch (e) { return sendJson(res, 400, { hata: e.message }); }

    const [dnsData, tlsData, httpData, robots, securityTxt] = await Promise.all([
      passive.collectDns(target.host),
      target.protocol === 'https' ? passive.collectTls(target.host, target.port) : Promise.resolve({ ok: false, error: 'HTTP hedefi' }),
      passive.fetchHead(target),
      passive.fetchPublicFile(target, '/robots.txt'),
      passive.fetchPublicFile(target, '/.well-known/security.txt'),
    ]);

    const headerAnaliz = httpData.ok ? passive.analyzeHeaders(httpData.headers) : null;
    const fp = httpData.ok ? passive.fingerprint(httpData.headers, httpData.bodySample) : [];
    const osint = httpData.ok ? passive.extractOsint(httpData.bodySample) : null;

    const bulgular = buildPassiveFindings({
      tls: tlsData, headerAnaliz, dns: dnsData, http: httpData, fingerprint: fp, osint, robots, securityTxt,
    });
    const skor = scoreAndSort(bulgular);

    return sendJson(res, 200, {
      hedef: target.host, tarih: nowIso(), tur: 'pasif',
      ...skor,
      ayrinti: { dns: dnsData, tls: tlsData, basliklar: headerAnaliz, teknoloji: fp, osint,
        http: httpData.ok ? { durum: httpData.statusCode, boyut: httpData.bodySize } : httpData },
    });
  }

  // 2) Dogrulama tokeni uret
  if (url.pathname === '/api/verify/token' && req.method === 'POST') {
    const body = JSON.parse(await readBody(req) || '{}');
    let target;
    try { target = getTarget(body.url); }
    catch (e) { return sendJson(res, 400, { hata: e.message }); }
    return sendJson(res, 200, verify.issueToken(target.host));
  }

  // 3) Sahipligi dogrula
  if (url.pathname === '/api/verify/check' && req.method === 'POST') {
    const body = JSON.parse(await readBody(req) || '{}');
    let target;
    try { target = getTarget(body.url); }
    catch (e) { return sendJson(res, 400, { hata: e.message }); }
    const result = await verify.verifyOwnership(target.host);
    return sendJson(res, 200, { hedef: target.host, ...result });
  }

  // 4) Aktif tarama (yalnizca dogrulanmis + onayli)
  if (url.pathname === '/api/scan/active' && req.method === 'POST') {
    const body = JSON.parse(await readBody(req) || '{}');
    let target;
    try { target = getTarget(body.url); }
    catch (e) { return sendJson(res, 400, { hata: e.message }); }

    if (body.onay !== true) {
      return sendJson(res, 403, { hata: 'Aktif tarama icin acik onay (onay=true) gereklidir.' });
    }
    if (!verify.isVerified(target.host)) {
      return sendJson(res, 403, {
        hata: 'Aktif tarama engellendi: alan adi sahipligi dogrulanmadi.',
        cozum: 'Once /api/verify/token ile token alin, DNS TXT veya dosya yontemiyle dogrulayin.',
      });
    }

    const active = await runActive(target);
    const bulgular = buildActiveFindings(active);
    const skor = scoreAndSort(bulgular);
    return sendJson(res, 200, {
      hedef: target.host, tarih: nowIso(), tur: 'aktif',
      ...skor, ayrinti: active,
    });
  }

  return sendJson(res, 404, { hata: 'Bilinmeyen uc nokta.' });
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'bilinmeyen').split(',')[0].trim();
  try {
    if (req.url.startsWith('/api/')) {
      await handleApi(req, res, ip);
    } else {
      await serveStatic(req, res);
    }
  } catch (e) {
    if (!res.headersSent) sendJson(res, 500, { hata: 'Sunucu hatasi: ' + String(e.message || e) });
    else res.end();
  }
});

server.listen(PORT, () => {
  console.log(`Guvenlik & OSINT Rapor sunucusu calisiyor: http://localhost:${PORT}`);
});
