// Pasif tarama ve OSINT toplama.
// Pasif = yalnizca herkese acik bilgiler ve hedefin kendi acik uc noktalarina
// tekil, zararsiz istekler. Sömürü, kaba kuvvet veya dizin taramasi YOKTUR.
import dns from 'node:dns/promises';
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import { withTimeout, isBlockedHost } from './util.js';

const UA = 'GuvenlikOSINT-Rapor/0.1 (+pasif-tarama; iletisim: site-yoneticisi)';

// --- DNS kayitlari ---
export async function collectDns(host) {
  const out = { host, records: {}, notes: [] };
  const q = async (type, fn) => {
    try {
      out.records[type] = await withTimeout(fn(), 5000, `DNS ${type}`);
    } catch (e) {
      out.records[type] = null;
      if (e.code && e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') {
        out.notes.push(`${type} sorgusu: ${e.code}`);
      }
    }
  };
  await Promise.all([
    q('A', () => dns.resolve4(host)),
    q('AAAA', () => dns.resolve6(host)),
    q('MX', () => dns.resolveMx(host)),
    q('NS', () => dns.resolveNs(host)),
    q('TXT', () => dns.resolveTxt(host)),
    q('CNAME', () => dns.resolveCname(host).catch(() => null)),
    q('SOA', () => dns.resolveSoa(host)),
  ]);
  // TXT icinden guvenlikle ilgili kayitlari isaretle (SPF, DMARC ipuclari)
  const txt = (out.records.TXT || []).map((r) => (Array.isArray(r) ? r.join('') : r));
  out.email = {
    spf: txt.find((t) => /^v=spf1/i.test(t)) || null,
    dmarcQueried: false,
  };
  try {
    const dmarc = await withTimeout(dns.resolveTxt('_dmarc.' + host), 5000, 'DMARC');
    out.email.dmarc = dmarc.map((r) => r.join('')).find((t) => /^v=DMARC1/i.test(t)) || null;
    out.email.dmarcQueried = true;
  } catch {
    out.email.dmarc = null;
    out.email.dmarcQueried = true;
  }
  return out;
}

// --- TLS sertifika bilgisi (yalnizca el sikismasi, veri gonderilmez) ---
export function collectTls(host, port = 443) {
  return withTimeout(new Promise((resolve) => {
    const socket = tls.connect(
      { host, port: Number(port), servername: host, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate(true);
        const proto = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError ? String(socket.authorizationError) : null;
        let daysLeft = null;
        if (cert && cert.valid_to) {
          daysLeft = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
        }
        resolve({
          ok: true,
          protocol: proto,
          cipher: cipher ? cipher.name : null,
          authorized,
          authError,
          subject: cert.subject || null,
          issuer: cert.issuer || null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          daysLeft,
          altNames: cert.subjectaltname || null,
          serialNumber: cert.serialNumber || null,
        });
        socket.end();
      }
    );
    socket.on('error', (e) => resolve({ ok: false, error: String(e.message || e) }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, error: 'TLS zaman asimi' });
    });
  }), 10000, 'TLS').catch((e) => ({ ok: false, error: String(e.message || e) }));
}

// --- HTTP(S) yaniti: durum, guvenlik basliklari, teknoloji izi ---
// Yalnizca hedefin kok URL'sine TEK bir GET istegi yapilir.
export function fetchHead(target) {
  const { url, host, protocol, port } = target;
  const lib = protocol === 'https' ? https : http;
  return withTimeout(new Promise((resolve) => {
    const req = lib.request(
      {
        method: 'GET',
        host,
        port: Number(port),
        path: url.pathname || '/',
        headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
        rejectUnauthorized: false,
        timeout: 10000,
      },
      (res) => {
        let body = '';
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (body.length < 20000) body += chunk.toString('utf8'); // yalnizca bas kismi
        });
        res.on('end', () => {
          resolve({
            ok: true,
            statusCode: res.statusCode,
            headers: res.headers,
            bodySample: body.slice(0, 20000),
            bodySize: size,
            finalUrl: url.href,
          });
        });
      }
    );
    req.on('error', (e) => resolve({ ok: false, error: String(e.message || e) }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'HTTP zaman asimi' });
    });
    req.end();
  }), 12000, 'HTTP').catch((e) => ({ ok: false, error: String(e.message || e) }));
}

// robots.txt ve security.txt gibi standart, herkese acik dosyalari okur.
export function fetchPublicFile(target, pathName) {
  const { host, protocol, port } = target;
  const lib = protocol === 'https' ? https : http;
  return withTimeout(new Promise((resolve) => {
    const req = lib.request(
      { method: 'GET', host, port: Number(port), path: pathName,
        headers: { 'User-Agent': UA }, rejectUnauthorized: false, timeout: 8000 },
      (res) => {
        let body = '';
        res.on('data', (c) => { if (body.length < 8000) body += c.toString('utf8'); });
        res.on('end', () => resolve({ ok: true, statusCode: res.statusCode, body: body.slice(0, 8000) }));
      }
    );
    req.on('error', (e) => resolve({ ok: false, error: String(e.message || e) }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'zaman asimi' }); });
    req.end();
  }), 9000, 'dosya').catch((e) => ({ ok: false, error: String(e.message || e) }));
}

// Guvenlik basliklarini degerlendirir.
const SECURITY_HEADERS = [
  { key: 'strict-transport-security', ad: 'HSTS', onem: 'yuksek' },
  { key: 'content-security-policy', ad: 'CSP', onem: 'yuksek' },
  { key: 'x-frame-options', ad: 'X-Frame-Options', onem: 'orta' },
  { key: 'x-content-type-options', ad: 'X-Content-Type-Options', onem: 'orta' },
  { key: 'referrer-policy', ad: 'Referrer-Policy', onem: 'dusuk' },
  { key: 'permissions-policy', ad: 'Permissions-Policy', onem: 'dusuk' },
];

export function analyzeHeaders(headers) {
  const h = headers || {};
  const present = [];
  const missing = [];
  for (const item of SECURITY_HEADERS) {
    if (h[item.key]) present.push({ ...item, deger: String(h[item.key]).slice(0, 200) });
    else missing.push(item);
  }
  // Bilgi sizdiran basliklar
  const leaks = [];
  for (const k of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    if (h[k]) leaks.push({ baslik: k, deger: String(h[k]).slice(0, 120) });
  }
  return { present, missing, leaks };
}

// Basit teknoloji izi (imza tabanli, herkese acik ipuclarindan).
export function fingerprint(headers, bodySample) {
  const h = headers || {};
  const b = (bodySample || '').toLowerCase();
  const tech = new Set();
  if (h.server) tech.add('Sunucu: ' + h.server);
  if (h['x-powered-by']) tech.add(h['x-powered-by']);
  if (b.includes('wp-content') || b.includes('/wp-includes/')) tech.add('WordPress');
  if (b.includes('/sites/default/files')) tech.add('Drupal');
  if (b.includes('cdn.shopify.com')) tech.add('Shopify');
  if (h['x-generator']) tech.add(String(h['x-generator']));
  if (b.includes('__next') || b.includes('/_next/')) tech.add('Next.js');
  if (b.includes('react') && b.includes('data-reactroot')) tech.add('React');
  if (h['set-cookie'] && String(h['set-cookie']).includes('laravel_session')) tech.add('Laravel');
  return [...tech];
}

// OSINT: hedef hakkinda herkese acik meta veriler (basliklardan/gövdeden).
export function extractOsint(bodySample) {
  const b = bodySample || '';
  const emails = [...new Set((b.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || []).slice(0, 20))];
  const socials = [...new Set(
    (b.match(/https?:\/\/(www\.)?(twitter|x|facebook|linkedin|instagram|youtube|github)\.com\/[^"'\s<>]+/gi) || [])
      .slice(0, 20)
  )];
  const title = (b.match(/<title[^>]*>([^<]{0,200})<\/title>/i) || [])[1] || null;
  const generator = (b.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{0,120})["']/i) || [])[1] || null;
  return { emails, socials, title: title ? title.trim() : null, generator };
}
