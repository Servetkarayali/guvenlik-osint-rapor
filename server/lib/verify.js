// Alan adi sahipligi dogrulamasi.
// Aktif tarama YALNIZCA bu dogrulama basariyla gectikten sonra izinlidir.
// Iki yontem: (1) DNS TXT kaydi, (2) hedef sitede dogrulama dosyasi.
import dns from 'node:dns/promises';
import https from 'node:https';
import http from 'node:http';
import { withTimeout, makeToken, nowIso } from './util.js';

// Bellek ici token deposu (uretimde kalici depo ile degistirilmelidir).
const tokens = new Map(); // host -> { token, createdAt, verified }

export function issueToken(host) {
  const token = makeToken();
  tokens.set(host, { token, createdAt: nowIso(), verified: false });
  return {
    host,
    token,
    dnsRecord: { type: 'TXT', name: `_gosr-verify.${host}`, value: token },
    fileMethod: { path: `/.well-known/gosr-verify.txt`, content: token },
    aciklama:
      'Bu alan adinin size ait oldugunu kanitlamak icin asagidaki iki yontemden BIRINI uygulayin, ' +
      'ardindan "Dogrula" adimina donun.',
  };
}

export function getToken(host) {
  return tokens.get(host) || null;
}

export function isVerified(host) {
  const t = tokens.get(host);
  return !!(t && t.verified);
}

async function checkDnsToken(host, token) {
  try {
    const records = await withTimeout(dns.resolveTxt('_gosr-verify.' + host), 6000, 'DNS TXT');
    const flat = records.map((r) => (Array.isArray(r) ? r.join('') : r));
    return flat.includes(token);
  } catch {
    return false;
  }
}

function checkFileToken(host, token) {
  const tryScheme = (lib, port) =>
    new Promise((resolve) => {
      const req = lib.request(
        { method: 'GET', host, port, path: '/.well-known/gosr-verify.txt',
          headers: { 'User-Agent': 'GuvenlikOSINT-Dogrulama/0.1' },
          rejectUnauthorized: false, timeout: 7000 },
        (res) => {
          let body = '';
          res.on('data', (c) => { if (body.length < 2000) body += c.toString('utf8'); });
          res.on('end', () => resolve(res.statusCode === 200 && body.trim() === token));
        }
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    });
  return withTimeout(
    (async () => (await tryScheme(https, 443)) || (await tryScheme(http, 80)))(),
    16000,
    'dosya dogrulama'
  ).catch(() => false);
}

// Her iki yontemi de dener; biri basariliysa dogrulanmis sayilir.
export async function verifyOwnership(host) {
  const t = tokens.get(host);
  if (!t) return { verified: false, reason: 'Bu alan adi icin once token uretilmeli.' };
  const [viaDns, viaFile] = await Promise.all([
    checkDnsToken(host, t.token),
    checkFileToken(host, t.token),
  ]);
  const verified = viaDns || viaFile;
  t.verified = verified;
  return {
    verified,
    method: viaDns ? 'dns-txt' : viaFile ? 'dosya' : null,
    reason: verified ? null : 'Token bulunamadi. Kayit yayilmasi birkac dakika surebilir.',
  };
}
