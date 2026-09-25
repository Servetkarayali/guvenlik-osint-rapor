// Ortak yardimci fonksiyonlar
import crypto from 'node:crypto';

// Kullanicinin girdigi URL'yi guvenli sekilde ayristirir ve dogrular.
// Yalnizca http/https kabul edilir. Basarisizsa hata firlatir.
export function parseTarget(raw) {
  if (!raw || typeof raw !== 'string') {
    throw new Error('URL bos olamaz.');
  }
  let input = raw.trim();
  if (!/^https?:\/\//i.test(input)) {
    input = 'https://' + input; // sema yoksa https varsay
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error('Gecersiz URL bicimi.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Yalnizca http ve https desteklenir.');
  }
  const host = url.hostname.toLowerCase();
  if (!host || host.length > 253) {
    throw new Error('Gecersiz alan adi.');
  }
  return {
    url,
    host,
    origin: url.origin,
    protocol: url.protocol.replace(':', ''),
    port: url.port || (url.protocol === 'https:' ? '443' : '80'),
  };
}

// Ozel/yerel IP araliklarini ve host adlarini reddetmek icin kontrol.
// SSRF onlemi: iç aglara istek atilmasini engeller.
export function isBlockedHost(host) {
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) {
    return true;
  }
  // IPv4 literal kontrolu
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;
    // 10.0.0.0/8
    if (o[0] === 10) return true;
    // 127.0.0.0/8
    if (o[0] === 127) return true;
    // 169.254.0.0/16 (link-local)
    if (o[0] === 169 && o[1] === 254) return true;
    // 172.16.0.0/12
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    // 192.168.0.0/16
    if (o[0] === 192 && o[1] === 168) return true;
    // 0.0.0.0/8
    if (o[0] === 0) return true;
  }
  // IPv6 loopback / yerel
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) {
    return true;
  }
  return false;
}

// Rastgele dogrulama tokeni uretir (alan adi sahipligi kaniti icin).
export function makeToken() {
  return 'gosr-verify-' + crypto.randomBytes(16).toString('hex');
}

export function nowIso() {
  return new Date().toISOString();
}

// Basit zaman asimli promise sarmalayici.
export function withTimeout(promise, ms, label = 'islem') {
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => reject(new Error(`${label} zaman asimina ugradi (${ms}ms).`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}
