// Toplanan verileri Turkce bulgulara, oneme ve puana donusturur.
// Bulgu onem seviyeleri: kritik, yuksek, orta, dusuk, bilgi.

const SEV_ORDER = { kritik: 0, yuksek: 1, orta: 2, dusuk: 3, bilgi: 4 };
const SEV_PUAN = { kritik: 25, yuksek: 15, orta: 8, dusuk: 3, bilgi: 0 };

function f(onem, baslik, aciklama, oneri) {
  return { onem, baslik, aciklama, oneri };
}

// Pasif verilerden bulgu uretir.
export function buildPassiveFindings(data) {
  const bulgular = [];
  const { tls, headerAnaliz, dns, http, fingerprint, osint, robots, securityTxt } = data;

  // TLS
  if (tls) {
    if (!tls.ok) {
      bulgular.push(f('yuksek', 'HTTPS/TLS baglantisi kurulamadi',
        `TLS el sikismasi basarisiz: ${tls.error}. Site sifreli baglanti sunmuyor olabilir.`,
        'Gecerli bir TLS sertifikasi kurun ve 443 portunda HTTPS sunun.'));
    } else {
      if (!tls.authorized) {
        bulgular.push(f('yuksek', 'TLS sertifikasi guvenilir degil',
          `Sertifika dogrulanamadi: ${tls.authError || 'bilinmeyen neden'}.`,
          'Taninmis bir sertifika otoritesinden gecerli sertifika kullanin.'));
      }
      if (tls.daysLeft !== null && tls.daysLeft < 0) {
        bulgular.push(f('kritik', 'TLS sertifikasi suresi dolmus',
          `Sertifika ${tls.validTo} tarihinde sona ermis.`, 'Sertifikayi hemen yenileyin.'));
      } else if (tls.daysLeft !== null && tls.daysLeft < 21) {
        bulgular.push(f('orta', 'TLS sertifikasi yakinda dolacak',
          `Sertifikanin bitmesine ${tls.daysLeft} gun kaldi.`, 'Otomatik yenileme kurun.'));
      }
      if (tls.protocol && /TLSv1(\.0|\.1)?$/.test(tls.protocol)) {
        bulgular.push(f('yuksek', 'Eski TLS surumu kullaniliyor',
          `Sunucu ${tls.protocol} ile baglandi.`, 'TLS 1.2 ve 1.3 disindaki surumleri kapatin.'));
      } else if (tls.protocol) {
        bulgular.push(f('bilgi', 'TLS surumu', `Baglanti ${tls.protocol} ile kuruldu.`, null));
      }
    }
  }

  // Guvenlik basliklari
  if (headerAnaliz) {
    for (const m of headerAnaliz.missing) {
      const onem = m.onem === 'yuksek' ? 'orta' : m.onem === 'orta' ? 'dusuk' : 'bilgi';
      bulgular.push(f(onem, `Eksik guvenlik basligi: ${m.ad}`,
        `${m.ad} basligi yanitta bulunmuyor.`,
        `${m.ad} basligini uygun degerle ekleyin.`));
    }
    for (const leak of headerAnaliz.leaks) {
      bulgular.push(f('dusuk', `Bilgi sizdiran baslik: ${leak.baslik}`,
        `Sunucu "${leak.baslik}: ${leak.deger}" bilgisini aciga cikariyor.`,
        'Surum/teknoloji bilgisini gizleyin.'));
    }
  }

  // E-posta guvenligi (SPF/DMARC)
  if (dns && dns.email) {
    if (!dns.email.spf) {
      bulgular.push(f('orta', 'SPF kaydi yok',
        'Alan adinda SPF (v=spf1) TXT kaydi bulunamadi.',
        'E-posta sahteciligini onlemek icin SPF kaydi ekleyin.'));
    }
    if (dns.email.dmarcQueried && !dns.email.dmarc) {
      bulgular.push(f('orta', 'DMARC kaydi yok',
        '_dmarc alt alan adinda DMARC kaydi bulunamadi.',
        'En az p=quarantine ile bir DMARC politikasi yayinlayin.'));
    }
  }

  // HTTP durum / yonlendirme
  if (http && http.ok) {
    bulgular.push(f('bilgi', 'HTTP yanit kodu', `Kok URL ${http.statusCode} dondu.`, null));
  } else if (http && !http.ok) {
    bulgular.push(f('orta', 'HTTP istegi basarisiz', `Hata: ${http.error}`, 'Sunucu erisilebilirligini kontrol edin.'));
  }

  // Teknoloji izi (bilgi)
  if (fingerprint && fingerprint.length) {
    bulgular.push(f('bilgi', 'Tespit edilen teknolojiler', fingerprint.join(', '),
      'Kullanilan bilesenleri guncel tutun.'));
  }

  // OSINT
  if (osint) {
    if (osint.emails && osint.emails.length) {
      bulgular.push(f('dusuk', 'Sayfada gorunur e-posta adresleri',
        `${osint.emails.length} adet e-posta bulundu: ${osint.emails.slice(0, 5).join(', ')}${osint.emails.length > 5 ? ' ...' : ''}`,
        'Spam/oltalama riskine karsi e-postalari gizleyin veya form kullanin.'));
    }
    if (osint.socials && osint.socials.length) {
      bulgular.push(f('bilgi', 'Bagli sosyal medya hesaplari',
        osint.socials.slice(0, 8).join(', '), null));
    }
  }

  // robots.txt / security.txt
  if (robots && robots.ok && robots.statusCode === 200) {
    const hassas = (robots.body.match(/Disallow:\s*\/[^\s]*/gi) || []).slice(0, 10);
    bulgular.push(f('bilgi', 'robots.txt mevcut',
      hassas.length ? `Disallow girdileri: ${hassas.join(' | ')}` : 'Ozel bir Disallow girdisi yok.',
      'Hassas dizinleri robots.txt ile aciga cikarmayin.'));
  }
  if (securityTxt) {
    if (securityTxt.ok && securityTxt.statusCode === 200) {
      bulgular.push(f('bilgi', 'security.txt mevcut', 'Guvenlik iletisim dosyasi bulundu (iyi uygulama).', null));
    } else {
      bulgular.push(f('dusuk', 'security.txt yok',
        '/.well-known/security.txt bulunamadi.',
        'Guvenlik arastirmacilarinin size ulasmasi icin security.txt ekleyin.'));
    }
  }

  return bulgular;
}

// Aktif verilerden bulgu uretir.
export function buildActiveFindings(active) {
  const bulgular = [];
  if (!active) return bulgular;

  const acikPortlar = (active.ports || []).filter((p) => p.durum === 'acik');
  const riskli = acikPortlar.filter((p) =>
    [21, 23, 3306, 3389, 6379, 5432, 110, 143].includes(p.port));
  if (acikPortlar.length) {
    bulgular.push(f('bilgi', 'Acik portlar',
      acikPortlar.map((p) => `${p.port}/${p.servis}`).join(', '), null));
  }
  for (const p of riskli) {
    bulgular.push(f('yuksek', `Riskli port acik: ${p.port} (${p.servis})`,
      `${p.servis} hizmeti internete acik gorunuyor.`,
      'Bu hizmeti guvenlik duvari/VPN arkasina alin veya kapatin.'));
  }

  for (const e of (active.endpoints || [])) {
    if (e.erisilebilir && ['/.git/config', '/.env', '/phpinfo.php', '/server-status'].includes(e.path)) {
      bulgular.push(f('kritik', `Hassas uc nokta erisilebilir: ${e.path}`,
        `${e.path} adresi 200 (erisilebilir) dondu; gizli bilgi sizabilir.`,
        'Bu dosya/uc noktaya web uzerinden erisimi engelleyin.'));
    } else if (e.erisilebilir && e.path === '/admin/') {
      bulgular.push(f('orta', 'Yonetim paneli erisilebilir: /admin/',
        'Yonetim arayuzu dogrudan erisilebilir gorunuyor.',
        'IP kisitlamasi ve guclu kimlik dogrulama uygulayin.'));
    }
  }
  return bulgular;
}

// Bulgulari siralar ve 0-100 arasi guvenlik puani hesaplar (100 = en iyi).
export function scoreAndSort(bulgular) {
  const sirali = [...bulgular].sort((a, b) => SEV_ORDER[a.onem] - SEV_ORDER[b.onem]);
  let ceza = 0;
  for (const b of bulgular) ceza += SEV_PUAN[b.onem] || 0;
  const puan = Math.max(0, 100 - ceza);
  const ozet = { kritik: 0, yuksek: 0, orta: 0, dusuk: 0, bilgi: 0 };
  for (const b of bulgular) ozet[b.onem]++;
  let not = 'A';
  if (puan < 90) not = 'B';
  if (puan < 75) not = 'C';
  if (puan < 55) not = 'D';
  if (puan < 35) not = 'E';
  if (puan < 20) not = 'F';
  return { bulgular: sirali, puan, not, ozet };
}
