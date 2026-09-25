// Arayuz mantigi. Sunucu API'sini cagirir ve raporu Turkce olarak cizer.
const $ = (id) => document.getElementById(id);

const urlInput = $('url');
const pasifBtn = $('pasifBtn');
const tokenBtn = $('tokenBtn');
const dogrulaBtn = $('dogrulaBtn');
const onayKutu = $('onayKutu');
const aktifBtn = $('aktifBtn');
const yukleniyor = $('yukleniyor');
const yukMetin = $('yukMetin');
const raporEl = $('rapor');

const SEV_ETIKET = { kritik: 'Kritik', yuksek: 'Yüksek', orta: 'Orta', dusuk: 'Düşük', bilgi: 'Bilgi' };

function yuk(goster, metin = 'Taranıyor…') {
  yukMetin.textContent = metin;
  yukleniyor.classList.toggle('gizli', !goster);
}

async function api(yol, govde) {
  const r = await fetch(yol, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(govde),
  });
  const veri = await r.json();
  if (!r.ok) throw new Error(veri.hata || veri.cozum || 'Bilinmeyen hata');
  return veri;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function raporCiz(veri) {
  const puanRenk = veri.puan >= 90 ? 'var(--iyi)' : veri.puan >= 55 ? 'var(--orta)' : 'var(--kritik)';
  const rozetler = ['kritik', 'yuksek', 'orta', 'dusuk', 'bilgi']
    .filter((s) => veri.ozet[s] > 0)
    .map((s) => `<span class="rozet ${s}">${SEV_ETIKET[s]}: ${veri.ozet[s]}</span>`)
    .join('');

  const bulgular = veri.bulgular.map((b) => `
    <div class="bulgu ${b.onem}">
      <span class="sev">${SEV_ETIKET[b.onem]}</span>
      <h4>${esc(b.baslik)}</h4>
      <p>${esc(b.aciklama)}</p>
      ${b.oneri ? `<p class="oneri">${esc(b.oneri)}</p>` : ''}
    </div>`).join('');

  raporEl.innerHTML = `
    <h2 class="baslik">Rapor — ${esc(veri.hedef)} <small style="color:var(--soluk);font-weight:400">(${veri.tur} tarama)</small></h2>
    <div class="ozet-grid">
      <div class="puan-daire" style="border-color:${puanRenk}">
        <span class="p">${veri.puan}</span><span class="n">Not: ${veri.not}</span>
      </div>
      <div class="rozetler">${rozetler || '<span class="rozet bilgi">Bulgu yok</span>'}</div>
    </div>
    <div class="arac-satir">
      <button onclick="window.print()">🖨️ Yazdır / PDF</button>
      <button id="jsonBtn">⬇️ JSON indir</button>
    </div>
    ${bulgular}
    <p class="ipucu">Tarih: ${esc(veri.tarih)}</p>
  `;
  raporEl.classList.remove('gizli');
  $('jsonBtn').onclick = () => {
    const blob = new Blob([JSON.stringify(veri, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `rapor-${veri.hedef}-${veri.tur}.json`;
    a.click();
  };
  raporEl.scrollIntoView({ behavior: 'smooth' });
}

function hataGoster(msg) {
  raporEl.innerHTML = `<div class="bulgu kritik"><h4>Hata</h4><p>${esc(msg)}</p></div>`;
  raporEl.classList.remove('gizli');
}

pasifBtn.onclick = async () => {
  const url = urlInput.value.trim();
  if (!url) return urlInput.focus();
  yuk(true, 'Pasif tarama ve OSINT toplanıyor…');
  raporEl.classList.add('gizli');
  try {
    raporCiz(await api('/api/scan/passive', { url }));
  } catch (e) { hataGoster(e.message); }
  finally { yuk(false); }
};

tokenBtn.onclick = async () => {
  const url = urlInput.value.trim();
  if (!url) return urlInput.focus();
  yuk(true, 'Doğrulama kodu üretiliyor…');
  try {
    const t = await api('/api/verify/token', { url });
    $('tokenKutu').innerHTML = `
      <p><strong>${esc(t.host)}</strong> için doğrulama. Aşağıdaki yöntemlerden <strong>birini</strong> uygulayın:</p>
      <p><strong>A) DNS TXT kaydı:</strong><br>
        Ad: <code>${esc(t.dnsRecord.name)}</code><br>
        Değer: <code>${esc(t.dnsRecord.value)}</code></p>
      <p><strong>B) Dosya yöntemi:</strong><br>
        Şu adrese: <code>${esc(t.fileMethod.path)}</code><br>
        Şu içerikle: <code>${esc(t.fileMethod.content)}</code></p>`;
    $('tokenKutu').classList.remove('gizli');
    dogrulaBtn.disabled = false;
  } catch (e) { hataGoster(e.message); }
  finally { yuk(false); }
};

dogrulaBtn.onclick = async () => {
  const url = urlInput.value.trim();
  const durum = $('dogrulaDurum');
  yuk(true, 'Sahiplik doğrulanıyor…');
  try {
    const r = await api('/api/verify/check', { url });
    if (r.verified) {
      durum.textContent = `✓ Doğrulandı (${r.method})`;
      durum.className = 'durum ok';
      onayKutu.disabled = false;
    } else {
      durum.textContent = `✗ ${r.reason || 'Doğrulanamadı'}`;
      durum.className = 'durum hata';
    }
  } catch (e) { durum.textContent = e.message; durum.className = 'durum hata'; }
  finally { yuk(false); }
};

onayKutu.onchange = () => { aktifBtn.disabled = !onayKutu.checked; };

aktifBtn.onclick = async () => {
  const url = urlInput.value.trim();
  yuk(true, 'Aktif tarama yapılıyor (portlar ve uç noktalar)…');
  raporEl.classList.add('gizli');
  try {
    raporCiz(await api('/api/scan/active', { url, onay: true }));
  } catch (e) { hataGoster(e.message); }
  finally { yuk(false); }
};

urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') pasifBtn.click(); });
