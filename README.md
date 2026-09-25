# Güvenlik & OSINT Rapor

Bir web sitesi adresi girildiğinde, **yasal sınırlar içinde** kapsamlı bir güvenlik
taraması ve OSINT (açık kaynak istihbarat) raporu üreten web uygulaması.
Sıfır bağımlılık, saf Node.js ile yazılmıştır (tedarik zinciri riski yoktur).

## Özellikler

### Pasif tarama + OSINT (her URL için)
Yalnızca herkese açık bilgileri toplar; hedefe zarar vermez:
- **DNS kayıtları**: A, AAAA, MX, NS, TXT, CNAME, SOA
- **E-posta güvenliği**: SPF ve DMARC kayıt kontrolü
- **TLS/SSL sertifikası**: geçerlilik, süre, protokol sürümü, yayıncı
- **HTTP güvenlik başlıkları**: HSTS, CSP, X-Frame-Options vb. eksik/var analizi
- **Bilgi sızıntısı**: Server, X-Powered-By gibi başlıklar
- **Teknoloji izi**: kullanılan CMS/çatı tespiti (imza tabanlı)
- **OSINT**: sayfada görünür e-postalar, sosyal medya bağlantıları, başlık/meta
- **robots.txt** ve **security.txt** kontrolü

### Aktif tarama (yalnızca sahiplik doğrulandıktan sonra)
İzinsiz aktif tarama yasal sorumluluk doğurabileceğinden, bu araç aktif taramayı
**yalnızca alan adı sahipliği kanıtlandıktan** ve kullanıcı **açık onay** verdikten
sonra çalıştırır:
1. Sistem bir doğrulama kodu üretir.
2. Kullanıcı bu kodu **DNS TXT kaydı** olarak veya `/.well-known/gosr-verify.txt`
   **dosyası** olarak yayınlar.
3. Sistem sahipliği doğrular.
4. Onay kutusu işaretlenince aktif tarama açılır:
   - Yaygın portların açık/kapalı durumu (yük bindirmeden, düşük eşzamanlılık)
   - Standart hassas uç noktaların (ör. `/.git/config`, `/.env`) erişilebilirliği

Aktif tarama kapsamı bilinçli olarak dardır: **sömürü, kaba kuvvet, yük testi veya
zafiyet istismarı yapılmaz.**

## Rapor
- 0–100 güvenlik puanı ve A–F notu
- Önem seviyesine göre sıralı bulgular (kritik → bilgi) ve her biri için öneri
- Türkçe arayüz ve rapor
- PDF (yazdır) ve JSON dışa aktarma

## Çalıştırma
```bash
npm start
# http://localhost:3000
```
Node.js 18+ gerekir. Harici bağımlılık yoktur.

## Güvenlik notları
- SSRF koruması: yerel/özel IP aralıkları (`127.0.0.0/8`, `10/8`, `192.168/16` vb.)
  ve `localhost` taranamaz.
- IP başına dakikada istek sınırı vardır.
- Token deposu bellek içidir; üretimde kalıcı bir depoyla değiştirilmelidir.

## Yasal uyarı
Bu araç yalnızca **yetkili güvenlik değerlendirmesi ve eğitim** amaçlıdır. Size ait
olmayan sistemlerde aktif tarama yapmak yasa dışı olabilir. Sorumlu ve yasal kullanım
tamamen kullanıcıya aittir.
