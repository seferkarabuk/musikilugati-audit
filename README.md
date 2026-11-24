# musikilugati-audit
musikilugati.com için güvenlik, SEO, performans ve erişilebilirlik denetim altyapısı

## Denetimler

- Lighthouse ile performans, erişilebilirlik, SEO ve en iyi uygulamalar
- Aynı alan adı altında sınırlı sayıda sayfa taraması ve bozuk bağlantı kontrolü
- Güvenlik başlıkları, çerez bayrakları ve karışık HTTP içeriği kontrolü
- robots.txt, sitemap.xml, title, meta description, canonical ve H1 kontrolleri
- Ana sayfadaki resimler için temel alt metni kontrolü

## Çalıştırma

GitHub Actions sekmesinden `Weekly comprehensive audit` iş akışını elle çalıştırabilirsiniz.
İş akışı ayrıca her Pazartesi saat 06:00 UTC'de otomatik çalışır.

Yerel çalışma:

```bash
npm ci
npx lighthouse https://musikilugati.com \
  --chrome-flags="--headless --no-sandbox" \
  --output=json \
  --output-path=reports/lighthouse.json \
  --only-categories=performance,seo,accessibility,best-practices
npm run audit
```

Raporlar `reports/audit.json`, `reports/lighthouse.json` ve `AUDIT_SUMMARY.md` içinde oluşur.
