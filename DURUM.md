# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-on-weak` / `--fail-on-pwned` eklendi

- Konu: İki bayrak eklendi — `--fail-on-weak` (verdict Weak ise çıkış kodu 1) ve `--fail-on-pwned` (HIBP'de bulunursa çıkış kodu 1). Hesap oluşturma/parola sıfırlama akışlarında gate olarak kullanılabilir.
- 4 yeni test eklendi (9 → 13), hepsi geçti. Ruff temiz. Gizlilik davranışı değişmedi (parola hâlâ hiçbir zaman diske/loga yazılmıyor).
- Durum: ✅ Henüz push edilmedi.

**Sıradaki iş:** GitHub'da `Password-Hygiene-Checker` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `password-hygiene-checker` komutu), `--format json` eklendi (gizlilik kuralı korunarak), ruff lint + CI lint job'u eklendi.
- Durum: ✅ Tüm testler geçiyor (9/9), ruff temiz, kurulum/çalıştırma/kaldırma gerçekten doğrulandı (sonrasında sistemden tamamen kaldırıldı, iz bırakılmadı).

**Sıradaki iş:** GitHub'da `Password-Hygiene-Checker` adıyla repo aç, git init + push.

---

## 2026-08-20 — İlk sürüm oluşturuldu

- Konu: Parola gücü + HIBP k-anonymity sızıntı kontrolü yapan CLI, testleri ve CI ile birlikte hazırlandı.
- Durum: ✅ Çalışıyor, 7/7 test geçti. Gerçek HIBP API çağrısı bu ortamda çalıştı (weak demo parola 2.266.543 sızıntıda bulundu, strong demo parola bulunmadı).
- Gizlilik notu: Script parolayı hiçbir zaman diske/loga yazmıyor; sadece skor/verdict/breach-count kaydediliyor (test ile doğrulandı).

**Sıradaki iş:** GitHub'da `Password-Hygiene-Checker` adıyla repo aç, git init + push.
