# 📊 Gelişmiş Linux Log Analiz Aracı

Bu proje, Linux sistemlerdeki auth.log, secure, syslog, kern.log gibi log dosyalarını analiz ederek SSH girişlerini, brute-force saldırılarını ve şüpheli IP aktivitelerini tespit eder. Ayrıca HTML ve JSON formatında detaylı bir güvenlik raporu oluşturur.

## 🚀 Özellikler

SSH başarısız/başarılı girişlerin tespiti

Brute-force saldırılarına karşı IP analizi

IP'lerin ülke/bayrak bilgisi (GeoIP)

HTML + JSON rapor çıktısı

Otomatik log dosyası bulma (Ubuntu, Debian, CentOS, macOS desteği)

GeoIP veritabanını otomatik indirir (alternatif kaynaklarla)

# 🔧 Gereksinimler

- Python 3.7+

- Aşağıdaki kütüphaneler:


```bash
pip install geoip2 jinja2 requests pytz
```

## 🖥️ Kurulum Adımları

## 1. Projeyi klonlayın veya dosyaları indirin
```bash
https://github.com/berkanbati/Log_Analyzer.git
cd Log_Analyzer
```
## 2. Bağımlılıkları yükleyin
```bash
pip install geoip2 jinja2 requests pytz
```
## 3. log_analiz.py dosyasını çalıştırın
```bash
python3 log_analiz.py
```
Raporlar otomatik olarak masaüstüne (Masaüstü/Desktop klasörü) kaydedilir.

# 🌍 GeoIP Veritabanı
- Kod ilk çalıştırıldığında GeoLite2-Country.mmdb dosyasını otomatik indirir.
- Eğer bağlantı kurulamazsa bu arşiv bağlantısı kullanılır.
Alternatif olarak manuel olarak GeoLite2-Country.mmdb dosyasını masaüstüne koyabilirsiniz.

# 📂 Rapor Örnekleri
- guvenlik_raporu.html: Tarayıcıda açılabilir görsel rapor. HTML uzantısında vermektedir.
- guvenlik_raporu.json: JSON çıktısı

# 📌 Notlar
- Sadece Linux/macOS sistemlerde çalışır.
- Log dosyalarının okunabilmesi için sudo/root yetkisi gerekebilir.
- Tarayıcıda saat dilimi algılanır, istenirse kullanıcı manuel de seçebilir.

# 🤝 Katkı Sağlama
- İyileştirmeler, hatalar veya yeni özellikler için pull request gönderebilirsiniz ✨
