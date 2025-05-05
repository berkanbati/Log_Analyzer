import os
import re
import json
import datetime
import gzip
import shutil
import requests
from collections import defaultdict
from jinja2 import Template
import geoip2.database
from pathlib import Path

# Masaüstü dizin yolu (GeoIP ve raporlar buraya kaydedilir)
MASAUSTU = Path.home() / "Masaüstü"
MASAUSTU.mkdir(exist_ok=True)
MMDB_PATH = MASAUSTU / "GeoLite2-Country.mmdb"

# Alternatif GeoIP kaynakları (lisanssız, otomatik indirme için)
GEOIP_KAYNAKLARI = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://web.archive.org/web/20230130182251/https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz"
]

# GeoIP veritabanını indir ve çıkar
def geoip_indir():
    for url in GEOIP_KAYNAKLARI:
        try:
            print(f"İndiriliyor: {url}")
            dosya_adi = MMDB_PATH.with_suffix(".mmdb.gz") if url.endswith(".gz") else MMDB_PATH
            response = requests.get(url, stream=True, timeout=20)
            response.raise_for_status()
            with open(dosya_adi, "wb") as f:
                for parca in response.iter_content(8192):
                    f.write(parca)
            # Eğer .gz ise çıkar
            if url.endswith(".gz"):
                with gzip.open(dosya_adi, "rb") as f_in:
                    with open(MMDB_PATH, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(dosya_adi)
            print("✅ GeoIP başarıyla indirildi.")
            return True
        except Exception as e:
            print(f"⚠️ Hata: {e}")
    print("❌ GeoIP indirilemedi.")
    return False

# GeoIP hazır mı kontrol et, gerekirse indir
if not MMDB_PATH.exists():
    print("GeoIP veritabanı bulunamadı. İndiriliyor...")
    if not geoip_indir():
        print("⚠️ GeoIP kurulamadı. Ülke bilgileri devre dışı kalacak.")

# GeoIP okuyucusunu başlatır
geoip_okuyucu = geoip2.database.Reader(str(MMDB_PATH)) if MMDB_PATH.exists() else None

# IP'den ülke kodunu alır
def ulke_bilgisi(ip):
    try:
        if geoip_okuyucu:
            sonuc = geoip_okuyucu.country(ip)
            return sonuc.country.iso_code.lower(), sonuc.country.name
    except:
        return "", "Bilinmiyor"
    return "", "Bilinmiyor"

# Desteklenen log yolları (Linux/macOS)
DESTEKLI_LOG_YOLLARI = [
    "/var/log/auth.log",        # Ubuntu/Debian
    "/var/log/secure",          # CentOS/RHEL
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/dpkg.log"
]

# İlk bulunan log dosyasını bul
def log_dosyasi_bul():
    for yol in DESTEKLI_LOG_YOLLARI:
        if os.path.exists(yol):
            return yol
    raise FileNotFoundError("⚠️ Hiçbir desteklenen log dosyası bulunamadı.")

# SSH girişlerini analiz et (başarılı/başarısız)
def ssh_analiz_et(log_path):
    pattern_fail = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
    pattern_success = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

    basarisiz = []
    basarili = []
    brute_force = defaultdict(int)

    with open(log_path, "r", errors="ignore") as f:
        for satir in f:
            if "sshd" not in satir:
                continue

            tarih = datetime.datetime.now().strftime("%Y") + " " + satir[:15]
            try:
                zaman = datetime.datetime.strptime(tarih, "%Y %b %d %H:%M:%S")
            except:
                zaman = ""

            if m := pattern_fail.search(satir):
                ip = m.group("ip")
                user = m.group("user")
                brute_force[ip] += 1
                kod, ad = ulke_bilgisi(ip)
                basarisiz.append({"zaman": zaman, "kullanici": user, "ip": ip, "ulke_kod": kod, "ulke_ad": ad})
            elif m := pattern_success.search(satir):
                ip = m.group("ip")
                user = m.group("user")
                kod, ad = ulke_bilgisi(ip)
                basarili.append({"zaman": zaman, "kullanici": user, "ip": ip, "ulke_kod": kod, "ulke_ad": ad})

    return basarisiz, basarili, brute_force

# HTML rapor oluştur (Jinja2 şablon ile)
def html_rapor_olustur(basarisiz, basarili, brute_force):
    with open("rapor_sablon.html", "r") as f:
        sablon = Template(f.read())
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = sablon.render(
        tarih=now,
        basarisiz=basarisiz,
        basarili=basarili,
        brute_ips=[{"ip": ip, "sayi": sayi} for ip, sayi in brute_force.items() if sayi >= 5]
    )
    with open(MMASAUSTU / "guvenlik_raporu.html", "w") as f:
        f.write(html)
    print("📄 HTML rapor hazır: guvenlik_raporu.html")

# JSON rapor oluşturma
def json_rapor_olustur(basarisiz, basarili, brute_force):
    json_data = {
        "basarisiz_girisler": basarisiz,
        "basarili_girisler": basarili,
        "brute_force_ipler": [{"ip": ip, "sayi": sayi} for ip, sayi in brute_force.items() if sayi >= 5]
    }
    with open(MMASAUSTU / "guvenlik_raporu.json", "w") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print("📄 JSON rapor hazır: guvenlik_raporu.json")

# Ana işlem
if __name__ == "__main__":
    try:
        log_yolu = log_dosyasi_bul()
        print(f"🔍 İncelenen log dosyası: {log_yolu}")
        basarisiz, basarili, brute = ssh_analiz_et(log_yolu)
        html_rapor_olustur(basarisiz, basarili, brute)
        json_rapor_olustur(basarisiz, basarili, brute)
        print("✅ Analiz tamamlandı.")
    except Exception as e:
        print(f"❌ Hata: {e}")
