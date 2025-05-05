import os
import re
import json
import datetime
import gzip
import shutil
import requests
from pathlib import Path
from collections import defaultdict
from jinja2 import Template

try:
    import geoip2.database
except ImportError:
    print("Eksik modül: pip install geoip2 jinja2 requests")
    exit()

# Masaüstü yolu
MASAUSTU = Path.home() / ("Masaüstü" if (Path.home() / "Masaüstü").exists() else "Desktop")
MASAUSTU.mkdir(exist_ok=True)
MMDB_PATH = MASAUSTU / "GeoLite2-Country.mmdb"

# GeoIP kaynakları
GEOIP_KAYNAKLARI = [
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://web.archive.org/web/20230130182251/https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz"
]

# GeoIP indir
def geoip_indir():
    for url in GEOIP_KAYNAKLARI:
        try:
            print(f"📦 İndiriliyor: {url}")
            hedef = MMDB_PATH.with_suffix(".mmdb.gz") if url.endswith(".gz") else MMDB_PATH
            r = requests.get(url, stream=True, timeout=20)
            r.raise_for_status()
            with open(hedef, "wb") as f:
                for parca in r.iter_content(8192):
                    f.write(parca)
            if url.endswith(".gz"):
                with gzip.open(hedef, "rb") as f_in, open(MMDB_PATH, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(hedef)
            print("✅ GeoIP indirildi.")
            return True
        except Exception as e:
            print(f"❌ Hata: {e}")
    return False

# GeoIP başlat
if not MMDB_PATH.exists():
    if not geoip_indir():
        print("⚠️ GeoIP başarısız.")
        geoip_okuyucu = None
    else:
        geoip_okuyucu = geoip2.database.Reader(str(MMDB_PATH))
else:
    geoip_okuyucu = geoip2.database.Reader(str(MMDB_PATH))

def ulke_bilgisi(ip):
    try:
        if geoip_okuyucu:
            res = geoip_okuyucu.country(ip)
            return res.country.iso_code.lower(), res.country.name
    except:
        return "", "Bilinmiyor"
    return "", "Bilinmiyor"

# ISO 8601 formatından tarih çek
def parse_datetime_from_log(line):
    try:
        match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
        if match:
            return match.group(1)
    except:
        return ""
    return ""

# Tüm log yolları
DESTEKLI_LOG_YOLLARI = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/messages",
    "/var/log/syslog", "/var/log/auth.log.1", "/var/log/secure.1",
    "/private/var/log/asl.log"
]

# .gz logları ekle
for path in Path("/var/log").glob("auth.log.*.gz"):
    DESTEKLI_LOG_YOLLARI.append(str(path))
for path in Path("/var/log").glob("secure.*.gz"):
    DESTEKLI_LOG_YOLLARI.append(str(path))

# İlk log dosyasını bul
def log_dosyasi_bul():
    for yol in DESTEKLI_LOG_YOLLARI:
        if os.path.exists(yol):
            if yol.endswith(".gz"):
                with gzip.open(yol, "rt", errors="ignore") as f_in, open("/tmp/logtemp", "w") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                return "/tmp/logtemp"
            return yol
    raise FileNotFoundError("Log dosyası bulunamadı.")

# SSH analiz
def ssh_analiz_et(log_path):
    fail_pat = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
    ok_pat = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
    basarisiz, basarili = [], []
    brute_force = defaultdict(int)

    with open(log_path, "r", errors="ignore") as f:
        for satir in f:
            if "sshd" not in satir:
                continue
            timestamp = parse_datetime_from_log(satir)
            if not timestamp:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            if m := fail_pat.search(satir):
                ip, user = m.group("ip"), m.group("user")
                kod, ad = ulke_bilgisi(ip)
                brute_force[ip] += 1
                basarisiz.append({
                    "timestamp": timestamp,
                    "zaman": timestamp,
                    "kullanici": user,
                    "ip": ip,
                    "ulke_kod": kod,
                    "ulke_ad": ad
                })
            elif m := ok_pat.search(satir):
                ip, user = m.group("ip"), m.group("user")
                kod, ad = ulke_bilgisi(ip)
                basarili.append({
                    "timestamp": timestamp,
                    "zaman": timestamp,
                    "kullanici": user,
                    "ip": ip,
                    "ulke_kod": kod,
                    "ulke_ad": ad
                })
    return basarisiz, basarili, brute_force

# HTML rapor
def html_rapor_olustur(basarisiz, basarili, brute):
    with open("rapor_sablon.html", encoding="utf-8") as f:
        tpl = Template(f.read())
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = tpl.render(
        tarih=now,
        basarisiz=basarisiz,
        basarili=basarili,
        brute_ips=[{"ip": ip, "sayi": sayi} for ip, sayi in brute.items() if sayi >= 5]
    )
    with open(MASAUSTU / "guvenlik_raporu.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("✅ HTML raporu: guvenlik_raporu.html")

# JSON rapor
def json_rapor_olustur(basarisiz, basarili, brute):
    rapor = {
        "basarisiz": basarisiz,
        "basarili": basarili,
        "brute_force": [{"ip": ip, "sayi": sayi} for ip, sayi in brute.items() if sayi >= 5]
    }
    with open(MASAUSTU / "guvenlik_raporu.json", "w", encoding="utf-8") as f:
        json.dump(rapor, f, indent=2, ensure_ascii=False)
    print("✅ JSON raporu: guvenlik_raporu.json")

# Main
def main():
    try:
        log_path = log_dosyasi_bul()
        print(f"🔍 Log: {log_path}")
        basarisiz, basarili, brute = ssh_analiz_et(log_path)
        html_rapor_olustur(basarisiz, basarili, brute)
        json_rapor_olustur(basarisiz, basarili, brute)
        print("🎉 Tüm işlemler tamamlandı.")
    except Exception as e:
        print(f"❌ Hata: {e}")

if __name__ == "__main__":
    main()
