#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #####################################################################################################################
# IP KAMERA GÜVENLİK DENETİM ARACI
#
# UYARI:
# Bu araç, yalnızca yetkilendirilmiş güvenlik denetimleri için tasarlanmıştır.
# YASAL UYARI: Bu yazılımı yalnızca sahip olduğunuz veya test etme yetkinizin olduğu sistemlerde kullanın.
# Yazılımın yasa dışı veya yetkisiz kullanımı kesinlikle yasaktır. Geliştirici, bu aracın neden
# olabileceği herhangi bir hasar veya yasa dışı faaliyetten sorumlu tutulamaz.
# Sorumluluk tamamen kullanıcıya aittir.
# #####################################################################################################################

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

# Renkli konsol çıktıları için colorama'yı başlat
init(autoreset=True)

def print_status(message, color):
    """Renkli durum mesajı yazdırır."""
    print(f"{color}{message}{Style.RESET_ALL}")

def main():
    """Ana fonksiyon."""
    parser = argparse.ArgumentParser(
        description="Belirli Marka IP Kameralar İçin Varsayılan Kimlik Bilgisi Denetim Aracı",
        epilog="ÖRNEK KULLANIM:\n"
               "python ip_camera_auditor.py iplist.txt\n"
               "python ip_camera_auditor.py iplist.txt --scheme https --user guest --password guest123",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("ip_list", help="Taranacak IP adreslerini içeren dosya (her satırda bir IP veya IP:PORT).")
    parser.add_argument("--scheme", choices=['http', 'https'], default=None,
                        help="Kullanılacak şema (http/https). Belirtilmezse porta göre otomatik seçilir (443->https, diğerleri->http).")
    parser.add_argument("--user", default="admin", help="Denenecek kullanıcı adı (varsayılan: admin).")
    parser.add_argument("--password", default="12345", help="Denenecek parola (varsayılan: 12345).")
    parser.add_argument("--threads", type=int, default=10, help="Eşzamanlı tarama için kullanılacak thread sayısı (varsayılan: 10).")

    args = parser.parse_args()

    print_status("IP Kamera Güvenlik Denetim Aracı Başlatıldı...", Fore.CYAN)
    print_status("UYARI: Bu aracı yalnızca yetkili olduğunuz sistemlerde kullanın.", Fore.YELLOW)

    targets = load_targets(args.ip_list, args.scheme)
    if not targets:
        print_status("Hedef listesi boş veya dosya okunamadı. Çıkılıyor.", Fore.RED)
        sys.exit(1)

    print_status(f"Toplam {len(targets)} hedef tarama için yüklendi.", Fore.GREEN)

    identified_devices = 0
    vulnerable_devices = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {executor.submit(scan_target, target, args.user, args.password): target for target in targets}

        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                is_identified, is_vuln = future.result()
                if is_identified:
                    identified_devices += 1
                if is_vuln:
                    vulnerable_devices += 1
            except Exception as exc:
                print_status(f"HATA: {target} taranırken bir istisna oluştu: {exc}", Fore.RED)

    # Sonuçları raporla
    print_status("\n" + "="*50, Fore.CYAN)
    print_status("TARAMA ÖZETİ".center(50), Fore.CYAN + Style.BRIGHT)
    print_status("="*50 + "\n", Fore.CYAN)
    print_status(f"Taranan Toplam IP Sayısı : {len(targets)}", Fore.WHITE)
    print_status(f"Tespit Edilen Hedef Cihaz Sayısı: {identified_devices}", Fore.GREEN if identified_devices > 0 else Fore.WHITE)
    print_status(f"Zafiyet Bulunan Cihaz Sayısı : {vulnerable_devices}", Fore.RED + Style.BRIGHT if vulnerable_devices > 0 else Fore.WHITE)
    print_status("\n" + "="*50, Fore.CYAN)
    print_status("Tarama Tamamlandı.", Fore.CYAN)


def scan_target(base_url, user, password):
    """
    Tek bir hedefi tarar: önce fingerprinting, sonra credential check.
    (is_identified, is_vulnerable) tuple'ı döndürür.
    """
    is_identified = is_target_brand(base_url)
    if is_identified:
        print_status(f"[!] Hedef Cihaz Tespit Edildi: {base_url}", Fore.GREEN)
        is_vuln = check_credentials(base_url, user, password)
        return True, is_vuln
    else:
        print_status(f"[-] {base_url} hedef marka bir cihaz olarak tanımlanamadı. Atlanıyor.", Fore.YELLOW)
        return False, False


def check_credentials(base_url, user, password):
    """
    Belirtilen yollarda Basic ve Digest kimlik doğrulama yöntemlerini dener.
    Zafiyet bulunursa True, bulunmazsa False döner.
    """
    TEST_PATHS = ['/', '/ISAPI/System/deviceInfo', '/doc/page/login.asp']
    auth_methods = {'Basic': HTTPBasicAuth, 'Digest': HTTPDigestAuth}
    vulnerable = False

    print_status(f"\n--- {base_url} ---", Fore.WHITE)

    for path in TEST_PATHS:
        url = f"{base_url}{path}"
        for auth_name, auth_class in auth_methods.items():
            try:
                r = requests.get(url, auth=auth_class(user, password), timeout=3, verify=False, allow_redirects=True)

                if r.status_code == 200:
                    print_status(f"[+] BAŞARILI: {url} [{auth_name}] -> {user}:{password} (Kod: 200)", Fore.RED)
                    vulnerable = True
                elif r.status_code == 401:
                    print_status(f"[-] Reddedildi: {url} [{auth_name}] (Kod: 401)", Fore.BLUE)
                elif r.status_code == 403:
                    print_status(f"[!] Erişim Yasak: {url} [{auth_name}] (Kod: 403 - Hesap kilitli olabilir)", Fore.MAGENTA)
                elif r.status_code == 404:
                    print_status(f"[!] Yol Bulunamadı: {url} [{auth_name}] (Kod: 404)", Fore.YELLOW)
                else:
                    print_status(f"[?] Diğer Durum: {url} [{auth_name}] (Kod: {r.status_code})", Fore.CYAN)

            except requests.exceptions.Timeout:
                print_status(f"[!] Zaman Aşımı: {url} [{auth_name}]", Fore.YELLOW)
            except requests.exceptions.ConnectionError:
                print_status(f"[!] Bağlantı Hatası: {url} [{auth_name}]", Fore.YELLOW)
            except requests.exceptions.RequestException as e:
                print_status(f"[!] Genel Hata: {url} [{auth_name}] -> {e}", Fore.YELLOW)

    if vulnerable:
        print_status(f"\n[!!!] ZAFİYET BULUNDU: {base_url} varsayılan kimlik bilgileriyle erişilebilir.", Fore.RED + Style.BRIGHT)
    else:
        print_status(f"\n[OK] {base_url} için varsayılan kimlik bilgileri kabul edilmedi.", Fore.GREEN)

    return vulnerable

def is_target_brand(base_url):
    """
    Bir hedefin aranan marka bir cihaz olup olmadığını birden fazla yöntemle doğrular.
    """
    # Parmak izi listeleri
    SERVER_HEADERS = ["Hikvision", "Hikvision-Webs", "App-webs", "HIKVISION"]
    HTML_KEYWORDS = [
        "Hikvision", "Hikvision Webs", "Hikvision Digital Technology",
        "Hikvision Network Camera", "Hikvision NVR", "Hikvision IP Camera",
        "Powered by Hikvision", "iVMS"
    ]
    BANNER_PATHS = ["/doc/page/login.asp", "/doc/page/main.asp"]
    ISAPI_PATH = "/ISAPI/System/deviceInfo"

    # Yöntem 1 & 2: Ana sayfayı kontrol et (Server Header ve HTML İçeriği)
    try:
        r = requests.get(base_url, timeout=3, verify=False, allow_redirects=True)

        # Yöntem 1: Server başlığını kontrol et
        server_header = r.headers.get('Server', '')
        if any(keyword in server_header for keyword in SERVER_HEADERS):
            return True

        # Yöntem 2: HTML içeriğini kontrol et
        html_content = r.text[:3000]
        if any(keyword in html_content for keyword in HTML_KEYWORDS):
            return True

    except requests.exceptions.RequestException:
        pass # Hata durumunda diğer yöntemlere geç

    # Yöntem 3: Özel banner path'lerini kontrol et
    for path in BANNER_PATHS:
        try:
            r = requests.get(f"{base_url}{path}", timeout=3, verify=False, allow_redirects=True)
            # Yönlendirme veya başarılı istek, path'in varlığını gösterir
            if r.status_code == 200 or r.history:
                return True
        except requests.exceptions.RequestException:
            continue

    # Yöntem 4: ISAPI davranış imzasını kontrol et (kimlik bilgisi olmadan)
    try:
        r = requests.get(f"{base_url}{ISAPI_PATH}", timeout=3, verify=False)
        server_header = r.headers.get('Server', '')
        if r.status_code == 401 and "Hikvision" in server_header:
            return True
    except requests.exceptions.RequestException:
        pass

    return False


def load_targets(filename, scheme_arg):
    """
    IP listesi dosyasını okur ve hedef URL listesi oluşturur.
    """
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                ip, port = parse_target(line)
                if not ip: # Eğer parse_target başarısız olduysa, bu satırı atla
                    continue

                scheme = scheme_arg
                if not scheme:
                    scheme = 'https' if port == 443 else 'http'

                targets.append(f"{scheme}://{ip}:{port}")
    except FileNotFoundError:
        print_status(f"HATA: '{filename}' dosyası bulunamadı.", Fore.RED)
        return None
    except Exception as e:
        print_status(f"HATA: '{filename}' dosyası okunurken bir hata oluştu: {e}", Fore.RED)
        return None
    return targets

def parse_target(line):
    """
    'IP' veya 'IP:PORT' formatındaki satırı ayrıştırır.
    """
    if ':' in line:
        parts = line.split(':')
        ip = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            print_status(f"UYARI: Geçersiz port '{parts[1]}'. Satır atlanıyor: {line}", Fore.YELLOW)
            return None, None
    else:
        ip = line
        port = 80
    return ip, port


if __name__ == "__main__":
    # HTTPS isteklerindeki InsecureRequestWarning uyarısını bastır
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main()

# #####################################################################################################################
#
# iplist.txt FORMATI:
#
# Dosya her satırda bir hedef belirtmelidir. Yorum satırları '#' ile başlayabilir.
#
# ÖRNEK:
# # Bu bir yorum satırıdır
# 192.168.1.10
# 192.168.1.11:8080
# 192.168.1.12:443
#
# #####################################################################################################################
