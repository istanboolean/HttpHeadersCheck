#!/usr/bin/env python3

import argparse # Argümanları işlemek için
from rich.console import Console # Kullanıcı dostu çıktı için
from rich.table import Table # Kullanıcı dostu çıktı için
from rich.text import Text # Kullanıcı dostu çıktı için
import requests # HTTP istekleri için
import ipaddress # IP adreslerini işlemek için
from urllib.parse import urlparse # URL'leri işlemek için
import urllib3 # SSL Hatasını Giderme (SSL: CERTIFICATE_VERIFY_FAILED)
# SSL Hatasını Giderme (SSL: CERTIFICATE_VERIFY_FAILED) Hata mesajını gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import codecs

def print_logo():
    logo = """
  _   _ _____ _____ ____     _   _ _____    _    ____  _____ ____  ____     ____ _   _ _____ ____ _  __
 | | | |_   _|_   _|  _ \   | | | | ____|  / \  |  _ \| ____|  _ \/ ___|   /___| | | | ____/ ___| |/ /
 | |_| | | |   | | | |_) |  | |_| |  _|   / _ \ | | | |  _| | |_) \___ \  | |   | |_| |  _|| |   | ' / 
 |  _  | | |   | | |  __/   |  _  | |___ / ___ \| |_| | |___|  _ < ___) | | |___|  _  | |__| |___| . \ 
 |_| |_| |_|   |_| |_|      |_| |_|_____/_/   \_\____/|_____|_| \_\____/   \____|_| |_|_____\____|_|\_\_
                                                                                                       
                                                                            PurpleBox | istanboolean"""

    # Logonun kodlamasını utf-8 olarak ayarlayın.
    logo_encoded = logo.encode("utf-8")

    # Logonuzu yazdırmak için codecs modülünü kullanın.
    print(codecs.decode(logo_encoded, "utf-8"))

print_logo()

security_headers = {
    'X-Content-Type-Options': {
        'recommended': True,
        'directives': ['nosniff'],
    },
    'X-Frame-Options': {
        'recommended': True,
        'directives': ['deny', 'sameorigin', 'allow-from'],
    },
    'Strict-Transport-Security': {
        'recommended': True,
        'directives': ['max-age=31536000'],
    },
    'Content-Security-Policy': {
        'recommended': True,
        'directives': ['default-src', 'script-src', 'img-src', 'style-src', 'font-src', 'connect-src', 'report-uri'],
    },
    'X-XSS-Protection': {
        'recommended': False,
        'directives': ['1; mode=block'],
    },
    'Referrer-Policy': {
        'recommended': True,
        'directives': ['no-referrer', 'origin', 'same-origin', 'strict-origin', 'origin-when-cross-origin'],
    },
    'Feature-Policy': {
        'recommended': True,
        'directives': ['accelerometer', 'ambient-light-sensor', 'autoplay', 'camera', 'clipboard-read', 'clipboard-write', 'geolocation', 'gyroscope', 'magnetometer', 'microphone', 'midi', 'payment', 'push', 'screen-orientation', 'speaker', 'usb'],
    },

    # Eklemek istediğiniz başlıkları buraya ekleyebilirsiniz.
}

# Argümanları tanımla
parser = argparse.ArgumentParser(description="HTTP Response Headers Kontrol Aracı")
parser.add_argument(
    "-d",
    "--domain",
    metavar="DOMAIN",
    help="HTTP başlıkları kontrol edilecek olan domain adresi",
)
parser.add_argument(
    "-t",
    "--target-ip",
    metavar="TARGET_IP",
    help="HTTP başlıkları kontrol edilecek olan hedef IP adresi",
)
parser.add_argument(
    "-c",
    "--check",
    nargs="+",
    metavar="HEADER",
    help="HTTP başlıklarını kontrol etmek için başlık adları belirtin. Örn. -c Header1 Header2",
)
parser.add_argument(
    "-C",
    "--check-all",
    action="store_true",
    help="Tüm HTTP başlıklarını kontrol etmek için kullanın.",
    # -h parametresi argparser içindeki --help modülünü çalıştırır. 
)

# Argümanları işle
args = parser.parse_args()

# Kullanıcı dostu çıktı için Rich kütüphanesi kullan
console = Console()

def normalize_url(url):
        if url == args.target_ip:
            url = args.target_ip
        else:
            url = args.domain
        try:
            ip_address = ipaddress.ip_address(url) 
            url = f"https://{url}"
        except ValueError:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url  
            else:
                url = url
        return url

def get_response_headers(url):
    try:
        url = normalize_url(url)  # URL'yi düzeltilmiş bir versiyonuyla güncelle
        response = requests.get(url, verify=False)  # SSL sertifikası doğrulamasını devre dışı bırak
        response_headers = response.headers
        return response_headers
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Hata:[/bold red] {e}")
        return None

def check_headers(headers_to_check, response_headers):
    if not response_headers:
        return [], []
    headers_found = []
    headers_not_found = []
    for header in headers_to_check:
        if header in response_headers:
            header_value = response_headers[header]
        else:
            header_value = None
        description_result = get_header_description(header, header_value)
        if header_value:
            headers_found.append((header, header_value, description_result))
        else:
            headers_not_found.append((header, "Not found", description_result))
    return headers_found, headers_not_found


def get_header_description(header_name, header_value):
    security_headers = {
    'X-Content-Type-Options': {
        'default_value': 'nosniff',
        'description': """Saldırganlar, web sitesinin yanıtlarında bulunan içerik türlerini değiştirerek, tarayıcının yanıtı yanlış yorumlamasını ve saldırganın kodunu çalıştırmasını sağlayabilir.
X-Content-Type-Options: nosniff (Bu başlık, tarayıcının yanıtı yanlış yorumlamasını ve saldırganın kodunu çalıştırmasını önlemek için, yanıtın MIME türünü analiz etmesini engeller.)
\033[93mX-Content-Type-Options:nosniff\033[0m önemli bir güvenlik önlemidir. Önerilen değerdir.
"""
    },
    'X-Frame-Options': {
        'default_value': 'deny',
        'description': """Bu başlık, web sitesinin çerçevelenmesine izin verilip verilmeyeceğini kontrol eder. Güvenli yönergeler şunlardır:
\033[93mSAMEORIGIN:\033[0m Sayfanın yalnızca orijinal kaynağında çerçevelerde görüntülenmesine izin verilir. 
\033[93mDENY:\033[0m Sayfanın hiçbir çerçevede görüntülenmesine izin verilmez. Katı bir security policy gerektiren durumlarda kullanılabilir. Bu, en güvenli seçenektir.
\033[93mALLOW-FROM:\033[0m Sayfanın yalnızca belirli bir kaynaktan çerçevelerde görüntülenmesine izin verilir. Örneğin, ALLOW-FROM https://example.com/ ile ayarlanırsa, 
sayfa yalnızca https://example.com/ içinde çerçevelerde görüntülenebilir."""
    },
    'Strict-Transport-Security': {
        'default_value': 'max-age=31536000',
        'description': """HTTPS üzerinden erişimi zorunlu kılar. Bu, saldırganların HTTP üzerinden saldırmasını zorlaştırır. 
HTTPS kullanımını zorlamak ve sertifikayı bir yıl boyunca hatırlamak için "max-age=31536000" ile ayarlanmalıdır.
\033[93mmax-age:\033[0m HSTS başlığının ne kadar süreyle geçerli olacağını belirtir. Bu örnekte, HSTS başlığı 1 yıl (31536000 saniye) boyunca geçerli olacaktır.
\033[93mincludeSubDomains:\033[0m HSTS başlığının sitenin tüm alt etki alanlarını da kapsayacağını belirtir. Bu, saldırganların HTTP üzerinden alt etki alanlarından saldırmasını zorlaştırır.
\033[93mpreload:\033[0m Tarayıcıların HSTS başlığını önbelleğe almasını sağlar. Bu, kullanıcıların web sitesine ilk kez eriştiklerinde bile HTTPS üzerinden erişmelerini sağlar. """
    },
    'X-XSS-Protection': {
        'default_value': '1; mode=block',
        'description': """Tarayıcıyı otomatik olarak XSS saldırılarını engellemek için "1; mode=block" ile ayarlanmalıdır.
\033[93m0:\033[0m XSS koruması devre dışı bırakılır.
\033[93m1:\033[0m XSS koruması etkinleştirilir, ancak tarayıcının kendi XSS korumasını kullanmaya devam etmesine izin verilir.
\033[93m1;\033[0m mode=block: XSS koruması etkinleştirilir ve tarayıcının kendi XSS korumasını kullanmasına izin verilmez. Bu, en güvenli seçenektir."""
    },
    'Content-Security-Policy': {
        'default_value': '',
        'description': """Bu başlık, web sayfasının tarayıcıda yüklenirken hangi kaynaklara (örneğin, betikler, görüntüler, stil dosyaları) erişebileceğini belirler. 
Web sitenizi XSS, CSRF, SQL injection ve diğer saldırılara karşı daha güvenli hale getirir.
web sitesinin tarayıcıda yüklenirken hangi kaynaklara erişebileceğini kontrol eden bir HTTP başlığıdır. CSP, XSS, CSRF, SQL injection ve diğer saldırılara karşı sitenizi daha güvenli hale getirebilir.

'default-src' direktifi, web sayfasının tarayıcıda yüklenirken hangi kaynaklara erişebileceğini belirler. Varsayılan değer 'self', yani yalnızca aynı kaynaktan gelen kaynaklara erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklara erişime izin veren 'script-src', 'img-src', 'style-src', 'font-src' ve 'connect-src' direktiflerini kullanmaktır.

'script-src' direktifi, web sayfasının hangi betiklere erişebileceğini belirler. 'self', yalnızca aynı kaynaktan gelen betiklere erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklardan gelen betiklere erişime izin veren 'https://example.com' gibi bir URL belirtmektir.

'img-src' direktifi, web sayfasının hangi görüntülere erişebileceğini belirler. 'self', yalnızca aynı kaynaktan gelen görüntülere erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklardan gelen görüntülere erişime izin veren 'https://example.com' gibi bir URL belirtmektir.

'style-src' direktifi, web sayfasının hangi stil dosyalarına erişebileceğini belirler. 'self', yalnızca aynı kaynaktan gelen stil dosyalarına erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklardan gelen stil dosyalarına erişime izin veren 'https://example.com' gibi bir URL belirtmektir.

'font-src' direktifi, web sayfasının hangi yazı tiplerine erişebileceğini belirler. 'self', yalnızca aynı kaynaktan gelen yazı tiplerine erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklardan gelen yazı tiplerine erişime izin veren 'https://example.com' gibi bir URL belirtmektir.

'connect-src' direktifi, web sayfasının hangi ağ bağlantılarına erişebileceğini belirler. 'self', yalnızca aynı kaynaktan gelen ağ bağlantılarına erişilebilir. Daha güvenli bir seçenek, yalnızca belirli kaynaklardan gelen ağ bağlantılarına erişime izin veren 'https://example.com' gibi bir URL belirtmektir.

'report-uri' direktifi, CSP ihlallerinin bildirileceği bir URL belirtir. Bu direktifi kullanarak, CSP ihlallerini izleme ve bunları düzeltmek için adımlar atabilirsiniz. 
Örnek kullanım: "default-src 'self'; script-src 'self' scripts.example.com; img-src *; style-src 'self' styles.example.com" """
    },
    'Content-Security-Policy-Report-Only': {
    'default_value': '',
    'description': """Bu başlık, bir web sayfasının tarayıcıda yüklenirken hangi kaynaklara (örneğin, betikler, görüntüler, stil dosyaları) erişebileceğini belirler, ancak tarayıcıda CSP ihlalleri oluştuğunda sadece raporlama yapar, yasaklama veya engelleme işlemi uygulamaz. Bu sayede, CSP politikalarınızı test edebilir ve olası ihlalleri izleyebilirsiniz.
    Örnek kullanım: "default-src 'self'; script-src 'self' scripts.example.com; report-uri /csp-report-endpoint;" """
},
    'Referrer-Policy': {
        'default_value': 'no-referrer',
        'description': """Bu başlık, bir web sitesinin bir başka web sitesine bir bağlantı gönderirken referans bilgisini (referrer) gönderip göndermeyeceğini kontrol eder.
\033[93mno-referrer:\033[0m Referans bilgisini tamamen engeller. origin: Referans bilgisini, yalnızca bağlantının geldiği web sitesine gönderir.
\033[93msame-origin:\033[0m Referans bilgisini, yalnızca aynı kaynaktan gelen bağlantılara gönderir.strict-origin: Referans bilgisini, yalnızca aynı kaynaktan gelen bağlantılara gönderir ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da gönderir.
\033[93morigin-when-cross-origin:\033[0m Referans bilgisini, yalnızca farklı kaynaklardan gelen bağlantılara gönderir ve ayrıca bağlantının geldiği web sitesinin protokolünü, sunucu adresini ve portunu da gönderir."""
    },
    'Feature-Policy': {
        'default_value': '',
        'description': """Bu headers web sitesinin kullanıcının cihazındaki hangi özelliklerin kullanılabileceğini kontrol eden bir HTTP başlığıdır.Özellik politikası belirtilmelidir.
\033[93mself:\033[0m Özelliğin veya API'nin yalnızca kendi kaynak tarafından kullanılmasına izin verir.
\033[93mnone:\033[0m Özelliğin veya API'nin hiç kullanılmasına izin vermez.
\033[93m*:\033[0m Özelliğin veya API'nin her kaynak tarafından kullanılmasına izin verir.
Feature-Policy: camera 'none'; microphone 'none'; geolocation 'none' Bu, kamera, mikrofon ve konumunuzun kullanılmasını tamamen engeller."""
    },
    'Permissions-Policy': {
        'default_value': '',
        'description': 'İzin politikası belirtilmelidir.'
    },
    
    # Diğer güvenlik başlıkları buraya eklenebilir.
}

    if header_name in security_headers:
        if header_value is None:
            return f'{header_name} başlığı eksik, doğru değeri olan "{security_headers[header_name]["default_value"]}" ile ayarlanmalıdır.'
        else:
            return f'{security_headers[header_name]["description"]}'
    else:
        return 'Bu başlık için açıklama bulunamadı.'

def main():
    # Kullanım talimatlarını ve parametreleri göster
    if args.domain:
        console.print(f"[bold green]Geçerli Domain:[/bold green] {args.domain}")
        url = args.domain
        response_headers = get_response_headers(url)
        args.print = True
        if response_headers and args.print:
            console.print("\n[bold cyan]HTTP Response Headers[/bold cyan]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Başlık", style="bold green")
            table.add_column("Değer", style="bold white")
            for key, value in response_headers.items():
                table.add_row(key, value)
            console.print(table)
        if args.check or args.check_all:
            headers_to_check = args.check if args.check else list(security_headers.keys())
            headers_found, headers_not_found = check_headers(headers_to_check, response_headers)
            console.print("\n[bold cyan]Başlık Kontrolleri (HEADERS and DIRECTIVES)[/bold cyan]\n")
            table_found = Table(show_header=True, header_style="bold cyan")
            table_found = Table(show_lines=True, header_style="bold cyan")
            table_found.add_column("Başlık", style="bold green")
            table_found.add_column("Değer", style="bold white")
            table_found.add_column("Açıklama", style="bold white")
            for header, value, _ in headers_found:
                description_result = get_header_description(header, value)
                table_found.add_row(header, value, "[bold green]OK[/bold green] - " + description_result)
            console.print(table_found)

            console.print("\n[bold cyan]Başlık Kontrolleri (HEADERS)[/bold cyan]\n")
            table_not_found = Table(show_header=True, header_style="bold cyan")
            table_not_found = Table(show_lines=True, header_style="bold cyan")
            table_not_found.add_column("Başlık", style="bold red")
            table_not_found.add_column("Değer", style="bold yellow")
            table_not_found.add_column("Açıklama", style="bold white")
            for header, value, _ in headers_not_found:
                description_result = get_header_description(header, value)
                table_not_found.add_row(header, value, "[bold red]Eksik[/bold red] - " + description_result)
            console.print(table_not_found)
    elif args.target_ip:
        console.print(f"[bold green]Geçerli Hedef IP:[/bold green] {args.target_ip}")
        url = args.target_ip
        response_headers = get_response_headers(url)
        args.print = True
        if response_headers and args.print:
            console.print("\n[bold cyan]HTTP Response Headers[/bold cyan]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Başlık", style="bold green")
            table.add_column("Değer", style="bold white")
            for key, value in response_headers.items():
                table.add_row(key, value)
            console.print(table)
        if args.check or args.check_all:
            headers_to_check = args.check if args.check else list(security_headers.keys())
            headers_found, headers_not_found = check_headers(headers_to_check, response_headers)
            console.print("\n[bold cyan]Başlık Kontrolleri (Başlığı Olanlar)[/bold cyan]\n")
            table_found = Table(show_header=True, header_style="bold cyan")
            table_found = Table(show_lines=True, header_style="bold cyan")
            table_found.add_column("Başlık", style="bold green")
            table_found.add_column("Değer", style="bold white")
            table_found.add_column("Açıklama", style="bold white")
            for header, value, _ in headers_found:
                description_result = get_header_description(header, value)
                table_found.add_row(header, value, "[bold green]OK[/bold green] - " + description_result)

            console.print(table_found)

            console.print("\n[bold cyan]Başlık Kontrolleri (Başlığı Olmayanlar)[/bold cyan]\n")
            table_not_found = Table(show_header=True, header_style="bold cyan")
            table_not_found = Table(show_lines=True, header_style="bold cyan")
            table_not_found.add_column("Başlık", style="bold red")
            table_not_found.add_column("Değer", style="bold yellow")
            table_not_found.add_column("Açıklama", style="bold white")
            for header, value, _ in headers_not_found:
                description_result = get_header_description(header, value)
                table_not_found.add_row(header, value, "[bold red]Eksik[/bold red] - " + description_result)
            console.print(table_not_found)
    else:
        console.print("[bold cyan]KOD KULLANIMI[/bold cyan]")
        console.print("=" * 30)
        console.print(
            """Bu tool, belirtilen bir domain veya hedef IP adresi için HTTP yanıt başlıklarını görüntüler.
Aynı zamanda eksik ve yanlış yapılandırılmış başlıklar hakkında çözüm önerileri sunar."""
        )
        console.print("\n[bold cyan]PARAMETRELER VE KULLANIMI[/bold cyan]")
        console.print("=" * 45)
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Parametre", style="bold red")
        table.add_column("Açıklama", style="bold white")
        table.add_row("-h ", "Help kütüphanesini getirir.")
        table.add_row("-d DOMAIN", "Domain adresini belirlemek için kullanılır.")
        table.add_row("-t TARGET_IP", "Hedef IP adresini belirlemek için kullanılır.")
        table.add_row("-c HEADER [HEADER ...]", "HTTP başlıklarını kontrol etmek için başlık adları belirtin. Örn. -c Header1 Header2")
        table.add_row("-C", "Tüm HTTP başlıklarını kontrol etmek için kullanın.")
        console.print(table)
        console.print("\n[bold cyan]KULLANIM ÖRNEKLERİ[/bold cyan]")
        console.print("=" * 30)
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Kullanım Örneği", style="bold red")
        table.add_column("Komut", style="bold white")
        table.add_row("Domain kontrolü örneği", "python3 httpcheck.py -d www.example.com")
        table.add_row("Hedef IP kontrolü örneği", "python3 httpcheck.py -t 192.168.1.1")
        table.add_row("Belirli başlıkları kontrol etme örneği", "python3 httpcheck.py -d www.example.com -c Server Date")
        table.add_row("Tüm başlıkları kontrol etme örneği", "python3 httpcheck.py -d example.com -C")
        console.print(table)

if __name__ == "__main__":
    main()
