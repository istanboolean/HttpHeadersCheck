#!/usr/bin/env python3

import argparse # Argümanları işlemek için
from rich.console import Console # Kullanıcı dostu çıktı için
from rich.table import Table # Kullanıcı dostu çıktı için
import requests # HTTP istekleri için
import ipaddress # IP adreslerini işlemek için
from urllib.parse import urlparse # URL'leri işlemek için
import urllib3 # SSL Hatasını Giderme (SSL: CERTIFICATE_VERIFY_FAILED)
# SSL Hatasını Giderme (SSL: CERTIFICATE_VERIFY_FAILED) Hata mesajını gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("""
  _   _ _____ _____ ____     _   _ _____    _    ____  _____ ____  ____     ____ _   _ _____ ____ _  __
 | | | |_   _|_   _|  _ \   | | | | ____|  / \  |  _ \| ____|  _ \/ ___|   / ___| | | | ____/ ___| |/ /
 | |_| | | |   | | | |_) |  | |_| |  _|   / _ \ | | | |  _| | |_) \___ \  | |   | |_| |  _|| |   | ' / 
 |  _  | | |   | | |  __/   |  _  | |___ / ___ \| |_| | |___|  _ < ___) | | |___|  _  | |__| |___| . \ 
 |_| |_| |_|   |_| |_|      |_| |_|_____/_/   \_\____/|_____|_| \_\____/   \____|_| |_|_____\____|_|\_\_
                                                                                                       
                                                                            PurpleBox | istanboolean""")


default_headers = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Feature-Policy",
    "Content-Security-Policy-Report-Only",
    "Cache-Control",
    "Clear-Site-Data",
    "X-Permitted-Cross-Domain-Policies",
    "Expect-CT",
    "Public-Key-Pins",
    "X-Content-Security-Policy",
    "X-Download-Options",
    "X-DNS-Prefetch-Control",
    "X-Robots-Tag",
    "X-Request-ID",
    "X-UA-Compatible",
]

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
        return []
    result_table = []
    for header in headers_to_check:
        if header in response_headers:
            result_table.append((header, response_headers[header], ""))
        else:
            result_table.append((header, "Not found", get_header_description(header)))
    return result_table

def get_header_description(header):
    descriptions = {
       
"X-Content-Type-Options":"""Tarayıcının dosyanın türünü değiştirmesini önler. Bu, potansiyel güvenlik açıklarını kapatır.
Öneri: Bu başlığı etkinleştirin ve "nosniff" değeri ile kullanın. Örnek: X-Content-Type-Options: nosniff""",

"X-Frame-Options":"""Web sitelerinin başka sitelerde çerçeve içinde görüntülenmesini engeller. Bu, sitenizin bütünlüğünü ve güvenliğini korur.
Öneri: Bu başlığı etkinleştirin ve "SAMEORIGIN" değeri ile kullanın. Örnek: X-Frame-Options: SAMEORIGIN""",

"Content-Security-Policy":"""Tarayıcıda yüklenebilecek kaynakları ve izin verilen eylemleri tanımlar. XSS gibi saldırılara karşı koruma sağlar.
Öneri: Güvenlik politikanızı oluşturun ve bu başlığı etkinleştirin. Örnek: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'""",

"Strict-Transport-Security":"""Tarayıcının sadece HTTPS üzerinden iletişim kurmasını zorlar. Veri iletimi sırasında güvenliği artırır.
Öneri: Bu başlığı etkinleştirin ve "max-age" değeri ile bir yıl gibi uzun bir süre belirleyin. Örnek: Strict-Transport-Security: max-age=31536000""",

"X-XSS-Protection":"""Tarayıcılara XSS saldırılarına karşı otomatik koruma sağlar. Zararlı kodların yürütülmesini engeller.
Öneri: Bu başlığı etkinleştirin ve "1; mode=block" değeri ile kullanın. Örnek: X-XSS-Protection: 1; mode=block""",

"Referrer-Policy":"""Tarayıcıların hangi bilgileri referer olarak gönderebileceğini belirler. Gizliliği ve güvenliği artırır.
Öneri: Bu başlığı etkinleştirin ve "no-referrer" veya "strict-origin" gibi uygun bir politika belirleyin. Örnek: Referrer-Policy: no-referrer""",

"Feature-Policy":"""Belirli tarayıcı özelliklerinin kullanımını sınırlar. Güvenliği ve gizliliği artırır.
Öneri: Tarayıcı özelliklerini sınırlamak için bu başlığı etkinleştirin ve uygun bir yapılandırmayı kullanın. Örnek: Feature-Policy: geolocation 'none'; camera 'self'""",

"Content-Security-Policy-Report-Only":"""Politika ihlallerini raporlamak için kullanılır, ancak tarayıcıya bir politika uygulanmaz. Güvenlik politikalarının izlenmesine yardımcı olur.
Öneri: Politika ihlali durumunda raporlar oluşturmak ve politikayı güncellemek için bu başlığı kullanabilirsiniz. Örnek: Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report-endpoint/""",

"Cache-Control":"""Açıklama: Tarayıcıların sayfanın önbelleğe alınma şeklini kontrol etmesini sağlar.
Öneri: Bu başlığı etkinleştirin ve önbellekleme davranışını belirleyin. Örnek: Cache-Control: no-cache, no-store, must-revalidate""",

"Clear-Site-Data":"""Tarayıcıya belirli verilerin önbelleğini temizlemesi için talimat verir. Gizliliği korur.
Öneri: Tarayıcı, belirli verileri temizlemek için bu başlığı kullanmalıdır. Örnek: Clear-Site-Data: 'cache', 'cookies'""",

"X-Permitted-Cross-Domain-Policies":"""Adobe Flash uygulamalarının farklı alanlardan veri almasını ve göndermesini kontrol eder.
Öneri: Bu başlığı etkinleştirin ve uygun bir yapılandırmayı kullanın. Örnek: X-Permitted-Cross-Domain-Policies: none""",

"Expect-CT":"""Sertifika geçerliliğini kontrol etme politikalarını belirler. Sertifika sorunlarını tespit eder ve raporlar.
Öneri: Bu başlığı etkinleştirin ve geçerlilik kontrol politikalarını belirleyin. Örnek: Expect-CT: enforce, max-age=3600""",  

"Public-Key-Pins":"""Tarayıcılara belirli bir SSL/TLS sertifikasını kullanmalarını emreder. Güvenliği artırır.
Öneri: Belirli bir sertifikayı kullanması gereken tarayıcıları belirtmek için bu başlığı etkinleştirin. Örnek: Public-Key-Pins: pin-sha256="base64+primary=="; max-age=5184000""",

"X-Content-Security-Policy":"""İçerik güvenliği politikalarını tanımlar.
Öneri: Tarayıcı, belirli içerik güvenliği politikalarını uygulamak için bu başlığı kullanmalıdır. Örnek: X-Content-Security-Policy: default-src 'self'""",

"X-Download-Options":"""Dosya indirme işlemlerini belirler.
Öneri: Tarayıcı, dosya indirme işlemlerini belirli bir şekilde işlemek için bu başlığı etkinleştirmelidir. Örnek: X-Download-Options: noopen""",

"X-DNS-Prefetch-Control":"""DNS önbellekleme davranışını kontrol eder.
Öneri: Tarayıcı, DNS önbellekleme davranışını yapılandırmaya izin veren bu başlığı etkinleştirmelidir. Örnek: X-DNS-Prefetch-Control: off""",

"X-Robots-Tag":"""Web tarayıcılarına ve arama motorlarına sayfanın dizinlenip dizinlenmeyeceğini belirtir.
Öneri: Sayfanızın dizinlenip dizinlenmeyeceğini belirlemek için bu başlığı etkinleştirin. Örnek: X-Robots-Tag: noindex, nofollow""",

"X-Request-ID":"""İstekleri benzersiz bir şekilde tanımlar ve izler.
Öneri: İstekleri izlemek ve yönetmek için bu başlığı kullanmalısınız. Örnek: X-Request-ID: unique-id""",

"X-UA-Compatible":"""Tarayıcıların sayfa uyumluluk modunu belirler.
Öneri: Tarayıcıların sayfanızın uyumluluk modunu doğru şekilde belirlemesi için bu başlığı etkinleştirin. Örnek: X-UA-Compatible: IE=edge"""

    }
    return descriptions.get(header, "Bu Başlık Kullanılıyor.")

def main():
    # Kullanım talimatlarını ve parametreleri göster
    if args.domain:
        console.print(f"[bold green]Geçerli Domain:[/bold green] {args.domain}")
        url = args.domain
        response_headers = get_response_headers(url)
        args.print= True
        if response_headers and args.print:
            console.print("\n[bold cyan]HTTP Response Headers[/bold cyan]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Başlık", style="bold green")
            table.add_column("Değer", style="bold white")
            for key, value in response_headers.items():
                table.add_row(key, value)
            console.print(table)
        if args.check or args.check_all:
            headers_to_check = args.check if args.check else default_headers
            checked_headers = check_headers(headers_to_check, response_headers)
            console.print("\n[bold cyan]Başlık Kontrolleri[/bold cyan]")
            table = Table(show_header=True, header_style="bold cyan")
            table = Table(show_lines=True, header_style="bold cyan")
            table.add_column("Başlık", style="bold red")
            table.add_column("Değer", style="bold yellow")
            table.add_column("Açıklama", style="bold white")
            for header, value, description in checked_headers:
                if header in response_headers:
                    table.add_row(header,value,"OK")
                else:
                    table.add_row(header, value, description)
                
            console.print(table)
            
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
            headers_to_check = args.check if args.check else default_headers
            checked_headers = check_headers(headers_to_check, response_headers)
            console.print("\n[bold cyan]Başlık Kontrolleri[/bold cyan]\n")
            table = Table(show_header=True, header_style="bold cyan")
            table = Table(show_lines=True, header_style="bold cyan")
            table.add_column("Başlık", style="bold red")
            table.add_column("Değer", style="bold yellow")
            table.add_column("Açıklama", style="bold white")
            for header, value, description in checked_headers:
                if header in response_headers:
                    table.add_row(header,value,"OK")
                    
                else:
                    table.add_row(header, value, description)
                
                
            console.print(table)
    else:
        console.print("[bold cyan]KOD KULLANIMI[/bold cyan]")
        console.print("=" * 30)
        console.print(
            """Bu tool, belirtilen bir domain veya hedef IP adresi için HTTP yanıt başlıklarını görüntüler.
Aynı zamanda eksik ve misconfigured headers hakkında çözüm önerileri sunar."""
        )
        console.print("\n[bold cyan]PARAMETRELER VE KULLANIMI[/bold cyan]")
        console.print("=" * 45)
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Parametre", style="bold red")
        table.add_column("Açıklama", style="bold white")
        table.add_row("-h ", "Help kütüphanesini getirir.")
        table.add_row("-d DOMAIN", "Domain adresini belirlemek için kullanılır.")
        table.add_row("-t TARGET_IP", "Hedef IP adresini belirlemek için kullanılır.")
        table.add_row("-c HEADER [HEADER ...]", "Belirli başlıkları kontrol etmek için kullanılır.")
        table.add_row("-C", "Tüm başlıkları kontrol etmek için kullanılır.")
        console.print(table)
        console.print("\n[bold cyan]KULLANIM ÖRNEKLERİ[/bold cyan]")
        console.print("=" * 30)
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Kullanım Örneği", style="bold red")
        table.add_column("Komut", style="bold white")
        table.add_row("Domain kontrolü örneği", "python3 httpcheck.py -d www.example.com")
        table.add_row("Hedef IP kontrolü örneği", "python3 httpcheck.py -t 192.168.1.1")
        table.add_row("Hedef IP kontrolü örneği", "python3 httpcheck.py -t 192.168.1.1 -c Server Date")
        table.add_row("Belirli başlıkları kontrol etme örneği", "python3 httpcheck.py -d www.example.com -c Server Date")
        table.add_row("Tüm başlıkları kontrol etme örneği", "python3 httpcheck.py -d example.com -C")
        console.print(table)

if __name__ == "__main__":
    main()