# Http Response Headers Check

### Giriş - Tanım

Bu Python tabanlı araç, HTTP yanıt başlıklarını kontrol etmek için tasarlanmıştır. HTTP, web tarayıcıları ve sunucular arasındaki iletişimde kullanılan temel bir protokoldür. Bu araç, verilen bir domain veya hedef IP adresinin HTTP yanıt başlıklarını inceleyerek eksik veya yanlış yapılandırılmış başlıkları tespit etmenizi sağlar. Bu başlıklar, web uygulamanızın güvenliği ve performansı için kritik öneme sahip olan ayarları içerir. Bu nedenle bu araç, web uygulamanızın sağlığını kontrol etmek ve düzeltmek için kullanabileceğiniz önemli bir yardımcıdır.


## Kullanım

Tool'u kullanmaya başlamak için aşağıdaki adımları izleyin:

| Adım | Açıklama |
| ---- | -------- |
| 1    | Bu repository'yi klonlayın: `https://github.com/istanboolean/HttpResponseHeadersCheck.git` |
| 2    | Klonladığınız dizine gidin: `cd HttpResponseHeadersCheck` |
| 3    | cd ile içine girin , HttpResponseCheck dosyasına girin. |
| 4    | dosya içini listelediğinizde "httpcheck.py" python dosyasını göreceksiniz. chmod +x ile dosyayı çalıştırılabilir duruma getirin.|
| 5    | Gerekli Python kütüphanelerini yükleyin: `pip install -r requirements.txt` Kütüphaneler otomatik yüklenir.|


                      Tool'u kullanın:    python3 httpcheck.py 
<img width="1171" alt="httpcheck" src="https://github.com/istanboolean/HttpResponseHeadersCheck/assets/98133561/e2f96ed8-c6d5-4c99-a1b3-ed1e101b372e">

                                                              

## Parametreler

  -Parametre-| -Açıklama-
| -----------| ------------------------------------------------------------|
-d DOMAIN    | Domain adresini belirlemek için kullanılır.
| -----------| ------------------------------------------------------------|
-t TARGET_IP | Hedef IP adresini belirlemek için kullanılır.
| -----------| ------------------------------------------------------------|
-p, --print | HTTP başlıklarını tablo şeklinde yazdırmak için kullanılır.
| -----------| ------------------------------------------------------------|
-c HEADER [HEADER ...] | Belirli başlıkları kontrol etmek için kullanılır.
| -----------| ------------------------------------------------------------|
-C | Tüm başlıkları kontrol etmek için kullanılır.
| -----------| ------------------------------------------------------------|



## Kullanım Örnekleri

Aşağıda, HTTP başlıklarını kontrol etmek için kullanabileceğiniz farklı örnekleri bulabilirsiniz:

| Örnek                                 | Komut                                          | Açıklama                                                               |
|-----------------------------------------|----------------------------------------------|------------------------------------------------------------------------|
| Domain kontrolü                         | `python3 httpcheck.py -d example.com`        | Belirtilen domain için HTTP başlıklarını kontrol eder.                 |
| Hedef IP kontrolü                       | `python3 httpcheck.py -t 192.168.1.33`       | Belirtilen IP adresi için HTTP başlıklarını kontrol eder.              |
| Domain kontrolü ve tabloyla görüntüleme | `python3 httpcheck.py -d example.com -p`     | HTTP başlıklarını tablo şeklinde görüntüler.                           |
| Belirli başlıkları kontrol etme         | `python3 httpcheck.py -d example.com -c Server Date` | Belirli başlıkları (örneğin, "Server" ve "Date") kontrol eder. |
| Tüm başlıkları kontrol etme             | `python3 httpcheck.py -d example.com -C`     | Tüm HTTP başlıklarını kontrol eder.                                    | 

## Kod Çalışması


Tool, "argparse" kütüphanesini kullanarak komut satırı argümanlarını işler ve kullanıcıdan girdi alır. "requests" kütüphanesini kullanarak HTTP istekleri gönderir ve yanıtları alır.
  "sys" kütüphanesini kullanarak Python yürütme ortamını kontrol eder. "rich" kütüphanesini kullanarak zengin metin çıktısı oluşturur.

Tool, belirtilen domain veya hedef IP adresine bir HTTP isteği gönderir. Yanıtın başlıkları, rich.table.Table sınıfı kullanılarak bir tablo şeklinde görüntülenir.

## Kullanılan Kütüphaneler

Bu aracı kullanmak için aşağıdaki Python kütüphanelerine ihtiyaç vardır:
|----------------------------------------------------------------------------------------------------|
| argparse:Komut satırı argümanlarını işlemek ve kullanıcıdan girdi almak için kullanılır.
| requests:HTTP istekleri göndermek ve yanıtları almak için kullanılır.
|sys: Python yürütme ortamını kontrol etmek için kullanılır.
|rich.console.Console:Zengin metin çıktısı oluşturmak için kullanılır.
|rich.table.Table:Tablo oluşturmak ve düzenlemek için kullanılır.
|rich.box:Tablo ve diğer bileşenlerin çerçevesini biçimlendirmek için kullanılır.

Ek Bilgiler

Tool, HTTP yanıt başlıklarının tümünü veya belirli başlıklarını görüntülemek için kullanılabilir.
Tool, tablo şeklinde zengin metin çıktısı oluşturur.
Tool, Python 3.6 veya üzeri sürümlerde çalışır.
